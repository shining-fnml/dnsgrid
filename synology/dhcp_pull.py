"""One-shot, standard-library DSM DHCP pull client. See dhcp_pull.ini.example."""

import argparse
import configparser
from datetime import datetime
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

try:
    from . import dsm_apply
except ImportError:
    import dsm_apply


MAX_BODY = 1024 * 1024
MAX_STATE = 4 * MAX_BODY
MAX_CONFIG = 16384
MAX_RESERVATIONS = 4096
BACKUP_LIMIT = 20
ENVELOPE_KEYS = {
    "schema_version", "site_id", "subnet", "version", "sha256",
    "published_at", "destructive_authorized", "payload",
}
STATE_KEYS = {
    "schema_version", "site_id", "ifname", "subnet", "fetched", "applied",
    "inflight", "pending", "blocked",
}
DIAGNOSTICS = {
    "invalid_response", "destructive_not_authorized", "dsm_drift",
    "dsm_failed", "verification_failed", "baseline_changed",
    "recovery_required",
}


class SafeError(Exception):
    def __init__(self, code):
        self.code = code


def require(condition, code="invalid_response"):
    if not condition:
        raise SafeError(code)


def digest(payload):
    return hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")).hexdigest()


def parse_json(body):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    try:
        return json.loads(body, object_pairs_hook=pairs, parse_constant=lambda _: require(False))
    except (ValueError, UnicodeError, RecursionError):
        raise SafeError("invalid_response") from None


def validate_envelope(value, config):
    require(isinstance(value, dict) and set(value) == ENVELOPE_KEYS)
    require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    require(type(value["site_id"]) is int and value["site_id"] == config["site_id"])
    require(value["subnet"] == config["subnet"])
    require(isinstance(value["version"], str) and
            re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value["version"]))
    require(isinstance(value["sha256"], str) and
            re.fullmatch(r"[0-9a-f]{64}", value["sha256"]))
    require(type(value["destructive_authorized"]) is bool)
    published = value["published_at"]
    require(isinstance(published, str) and len(published) <= 64 and
            re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", published))
    try:
        require(datetime.fromisoformat(published.replace("Z", "+00:00")).tzinfo is not None)
        payload = dsm_apply.validate_payload(value["payload"])
        require(payload["ifname"] == config["ifname"])
        require(len(payload["reservationData"]) <= MAX_RESERVATIONS)
        network = ipaddress.IPv4Network(config["subnet"])
        for item in payload["reservationData"]:
            address = ipaddress.IPv4Address(item["ip"])
            require(address in network and address not in (network.network_address, network.broadcast_address))
    except (ValueError, TypeError):
        raise SafeError("invalid_response") from None
    require(digest(value["payload"]) == value["sha256"])
    return value


def etag(envelope):
    return '"' + envelope["version"] + '"'


def equal(left, right):
    return dsm_apply.canonical_lines(dsm_apply.validate_payload(left)) == \
        dsm_apply.canonical_lines(dsm_apply.validate_payload(right))


def secure_parents(path):
    """Reject symlinked or untrusted writable ancestors, not just the leaf."""
    require(path.is_absolute(), "unsafe_path")
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in {0, os.geteuid()} and
                not info.st_mode & 0o022, "unsafe_path")


def secure_file(fd, writable=False):
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            info.st_nlink == 1 and
            stat.S_IMODE(info.st_mode) in ({0o600} if writable else {0o400, 0o600}), "unsafe_file")


def read_private(path, maximum):
    path = Path(os.path.abspath(path))
    secure_parents(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as file:
        secure_file(file.fileno())
        body = file.read(maximum + 1)
        require(len(body) <= maximum, "size_limit")
        return body


def load_config(path):
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(read_private(path, MAX_CONFIG).decode("utf-8"))
        require(parser.sections() == ["dhcp_pull"] and not parser.defaults(), "invalid_config")
        section = parser["dhcp_pull"]
        require(set(section) <= {
            "base_url", "site_id", "ifname", "subnet", "token", "state_dir", "timeout", "ca_file",
        }, "invalid_config")
        config = dict(section)
        url = urllib.parse.urlsplit(config["base_url"])
        require(url.scheme == "https" and url.hostname and not url.username and not url.password
                and not url.query and not url.fragment and
                not any(ord(char) <= 32 or ord(char) == 127 for char in config["base_url"]),
                "invalid_config")
        # Force port validation here, before any credential-bearing request.
        url.port
        config["base_url"] = config["base_url"].rstrip("/")
        config["site_id"] = int(config["site_id"])
        require(config["site_id"] > 0 and str(config["site_id"]) == section["site_id"], "invalid_config")
        require(re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", config["ifname"]), "invalid_config")
        network = ipaddress.IPv4Network(config["subnet"], strict=True)
        require(str(network) == config["subnet"] and network.prefixlen == 24, "invalid_config")
        token = config["token"]
        require(16 <= len(token) <= 256 and token != "CHANGE_ME_BEFORE_USE" and
                re.fullmatch(r"[A-Za-z0-9_.~-]+", token), "invalid_config")
        config["timeout"] = int(config.get("timeout", "30"))
        require(1 <= config["timeout"] <= 120, "invalid_config")
        config["state_dir"] = Path(config["state_dir"])
        require(config["state_dir"].is_absolute(), "invalid_config")
        if config.get("ca_file"):
            config["ca_file"] = str(Path(config["ca_file"]))
            require(Path(config["ca_file"]).is_absolute(), "invalid_config")
        return config
    except (ValueError, KeyError, configparser.Error, UnicodeError):
        raise SafeError("invalid_config") from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, url):
        return None


class Transport:
    def __init__(self, config):
        self.config = config
        context = ssl.create_default_context(cafile=config.get("ca_file") or None)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect(),
        )

    def request(self, method, resource, body=None, conditional=None):
        url = self.config["base_url"] + "/api/dhcp/sites/" + str(self.config["site_id"]) + "/" + resource + "/"
        headers = {"Authorization": "Bearer " + self.config["token"], "Accept": "application/json"}
        if conditional:
            headers["If-None-Match"] = conditional
        if body is not None:
            body = json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        deadline = time.monotonic() + self.config["timeout"]
        try:
            try:
                response = self.opener.open(request, timeout=self.config["timeout"])
            except urllib.error.HTTPError as error:
                if method == "GET" and error.code == 304:
                    response = error
                else:
                    error.close()
                    raise SafeError("http_failed") from None
            with response:
                status = response.code
                require((method == "GET" and status in {200, 304}) or
                        (method == "POST" and status in {200, 201, 202, 204}), "http_failed")
                length = response.headers.get("Content-Length")
                if length is not None:
                    require(length.isdigit() and int(length) <= MAX_BODY, "size_limit")
                chunks, count = [], 0
                while True:
                    require(time.monotonic() <= deadline, "network_timeout")
                    chunk = response.read1(min(65536, MAX_BODY - count + 1))
                    if not chunk:
                        break
                    count += len(chunk)
                    require(count <= MAX_BODY, "size_limit")
                    chunks.append(chunk)
                return status, response.headers.get("ETag"), b"".join(chunks)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, http.client.HTTPException):
            raise SafeError("network_failed") from None


def empty_state(config):
    return dict(schema_version=1, site_id=config["site_id"], ifname=config["ifname"],
                subnet=config["subnet"], fetched=None, applied=None, inflight=None,
                pending=None, blocked=False)


def acknowledgement(envelope, status, diagnostic=None):
    result = dict(schema_version=1, version=envelope["version"], sha256=envelope["sha256"], status=status)
    if diagnostic:
        require(diagnostic in DIAGNOSTICS, "invalid_state")
        result["diagnostic"] = diagnostic
    return result


def validate_state(state, config):
    require(isinstance(state, dict) and set(state) == STATE_KEYS, "invalid_state")
    initial = empty_state(config)
    for key in ("schema_version", "site_id", "ifname", "subnet"):
        require(type(state[key]) is type(initial[key]) and state[key] == initial[key], "invalid_state")
    require(type(state["blocked"]) is bool, "invalid_state")
    for key in ("fetched", "applied", "inflight"):
        if state[key] is not None:
            validate_envelope(state[key], config)
    pending = state["pending"]
    if pending is not None:
        require(isinstance(pending, dict) and set(pending) in (
            {"schema_version", "version", "sha256", "status"},
            {"schema_version", "version", "sha256", "status", "diagnostic"},
        ), "invalid_state")
        require(pending["status"] in {"applied", "failed", "rejected"}, "invalid_state")
        if "diagnostic" in pending:
            require(pending["diagnostic"] in DIAGNOSTICS, "invalid_state")
        matches = [state[key] for key in ("fetched", "applied", "inflight")
                   if state[key] is not None and state[key]["version"] == pending["version"] and
                   state[key]["sha256"] == pending["sha256"]]
        require(matches and pending == acknowledgement(matches[0], pending["status"], pending.get("diagnostic")),
                "invalid_state")
        if pending["status"] == "applied":
            require(state["applied"] is not None and
                    pending == acknowledgement(state["applied"], "applied"), "invalid_state")
    return state


class Store:
    def __init__(self, config):
        self.config = config
        self.path = config["state_dir"]
        self.fd = None
        self.lock = None

    def __enter__(self):
        try:
            secure_parents(self.path)
            created = False
            try:
                self.path.mkdir(mode=0o700)
                created = True
            except FileExistsError:
                pass
            self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(self.fd)
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, "unsafe_directory")
            if created:
                parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
            self.lock = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                0o600, dir_fd=self.fd)
            secure_file(self.lock, writable=True)
            try:
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SafeError("already_running") from None
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def load(self):
        try:
            fd = os.open("state.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        except FileNotFoundError:
            return empty_state(self.config)
        with os.fdopen(fd, "rb") as file:
            secure_file(file.fileno(), writable=True)
            body = file.read(MAX_STATE + 1)
            require(len(body) <= MAX_STATE, "size_limit")
            return validate_state(parse_json(body), self.config)

    def save(self, state):
        validate_state(state, self.config)
        body = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        require(len(body) <= MAX_STATE, "size_limit")
        # Never replace an unexpected leaf (including a hardlink).
        try:
            old = os.open("state.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        except FileNotFoundError:
            pass
        else:
            try:
                secure_file(old, writable=True)
            finally:
                os.close(old)
        name = ".state-" + uuid.uuid4().hex
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            with os.fdopen(fd, "wb") as file:
                file.write(body)
                file.flush()
                os.fsync(file.fileno())
            os.replace(name, "state.json", src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(name, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def backup(self, response, payload):
        directory = self.path / "backups"
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o700, "unsafe_directory")
        backup = dsm_apply.backup_reservations(directory, response, payload)
        for path in (backup, directory):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        os.fsync(self.fd)
        self.prune_backups(directory, backup)

    def prune_backups(self, directory, newest):
        """Only remove complete, private backups made by the shared helper."""
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened = []
        try:
            pattern = re.compile(
                r"dsm-" + re.escape(self.config["ifname"]) +
                r"-\d{8}T\d{12}Z-[A-Za-z0-9_-]{8}",
            )
            names = os.listdir(fd)
            for name in names:
                require(pattern.fullmatch(name), "unsafe_backup")
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                opened.append((name, child))
                info = os.fstat(child)
                require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                        "unsafe_backup")
                require(set(os.listdir(child)) == {"response.json", "reservations.json"}, "unsafe_backup")
                for filename in ("response.json", "reservations.json"):
                    file = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=child)
                    try:
                        secure_file(file, writable=True)
                    finally:
                        os.close(file)
            keep = {name for name in sorted(names, reverse=True)[:BACKUP_LIMIT]}
            # Clock adjustments must not cause deletion of the just-created backup.
            if newest.name not in keep:
                keep.discard(min(keep))
                keep.add(newest.name)
            for name, child in opened:
                if name in keep:
                    continue
                for filename in ("response.json", "reservations.json"):
                    os.unlink(filename, dir_fd=child)
                os.fsync(child)
                os.rmdir(name, dir_fd=fd)
            os.fsync(fd)
        finally:
            for _, child in opened:
                os.close(child)
            os.close(fd)


def read_live(config):
    response = dsm_apply.call_api("get", config["ifname"], max_output=MAX_BODY)
    payload = dsm_apply.current_payload(response, config["ifname"])
    require(len(payload["reservationData"]) <= MAX_RESERVATIONS, "dsm_failed")
    return response, payload


def report(transport, store, state):
    if state["pending"] is None:
        return True
    try:
        transport.request("POST", "results", state["pending"])
    except SafeError:
        return False
    state["pending"] = None
    store.save(state)
    return True


def reject(transport, store, state, envelope, code):
    state["fetched"] = envelope
    state["pending"] = acknowledgement(envelope, "rejected", code)
    store.save(state)
    report(transport, store, state)
    return 2


def run(config, reconcile=False):
    with Store(config) as store:
        state = store.load()
        transport = Transport(config)
        conditional = etag(state["applied"]) if state["applied"] else None
        status, received_tag, body = transport.request("GET", "latest", conditional=conditional)
        if status == 304:
            require(conditional is not None and not body)
            require(received_tag is None or received_tag == conditional)
            envelope = state["applied"]
        else:
            envelope = validate_envelope(parse_json(body), config)
            require(received_tag is None or received_tag == etag(envelope))
        try:
            response, live = read_live(config)
        except (ValueError, OSError, subprocess.SubprocessError, SafeError):
            state["fetched"] = envelope
            state["pending"] = acknowledgement(envelope, "failed", "dsm_failed")
            store.save(state)
            report(transport, store, state)
            return 1
        if state["inflight"] is not None:
            attempt = state["inflight"]
            if equal(live, attempt["payload"]):
                state["applied"] = attempt
                state["pending"] = acknowledgement(attempt, "applied")
                state["blocked"] = False
            else:
                state["blocked"] = True
                state["fetched"] = attempt
                state["pending"] = acknowledgement(attempt, "failed", "recovery_required")
            state["inflight"] = None
            store.save(state)
        drift = state["applied"] is not None and not equal(live, state["applied"]["payload"])
        if drift and state["pending"] is not None and state["pending"]["status"] == "applied":
            state["pending"] = acknowledgement(state["applied"], "rejected", "dsm_drift")
            store.save(state)
        if (drift or state["blocked"]) and not reconcile:
            # Preserve an undelivered report, but never claim applied after drift.
            if state["pending"] is not None:
                if not report(transport, store, state):
                    return 1
            return reject(transport, store, state, envelope, "dsm_drift")
        if not report(transport, store, state):
            return 1
        # Reusing a version with different content or authorization is invalid.
        for known in (state["applied"], state["fetched"]):
            if known is not None and known["version"] == envelope["version"]:
                require(known == envelope)
        state["fetched"] = envelope
        desired = envelope["payload"]
        new_count = len(desired["reservationData"])
        baseline = max(len(live["reservationData"]),
                       len(state["applied"]["payload"]["reservationData"]) if state["applied"] else 0)
        if (new_count == 0 or new_count * 2 < baseline) and not envelope["destructive_authorized"]:
            return reject(transport, store, state, envelope, "destructive_not_authorized")
        if equal(live, desired):
            if state["applied"] == envelope and not state["blocked"]:
                return 0
            state["applied"] = envelope
            state["blocked"] = False
            state["pending"] = acknowledgement(envelope, "applied")
            store.save(state)
            return 0 if report(transport, store, state) else 1
        try:
            store.backup(response, live)
            _, latest = read_live(config)
            if not equal(live, latest):
                return reject(transport, store, state, envelope, "baseline_changed")
            state["inflight"] = envelope
            store.save(state)
        except (ValueError, OSError, subprocess.SubprocessError):
            # No DSM write occurred. Never acknowledge an undurable attempt.
            raise SafeError("persistence_failed") from None
        diagnostic = "dsm_failed"
        try:
            dsm_apply.call_api("set", config["ifname"], desired["reservationData"], max_output=MAX_BODY)
            diagnostic = "verification_failed"
            _, verified = read_live(config)
            require(equal(verified, desired), diagnostic)
        except (ValueError, OSError, subprocess.SubprocessError, SafeError):
            state["pending"] = acknowledgement(envelope, "failed", diagnostic)
            store.save(state)
            report(transport, store, state)
            return 1
        state["applied"] = envelope
        state["inflight"] = None
        state["blocked"] = False
        state["pending"] = acknowledgement(envelope, "applied")
        store.save(state)
        return 0 if report(transport, store, state) else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Pull, validate and apply DSM IPv4 reservations once.")
    parser.add_argument("--config", required=True, type=Path, help="private dhcp_pull.ini file")
    parser.add_argument("--reconcile", action="store_true", help="operator-reviewed drift reconciliation for this run only")
    options = parser.parse_args(argv)
    try:
        result = run(load_config(options.config), options.reconcile)
        print({0: "DHCP pull completed.", 1: "DHCP pull failed; retry required.",
               2: "DHCP pull rejected; operator review required."}[result])
        return result
    except SafeError as error:
        print("DHCP pull stopped: " + error.code + ".", file=sys.stderr)
        return 3 if error.code == "already_running" else 1
    except (OSError, ValueError, subprocess.SubprocessError, RecursionError, TypeError):
        print("DHCP pull stopped: local_or_transport_failure.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
