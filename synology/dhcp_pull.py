"""One-shot, standard-library DSM DHCP pull client. See dhcp_pull.ini.example."""

import argparse
import configparser
from datetime import datetime
import errno
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
    "inflight", "baseline", "pending", "last_report", "blocked",
}
DIAGNOSTICS = {
    "invalid_response", "destructive_not_authorized", "dsm_drift",
    "dsm_failed", "verification_failed", "baseline_changed",
    "recovery_required",
    "mapping_mismatch",
}
NEW_REPORT = object()


class SafeError(Exception):
    def __init__(self, code, diagnostic=None):
        self.code = code
        self.diagnostic = diagnostic


class FilesystemDiagnostic:
    """Only local paths and trusted, structured validation facts belong here."""
    def __init__(self, path, context, operation, failed, observed=None, expected=None):
        self.path = path
        self.context = context
        self.operation = operation
        self.failed = failed
        self.observed = observed
        self.expected = expected

    def render(self):
        path = json.dumps(str(self.path), ensure_ascii=True)
        if len(path) > 320:
            path = path[:320] + '..." [truncated]'
        detail = f"{self.context}: {self.operation} path={path}; failed={','.join(self.failed)}"
        if self.observed:
            detail += "; observed " + self.observed
        if self.expected:
            detail += "; expected " + self.expected
        return detail


def local_call(path, context, operation, function, *args, **kwargs):
    """Annotate only known local operations, preserving OSError handling."""
    try:
        return function(*args, **kwargs)
    except OSError as error:
        reason = {
            errno.ENOENT: "missing",
            errno.EACCES: "permission_denied",
            errno.EPERM: "permission_denied",
            errno.ELOOP: "symlink_rejected",
            errno.ENOTDIR: "not_directory_or_symlink_rejected",
            errno.EEXIST: "already_exists",
            errno.ENOSPC: "no_space",
            errno.EROFS: "read_only_filesystem",
            errno.EIO: "io_error",
        }.get(error.errno, "filesystem_error")
        error.diagnostic = FilesystemDiagnostic(
            path, context, operation, (reason,),
            observed=f"errno={error.errno}" if error.errno is not None else None,
        )
        raise


def require_absolute(path, code, context):
    if not path.is_absolute():
        raise SafeError(code, FilesystemDiagnostic(
            path, context, "validate path", ("nonabsolute_path",),
            observed="relative path", expected="absolute path",
        ))


def check_metadata(info, path, context, operation, code, *, directory=False,
                   parent=False, writable=False):
    euid = os.geteuid()
    mode = stat.S_IMODE(info.st_mode)
    kind = next((name for name, check in (
        ("symlink", stat.S_ISLNK), ("directory", stat.S_ISDIR),
        ("regular_file", stat.S_ISREG), ("fifo", stat.S_ISFIFO),
        ("socket", stat.S_ISSOCK), ("character_device", stat.S_ISCHR),
        ("block_device", stat.S_ISBLK),
    ) if check(info.st_mode)), "unknown")
    failed = []
    if directory and not stat.S_ISDIR(info.st_mode):
        failed.append("symlink" if kind == "symlink" else "nondirectory")
    elif not directory and not stat.S_ISREG(info.st_mode):
        failed.append("symlink" if kind == "symlink" else "not_regular_file")
    if info.st_uid not in ({0, euid} if parent else {euid}):
        failed.append("untrusted_owner")
    if parent:
        if mode & 0o022:
            failed.append("group_or_other_writable")
        expected = f"type=directory uid=0 or {euid} (euid) mode&0o0022=0"
    else:
        modes = {0o700} if directory else {0o600} if writable else {0o400, 0o600}
        if mode not in modes:
            failed.append("mode_not_private")
        expected = (f"type={'directory' if directory else 'regular_file'} uid={euid} (euid) "
                    "mode=" + " or ".join(f"0o{value:04o}" for value in sorted(modes)))
        if not directory:
            if info.st_nlink != 1:
                failed.append("link_count_not_one")
            expected += " nlink=1"
    if failed:
        raise SafeError(code, FilesystemDiagnostic(
            path, context, operation, tuple(failed),
            observed=f"type={kind} uid={info.st_uid} mode=0o{mode:04o} nlink={info.st_nlink} euid={euid}",
            expected=expected,
        ))


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
    require(isinstance(value["subnet"], str))
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
        require(len(payload["reservationData"]) <= MAX_RESERVATIONS)
        network = ipaddress.IPv4Network(value["subnet"], strict=True)
        require(str(network) == value["subnet"] and network.prefixlen == 24)
        for item in payload["reservationData"]:
            address = ipaddress.IPv4Address(item["ip"])
            require(address in network and address not in (network.network_address, network.broadcast_address))
    except (ValueError, TypeError):
        raise SafeError("invalid_response") from None
    require(digest(value["payload"]) == value["sha256"])
    require(payload["ifname"] == config["ifname"] and value["subnet"] == config["subnet"],
            "mapping_mismatch")
    return value


def etag(envelope):
    return '"' + envelope["version"] + '"'


def equal(left, right):
    return dsm_apply.canonical_lines(dsm_apply.validate_payload(left)) == \
        dsm_apply.canonical_lines(dsm_apply.validate_payload(right))


def secure_parents(path, context="local path"):
    """Reject symlinked or untrusted writable ancestors, not just the leaf."""
    require_absolute(path, "unsafe_path", context)
    for parent in reversed(path.parents):
        info = local_call(parent, context, "lstat ancestor", parent.lstat)
        check_metadata(info, parent, context, "validate ancestor", "unsafe_path",
                       directory=True, parent=True)


def secure_file(fd, writable=False, *, path="<open file>", context="local file"):
    info = local_call(path, context, "fstat file", os.fstat, fd)
    check_metadata(info, path, context, "validate file", "unsafe_file", writable=writable)


def read_private(path, maximum, context="private file"):
    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd() / path
    secure_parents(path, context)
    fd = local_call(path, context, "open file (no symlinks)", os.open,
                    path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as file:
        secure_file(file.fileno(), path=path, context=context)
        body = local_call(path, context, "read file", file.read, maximum + 1)
        require(len(body) <= maximum, "size_limit")
        return body


def load_config(path):
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(read_private(path, MAX_CONFIG, "config").decode("utf-8"))
        require(parser.sections() == ["dhcp_pull"] and not parser.defaults(), "invalid_config")
        section = parser["dhcp_pull"]
        require(set(section) <= {
            "base_url", "allow_http_over_vpn", "site_id", "ifname", "subnet", "token",
            "state_dir", "timeout", "ca_file",
        }, "invalid_config")
        config = dict(section)
        allow_http = config.get("allow_http_over_vpn", "false")
        require(allow_http in {"true", "false"}, "invalid_config")
        config["allow_http_over_vpn"] = allow_http == "true"
        url = urllib.parse.urlsplit(config["base_url"])
        require((url.scheme == "https" or (url.scheme == "http" and config["allow_http_over_vpn"]))
                and url.hostname and not url.username and not url.password
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
        require_absolute(config["state_dir"], "invalid_config", "state")
        if config.get("ca_file"):
            config["ca_file"] = str(Path(config["ca_file"]))
            require_absolute(Path(config["ca_file"]), "invalid_config", "CA")
        return config
    except (ValueError, KeyError, configparser.Error, UnicodeError):
        raise SafeError("invalid_config") from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, url):
        return None


class Transport:
    def __init__(self, config):
        self.config = config
        if config.get("ca_file"):
            ca_data = read_private(config["ca_file"], MAX_BODY, "CA").decode("ascii")
            context = ssl.create_default_context(cadata=ca_data)
        else:
            context = ssl.create_default_context()
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
                baseline=None, pending=None, last_report=None, blocked=False)


def acknowledgement(envelope, status, diagnostic=None, *, report_id=NEW_REPORT):
    result = dict(schema_version=1, version=envelope["version"], sha256=envelope["sha256"], status=status)
    if report_id is NEW_REPORT:
        report_id = str(uuid.uuid4())
    if report_id is not None:
        result["report_id"] = report_id
    if diagnostic:
        require(diagnostic in DIAGNOSTICS, "invalid_state")
        result["diagnostic"] = diagnostic
    return result


def queue_ack(state, envelope, status, diagnostic=None):
    expected = acknowledgement(envelope, status, diagnostic, report_id=None)
    pending = state["pending"]
    if pending is not None and {key: value for key, value in pending.items() if key != "report_id"} == expected:
        return
    state["pending"] = acknowledgement(envelope, status, diagnostic)


def validate_state(state, config):
    if isinstance(state, dict) and set(state) == STATE_KEYS - {"last_report"}:
        state["last_report"] = None
    require(isinstance(state, dict) and set(state) == STATE_KEYS, "invalid_state")
    initial = empty_state(config)
    for key in ("schema_version", "site_id", "ifname", "subnet"):
        require(type(state[key]) is type(initial[key]) and state[key] == initial[key], "invalid_state")
    require(type(state["blocked"]) is bool, "invalid_state")
    last = state["last_report"]
    if last is not None:
        require(isinstance(last, dict) and set(last) == {"version", "sha256", "status"}, "invalid_state")
        require(isinstance(last["version"], str) and
                re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", last["version"]), "invalid_state")
        require(isinstance(last["sha256"], str) and
                re.fullmatch(r"[0-9a-f]{64}", last["sha256"]), "invalid_state")
        require(last["status"] in {"applied", "failed", "rejected"}, "invalid_state")
    for key in ("fetched", "applied", "inflight"):
        if state[key] is not None:
            validate_envelope(state[key], config)
    require((state["inflight"] is None) == (state["baseline"] is None), "invalid_state")
    if state["baseline"] is not None:
        baseline = dsm_apply.validate_payload(state["baseline"])
        require(baseline["ifname"] == config["ifname"] and
                len(baseline["reservationData"]) <= MAX_RESERVATIONS, "invalid_state")
    pending = state["pending"]
    if pending is not None:
        require(isinstance(pending, dict) and set(pending) in (
            {"schema_version", "version", "sha256", "status"},
            {"schema_version", "version", "sha256", "status", "diagnostic"},
            {"schema_version", "version", "sha256", "status", "report_id"},
            {"schema_version", "version", "sha256", "status", "diagnostic", "report_id"},
        ), "invalid_state")
        report_id = pending.get("report_id")
        if "report_id" in pending:
            require(isinstance(report_id, str) and len(report_id) == 36, "invalid_state")
            try:
                identifier = uuid.UUID(report_id)
                require(identifier.int != 0 and str(identifier) == report_id, "invalid_state")
            except ValueError:
                raise SafeError("invalid_state") from None
        require(type(pending["schema_version"]) is int and pending["schema_version"] == 1,
                "invalid_state")
        require(isinstance(pending["version"], str) and
                re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", pending["version"]), "invalid_state")
        require(isinstance(pending["sha256"], str) and
                re.fullmatch(r"[0-9a-f]{64}", pending["sha256"]), "invalid_state")
        require(pending["status"] in {"applied", "failed", "rejected"}, "invalid_state")
        if "diagnostic" in pending:
            require(pending["diagnostic"] in DIAGNOSTICS, "invalid_state")
        matches = [state[key] for key in ("fetched", "applied", "inflight")
                   if state[key] is not None and state[key]["version"] == pending["version"] and
                   state[key]["sha256"] == pending["sha256"]]
        minimal_rejection = pending["status"] == "rejected" and pending.get("diagnostic") == "mapping_mismatch"
        require(minimal_rejection or
                (matches and pending == acknowledgement(
                    matches[0], pending["status"], pending.get("diagnostic"), report_id=report_id,
                )),
                "invalid_state")
        if pending["status"] == "applied":
            require(state["applied"] is not None and
                    pending == acknowledgement(state["applied"], "applied", report_id=report_id), "invalid_state")
    return state


class Store:
    def __init__(self, config):
        self.config = config
        self.path = config["state_dir"]
        self.fd = None
        self.lock = None

    def __enter__(self):
        try:
            secure_parents(self.path, "state")
            created = False
            try:
                local_call(self.path, "state", "mkdir", self.path.mkdir, mode=0o700)
                created = True
            except FileExistsError:
                pass
            self.fd = local_call(self.path, "state", "open directory (no symlinks)", os.open,
                                 self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = local_call(self.path, "state", "fstat directory", os.fstat, self.fd)
            check_metadata(info, self.path, "state", "validate directory", "unsafe_directory",
                           directory=True)
            if created:
                parent = local_call(self.path.parent, "state", "open parent for sync", os.open,
                                    self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    local_call(self.path.parent, "state", "sync parent", os.fsync, parent)
                finally:
                    os.close(parent)
            self.lock = local_call(
                self.path / "lock", "state lock", "open file (no symlinks)", os.open,
                "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.fd,
            )
            secure_file(self.lock, writable=True, path=self.path / "lock", context="state lock")
            try:
                local_call(self.path / "lock", "state lock", "lock file", fcntl.flock,
                           self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
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
            fd = local_call(self.path / "state.json", "state", "open file (no symlinks)", os.open,
                            "state.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        except FileNotFoundError:
            return empty_state(self.config)
        with os.fdopen(fd, "rb") as file:
            secure_file(file.fileno(), writable=True, path=self.path / "state.json", context="state")
            body = local_call(self.path / "state.json", "state", "read file", file.read, MAX_STATE + 1)
            require(len(body) <= MAX_STATE, "size_limit")
            return validate_state(parse_json(body), self.config)

    def save(self, state):
        validate_state(state, self.config)
        body = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        require(len(body) <= MAX_STATE, "size_limit")
        # Never replace an unexpected leaf (including a hardlink).
        try:
            old = local_call(self.path / "state.json", "state", "open file before replace", os.open,
                             "state.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        except FileNotFoundError:
            pass
        else:
            try:
                secure_file(old, writable=True, path=self.path / "state.json", context="state")
            finally:
                os.close(old)
        name = ".state-" + uuid.uuid4().hex
        try:
            path = self.path / name
            fd = local_call(path, "state", "create temporary file", os.open,
                            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=self.fd)
            with os.fdopen(fd, "wb") as file:
                local_call(path, "state", "write temporary file", file.write, body)
                local_call(path, "state", "flush temporary file", file.flush)
                local_call(path, "state", "sync temporary file", os.fsync, file.fileno())
            local_call(self.path / "state.json", "state", "replace file", os.replace,
                       name, "state.json", src_dir_fd=self.fd, dst_dir_fd=self.fd)
            local_call(self.path, "state", "sync directory", os.fsync, self.fd)
        finally:
            try:
                local_call(self.path / name, "state", "remove temporary file", os.unlink,
                           name, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def backup(self, response, payload):
        directory = self.path / "backups"
        try:
            local_call(directory, "backups", "mkdir", directory.mkdir, mode=0o700)
        except FileExistsError:
            pass
        info = local_call(directory, "backups", "lstat directory", directory.lstat)
        check_metadata(info, directory, "backups", "validate directory", "unsafe_directory",
                       directory=True)
        backup = local_call(directory, "backups", "create backup", dsm_apply.backup_reservations,
                            directory, response, payload)
        for path in (backup, directory):
            fd = local_call(path, "backups", "open directory for sync", os.open,
                            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                local_call(path, "backups", "sync directory", os.fsync, fd)
            finally:
                os.close(fd)
        local_call(self.path, "state", "sync directory", os.fsync, self.fd)
        self.prune_backups(directory, backup)

    def prune_backups(self, directory, newest):
        """Only remove complete, private backups made by the shared helper."""
        fd = local_call(directory, "backups", "open directory (no symlinks)", os.open,
                        directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened = []
        try:
            pattern = re.compile(
                r"dsm-" + re.escape(self.config["ifname"]) +
                r"-\d{8}T\d{12}Z-[A-Za-z0-9_-]{8}",
            )
            names = local_call(directory, "backups", "list directory", os.listdir, fd)
            for name in names:
                path = directory / name
                if not pattern.fullmatch(name):
                    raise SafeError("unsafe_backup", FilesystemDiagnostic(
                        path, "backups", "validate name", ("unexpected_backup_name",),
                        expected="backup name generated by the DSM helper",
                    ))
                child = local_call(path, "backups", "open directory (no symlinks)", os.open,
                                   name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                opened.append((name, child))
                info = local_call(path, "backups", "fstat directory", os.fstat, child)
                check_metadata(info, path, "backups", "validate directory", "unsafe_backup",
                               directory=True)
                if set(local_call(path, "backups", "list directory", os.listdir, child)) != {
                        "response.json", "reservations.json"}:
                    raise SafeError("unsafe_backup", FilesystemDiagnostic(
                        path, "backups", "validate contents", ("unexpected_backup_contents",),
                        expected="only response.json and reservations.json",
                    ))
                for filename in ("response.json", "reservations.json"):
                    file = local_call(path / filename, "backups", "open file (no symlinks)", os.open,
                                      filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=child)
                    try:
                        secure_file(file, writable=True, path=path / filename, context="backups")
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
        status, _, body = transport.request("POST", "results", state["pending"])
        require(status == 200, "invalid_ack")
        receipt = parse_json(body)
        require(isinstance(receipt, dict) and set(receipt) == {"status"} and
                receipt["status"] == state["pending"]["status"], "invalid_ack")
    except SafeError:
        return False
    state["last_report"] = {key: state["pending"][key] for key in ("version", "sha256", "status")}
    state["pending"] = None
    store.save(state)
    return True


def reject(transport, store, state, envelope, code):
    state["fetched"] = envelope
    queue_ack(state, envelope, "rejected", code)
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
            raw = parse_json(body)
            try:
                envelope = validate_envelope(raw, config)
            except SafeError as error:
                if error.code != "mapping_mismatch":
                    raise
                require(received_tag is None or received_tag == etag(raw))
                queue_ack(state, raw, "rejected", "mapping_mismatch")
                store.save(state)
                report(transport, store, state)
                return 2
            require(received_tag is None or received_tag == etag(envelope))
        try:
            response, live = read_live(config)
        except (ValueError, OSError, subprocess.SubprocessError, SafeError):
            state["fetched"] = envelope
            queue_ack(state, envelope, "failed", "dsm_failed")
            store.save(state)
            report(transport, store, state)
            return 1
        if state["inflight"] is not None:
            attempt = state["inflight"]
            if equal(live, attempt["payload"]):
                state["applied"] = attempt
                queue_ack(state, attempt, "applied")
                state["blocked"] = False
            elif equal(live, state["baseline"]):
                state["blocked"] = False
            else:
                state["blocked"] = True
                state["fetched"] = attempt
                queue_ack(state, attempt, "failed", "recovery_required")
            state["inflight"] = None
            state["baseline"] = None
            store.save(state)
        drift = state["applied"] is not None and not equal(live, state["applied"]["payload"])
        if drift and state["pending"] is not None and state["pending"]["status"] == "applied":
            queue_ack(state, state["applied"], "rejected", "dsm_drift")
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
            delivered = {"version": envelope["version"], "sha256": envelope["sha256"], "status": "applied"}
            if state["applied"] == envelope and not state["blocked"] and state["last_report"] == delivered:
                return 0
            state["applied"] = envelope
            state["blocked"] = False
            queue_ack(state, envelope, "applied")
            store.save(state)
            return 0 if report(transport, store, state) else 1
        try:
            store.backup(response, live)
            _, latest = read_live(config)
            if not equal(live, latest):
                return reject(transport, store, state, envelope, "baseline_changed")
            state["inflight"] = envelope
            state["baseline"] = live
            store.save(state)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            # No DSM write occurred. Never acknowledge an undurable attempt.
            raise SafeError("persistence_failed", getattr(error, "diagnostic", None)) from None
        diagnostic = "dsm_failed"
        try:
            dsm_apply.call_api("set", config["ifname"], desired["reservationData"], max_output=MAX_BODY)
            diagnostic = "verification_failed"
            _, verified = read_live(config)
            require(equal(verified, desired), diagnostic)
        except (ValueError, OSError, subprocess.SubprocessError, SafeError):
            queue_ack(state, envelope, "failed", diagnostic)
            store.save(state)
            report(transport, store, state)
            return 1
        state["applied"] = envelope
        state["inflight"] = None
        state["baseline"] = None
        state["blocked"] = False
        queue_ack(state, envelope, "applied")
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
        detail = " " + error.diagnostic.render() if error.diagnostic is not None else ""
        print("DHCP pull stopped: " + error.code + "." + detail, file=sys.stderr)
        return 3 if error.code == "already_running" else 1
    except (OSError, ValueError, subprocess.SubprocessError, RecursionError, TypeError) as error:
        diagnostic = getattr(error, "diagnostic", None) if isinstance(error, OSError) else None
        detail = " " + diagnostic.render() if diagnostic is not None else ""
        print("DHCP pull stopped: local_or_transport_failure." + detail, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
