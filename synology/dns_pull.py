"""Standalone NAS DNS installer (stdlib only); never restarts or reloads DNS.

Administrator-owned /etc/dnsgrid-dns-pull.ini:
    [dns_pull]
    source_host = hub.example.net
    source_user = dnsreader
    source_port = 22
    source_directory = /srv/dnsgrid/export
    identity_file = /etc/dnsgrid/read_key
    known_hosts = /etc/dnsgrid/known_hosts
    backup_directory = /volume1/dnsgrid-backups
    named_checkzone = /usr/bin/named-checkzone
    # destination_directory defaults to DSM's master zone directory.

Forced SSH request example: dnsgrid-update dnsgrid-2026100801 2026100801.
Exit codes: 0 success, 2 input/configuration, 3 busy, 4 transfer,
5 validation, 6 installation failed/rolled back, 7 rollback incomplete.
Per-file replacements are atomic; the whole set is not. Retain backups for
administrator recovery. Strict SFTP/read-only access must be set up on the hub;
SSH key restrictions alone do not restrict filesystem access.
"""

import argparse
from contextlib import contextmanager
import configparser
from datetime import date, datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import stat
import subprocess
import sys
import tempfile


MAX_MANIFEST = 128 * 1024
MAX_ZONE = 4 * 1024 * 1024
MAX_ZONES = 256
TIMEOUT = 120
DEFAULT_DESTINATION = "/volume1/@appstore/DNSServer/named/etc/zone/master"
STATE_NAME = ".dnsgrid-state.json"
LOCK_NAME = ".dnsgrid-pull.lock"


class PullError(Exception):
    def __init__(self, message, code=2):
        super().__init__(message)
        self.code = code


def validate_request(generation, serial):
    if not isinstance(serial, str) or not re.fullmatch(r"[0-9]{10}", serial):
        raise PullError("Serial must be a ten-digit YYYYMMDDnn value.")
    value = int(serial)
    try:
        date(int(serial[:4]), int(serial[4:6]), int(serial[6:8]))
    except ValueError:
        raise PullError("Serial contains an invalid date.") from None
    if value > 0xFFFFFFFF or generation != "dnsgrid-" + serial:
        raise PullError("Invalid generation or unsigned 32-bit serial.")
    return generation, value


def valid_zone(name):
    return (
        isinstance(name, str) and name != "manifest.json" and len(name) <= 253 and "." in name
        and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in name.split("."))
    )


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key.")
        result[key] = value
    return result


def decode_manifest(data, generation, serial):
    if len(data) > MAX_MANIFEST:
        raise PullError("Manifest exceeds the size limit.", 5)
    try:
        manifest = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
        if not isinstance(manifest, dict) or set(manifest) != {
            "version", "generation", "serial", "published_at", "zones",
        }:
            raise ValueError
        if type(manifest["version"]) is not int or manifest["version"] != 1:
            raise ValueError
        if type(manifest["serial"]) is not int or manifest["serial"] != serial:
            raise ValueError
        if manifest["generation"] != generation:
            raise ValueError
        published = manifest["published_at"]
        if not isinstance(published, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]{1,6})?(?:Z|\+00:00)", published,
        ):
            raise ValueError
        if datetime.fromisoformat(published.replace("Z", "+00:00")).utcoffset() != timezone.utc.utcoffset(None):
            raise ValueError
        zones = manifest["zones"]
        if not isinstance(zones, list) or not 1 <= len(zones) <= MAX_ZONES:
            raise ValueError
        names = set()
        for zone in zones:
            if not isinstance(zone, dict) or set(zone) != {"name", "filename", "sha256", "size"}:
                raise ValueError
            name = zone["name"]
            if not valid_zone(name) or zone["filename"] != name or name in names:
                raise ValueError
            if not isinstance(zone["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", zone["sha256"]):
                raise ValueError
            if type(zone["size"]) is not int or not 1 <= zone["size"] <= MAX_ZONE:
                raise ValueError
            names.add(name)
        return manifest
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise PullError("Invalid generation manifest.", 5) from None


def _absolute_path(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise PullError("Invalid local configuration path.")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        raise PullError("Local configuration paths must be absolute and normalized.")
    return path


def _protected(info):
    return info.st_uid in {0, os.geteuid()} and not info.st_mode & 0o022


def check_path(path, missing=False):
    """Reject symlinks and untrusted directory ancestors, not just final links."""
    parts = [*reversed(path.parents), path]
    for index, part in enumerate(parts):
        try:
            info = part.lstat()
        except FileNotFoundError:
            if missing:
                return
            raise PullError("Required local path is unavailable.") from None
        if stat.S_ISLNK(info.st_mode):
            raise PullError("Symlinks are not permitted in local paths.")
        if index < len(parts) - 1 and (not stat.S_ISDIR(info.st_mode) or not _protected(info)):
            raise PullError("Local directory ancestors must be administrator-owned and protected.")


def read_regular(path, limit, protected=False, missing=False):
    check_path(path, missing=missing)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if missing:
            return None
        raise PullError("Required file is unavailable.") from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PullError("Only regular, non-hardlinked files are permitted.")
        if protected and not _protected(info):
            raise PullError("Configuration and state files must be administrator-owned and protected.")
        if info.st_size > limit:
            raise PullError("File exceeds the size limit.", 5)
        data = handle.read(limit + 1)
        if len(data) > limit or len(data) != info.st_size:
            raise PullError("File changed or exceeds the size limit.", 5)
        return data, info


def load_config(path):
    path = _absolute_path(str(path))
    data, _ = read_regular(path, 32 * 1024, protected=True)
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(data.decode("utf-8"))
        if parser.defaults() or parser.sections() != ["dns_pull"]:
            raise ValueError
        values = dict(parser["dns_pull"])
        required = {
            "source_host", "source_user", "source_port", "source_directory",
            "identity_file", "known_hosts", "backup_directory", "named_checkzone",
        }
        if not required <= values.keys() or set(values) - required - {"destination_directory"}:
            raise ValueError
        user = values["source_user"]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", user):
            raise ValueError
        host = values["source_host"]
        if "%" in host or any(ord(c) < 32 or ord(c) == 127 for c in host):
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
            values["source_host"] = "[" + str(address) + "]" if address.version == 6 else str(address)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host) or not all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in host.split(".")
            ):
                raise ValueError
        port = values["source_port"]
        if not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535:
            raise ValueError
        source = values["source_directory"]
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", source) or ".." in PurePosixPath(source).parts or str(PurePosixPath(source)) != source:
            raise ValueError
        for key in ("identity_file", "known_hosts", "backup_directory", "named_checkzone"):
            values[key] = _absolute_path(values[key])
        values["destination_directory"] = _absolute_path(values.get("destination_directory", DEFAULT_DESTINATION))
        for key in ("identity_file", "known_hosts"):
            # Do not read credentials; inspect their descriptor and permissions.
            check_path(values[key])
            info = values[key].lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not _protected(info):
                raise ValueError
        check_path(values["named_checkzone"], missing=True)
        return values
    except (configparser.Error, ValueError, UnicodeError):
        raise PullError("Invalid administrator DNS pull configuration.") from None


def ensure_directory(path, create=False):
    check_path(path, missing=create)
    if create and not path.exists():
        ensure_directory(path.parent)
        path.mkdir(mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or not _protected(info):
        raise PullError("DNS pull directories must be administrator-owned and protected.")


@contextmanager
def run_lock(directory):
    path = directory / LOCK_NAME
    check_path(path, missing=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not _protected(info):
            raise PullError("Unsafe lock file.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PullError("Another DNS pull is running.", 3) from None
        yield
    finally:
        os.close(fd)


def _file_limit(limit):
    _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    bound = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
    resource.setrlimit(resource.RLIMIT_FSIZE, (bound, bound))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for kind, limit in ((resource.RLIMIT_AS, 256 * 1024 * 1024), (resource.RLIMIT_CPU, 60)):
        _, hard = resource.getrlimit(kind)
        bound = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
        resource.setrlimit(kind, (bound, bound))


def fetch(config, generation, filename, destination, limit):
    remote_path = str(PurePosixPath(config["source_directory"]) / "generations" / generation / filename)
    remote = config["source_user"] + "@" + config["source_host"] + ":" + remote_path
    args = [
        "/usr/bin/scp", "-F", "/dev/null", "-B", "-P", config["source_port"],
        "-i", str(config["identity_file"]),
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + str(config["known_hosts"]),
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "-o", "IdentityAgent=none",
        "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
        "--", remote, str(destination),
    ]
    try:
        subprocess.run(
            args, check=True, timeout=TIMEOUT, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            preexec_fn=lambda: _file_limit(limit),
        )
    except (OSError, subprocess.SubprocessError):
        raise PullError("Generation transfer failed or timed out.", 4) from None


def check_zone(config, name, path, stage):
    executable = config["named_checkzone"]
    check_path(executable, missing=True)
    if not executable.exists():
        raise PullError("named-checkzone is unavailable.", 5)
    info = executable.lstat()
    if not stat.S_ISREG(info.st_mode) or not _protected(info) or not os.access(executable, os.X_OK):
        raise PullError("named-checkzone is unavailable or untrusted.", 5)
    # A real file and RLIMIT_FSIZE bound diagnostic output without pipe buffering.
    with tempfile.TemporaryFile(dir=stage) as output:
        try:
            subprocess.run(
                [str(executable), name, str(path)], check=True, timeout=TIMEOUT,
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                shell=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                preexec_fn=lambda: _file_limit(MAX_MANIFEST),
            )
            output.seek(0)
            text = output.read(MAX_MANIFEST + 1).decode("ascii")
        except (OSError, subprocess.SubprocessError, UnicodeError):
            raise PullError("Zone validation failed or timed out.", 5) from None
    matches = re.findall(
        r"^zone " + re.escape(name) + r"/IN: loaded serial ([0-9]{1,10})(?: \(DNSSEC signed\))?$",
        text, re.MULTILINE,
    )
    if len(text) > MAX_MANIFEST or len(matches) != 1 or not text.rstrip().endswith("\nOK"):
        raise PullError("Unsupported named-checkzone serial output.", 5)
    serial = int(matches[0])
    if serial > 0xFFFFFFFF:
        raise PullError("Zone has an invalid SOA serial.", 5)
    return serial


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _metadata(info):
    return {
        "uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode),
        "atime_ns": info.st_atime_ns, "mtime_ns": info.st_mtime_ns,
    }


def _sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def atomic_write(path, data, metadata=None, restore_times=False):
    check_path(path, missing=True)
    fd, temporary = tempfile.mkstemp(prefix=".dnsgrid-write-", dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            if metadata:
                info = os.fstat(output.fileno())
                if (info.st_uid, info.st_gid) != (metadata["uid"], metadata["gid"]):
                    os.fchown(output.fileno(), metadata["uid"], metadata["gid"])
                os.fchmod(output.fileno(), metadata["mode"])
                if restore_times:
                    os.utime(output.fileno(), ns=(metadata["atime_ns"], metadata["mtime_ns"]))
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _zone_identity(manifest):
    return sorted((z["name"], z["sha256"], z["size"]) for z in manifest["zones"])


def backup_targets(directory, generation, originals, prior_state):
    backup = Path(tempfile.mkdtemp(prefix="backup-" + generation + "-", dir=directory))
    metadata = {"zones": {}, "state": None}
    # Record previous state and every target before the first master replacement.
    if prior_state is not None:
        _write_private(backup / STATE_NAME, prior_state[0])
        metadata["state"] = _metadata(prior_state[1])
    for name, previous in originals.items():
        metadata["zones"][name] = None if previous is None else _metadata(previous[1])
        if previous is not None:
            _write_private(backup / name, read_regular(previous[0], MAX_ZONE)[0])
    _write_private(backup / ".metadata.json", json.dumps(metadata, sort_keys=True).encode("ascii"))
    _sync_directory(backup)
    _sync_directory(directory)
    return backup


def install(config, manifest, staged, originals, prior_state):
    destination = config["destination_directory"]
    directory = config["backup_directory"]
    state_path = directory / STATE_NAME
    attempted = []
    state_attempted = False
    try:
        backup_targets(directory, manifest["generation"], originals, prior_state)
        for zone in manifest["zones"]:
            name = zone["name"]
            # Include a replacement that fails after rename (e.g. directory fsync).
            attempted.append(name)
            previous = originals[name]
            metadata = _metadata(previous[1]) if previous else {
                "uid": os.geteuid(), "gid": os.getegid(), "mode": 0o644,
            }
            data = read_regular(staged[name], MAX_ZONE)[0]
            if len(data) != zone["size"] or _digest(data) != zone["sha256"]:
                raise PullError("Staged zone changed after validation.", 5)
            atomic_write(destination / name, data, metadata)
        state_attempted = True
        atomic_write(state_path, json.dumps(manifest, sort_keys=True).encode("ascii") + b"\n")
    except (OSError, PullError):
        failures = []
        for name in reversed(attempted):
            try:
                previous = originals[name]
                if previous is None:
                    check_path(destination / name, missing=True)
                    (destination / name).unlink(missing_ok=True)
                    _sync_directory(destination)
                else:
                    atomic_write(
                        destination / name, read_regular(previous[0], MAX_ZONE)[0],
                        _metadata(previous[1]), restore_times=True,
                    )
            except (OSError, PullError):
                failures.append(name)
        if state_attempted:
            try:
                if prior_state is None:
                    check_path(state_path, missing=True)
                    state_path.unlink(missing_ok=True)
                    _sync_directory(directory)
                else:
                    atomic_write(state_path, prior_state[0], _metadata(prior_state[1]), restore_times=True)
            except (OSError, PullError):
                failures.append("state")
        if failures:
            raise PullError(
                "Installation failed; rollback incomplete for %d item(s). Administrator recovery required." % len(failures),
                7,
            ) from None
        raise PullError("Installation failed; previous files and state restored.", 6) from None


def pull(config, generation, serial, dry_run=False):
    destination, directory = config["destination_directory"], config["backup_directory"]
    ensure_directory(destination)
    ensure_directory(directory, create=True)
    with run_lock(directory):
        prior_state = read_regular(directory / STATE_NAME, MAX_MANIFEST, protected=True, missing=True)
        state = None
        if prior_state is not None:
            try:
                raw = json.loads(prior_state[0].decode("utf-8"), object_pairs_hook=_unique_object)
                old_generation, old_serial = validate_request(raw["generation"], str(raw["serial"]))
                state = decode_manifest(prior_state[0], old_generation, old_serial)
            except (ValueError, KeyError, TypeError, UnicodeError):
                raise PullError("Invalid protected installation state.", 5) from None
            if state["serial"] > serial:
                raise PullError("Refusing a serial downgrade below installed state.", 5)
        with tempfile.TemporaryDirectory(prefix=".dnsgrid-stage-", dir=directory) as temporary:
            stage = Path(temporary)
            manifest_path = stage / "manifest.json"
            fetch(config, generation, "manifest.json", manifest_path, MAX_MANIFEST)
            manifest = decode_manifest(read_regular(manifest_path, MAX_MANIFEST)[0], generation, serial)
            if state and state["serial"] == serial and _zone_identity(state) != _zone_identity(manifest):
                raise PullError("Equal serial identifies different generation contents.", 5)
            # Original snapshots and backups live on disk, not in a zone-sized
            # aggregate in memory. Also budget destination growth and a temporary.
            existing_sizes = 0
            destination_growth = 0
            for zone in manifest["zones"]:
                target = destination / zone["name"]
                check_path(target, missing=True)
                size = target.lstat().st_size if target.exists() else 0
                existing_sizes += size
                destination_growth += max(0, zone["size"] - size)
            destination_needed = destination_growth + MAX_ZONE
            needed = sum(zone["size"] for zone in manifest["zones"]) + 2 * existing_sizes + MAX_ZONE + MAX_MANIFEST
            if directory.stat().st_dev == destination.stat().st_dev:
                needed += destination_needed
            disk = os.statvfs(directory)
            target_disk = os.statvfs(destination)
            if disk.f_bavail * disk.f_frsize < needed or target_disk.f_bavail * target_disk.f_frsize < destination_needed:
                raise PullError("Insufficient staging and backup disk space.", 4)
            staged, originals = {}, {}
            for zone in manifest["zones"]:
                name = zone["name"]
                path = stage / name
                fetch(config, generation, name, path, zone["size"])
                data, _ = read_regular(path, MAX_ZONE)
                if len(data) != zone["size"] or _digest(data) != zone["sha256"]:
                    raise PullError("Zone size or checksum does not match the manifest.", 5)
                if re.search(rb"\$INCLUDE(?:\s|$)", data, re.IGNORECASE):
                    raise PullError("Generation zones must be self-contained; INCLUDE is unsupported.", 5)
                if check_zone(config, name, path, stage) != serial:
                    raise PullError("Zone SOA serial does not match the requested generation.", 5)
                staged[name] = path
            for zone in manifest["zones"]:
                name = zone["name"]
                previous = read_regular(destination / name, MAX_ZONE, missing=True)
                if previous is None:
                    originals[name] = None
                    continue
                snapshot = stage / (".installed-" + name)
                _write_private(snapshot, previous[0])
                originals[name] = (snapshot, previous[1])
                installed_serial = check_zone(config, name, snapshot, stage)
                if installed_serial > serial:
                    raise PullError("Refusing a downgrade below an installed zone serial.", 5)
                if installed_serial == serial and _digest(previous[0]) != zone["sha256"]:
                    raise PullError("Equal serial has different installed zone contents.", 5)
            identical = all(
                originals[z["name"]] is not None
                and _digest(read_regular(originals[z["name"]][0], MAX_ZONE)[0]) == z["sha256"]
                for z in manifest["zones"]
            )
            if state and state["serial"] == serial and identical:
                return "Already installed: %d zone file(s) verified; no changes." % len(staged)
            if dry_run:
                return "Dry run: %d zone file(s) validated; no installation or state changes." % len(staged)
            # The lock coordinates this utility, not independent administrator edits.
            for name, previous in originals.items():
                current = read_regular(destination / name, MAX_ZONE, missing=True)
                if (previous is None) != (current is None) or (
                    previous is not None and (
                        read_regular(previous[0], MAX_ZONE)[0] != current[0]
                        or any(_metadata(previous[1])[key] != _metadata(current[1])[key]
                               for key in ("uid", "gid", "mode", "mtime_ns"))
                    )
                ):
                    raise PullError("Installed files changed during validation; rerun.", 5)
            current_state = read_regular(directory / STATE_NAME, MAX_MANIFEST, protected=True, missing=True)
            if (prior_state is None) != (current_state is None) or (
                prior_state is not None and prior_state[0] != current_state[0]
            ):
                raise PullError("Installation state changed during validation; rerun.", 5)
            install(config, manifest, staged, originals, prior_state)
            return "Installed %d zone file(s); DNS loading/reload was not performed." % len(staged)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("generation", nargs="?", help="immutable dnsgrid-YYYYMMDDnn generation")
    parser.add_argument("serial", nargs="?", help="ten-digit YYYYMMDDnn SOA serial")
    parser.add_argument("--config", default="/etc/dnsgrid-dns-pull.ini", help="administrator-owned local INI")
    parser.add_argument("--forced-command", action="store_true", help="validate SSH_ORIGINAL_COMMAND instead of positional arguments")
    parser.add_argument("--dry-run", action="store_true", help="fetch and validate without installing zone files or state")
    options = parser.parse_args(argv)
    try:
        if options.forced_command:
            if options.generation is not None or options.serial is not None:
                raise PullError("Forced mode does not accept positional arguments.")
            command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
            match = re.fullmatch(r"dnsgrid-update (dnsgrid-[0-9]{10}) ([0-9]{10})", command)
            if not match:
                raise PullError("Rejected forced SSH command.")
            generation, serial = validate_request(*match.groups())
        else:
            generation, serial = validate_request(options.generation, options.serial)
        config = load_config(options.config)
        print(pull(config, generation, serial, options.dry_run))
        return 0
    except PullError as error:
        print("DNS pull: " + str(error), file=sys.stderr)
        return error.code
    except OSError:
        print("DNS pull: local filesystem operation failed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
