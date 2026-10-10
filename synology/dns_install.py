"""Periodic, standalone DSM DNS installer (Python 3 standard library only).

Administrator-owned INI [dns_install] requires inbox_directory,
outbox_directory, destination_directory, state_directory, allowed_zones
(comma separated), and named_checkzone (absolute executable).

The SFTP account may write only the inbox, not its parent, outbox, state,
destination, script, or configuration. State and backup directories are 0700.
No network access, DNS restart, or reload is performed. Replacements are atomic
per file, not across the zone set. A durable journal permits rollback after a
crash; incomplete rollback blocks installation until recovery succeeds.
Exit codes: 0 success, 2 configuration, 3 busy, 5 rejected delivery,
6 installation failure, 7 incomplete recovery.
"""

import argparse
import configparser
from datetime import date, datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import uuid
from contextlib import ExitStack


MAX_MANIFEST = 128 * 1024
MAX_ZONE = 4 * 1024 * 1024
MAX_ZONES = 256
TIMEOUT = 120
STATE_NAME = "installed.json"
JOURNAL_NAME = "transaction.json"
LOCK_NAME = "installer.lock"
DELIVERY = re.compile(r"dnsgrid-([0-9]{10})-[0-9a-f]{32}")
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


class InstallError(Exception):
    def __init__(self, summary="Delivery rejected.", code=5):
        super().__init__(summary)
        self.code = code


def protected(info):
    return info.st_uid in {0, os.geteuid()} and not info.st_mode & 0o022


def absolute(value):
    if (not isinstance(value, str) or not value.startswith("/")
            or str(Path(value)) != value or ".." in Path(value).parts
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise InstallError("Invalid configuration.", 2)
    return Path(value)


def open_directory(path, inbox=False):
    """Walk with openat; no checked path is subsequently reopened by pathname."""
    path = absolute(str(path))
    fd = os.open("/", DIR_FLAGS)
    try:
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            parent = os.fstat(fd)
            # A root-owned sticky shared ancestor cannot rename the protected,
            # administrator-owned next component (e.g. a private test root).
            sticky = parent.st_uid == 0 and parent.st_mode & stat.S_ISVTX
            if not protected(parent) and not sticky:
                raise InstallError("Unprotected directory ancestor.", 2)
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            intermediate_sticky = (
                index < len(parts) - 1 and info.st_uid == 0
                and bool(info.st_mode & stat.S_ISVTX)
            )
            if (index != len(parts) - 1 or not inbox) and not protected(info) and not intermediate_sticky:
                raise InstallError("Unprotected directory.", 2)
        if not parts and inbox:
            raise InstallError("Invalid inbox.", 2)
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_file(directory, name, limit, trusted=False, missing=False):
    try:
        fd = os.open(name, FILE_FLAGS, dir_fd=directory)
    except FileNotFoundError:
        if missing:
            return None
        raise
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > limit or (trusted and not protected(before))):
            raise InstallError()
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        if (len(data) != before.st_size or len(data) > limit
                or after.st_nlink != 1 or after.st_size != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
                or after.st_ctime_ns != before.st_ctime_ns):
            raise InstallError()
        return data, before


def trusted_file(path):
    path = absolute(str(path))
    fd = open_directory(path.parent)
    try:
        data, _ = read_file(fd, path.name, MAX_MANIFEST, trusted=True)
        return data
    finally:
        os.close(fd)


def valid_zone(name):
    return (isinstance(name, str) and len(name) <= 253 and "." in name
            and name != "manifest.json"
            and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in name.split(".")))


def load_config(path):
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(trusted_file(path).decode("utf-8"))
        if parser.defaults() or parser.sections() != ["dns_install"]:
            raise ValueError
        values = dict(parser["dns_install"])
        if set(values) != {"inbox_directory", "outbox_directory",
                           "destination_directory", "state_directory",
                           "allowed_zones", "named_checkzone"}:
            raise ValueError
        zones = [name.strip() for name in values["allowed_zones"].split(",")]
        if (not 1 <= len(zones) <= MAX_ZONES or len(set(zones)) != len(zones)
                or not all(valid_zone(name) for name in zones)):
            raise ValueError
        values["allowed_zones"] = set(zones)
        for key in set(values) - {"allowed_zones"}:
            values[key] = absolute(values[key])
        directories = [values[key] for key in values if key.endswith("_directory")]
        for left in directories:
            for right in directories:
                if left != right and (left in right.parents or right in left.parents):
                    raise ValueError
        if len(set(directories)) != 4:
            raise ValueError
        return values
    except (ValueError, UnicodeError, configparser.Error):
        raise InstallError("Invalid configuration.", 2) from None


def serial_value(text):
    if not isinstance(text, str) or not re.fullmatch(r"[0-9]{10}", text):
        raise InstallError()
    try:
        date(int(text[:4]), int(text[4:6]), int(text[6:8]))
    except ValueError:
        raise InstallError() from None
    value = int(text)
    if value > 0xFFFFFFFF or str(value) != text:
        raise InstallError()
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def decode_json(data):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise InstallError() from None


def decode_manifest(data, delivery, allowed):
    match = DELIVERY.fullmatch(delivery)
    if not match:
        raise InstallError()
    serial = serial_value(match[1])
    manifest = decode_json(data)
    try:
        if (type(manifest) is not dict
                or set(manifest) != {"version", "generation", "serial", "published_at", "zones"}
                or type(manifest["version"]) is not int or manifest["version"] != 1
                or type(manifest["serial"]) is not int or manifest["serial"] != serial
                or manifest["generation"] != "dnsgrid-" + match[1]):
            raise ValueError
        published = manifest["published_at"]
        if not isinstance(published, str) or not re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                r"(?:\.[0-9]{1,6})?(?:Z|\+00:00)", published):
            raise ValueError
        datetime.fromisoformat(published.replace("Z", "+00:00"))
        zones = manifest["zones"]
        if type(zones) is not list or not 1 <= len(zones) <= MAX_ZONES:
            raise ValueError
        names = set()
        for zone in zones:
            if type(zone) is not dict or set(zone) != {"name", "filename", "size", "sha256"}:
                raise ValueError
            name = zone["name"]
            if not valid_zone(name) or zone["filename"] != name or name in names:
                raise ValueError
            if type(zone["size"]) is not int or not 1 <= zone["size"] <= MAX_ZONE:
                raise ValueError
            if not isinstance(zone["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", zone["sha256"]):
                raise ValueError
            names.add(name)
        if names != allowed:
            raise ValueError
        return manifest
    except (ValueError, TypeError, KeyError, OverflowError):
        raise InstallError() from None


def soa_serial(data):
    """Tokenize master-file records without treating comments or TXT as SOAs."""
    try:
        text = data.decode("ascii")
    except UnicodeError:
        raise InstallError() from None
    tokens, record, records = [], [], []
    depth = 0
    # Quoted strings and escapes are kept as opaque tokens.
    pattern = r'"(?:[^"\\]|\\.)*"|\\.|;[^\n]*|[()]|\n|[^\s();"\\]+'
    for match in re.finditer(pattern, text):
        token = match[0]
        if token.startswith(";"):
            continue
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
            if depth < 0:
                raise InstallError()
        elif token == "\n":
            if not depth and record:
                records.append(record)
                record = []
        else:
            record.append(token)
    if depth:
        raise InstallError()
    if record:
        records.append(record)
    for record in records:
        if record[0].startswith("$"):
            if record[0].upper() not in {"$ORIGIN", "$TTL"}:
                raise InstallError()
            continue
        # Only the record header can contain a type: once another type is seen,
        # SOA in its RDATA is not a type (notably unquoted TXT strings).
        # Skip the owner (unless the first token is a class/TTL/type), then
        # optional TTL/class. Reject external directives above.
        index = 0 if record[0].upper() in {"IN", "SOA"} or record[0].isdigit() else 1
        while index < len(record) and (
                record[index].upper() in {"IN", "CH", "HS"}
                or re.fullmatch(r"[0-9]+[smhdwSMHDW]?", record[index])):
            index += 1
        if index < len(record) and record[index].upper() == "SOA":
            tail = record[index + 1:]
            if (len(tail) != 7 or not re.fullmatch("[0-9]{10}", tail[2])
                    or not all(re.fullmatch("[0-9]+[smhdwSMHDW]?", token) for token in tail[3:])):
                raise InstallError()
            tokens.append(serial_value(tail[2]))
    if len(tokens) != 1:
        raise InstallError()
    return tokens[0]


def atomic_write(directory, name, data, mode=0o600):
    temporary = ".installer-" + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 mode, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def check_zone(config, name, path, stage):
    try:
        fd = open_directory(config["named_checkzone"].parent)
        try:
            executable = os.open(config["named_checkzone"].name, FILE_FLAGS, dir_fd=fd)
            try:
                info = os.fstat(executable)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or not protected(info) or not info.st_mode & 0o111):
                    raise InstallError("Zone validation failed.")
            finally:
                os.close(executable)
        finally:
            os.close(fd)
        subprocess.run([str(config["named_checkzone"]), name, str(path)],
                       cwd=stage, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=TIMEOUT, check=True, shell=False)
    except (OSError, subprocess.SubprocessError):
        raise InstallError("Zone validation failed.") from None


def snapshot(config, inbox, delivery, stage):
    fd = os.open(delivery, DIR_FLAGS, dir_fd=inbox)
    try:
        raw, _ = read_file(fd, "manifest.json", MAX_MANIFEST)
        # The inbox is never used by validation or named-checkzone.
        (stage / "manifest.json").write_bytes(raw)
        manifest = decode_manifest(raw, delivery, config["allowed_zones"])
        expected = {"manifest.json"} | config["allowed_zones"]
        if set(os.listdir(fd)) != expected:
            raise InstallError()
        for zone in manifest["zones"]:
            name = zone["name"]
            data, _ = read_file(fd, name, MAX_ZONE)
            (stage / name).write_bytes(data)
        if set(os.listdir(fd)) != expected:
            raise InstallError()
    finally:
        os.close(fd)
    for zone in manifest["zones"]:
        name = zone["name"]
        data = (stage / name).read_bytes()
        if (len(data) != zone["size"] or hashlib.sha256(data).hexdigest() != zone["sha256"]
                or soa_serial(data) != manifest["serial"]):
            raise InstallError()
        check_zone(config, name, stage / name, stage)
    content = [{"name": z["name"], "size": z["size"], "sha256": z["sha256"]}
               for z in sorted(manifest["zones"], key=lambda z: z["name"])]
    return manifest["serial"], hashlib.sha256(json_bytes(content)).hexdigest()


def read_state(state):
    value = read_file(state, STATE_NAME, MAX_MANIFEST, trusted=True, missing=True)
    if value is None:
        return None
    data = decode_json(value[0])
    if (type(data) is not dict or set(data) != {"serial", "fingerprint"}
            or type(data["serial"]) is not int
            or not isinstance(data["fingerprint"], str)
            or not re.fullmatch("[0-9a-f]{64}", data["fingerprint"])):
        raise InstallError("Invalid installer state.", 7)
    serial_value(str(data["serial"]))
    return data


def check_existing_baseline(destination, stage, names, serial):
    """Bootstrap safely when no durable installer high-water mark exists."""
    for name in sorted(names):
        existing = read_file(destination, name, MAX_ZONE, trusted=True, missing=True)
        if existing is None:
            continue
        previous_serial = soa_serial(existing[0])
        if serial < previous_serial or (
                serial == previous_serial and existing[0] != (stage / name).read_bytes()):
            raise InstallError("Serial reuse or regression rejected.")


def recover(state, destination):
    raw = read_file(state, JOURNAL_NAME, MAX_MANIFEST, trusted=True, missing=True)
    if raw is None:
        return
    try:
        journal = decode_json(raw[0])
        if (type(journal) is not dict
                or set(journal) != {"backup", "entries", "previous_state"}
                or not isinstance(journal["backup"], str)
                or not re.fullmatch("backup-[0-9a-f]{32}", journal["backup"])
                or type(journal["entries"]) is not list
                or not 1 <= len(journal["entries"]) <= MAX_ZONES):
            raise InstallError()
        backup = os.open(journal["backup"], DIR_FLAGS, dir_fd=state)
        try:
            if not protected(os.fstat(backup)) or stat.S_IMODE(os.fstat(backup).st_mode) != 0o700:
                raise InstallError()
            for entry in journal["entries"]:
                if (type(entry) is not dict or set(entry) != {"name", "present", "mode"}
                        or not valid_zone(entry["name"]) or type(entry["present"]) is not bool
                        or type(entry["mode"]) is not int or entry["mode"] & ~0o777):
                    raise InstallError()
                if entry["present"]:
                    data, _ = read_file(backup, entry["name"], MAX_ZONE, trusted=True)
                    atomic_write(destination, entry["name"], data, entry["mode"])
                else:
                    try:
                        os.unlink(entry["name"], dir_fd=destination)
                    except FileNotFoundError:
                        pass
                    os.fsync(destination)
            previous = journal["previous_state"]
            if previous is None:
                try:
                    os.unlink(STATE_NAME, dir_fd=state)
                except FileNotFoundError:
                    pass
                os.fsync(state)
            else:
                atomic_write(state, STATE_NAME, json_bytes(previous))
        finally:
            os.close(backup)
        os.unlink(JOURNAL_NAME, dir_fd=state)
        os.fsync(state)
    except (OSError, InstallError, ValueError, TypeError, KeyError):
        raise InstallError("Recovery incomplete; installation blocked.", 7) from None


def install(state, destination, stage, names, next_state, previous):
    backup_name = "backup-" + uuid.uuid4().hex
    os.mkdir(backup_name, mode=0o700, dir_fd=state)
    backup = os.open(backup_name, DIR_FLAGS, dir_fd=state)
    entries = []
    try:
        for name in sorted(names):
            old = read_file(destination, name, MAX_ZONE, trusted=True, missing=True)
            mode = stat.S_IMODE(old[1].st_mode) if old else 0o644
            if old:
                atomic_write(backup, name, old[0])
            entries.append({"name": name, "present": old is not None, "mode": mode})
        os.fsync(backup)
        os.fsync(state)
    finally:
        os.close(backup)
    journal_bytes = json_bytes({
        "backup": backup_name, "entries": entries, "previous_state": previous,
    })
    atomic_write(state, JOURNAL_NAME, journal_bytes)
    try:
        for entry in entries:
            atomic_write(destination, entry["name"], (stage / entry["name"]).read_bytes(), entry["mode"])
        atomic_write(state, STATE_NAME, json_bytes(next_state))
        os.unlink(JOURNAL_NAME, dir_fd=state)
        os.fsync(state)
    except (OSError, InstallError):
        # Even a directory fsync failure after unlink must not discard the
        # only recovery metadata while reporting an unsuccessful install.
        try:
            if read_file(state, JOURNAL_NAME, MAX_MANIFEST, trusted=True, missing=True) is None:
                atomic_write(state, JOURNAL_NAME, journal_bytes)
        except (OSError, InstallError):
            raise InstallError("Recovery incomplete; installation blocked.", 7) from None
        recover(state, destination)
        raise InstallError("Installation failed; previous files restored.", 6) from None


def result(outbox, delivery, serial, status, summary):
    atomic_write(outbox, delivery + ".json", json_bytes({
        "delivery": delivery, "serial": serial, "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
    }), 0o644)


def completed_result(outbox, delivery, serial):
    """Only administrator-protected receipts may suppress completed work."""
    raw = read_file(outbox, delivery + ".json", MAX_MANIFEST, trusted=True, missing=True)
    if raw is None:
        return False
    receipt = decode_json(raw[0])
    try:
        if (type(receipt) is not dict
                or set(receipt) != {"delivery", "serial", "status", "timestamp", "summary"}
                or receipt["delivery"] != delivery
                or type(receipt["serial"]) is not int or receipt["serial"] != serial
                or receipt["status"] not in {"installed", "already_installed", "failed"}
                or not isinstance(receipt["summary"], str) or len(receipt["summary"]) > 256
                or any(ord(c) < 32 or ord(c) == 127 for c in receipt["summary"])
                or not isinstance(receipt["timestamp"], str)
                or not re.fullmatch(
                    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                    r"(?:\.[0-9]{1,6})?(?:Z|\+00:00)", receipt["timestamp"])):
            raise ValueError
        datetime.fromisoformat(receipt["timestamp"].replace("Z", "+00:00"))
        serial_value(str(serial))
        return receipt["status"] in {"installed", "already_installed"}
    except (ValueError, TypeError, KeyError, OverflowError):
        raise InstallError("Invalid delivery receipt.") from None


def run(config, dry_run=False):
    with ExitStack() as stack:
        directories = {}
        for key in ("inbox_directory", "outbox_directory", "destination_directory", "state_directory"):
            fd = open_directory(config[key], inbox=key == "inbox_directory")
            stack.callback(os.close, fd)
            directories[key] = fd
        state = directories["state_directory"]
        if stat.S_IMODE(os.fstat(state).st_mode) != 0o700:
            raise InstallError("State directory must be private.", 2)
        lock = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                       0o600, dir_fd=state)
        stack.callback(os.close, lock)
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not protected(info):
            raise InstallError("Invalid installer lock.", 2)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError("Installer busy.", 3) from None
        destination = directories["destination_directory"]
        if dry_run:
            if read_file(state, JOURNAL_NAME, MAX_MANIFEST, trusted=True, missing=True):
                raise InstallError("Recovery required before dry run.", 7)
        else:
            recover(state, destination)
        previous = read_state(state)
        inbox = directories["inbox_directory"]
        code = 0
        for delivery in sorted(os.listdir(inbox)):
            match = DELIVERY.fullmatch(delivery)
            if not match:  # Includes unfinished .partial uploads.
                continue
            serial = int(match[1])
            try:
                if not dry_run and completed_result(directories["outbox_directory"], delivery, serial):
                    continue
                with tempfile.TemporaryDirectory(prefix=".stage-", dir=config["state_directory"]) as folder:
                    stage = Path(folder)
                    serial, fingerprint = snapshot(config, inbox, delivery, stage)
                    current = {"serial": serial, "fingerprint": fingerprint}
                    if previous is None:
                        check_existing_baseline(destination, stage, config["allowed_zones"], serial)
                    if previous and (serial < previous["serial"]
                                     or (serial == previous["serial"] and current != previous)):
                        raise InstallError("Serial reuse or regression rejected.")
                    status = "already_installed" if current == previous else "installed"
                    if not dry_run:
                        if status == "installed":
                            install(state, destination, stage, config["allowed_zones"], current, previous)
                            previous = current
            except (OSError, InstallError):
                error = sys.exc_info()[1]
                failure = error if isinstance(error, InstallError) else InstallError("Delivery processing failed.", 6)
                code = max(code, failure.code)
                if not dry_run:
                    result(directories["outbox_directory"], delivery, serial, "failed", str(failure))
                if failure.code == 7:
                    break
            else:
                if not dry_run:
                    result(directories["outbox_directory"], delivery, serial, status,
                           "Already installed." if status == "already_installed" else "Installation complete.")
        return code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="/etc/dnsgrid-dns-install.ini")
    parser.add_argument("--dry-run", action="store_true", help="Validate only; do not install or publish results.")
    args = parser.parse_args(argv)
    try:
        trusted_file(Path(__file__).absolute())
        config = load_config(absolute(args.config))
        return run(config, args.dry_run)
    except InstallError as error:
        print(str(error), file=sys.stderr)
        return error.code
    except (OSError, ValueError):
        print("Installer configuration or filesystem unavailable.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
