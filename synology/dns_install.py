"""Periodic, standalone DSM DNS installer (Python 3 standard library only).

Administrator-owned INI [dns_install] requires inbox_directory,
outbox_directory, destination_directory, state_directory, allowed_zones
(comma separated), and named_checkzone (absolute executable).
Optional package_owner and package_root together trust a local DSM package
account within that root only; its UID and primary GID are resolved locally.
Optional rndc (absolute executable) and rndc_key (absolute key file path)
together enable ONE general reload per run, after the complete zone set was
validated and installed: rndc -k <rndc_key> -s 127.0.0.1 -p 953 reload.
Without both settings no reload is performed and installed files are not
confirmed loaded by named.

The SFTP account may write only the inbox, not its parent, outbox, state,
destination, script, or configuration. State and backup directories are 0700.
No network access other than the local RNDC control channel and no DNS
restart are performed. Replacements are atomic per file, not across the zone
set. A durable journal permits rollback after a crash; incomplete rollback
blocks installation until recovery succeeds. A durable pending-reload record
keeps a failed or interrupted reload retryable on later runs without resending.
Exit codes: 0 success, 2 configuration, 3 busy, 5 rejected delivery,
6 installation failure, 7 incomplete recovery, 8 files installed but the
general RNDC reload failed (retried on the next run).
"""

import argparse
import configparser
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
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
RELOAD_NAME = "reload.json"
RELOAD_TIMEOUT = 60
RELOAD_OUTPUT = 200
RELOAD_RESULTS = {"succeeded", "failed", "superseded"}
MAX_PENDING = 64
RNDC_SERVER = "127.0.0.1"
RNDC_PORT = "953"
DELIVERY = re.compile(r"dnsgrid-(0|[1-9][0-9]{0,9})-[0-9a-f]{32}")
MAX_SERIAL = 0xFFFFFFFF
HALF_SERIAL = 0x80000000
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


class InstallError(Exception):
    def __init__(self, summary="Delivery rejected.", code=5):
        super().__init__(summary)
        self.code = code


def protected(info):
    return info.st_uid in {0, os.geteuid()} and not info.st_mode & 0o022


def package_protected(info, config):
    return (info.st_uid in {0, config["package_identity"][0]}
            and not info.st_mode & 0o022)


def validation_error(path, info, summary="Unsafe filesystem object.", code=2):
    return InstallError(
        f"{summary} Path/component {str(path)!r}: uid={info.st_uid}, "
        f"gid={info.st_gid}, mode={stat.S_IMODE(info.st_mode):04o}.", code)


def in_package(path, config):
    return (config and "package_identity" in config
            and (path == config["package_root"] or config["package_root"] in path.parents))


def absolute(value):
    if (not isinstance(value, str) or not value.startswith("/")
            or str(Path(value)) != value or ".." in Path(value).parts
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise InstallError("Invalid configuration.", 2)
    return Path(value)


def open_directory(path, inbox=False, config=None):
    """Walk with openat; no checked path is subsequently reopened by pathname."""
    path = absolute(str(path))
    fd = os.open("/", DIR_FLAGS)
    try:
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            parent_path = Path("/", *parts[:index])
            child_path = parent_path / part
            parent = os.fstat(fd)
            # A root-owned sticky shared ancestor cannot rename the protected,
            # administrator-owned next component (e.g. a private test root).
            package_parent = in_package(parent_path, config)
            sticky = not package_parent and parent.st_uid == 0 and parent.st_mode & stat.S_ISVTX
            safe = package_protected(parent, config) if package_parent else protected(parent)
            if not safe and not sticky:
                raise validation_error(parent_path, parent, "Unprotected directory ancestor.")
            try:
                child = os.open(part, DIR_FLAGS, dir_fd=fd)
            except OSError:
                info = os.stat(part, dir_fd=fd, follow_symlinks=False)
                raise validation_error(child_path, info, "Cannot open directory safely.") from None
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            intermediate_sticky = (
                index < len(parts) - 1 and info.st_uid == 0
                and bool(info.st_mode & stat.S_ISVTX)
                and not in_package(child_path, config)
            )
            safe = package_protected(info, config) if in_package(child_path, config) else protected(info)
            if (index != len(parts) - 1 or not inbox) and not safe and not intermediate_sticky:
                raise validation_error(child_path, info, "Unprotected directory.")
        if not parts and inbox:
            raise InstallError("Invalid inbox.", 2)
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_file(directory, name, limit, trusted=False, missing=False, package=None, path=None):
    try:
        fd = os.open(name, FILE_FLAGS, dir_fd=directory)
    except FileNotFoundError:
        if missing:
            return None
        raise InstallError(f"Required file {str(path or name)!r} is missing.", 2 if trusted else 5) from None
    except OSError:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        raise validation_error(path or name, info, "Cannot open file safely.", 5) from None
    before = os.fstat(fd)
    safe = (before.st_uid == package["package_identity"][0]
            or (before.st_uid == 0 and not before.st_mode & 0o022)
            if package and "package_identity" in package else protected(before))
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size > limit or (trusted and not safe)):
        os.close(fd)
        raise validation_error(path or name, before, "Untrusted file.", 5)
    with os.fdopen(fd, "rb") as stream:
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        if (len(data) != before.st_size or len(data) > limit
                or after.st_nlink != 1 or after.st_size != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
                or after.st_ctime_ns != before.st_ctime_ns):
            raise InstallError(f"File {str(path or name)!r} changed while being acquired.")
        return data, before


def trusted_file(path):
    path = absolute(str(path))
    fd = open_directory(path.parent)
    try:
        data, _ = read_file(fd, path.name, MAX_MANIFEST, trusted=True, path=path)
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
        required = {"inbox_directory", "outbox_directory",
                    "destination_directory", "state_directory",
                    "allowed_zones", "named_checkzone"}
        reload_keys = {"rndc", "rndc_key"}
        if len(reload_keys & set(values)) == 1:
            raise InstallError("Invalid configuration: rndc and rndc_key must be configured together.", 2)
        if set(values) - reload_keys not in (required, required | {"package_owner", "package_root"}):
            raise ValueError
        if "package_owner" in values:
            try:
                account = pwd.getpwnam(values["package_owner"])
            except KeyError:
                raise InstallError("Unknown configured package_owner account.", 2) from None
            values["package_identity"] = (account.pw_uid, account.pw_gid)
        zones = [name.strip() for name in values["allowed_zones"].split(",")]
        if (not 1 <= len(zones) <= MAX_ZONES or len(set(zones)) != len(zones)
                or not all(valid_zone(name) for name in zones)):
            raise ValueError
        values["allowed_zones"] = set(zones)
        for key in sorted(reload_keys & set(values)):
            try:
                absolute(values[key])
            except InstallError:
                raise InstallError(
                    f"Invalid configuration: {key} must be an absolute normalized path.", 2) from None
        for key in set(values) - {"allowed_zones", "package_owner", "package_identity"}:
            values[key] = absolute(values[key])
        directories = [values[key] for key in values if key.endswith("_directory")]
        for left in directories:
            for right in directories:
                if left != right and (left in right.parents or right in left.parents):
                    raise ValueError
        if len(set(directories)) != 4:
            raise ValueError
        if "rndc" in values:
            if values["rndc"] == values["rndc_key"] or any(
                    directory == values[key] or directory in values[key].parents
                    for directory in directories for key in ("rndc", "rndc_key")):
                raise InstallError(
                    "Invalid configuration: rndc and rndc_key must be distinct absolute "
                    "paths outside the inbox, outbox, state and destination directories.", 2)
        if "package_identity" in values:
            root = values["package_root"]
            if any(root not in values[key].parents
                   for key in ("destination_directory", "named_checkzone")):
                raise ValueError
            if any(in_package(values[key], values) or values[key] in root.parents
                   for key in ("inbox_directory", "outbox_directory", "state_directory")):
                raise ValueError
        return values
    except (ValueError, UnicodeError, configparser.Error):
        raise InstallError("Invalid configuration.", 2) from None


def serial_value(text, context="SOA serial"):
    if not isinstance(text, str) or not re.fullmatch(r"[0-9]{1,10}", text):
        raise InstallError(f"Invalid {context}: expected decimal uint32 (0..{MAX_SERIAL}).")
    value = int(text)
    if value > MAX_SERIAL:
        raise InstallError(f"Invalid {context} {text!r}: outside uint32 range 0..{MAX_SERIAL}.")
    return value


def compare_serial(serial, previous, context):
    """RFC 1982 ordering; a half-range difference has no defined order."""
    difference = (serial - previous) & MAX_SERIAL
    if difference == HALF_SERIAL:
        raise InstallError(
            f"Ambiguous RFC 1982 serial comparison for {context}: "
            f"candidate {serial}, installed {previous}; difference is 2^31.")
    return 0 if difference == 0 else (1 if difference < HALF_SERIAL else -1)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def decode_json(data, context="JSON"):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise InstallError(f"Invalid {context}: malformed JSON or duplicate object key.") from None


def decode_manifest(data, delivery, allowed):
    match = DELIVERY.fullmatch(delivery)
    if not match:
        raise InstallError(f"Invalid delivery ID {delivery!r}: expected canonical uint32 serial and lowercase UUID.")
    serial = serial_value(match[1], "delivery serial")
    manifest = decode_json(data, f"manifest for {delivery!r}")
    try:
        if (type(manifest) is not dict
                or set(manifest) != {"version", "generation", "serial", "published_at", "zones"}
                or type(manifest["version"]) is not int or manifest["version"] != 1):
            raise InstallError("Invalid manifest schema or version.")
        if type(manifest["serial"]) is not int:
            raise InstallError("Invalid manifest serial: expected an integer uint32.")
        serial_value(str(manifest["serial"]), "manifest serial")
        if manifest["serial"] != serial:
            raise InstallError(f"Manifest serial {manifest['serial']} does not match delivery serial {serial}.")
        if manifest["generation"] != "dnsgrid-" + match[1]:
            raise InstallError(f"Manifest generation does not match delivery serial {serial}.")
        published = manifest["published_at"]
        if not isinstance(published, str) or not re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                r"(?:\.[0-9]{1,6})?(?:Z|\+00:00)", published):
            raise InstallError("Invalid manifest published_at: expected a UTC timestamp.")
        datetime.fromisoformat(published.replace("Z", "+00:00"))
        zones = manifest["zones"]
        if type(zones) is not list or not 1 <= len(zones) <= MAX_ZONES:
            raise InstallError(f"Invalid manifest zones: expected 1..{MAX_ZONES} entries.")
        names = set()
        for zone in zones:
            if type(zone) is not dict or set(zone) != {"name", "filename", "size", "sha256"}:
                raise InstallError("Invalid manifest zone entry schema.")
            name = zone["name"]
            if not valid_zone(name):
                raise InstallError(f"Invalid manifest zone name {name!r}.")
            if zone["filename"] != name:
                raise InstallError(f"Invalid filename {zone['filename']!r} for zone {name!r}; must equal the zone name.")
            if name in names:
                raise InstallError(f"Duplicate manifest zone {name!r}.")
            if type(zone["size"]) is not int or not 1 <= zone["size"] <= MAX_ZONE:
                raise InstallError(f"Invalid size for zone {name!r}: expected 1..{MAX_ZONE} bytes.")
            if not isinstance(zone["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", zone["sha256"]):
                raise InstallError(f"Invalid SHA-256 checksum for zone {name!r}.")
            names.add(name)
        if names != allowed:
            raise InstallError(f"Manifest zone allowlist mismatch: missing {sorted(allowed - names)!r}; unexpected {sorted(names - allowed)!r}.")
        return manifest
    except (ValueError, TypeError, KeyError, OverflowError):
        raise InstallError("Invalid manifest value or UTC publication timestamp.") from None


def soa_serial(data, context="zone"):
    """Tokenize master-file records without treating comments or TXT as SOAs."""
    try:
        text = data.decode("ascii")
    except UnicodeError:
        raise InstallError(f"Invalid {context}: zone file must be ASCII.") from None
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
                raise InstallError(f"Invalid {context}: unmatched closing parenthesis.")
        elif token == "\n":
            if not depth and record:
                records.append(record)
                record = []
        else:
            record.append(token)
    if depth:
        raise InstallError(f"Invalid {context}: unclosed record parenthesis.")
    if record:
        records.append(record)
    for record in records:
        if record[0].startswith("$"):
            if record[0].upper() not in {"$ORIGIN", "$TTL"}:
                raise InstallError(f"Invalid {context}: external or unsupported directive {record[0]!r}.")
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
            if (len(tail) != 7
                    or not all(re.fullmatch("[0-9]+[smhdwSMHDW]?", token) for token in tail[3:])):
                raise InstallError(f"Invalid {context}: malformed SOA record.")
            tokens.append(serial_value(tail[2], f"SOA serial in {context}"))
    if len(tokens) != 1:
        raise InstallError(f"Invalid {context}: expected exactly one SOA record, found {len(tokens)}.")
    return tokens[0]


def atomic_write(directory, name, data, mode=0o600, owner=None):
    temporary = ".installer-" + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 mode, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            if owner is not None:
                os.fchown(stream.fileno(), *owner)
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


def check_executable(config, key, summary, code):
    """Validate a configured executable through anchored descriptors."""
    path = config[key]
    fd = open_directory(path.parent, config=config)
    try:
        try:
            executable = os.open(path.name, FILE_FLAGS, dir_fd=fd)
        except OSError:
            info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            raise validation_error(path, info, summary, code) from None
        try:
            info = os.fstat(executable)
            safe = package_protected(info, config) if in_package(path, config) else protected(info)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or not safe or not info.st_mode & 0o111):
                raise validation_error(path, info, summary, code)
        finally:
            os.close(executable)
    finally:
        os.close(fd)


def check_zone(config, name, path, stage):
    try:
        check_executable(config, "named_checkzone", "Unsafe validator.", 5)
        subprocess.run([str(config["named_checkzone"]), name, str(path)],
                       cwd=stage, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=TIMEOUT, check=True, shell=False)
    except (OSError, subprocess.SubprocessError):
        raise InstallError(f"Zone validation failed for {name!r} at {str(path)!r}.") from None


def check_rndc(config):
    """Validate the RNDC executable and key file metadata; never read the key."""
    try:
        check_executable(config, "rndc", "Unsafe RNDC executable.", 2)
        path = config["rndc_key"]
        fd = open_directory(path.parent, config=config)
        try:
            try:
                key = os.open(path.name, FILE_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                raise InstallError(f"Configured rndc_key {str(path)!r} is missing.", 2) from None
            except OSError:
                info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
                raise validation_error(path, info, "Unsafe RNDC key file.", 2) from None
            try:
                info = os.fstat(key)
                owners = {0, os.geteuid()}
                if in_package(path, config):
                    owners.add(config["package_identity"][0])
                # Group read is allowed; group write and any world access are not.
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid not in owners or info.st_mode & 0o027):
                    raise validation_error(path, info, "Unsafe RNDC key file.", 2)
            finally:
                os.close(key)
        finally:
            os.close(fd)
    except FileNotFoundError:
        raise InstallError("Configured RNDC executable or key path is missing.", 2) from None
    except OSError:
        raise InstallError("Configured RNDC executable or key path is unavailable.", 2) from None


def reload_command(config):
    """Fixed argv for ONE general reload: no zone argument, local control channel only."""
    return [str(config["rndc"]), "-k", str(config["rndc_key"]),
            "-s", RNDC_SERVER, "-p", RNDC_PORT, "reload"]


def sanitized(data):
    text = "".join(c if 32 <= ord(c) < 127 else " " for c in data.decode("ascii", "replace"))
    return " ".join(text.split())[:RELOAD_OUTPUT]


def general_reload(config):
    """Run one general RNDC reload; True only for exit status 0 within the timeout.

    Output is captured in a private temporary file, bounded and sanitized, and
    written only to local stderr diagnostics, never to receipts.
    """
    try:
        check_rndc(config)
    except InstallError as error:
        print(f"General RNDC reload not attempted: {error}", file=sys.stderr)
        return False
    try:
        with tempfile.TemporaryFile(dir=config["state_directory"]) as output:
            process = subprocess.run(
                reload_command(config), cwd="/", stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT,
                timeout=RELOAD_TIMEOUT, check=False, shell=False)
            output.seek(0)
            detail = sanitized(output.read(RELOAD_OUTPUT * 2))
    except subprocess.TimeoutExpired:
        print(f"General RNDC reload timed out after {RELOAD_TIMEOUT} seconds; "
              "zones not confirmed loaded.", file=sys.stderr)
        return False
    except (OSError, subprocess.SubprocessError):
        print("General RNDC reload could not be started; zones not confirmed loaded.",
              file=sys.stderr)
        return False
    if process.returncode != 0:
        print(f"General RNDC reload failed with exit status {process.returncode}; "
              f"zones not confirmed loaded. rndc output: {detail!r}", file=sys.stderr)
        return False
    print("General RNDC reload succeeded; serving of the new records is not verified.",
          file=sys.stderr)
    return True


def snapshot(config, inbox, delivery, stage):
    delivery_path = config["inbox_directory"] / delivery
    try:
        fd = os.open(delivery, DIR_FLAGS, dir_fd=inbox)
    except OSError:
        raise InstallError(f"Cannot open delivery directory safely: {str(delivery_path)!r}.") from None
    try:
        raw, _ = read_file(fd, "manifest.json", MAX_MANIFEST, path=delivery_path / "manifest.json")
        # The inbox is never used by validation or named-checkzone.
        (stage / "manifest.json").write_bytes(raw)
        manifest = decode_manifest(raw, delivery, config["allowed_zones"])
        expected = {"manifest.json"} | config["allowed_zones"]
        if set(os.listdir(fd)) != expected:
            raise InstallError(f"Unexpected or missing files in delivery {str(delivery_path)!r}.")
        for zone in manifest["zones"]:
            name = zone["name"]
            data, _ = read_file(fd, name, MAX_ZONE, path=delivery_path / name)
            (stage / name).write_bytes(data)
        if set(os.listdir(fd)) != expected:
            raise InstallError(f"Delivery file set changed during acquisition: {str(delivery_path)!r}.")
    finally:
        os.close(fd)
    for zone in manifest["zones"]:
        name = zone["name"]
        data = (stage / name).read_bytes()
        context = f"zone {name!r} at {str(delivery_path / name)!r}"
        if len(data) != zone["size"]:
            raise InstallError(f"Size mismatch for {context}: expected {zone['size']}, acquired {len(data)}.")
        if hashlib.sha256(data).hexdigest() != zone["sha256"]:
            raise InstallError(f"SHA-256 checksum mismatch for {context}.")
        actual_serial = soa_serial(data, context)
        if actual_serial != manifest["serial"]:
            raise InstallError(f"SOA serial mismatch for {context}: found {actual_serial}, manifest {manifest['serial']}.")
        check_zone(config, name, stage / name, stage)
    content = [{"name": z["name"], "size": z["size"], "sha256": z["sha256"]}
               for z in sorted(manifest["zones"], key=lambda z: z["name"])]
    return manifest["serial"], hashlib.sha256(json_bytes(content)).hexdigest()


def read_state(state):
    value = read_file(state, STATE_NAME, MAX_MANIFEST, trusted=True, missing=True)
    if value is None:
        return None
    try:
        data = decode_json(value[0], f"installer state {STATE_NAME!r}")
    except InstallError as error:
        raise InstallError(str(error), 7) from None
    if (type(data) is not dict or set(data) != {"serial", "fingerprint"}
            or type(data["serial"]) is not int
            or not isinstance(data["fingerprint"], str)
            or not re.fullmatch("[0-9a-f]{64}", data["fingerprint"])):
        raise InstallError("Invalid installer state.", 7)
    try:
        serial_value(str(data["serial"]), f"installer state serial in {STATE_NAME!r}")
    except InstallError as error:
        raise InstallError(str(error), 7) from None
    return data


def check_existing_baseline(destination, stage, names, serial, config=None):
    """Bootstrap safely when no durable installer high-water mark exists."""
    for name in sorted(names):
        existing = read_file(destination, name, MAX_ZONE, trusted=True, missing=True,
                             package=config, path=config["destination_directory"] / name if config else name)
        if existing is None:
            continue
        path = config["destination_directory"] / name if config else name
        context = f"installed zone {name!r} at {str(path)!r}"
        previous_serial = soa_serial(existing[0], context)
        ordering = compare_serial(serial, previous_serial, context)
        if ordering < 0 or (
                ordering == 0 and existing[0] != (stage / name).read_bytes()):
            raise InstallError(
                f"Serial reuse or regression rejected for {context}: "
                f"candidate {serial}, installed {previous_serial}.")


def recover(state, destination, names=None):
    raw = read_file(state, JOURNAL_NAME, MAX_MANIFEST, trusted=True, missing=True)
    if raw is None:
        return
    legacy_message = "Legacy journal requires recovery with the previous installer."
    try:
        journal = decode_json(raw[0])
        if type(journal) is dict and "version" not in journal:
            raise InstallError(legacy_message, 7)
        if (type(journal) is not dict
                or set(journal) != {"version", "backup", "entries", "previous_state"}
                or type(journal["version"]) is not int or journal["version"] != 2
                or not isinstance(journal["backup"], str)
                or not re.fullmatch("backup-[0-9a-f]{32}", journal["backup"])
                or type(journal["entries"]) is not list
                or not 1 <= len(journal["entries"]) <= MAX_ZONES):
            raise InstallError(f"Invalid recovery journal {JOURNAL_NAME!r}: schema or backup name.")
        seen = set()
        for entry in journal["entries"]:
            if (type(entry) is not dict or set(entry) != {"name", "present", "mode", "uid", "gid"}
                    or not valid_zone(entry["name"]) or entry["name"] in seen
                    or (names is not None and entry["name"] not in names)
                    or type(entry["present"]) is not bool
                    or type(entry["mode"]) is not int or entry["mode"] & ~0o7777
                    or any(type(entry[key]) is not int or not 0 <= entry[key] < 2**32 - 1
                           for key in ("uid", "gid"))):
                raise InstallError(f"Invalid recovery journal {JOURNAL_NAME!r}: zone entry metadata.")
            seen.add(entry["name"])
        backup = os.open(journal["backup"], DIR_FLAGS, dir_fd=state)
        try:
            info = os.fstat(backup)
            if not protected(info) or stat.S_IMODE(info.st_mode) != 0o700:
                raise validation_error(journal["backup"], info, "Unprotected backup.", 7)
            for entry in journal["entries"]:
                if entry["present"]:
                    data, _ = read_file(backup, entry["name"], MAX_ZONE, trusted=True)
                    atomic_write(destination, entry["name"], data, entry["mode"],
                                 owner=(entry["uid"], entry["gid"]))
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
    except InstallError as error:
        if str(error) == legacy_message:
            raise
        raise InstallError(f"Recovery incomplete; installation blocked. {error}", 7) from None
    except (OSError, ValueError, TypeError, KeyError):
        raise InstallError("Recovery incomplete; installation blocked.", 7) from None


def install(state, destination, stage, names, next_state, previous, config=None):
    backup_name = "backup-" + uuid.uuid4().hex
    os.mkdir(backup_name, mode=0o700, dir_fd=state)
    backup = os.open(backup_name, DIR_FLAGS, dir_fd=state)
    entries = []
    try:
        for name in sorted(names):
            old = read_file(destination, name, MAX_ZONE, trusted=True, missing=True,
                            package=config, path=config["destination_directory"] / name if config else name)
            mode = stat.S_IMODE(old[1].st_mode) if old else 0o644
            if old:
                atomic_write(backup, name, old[0])
            entries.append({"name": name, "present": old is not None, "mode": mode,
                            "uid": old[1].st_uid if old else os.geteuid(),
                            "gid": old[1].st_gid if old else os.getegid()})
        os.fsync(backup)
        os.fsync(state)
    finally:
        os.close(backup)
    journal_bytes = json_bytes({
        "version": 2, "backup": backup_name, "entries": entries, "previous_state": previous,
    })
    atomic_write(state, JOURNAL_NAME, journal_bytes)
    try:
        for entry in entries:
            owner = config.get("package_identity") if config else None
            atomic_write(destination, entry["name"], (stage / entry["name"]).read_bytes(),
                         0o644, **({"owner": owner} if owner else {}))
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
        recover(state, destination, names)
        raise InstallError("Installation failed; previous files restored.", 6) from None


def result(outbox, delivery, serial, status, summary, reload=None):
    receipt = {
        "delivery": delivery, "serial": serial, "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
    }
    if reload is not None:
        receipt["reload"] = reload
    atomic_write(outbox, delivery + ".json", json_bytes(receipt), 0o644)


RELOAD_SUMMARIES = {
    ("installed", "succeeded"):
        "Files installed; general RNDC reload succeeded. Serving of the new records not verified.",
    ("already_installed", "succeeded"):
        "Already installed; general RNDC reload succeeded. Serving of the new records not verified.",
    ("installed", "failed"):
        "Files installed; general RNDC reload failed or unconfirmed. The installer retries it.",
    ("already_installed", "failed"):
        "Already installed; general RNDC reload failed or unconfirmed. The installer retries it.",
    ("installed", "superseded"):
        "Files installed, then superseded by a newer installation before a successful reload.",
    ("already_installed", "superseded"):
        "Already installed, then superseded by a newer installation before a successful reload.",
}


def read_pending(state):
    """Deliveries whose files were installed and still await a general reload."""
    value = read_file(state, RELOAD_NAME, MAX_MANIFEST, trusted=True, missing=True)
    if value is None:
        return []
    try:
        data = decode_json(value[0], f"pending reload state {RELOAD_NAME!r}")
        if (type(data) is not dict or set(data) != {"version", "deliveries"}
                or type(data["version"]) is not int or data["version"] != 1
                or type(data["deliveries"]) is not list
                or not 1 <= len(data["deliveries"]) <= MAX_PENDING):
            raise ValueError
        seen = set()
        for entry in data["deliveries"]:
            if (type(entry) is not dict
                    or set(entry) != {"delivery", "serial", "status", "fingerprint"}
                    or not isinstance(entry["delivery"], str) or entry["delivery"] in seen
                    or entry["status"] not in {"installed", "already_installed"}
                    or not isinstance(entry["fingerprint"], str)
                    or not re.fullmatch("[0-9a-f]{64}", entry["fingerprint"])):
                raise ValueError
            match = DELIVERY.fullmatch(entry["delivery"])
            if (not match or type(entry["serial"]) is not int
                    or serial_value(match[1]) != entry["serial"]):
                raise ValueError
            seen.add(entry["delivery"])
        return data["deliveries"]
    except (InstallError, ValueError, TypeError):
        raise InstallError(f"Invalid pending reload state {RELOAD_NAME!r}; "
                           "administrator review required.", 7) from None


def write_pending(state, entries):
    if entries:
        atomic_write(state, RELOAD_NAME, json_bytes({"version": 1, "deliveries": entries}))
    else:
        try:
            os.unlink(RELOAD_NAME, dir_fd=state)
        except FileNotFoundError:
            pass
        os.fsync(state)


def completed_result(outbox, delivery, serial):
    """Only administrator-protected receipts may suppress completed work."""
    raw = read_file(outbox, delivery + ".json", MAX_MANIFEST, trusted=True, missing=True)
    if raw is None:
        return False
    receipt = decode_json(raw[0])
    try:
        if (type(receipt) is not dict
                or set(receipt) - {"reload"} != {"delivery", "serial", "status", "timestamp", "summary"}
                or ("reload" in receipt and (
                    receipt["reload"] not in RELOAD_RESULTS
                    or receipt["status"] not in {"installed", "already_installed"}))
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
            fd = open_directory(config[key], inbox=key == "inbox_directory",
                                config=config if key == "destination_directory" else None)
            stack.callback(os.close, fd)
            directories[key] = fd
        state = directories["state_directory"]
        if stat.S_IMODE(os.fstat(state).st_mode) != 0o700:
            raise validation_error(config["state_directory"], os.fstat(state),
                                   "State directory must be private.")
        try:
            lock = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                           0o600, dir_fd=state)
        except OSError:
            info = os.stat(LOCK_NAME, dir_fd=state, follow_symlinks=False)
            raise validation_error(config["state_directory"] / LOCK_NAME, info,
                                   "Cannot open installer lock safely.") from None
        stack.callback(os.close, lock)
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not protected(info):
            raise validation_error(config["state_directory"] / LOCK_NAME, info,
                                   "Invalid installer lock.")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError("Installer busy.", 3) from None
        destination = directories["destination_directory"]
        if dry_run:
            if read_file(state, JOURNAL_NAME, MAX_MANIFEST, trusted=True, missing=True):
                raise InstallError("Recovery required before dry run.", 7)
        else:
            recover(state, destination, config["allowed_zones"])
        previous = read_state(state)
        pending = read_pending(state)
        reload_enabled = "rndc" in config
        if reload_enabled:
            # Refuse to install files that could not be activated as configured.
            check_rndc(config)
        elif pending:
            print("Pending RNDC reload recorded, but rndc/rndc_key are not configured; "
                  "zones not confirmed loaded.", file=sys.stderr)
        waiting = {entry["delivery"] for entry in pending}
        outbox = directories["outbox_directory"]
        inbox = directories["inbox_directory"]
        code = 0
        installed_without_reload = False
        for delivery in sorted(os.listdir(inbox)):
            match = DELIVERY.fullmatch(delivery)
            if not match:  # Includes unfinished .partial uploads.
                continue
            serial = int(match[1])
            try:
                serial_value(match[1], f"delivery serial in {delivery!r}")
                if not dry_run and (delivery in waiting or completed_result(outbox, delivery, serial)):
                    continue
                with tempfile.TemporaryDirectory(prefix=".stage-", dir=config["state_directory"]) as folder:
                    stage = Path(folder)
                    serial, fingerprint = snapshot(config, inbox, delivery, stage)
                    current = {"serial": serial, "fingerprint": fingerprint}
                    if previous is None:
                        check_existing_baseline(destination, stage, config["allowed_zones"], serial, config)
                    if previous:
                        ordering = compare_serial(serial, previous["serial"], f"installer state {STATE_NAME!r}")
                        if ordering < 0 or (ordering == 0 and current != previous):
                            raise InstallError(
                                f"Serial reuse or regression rejected for installer state: "
                                f"candidate {serial}, installed {previous['serial']}.")
                    status = "already_installed" if current == previous else "installed"
                    if not dry_run:
                        if reload_enabled and len(pending) >= MAX_PENDING:
                            raise InstallError("Too many deliveries awaiting a general RNDC reload; "
                                               "resolve the pending reload first.", 6)
                        if status == "installed":
                            install(state, destination, stage, config["allowed_zones"], current, previous, config)
                            previous = current
            except (OSError, InstallError):
                error = sys.exc_info()[1]
                failure = error if isinstance(error, InstallError) else InstallError(
                    f"Delivery {delivery!r} filesystem processing failed at {str(error.filename)!r}.", 6)
                print(str(failure), file=sys.stderr)
                code = max(code, failure.code)
                if not dry_run:
                    result(outbox, delivery, serial, "failed", str(failure)[:256])
                if failure.code == 7:
                    break
            else:
                if dry_run:
                    continue
                if reload_enabled:
                    # Durable before any receipt: a crash before this point
                    # leaves no receipt, so the delivery is reprocessed as
                    # already_installed and joins the pending reload.
                    pending.append({"delivery": delivery, "serial": serial,
                                    "status": status, "fingerprint": current["fingerprint"]})
                    waiting.add(delivery)
                    write_pending(state, pending)
                else:
                    installed_without_reload = True
                    result(outbox, delivery, serial, status,
                           "Already installed; RNDC reload not configured." if status == "already_installed"
                           else "Installation complete; RNDC reload not configured.")
        if installed_without_reload:
            print("RNDC reload not configured: installed files are not confirmed loaded by named.",
                  file=sys.stderr)
        if dry_run:
            if pending:
                print("General RNDC reload pending; dry run does not reload.", file=sys.stderr)
            return code
        if reload_enabled and pending:
            if code >= 7 or read_file(state, JOURNAL_NAME, MAX_MANIFEST, trusted=True, missing=True):
                print("General RNDC reload deferred: recovery incomplete.", file=sys.stderr)
                return code
            # ONE general reload for the complete installed zone set.
            reloaded = general_reload(config)
            for entry in pending:
                outcome = "failed"
                if reloaded:
                    outcome = ("succeeded" if previous and entry["fingerprint"] == previous["fingerprint"]
                               else "superseded")
                result(outbox, entry["delivery"], entry["serial"], entry["status"],
                       RELOAD_SUMMARIES[(entry["status"], outcome)], outcome)
            if reloaded:
                # Cleared only after every receipt is durable; a crash before
                # this repeats the idempotent general reload and receipts.
                write_pending(state, [])
            else:
                code = max(code, 8)
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
