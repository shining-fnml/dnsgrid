"""Immutable, bounded generation storage for local DNS publication."""

import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from django.core.exceptions import ValidationError
from .dns_serial import validate_serial
from .models import Configuration, normalize_domain

RETENTION = 10
MAX_ZONE_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024


def validate_generation(generation, serial):
    validate_serial(serial)
    if generation != f"dnsgrid-{serial}":
        raise ValidationError("Invalid DNS generation identifier.")


def _directory(path):
    if not stat.S_ISDIR(path.lstat().st_mode) or path.resolve() != path.absolute():
        raise ValidationError("Generation storage must use real directories without symlinks.")
    return path


def _read(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValidationError("Invalid or excessive generation file.")
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValidationError("Excessive generation file.")
    return content


def _atomic(path, content, exclusive=False, mode=0o644):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".dnsgrid-", delete=False) as stream:
            temporary = stream.name
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        if exclusive:
            try:
                os.link(temporary, path)
            except FileExistsError:
                if _read(path, max(len(content), MAX_MANIFEST_BYTES)) != content:
                    raise ValidationError("Same serial cannot identify different zone bytes; seed upward.")
        else:
            os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _root(directory, create=False):
    parent = _directory(Path(directory))
    root = parent / "generations"
    if create:
        root.mkdir(exist_ok=True)
    return _directory(root)


def read_generation(directory, generation):
    if not isinstance(generation, str) or not re.fullmatch(r"dnsgrid-[0-9]{10}", generation):
        raise ValidationError("Invalid DNS generation identifier.")
    serial = int(generation.removeprefix("dnsgrid-"))
    validate_generation(generation, serial)
    path = _directory(_root(directory) / generation)
    raw = _read(path / "manifest.json", MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(raw)
        if (
            type(manifest) is not dict
            or set(manifest) != {"version", "generation", "serial", "published_at", "zones"}
            or type(manifest["version"]) is not int or manifest["version"] != 1
            or type(manifest["serial"]) is not int or manifest["serial"] != serial
            or manifest["generation"] != generation
            or not isinstance(manifest["published_at"], str)
            or datetime.fromisoformat(manifest["published_at"]).utcoffset().total_seconds() != 0
            or type(manifest["zones"]) is not list or not 1 <= len(manifest["zones"]) <= 256
        ):
            raise ValueError
        names = set()
        for zone in manifest["zones"]:
            if type(zone) is not dict or set(zone) != {"name", "filename", "sha256", "size"}:
                raise ValueError
            name = zone["name"]
            if (
                normalize_domain(name) != name or name in names or zone["filename"] != name
                or type(zone["size"]) is not int or not 1 <= zone["size"] <= MAX_ZONE_BYTES
                or not isinstance(zone["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", zone["sha256"])
            ):
                raise ValueError
            names.add(name)
            content = _read(path / name, MAX_ZONE_BYTES)
            if len(content) != zone["size"] or hashlib.sha256(content).hexdigest() != zone["sha256"]:
                raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError) as error:
        raise ValidationError("Invalid or corrupted immutable generation.") from error
    return path, manifest


def _owned_generations(root):
    owned = []
    for entry in root.iterdir():
        if entry.is_symlink() or not re.fullmatch(r"dnsgrid-[0-9]{10}", entry.name):
            continue
        try:
            _, manifest = read_generation(root.parent, entry.name)
        except (ValidationError, OSError):
            continue
        allowed = {"manifest.json", ".pin", ".delivery.json"} | {zone["filename"] for zone in manifest["zones"]}
        if {child.name for child in entry.iterdir()} <= allowed:
            owned.append(entry)
    return sorted(owned, key=lambda entry: entry.name)


def _make_room(root, current, new):
    owned = _owned_generations(root)
    needed = len(owned) - RETENTION + (0 if any(p.name == new for p in owned) else 1)
    for path in owned:
        if needed <= 0:
            break
        if path.name in (current, new) or (path / ".pin").exists():
            continue
        _, manifest = read_generation(root.parent, path.name)
        for zone in manifest["zones"]:
            (path / zone["filename"]).unlink()
        (path / "manifest.json").unlink()
        (path / ".delivery.json").unlink(missing_ok=True)
        path.rmdir()
        needed -= 1
    if needed > 0:
        raise ValidationError("Generation retention is full of pinned generations. Administrator review is required before publishing.")


def preflight_generation(config, zones):
    """Reject serial reuse before overwriting the mutable zone-named files."""
    generation = f"dnsgrid-{config.soa_serial}"
    directory = Path(config.dns_export_directory)
    if directory.exists():
        _directory(directory)
    path = Path(config.dns_export_directory) / "generations" / generation
    if not path.exists():
        return
    _directory(path)
    for name, text in zones.values():
        target = path / name
        if target.exists() or target.is_symlink():
            if _read(target, MAX_ZONE_BYTES) != text.encode("utf-8"):
                raise ValidationError("Same serial cannot identify different zone bytes; seed upward.")
    if (path / "manifest.json").exists():
        _, manifest = read_generation(config.dns_export_directory, generation)
        if {zone["name"] for zone in manifest["zones"]} != {name for name, _ in zones.values()}:
            raise ValidationError("Same serial cannot identify different zone bytes; seed upward.")


def commit_generation(config, zones):
    root = _root(config.dns_export_directory, create=True)
    generation = f"dnsgrid-{config.soa_serial}"
    validate_generation(generation, config.soa_serial)
    _make_room(root, config.dns_published_generation, generation)
    path = root / generation
    path.mkdir(exist_ok=True)
    _directory(path)
    entries = []
    created = []
    try:
        for name, text in sorted(zones.values()):
            content = text.encode("utf-8")
            if not 1 <= len(content) <= MAX_ZONE_BYTES or normalize_domain(name) != name:
                raise ValidationError("Invalid generation zone name or size.")
            entries.append({
                "name": name, "filename": name, "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            })
            existed = (path / name).exists()
            if not existed:
                created.append(path / name)
            _atomic(path / name, content, exclusive=True)
        if (path / "manifest.json").exists():
            _, manifest = read_generation(config.dns_export_directory, generation)
            if manifest["zones"] != entries:
                raise ValidationError("Same serial cannot identify different zone bytes; seed upward.")
        else:
            manifest = {
                "version": 1, "generation": generation, "serial": config.soa_serial,
                "published_at": datetime.now(timezone.utc).isoformat(), "zones": entries,
            }
            _atomic(path / "manifest.json", (json.dumps(manifest, sort_keys=True) + "\n").encode(), exclusive=True)
    except (OSError, ValidationError):
        if not (path / "manifest.json").exists():
            for target in created:
                target.unlink(missing_ok=True)
        if not any(path.iterdir()):
            path.rmdir()
        raise
    _atomic(root.parent / "manifest.json", (json.dumps(manifest, sort_keys=True) + "\n").encode())
    Configuration.objects.filter(pk=1).update(dns_published_generation=generation)
    return generation


def pending_generations(directory):
    root = Path(directory) / "generations"
    if not root.exists():
        return []
    try:
        return [path.name for path in _owned_generations(_directory(root)) if (path / ".pin").exists()]
    except (ValidationError, OSError):
        return []
