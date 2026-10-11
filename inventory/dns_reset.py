"""Preview and roll-forward recovery for local-only test publication resets."""

import hashlib
import json
import os
import re
import uuid
from pathlib import Path

from django.core.exceptions import ValidationError
from django.db import transaction

from .dns_publication import MAX_ZONE_BYTES, _atomic, _directory, _read, read_generation
from .dns_serial import content_fingerprint, initial_serial, validate_serial
from .models import Configuration, normalize_domain

JOURNAL = ".dnsgrid-reset.json"
MAX_JOURNAL = 4 * 1024 * 1024
PROTECTED = {"installed.json", "transaction.json", "backups", "generations"}


def ensure_ready(directory):
    if directory and os.path.lexists(Path(directory) / JOURNAL):
        raise ValidationError(
            "Local DNS reset recovery is outstanding. Run reset_dns_publication --recover "
            "with both acknowledgements; do not delete its journal or lock files."
        )


def _root(directory):
    path = Path(directory)
    if not directory or not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise ValidationError("Reset requires a configured absolute, non-root managed export directory.")
    return _directory(path)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _config_state(config):
    # Persist only a digest, not configuration values (which include credentials).
    return _digest({
        "configuration": {
            field.attname: getattr(config, field.attname)
            for field in config._meta.concrete_fields
        },
        "content": content_fingerprint(config),
    })


def _file(path):
    content = _read(path, MAX_ZONE_BYTES)
    if path.stat().st_nlink != 1:
        raise ValidationError("Hard-linked publication artifacts require administrator review.")
    return {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}


def _generation(directory, name):
    from .dns_delivery import _attempt
    path, manifest = read_generation(str(directory), name)
    allowed = {"manifest.json", ".pin", ".delivery.json"} | {
        zone["filename"] for zone in manifest["zones"]
    }
    if allowed & PROTECTED:
        raise ValidationError(f"Protected filename in {path}; review manually.")
    children = list(path.iterdir())
    if any(child.name not in allowed for child in children):
        raise ValidationError(f"Unexpected contents in {path}; review or quarantine manually.")
    _attempt(path, manifest)
    return {child.name: _file(child) for child in sorted(children)}


def _artifacts(config):
    from .exporters import _dns_zones
    root = _root(config.dns_export_directory)
    artifacts = {}
    names = {name for name, _ in _dns_zones(config, []).values()}
    generations = root / "generations"
    if os.path.lexists(generations):
        for entry in sorted(_directory(generations).iterdir()):
            if not re.fullmatch(r"dnsgrid-(?:0|[1-9][0-9]{0,9})", entry.name):
                if entry.is_symlink() or entry.name.startswith("dnsgrid-"):
                    raise ValidationError(f"Malformed entry in generation storage: {entry}. Review manually.")
                continue
            files = _generation(root, entry.name)
            artifacts[f"generations/{entry.name}"] = files
            _, manifest = read_generation(str(root), entry.name)
            names.update(zone["filename"] for zone in manifest["zones"])
    # These historical download names are known managed loose zone artifacts.
    names.add("forward.zone")
    names.update(entry.name for entry in root.iterdir()
                 if re.fullmatch(r"reverse-(?:0|[1-9][0-9]{0,2})\.zone", entry.name)
                 and int(entry.name[8:-5]) <= 255)
    manifest_path = root / "manifest.json"
    if os.path.lexists(manifest_path):
        try:
            manifest = json.loads(_read(manifest_path, MAX_ZONE_BYTES))
            generation = manifest["generation"]
            _, saved = read_generation(str(root), generation)
            if manifest != saved:
                raise ValueError
        except (ValueError, TypeError, KeyError) as error:
            raise ValidationError("Loose manifest is malformed; review it before resetting.") from error
        artifacts["manifest.json"] = _file(manifest_path)
    for name in sorted(names):
        if Path(name).name != name or name.startswith(".") or name in PROTECTED | {"manifest.json"}:
            raise ValidationError("Unsafe managed zone filename.")
        if os.path.lexists(root / name):
            artifacts[name] = _file(root / name)
    return artifacts


def preview(timestamp=None):
    # No mkdir, lock-file creation, or database UPDATE in the default preview.
    config = Configuration.objects.get(pk=1)
    root = _root(config.dns_export_directory)
    ensure_ready(str(root))
    timestamp = initial_serial() if timestamp is None else timestamp
    validate_serial(timestamp)
    now = initial_serial()
    if timestamp == 0 or not now - 900 <= timestamp <= now:
        raise ValidationError("Preview timestamp is stale, zero or in the future; generate a new preview.")
    plan = {
        "version": 1, "directory": str(root), "old_serial": config.soa_serial,
        "timestamp": timestamp, "state": _config_state(config), "artifacts": _artifacts(config),
    }
    return plan, _digest(plan)


def _sync(path):
    descriptor = os.open(_directory(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_plan(plan):
    if (type(plan) is not dict or set(plan) != {
            "version", "directory", "old_serial", "timestamp", "state", "artifacts"}
            or plan["version"] != 1 or not isinstance(plan["state"], str)
            or not re.fullmatch("[0-9a-f]{64}", plan["state"])
            or type(plan["artifacts"]) is not dict):
        raise ValidationError("Malformed local reset journal; preserve it for administrator recovery.")
    validate_serial(plan["old_serial"])
    validate_serial(plan["timestamp"])
    if plan["timestamp"] == 0:
        raise ValidationError("Reset timestamp cannot be zero.")
    for name, files in plan["artifacts"].items():
        if not isinstance(name, str):
            raise ValidationError("Unsafe reset journal artifact path.")
        path = Path(name)
        if (path.is_absolute() or ".." in path.parts
                or str(path) != name or len(path.parts) not in (1, 2)):
            raise ValidationError("Unsafe reset journal artifact path.")
        if len(path.parts) == 2:
            if path.parts[0] != "generations" or not re.fullmatch(
                    r"dnsgrid-(?:0|[1-9][0-9]{0,9})", path.name):
                raise ValidationError("Unsafe reset generation path.")
        elif (name.startswith(".") or name in PROTECTED
              or (name not in {"manifest.json", "forward.zone"}
              and not re.fullmatch(r"reverse-(?:0|[1-9][0-9]{0,2})\.zone", name)
              and normalize_domain(name) != name)):
            raise ValidationError("Unsafe reset loose artifact path.")
        if len(path.parts) == 2 and type(files) is not dict:
            raise ValidationError("Malformed reset generation inventory.")
        entries = files.values() if len(path.parts) == 2 else [files]
        for entry in entries:
            if (type(entry) is not dict or set(entry) != {"size", "sha256"}
                    or type(entry["size"]) is not int or not 0 <= entry["size"] <= MAX_ZONE_BYTES
                    or not isinstance(entry["sha256"], str)
                    or not re.fullmatch("[0-9a-f]{64}", entry["sha256"])):
                raise ValidationError("Malformed reset artifact fingerprint.")


def _finish(root, record):
    plan = record["plan"]
    _validate_plan(plan)
    if plan["directory"] != str(root):
        raise ValidationError("Reset journal belongs to another export directory.")
    quarantine_name = record["quarantine"]
    if not isinstance(quarantine_name, str) or not re.fullmatch(
            r"\.dnsgrid-reset-[0-9a-f]{32}", quarantine_name):
        raise ValidationError("Unsafe reset quarantine path.")
    quarantine = _directory(root / quarantine_name)
    _directory(quarantine / "generations")
    generations = root / "generations"
    if os.path.lexists(generations):
        planned = {Path(n).name for n in plan["artifacts"] if n.startswith("generations/")}
        if any(re.fullmatch(r"dnsgrid-(?:0|[1-9][0-9]{0,9})", p.name) and p.name not in planned
               for p in _directory(generations).iterdir()):
            raise ValidationError("Unplanned live generation appeared; preserve journal and review manually.")
    if {p.name for p in quarantine.iterdir()} - (
            {"generations"} | {n for n in plan["artifacts"] if "/" not in n}):
        raise ValidationError("Unexpected quarantine contents; preserve journal and review manually.")
    if {p.name for p in (quarantine / "generations").iterdir()} - {
            Path(n).name for n in plan["artifacts"] if n.startswith("generations/")}:
        raise ValidationError("Unexpected quarantined generations; preserve journal and review manually.")
    config = Configuration.load()
    after = Configuration.objects.get(pk=1)
    after.soa_serial = plan["timestamp"]
    after.dns_content_hash = content_fingerprint(config)
    after.dns_published_generation = ""
    if record["after"] != _config_state(after):
        raise ValidationError("Reset completion fingerprint is invalid; preserve journal for administrator recovery.")
    current_state = _config_state(config)
    already_committed = current_state == record["after"]
    if current_state != plan["state"] and not already_committed:
        raise ValidationError("Configuration or inventory changed during reset; preserve journal for administrator recovery.")
    # Validate every source/destination before moving anything. Recovery never restores
    # stale attempts to the live tree; it rolls forward using the original exact plan.
    pending = []
    for name, expected in plan["artifacts"].items():
        source, target = root / name, quarantine / name
        live, staged = os.path.lexists(source), os.path.lexists(target)
        if live == staged:
            raise ValidationError(f"Reset artifact missing or duplicated: {name}; preserve journal and quarantine.")
        base = root if live else quarantine
        actual = (_generation(base, Path(name).name) if name.startswith("generations/")
                  else _file(base / name))
        if actual != expected:
            raise ValidationError(f"Reset artifact changed: {name}; preserve journal and review manually.")
        if live:
            pending.append((source, target))
    for source, target in pending:
        _directory(source.parent)
        _directory(target.parent)
        os.replace(source, target)
        _sync(target.parent)
        _sync(source.parent)
    if not already_committed:
        from .services import _reset_dns_tracking
        _reset_dns_tracking(config, after.soa_serial)
    return quarantine


def reset(timestamp=None, token=None, *, confirmed=False, unloaded=False, nas_handled=False, recover=False):
    if not (confirmed is True and unloaded is True and nas_handled is True):
        raise ValidationError(
            "Explicit confirmation and acknowledgements that legacy serials were NEVER loaded "
            "by any DNS server and NAS scheduling/stale deliveries have been handled are required."
        )
    from .dns_delivery import _lock
    from .services import _claim_revision
    config = Configuration.objects.get(pk=1)
    root = _root(config.dns_export_directory)
    with _lock(str(root), recovery=True):
        with transaction.atomic():
            _claim_revision(config.revision, changed=False, reset_recovery=True)
            if Configuration.load().dns_export_directory != str(root):
                raise ValidationError("Export directory changed; generate a new preview.")
            journal = root / JOURNAL
            if recover:
                if not os.path.lexists(journal):
                    return None
                try:
                    record = json.loads(_read(journal, MAX_JOURNAL))
                    if type(record) is not dict or set(record) != {"plan", "quarantine", "after"}:
                        raise ValueError
                except (ValueError, TypeError, UnicodeError, RecursionError) as error:
                    raise ValidationError("Malformed reset journal; preserve it for administrator recovery.") from error
            else:
                plan, actual_token = preview(timestamp)
                if not token or actual_token != token:
                    raise ValidationError("Missing or stale preview token; generate a new preview.")
                quarantine = root / f".dnsgrid-reset-{uuid.uuid4().hex}"
                quarantine.mkdir(mode=0o700)
                (quarantine / "generations").mkdir(mode=0o700)
                _sync(quarantine)
                after = Configuration.load()
                after.soa_serial = plan["timestamp"]
                after.dns_content_hash = content_fingerprint(after)
                after.dns_published_generation = ""
                record = {"plan": plan, "quarantine": quarantine.name, "after": _config_state(after)}
                content = (json.dumps(record, sort_keys=True) + "\n").encode()
                if len(content) > MAX_JOURNAL:
                    raise ValidationError("Reset plan exceeds the recovery journal limit; review artifacts manually.")
                _atomic(journal, content, mode=0o600)
            quarantine = _finish(root, record)
        # Commit DB before retiring the journal. A failure here is recoverable even
        # when DB commit succeeded; the recorded after-state detects that case.
        os.replace(journal, quarantine / "completed.json")
        _sync(quarantine)
        _sync(root)
        return quarantine
