"""Persist exact SFTP attempts; only a matching NAS receipt releases retention."""

import fcntl
import hashlib
import json
import os
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path

from django.core.exceptions import ValidationError
from django.db import transaction

from . import dns_sftp
from .dns_publication import _atomic, _directory, _read, pending_generations, read_generation
from .exporters import publish_dns_zones
from .models import Configuration
from .services import _claim_revision

STATUSES = {
    "inflight", "delivered", "unconfirmed", "failure",
    "installed", "already_installed", "failed", "pending", "invalid",
}
CONFIRMED = {"installed", "already_installed"}
LABELS = {
    "inflight": "Consegna in corso, in attesa di elaborazione NAS.",
    "delivered": "Consegnato via SFTP, in attesa di elaborazione NAS.",
    "unconfirmed": "Consegna SFTP non confermata; controllare esito NAS.",
    "failure": "Consegna SFTP fallita; nessuna installazione confermata.",
    "installed": "File installati sul NAS; caricamento delle zone non verificato.",
    "already_installed": "File già installati sul NAS; caricamento delle zone non verificato.",
    "failed": "Installazione NAS fallita; consultare la diagnostica locale.",
    "pending": "Esito non disponibile, in attesa di elaborazione NAS.",
    "invalid": "Esito NAS non valido; nessuna installazione confermata.",
}


def enabled(config):
    return bool(config.dns_sftp_host and config.dns_sftp_user
                and config.dns_sftp_inbox and config.dns_sftp_outbox)


def _target(config):
    fields = ("dns_sftp_host", "dns_sftp_user", "dns_sftp_port", "dns_sftp_inbox", "dns_sftp_outbox")
    return hashlib.sha256(json.dumps(
        [getattr(config, field) for field in fields], ensure_ascii=True,
    ).encode()).hexdigest()


@contextmanager
def _lock(directory):
    parent = _directory(Path(directory))
    descriptor = os.open(
        parent / ".dnsgrid-delivery.lock",
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600,
    )
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValidationError("Invalid DNS delivery lock.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValidationError("Another DNS delivery or result check is running; retry later.") from error
        yield
    finally:
        os.close(descriptor)


def _attempt(path, manifest):
    target = path / ".delivery.json"
    if not target.exists() and not target.is_symlink():
        return None
    try:
        attempt = json.loads(_read(target, 8192))
        if (type(attempt) is not dict
                or set(attempt) != {"version", "generation", "serial", "delivery", "status", "target"}
                or type(attempt["version"]) is not int or attempt["version"] != 1
                or attempt["generation"] != manifest["generation"]
                or type(attempt["serial"]) is not int or attempt["serial"] != manifest["serial"]
                or not isinstance(attempt["status"], str) or attempt["status"] not in STATUSES
                or not isinstance(attempt["target"], str) or len(attempt["target"]) != 64
                or any(char not in "0123456789abcdef" for char in attempt["target"])):
            raise ValueError
        dns_sftp.validate_delivery(attempt["delivery"], manifest["serial"])
        return attempt
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, UnicodeError, OSError, ValidationError) as error:
        raise ValidationError("Invalid saved DNS delivery metadata; administrator review required.") from error


def _save(path, attempt):
    _atomic(path / ".delivery.json", (json.dumps(attempt, sort_keys=True) + "\n").encode(), mode=0o600)


def _prepare(config, generation, fresh=False):
    path, manifest = read_generation(config.dns_export_directory, generation)
    attempt = _attempt(path, manifest)
    if not fresh and attempt and attempt["target"] == _target(config):
        if attempt["status"] not in CONFIRMED:
            _atomic(path / ".pin", b"Awaiting matching NAS installation receipt.\n", mode=0o600)
        return path, manifest, attempt, False
    # Pin first: persistence/network failures must not expose the generation to pruning.
    _atomic(path / ".pin", b"Awaiting matching NAS installation receipt.\n", mode=0o600)
    attempt = {
        "version": 1, "generation": generation, "serial": manifest["serial"],
        "delivery": f"dnsgrid-{manifest['serial']}-{uuid.uuid4().hex}", "status": "inflight",
        "target": _target(config),
    }
    _save(path, attempt)
    return path, manifest, attempt, True


def _send(config, path, manifest, attempt):
    try:
        status, summary = dns_sftp.deliver(config, path, manifest, attempt["delivery"])
    except (ValidationError, OSError):
        status, summary = "failure", LABELS["failure"]
    if status not in {"delivered", "unconfirmed", "failure"}:
        status, summary = "unconfirmed", LABELS["unconfirmed"]
    with transaction.atomic():
        _claim_revision(Configuration.load().revision, changed=False)
        attempt["status"] = status
        _save(path, attempt)
    return status, summary


def publish_and_deliver(expected_revision):
    config = Configuration.load()
    if not enabled(config):
        written, errors = publish_dns_zones(expected_revision)
        return written, errors, "disabled", "Local publication only; NAS SFTP delivery is disabled."
    with _lock(config.dns_export_directory):
        with transaction.atomic():
            _claim_revision(_revision(expected_revision), changed=False)
            if Configuration.load().dns_export_directory != config.dns_export_directory:
                raise ValidationError("DNS export directory changed; reload before delivery.")
            written, errors = publish_dns_zones(expected_revision)
            config = Configuration.load()
            if errors:
                return written, errors, "failure", "Local publication incomplete; no SFTP delivery attempted."
            if not enabled(config):
                return written, errors, "disabled", "Local publication only; NAS SFTP delivery is disabled."
            path, manifest, attempt, send = _prepare(config, config.dns_published_generation)
        if send:
            status, summary = _send(config, path, manifest, attempt)
        else:
            status, summary = attempt["status"], LABELS[attempt["status"]]
        return written, errors, status, summary


def retry_delivery(expected_revision, generation):
    config = Configuration.load()
    with _lock(config.dns_export_directory):
        with transaction.atomic():
            _claim_revision(expected_revision, changed=False)
            if Configuration.load().dns_export_directory != config.dns_export_directory:
                raise ValidationError("DNS export directory changed; reload before delivery.")
            config = Configuration.load()
            if not enabled(config):
                raise ValidationError("NAS SFTP delivery is disabled.")
            path, manifest, attempt, _ = _prepare(config, generation, fresh=True)
        return _send(config, path, manifest, attempt)


def check_result(expected_revision, generation, delivery):
    config = Configuration.load()
    with _lock(config.dns_export_directory):
        with transaction.atomic():
            _claim_revision(expected_revision, changed=False)
            if Configuration.load().dns_export_directory != config.dns_export_directory:
                raise ValidationError("DNS export directory changed; reload before checking.")
            config = Configuration.load()
            if not enabled(config):
                raise ValidationError("NAS SFTP delivery is disabled.")
            path, manifest = read_generation(config.dns_export_directory, generation)
            attempt = _attempt(path, manifest)
            dns_sftp.validate_delivery(delivery, manifest["serial"])
            if not attempt or attempt["delivery"] != delivery:
                raise ValidationError("DNS delivery changed. Reload before checking the NAS result.")
            if attempt["target"] != _target(config):
                raise ValidationError("NAS delivery destination changed. Deliver to the current destination before checking.")
            if attempt["status"] in CONFIRMED:
                (path / ".pin").unlink(missing_ok=True)
                return attempt["status"], LABELS[attempt["status"]]
            _atomic(path / ".pin", b"Awaiting matching NAS installation receipt.\n", mode=0o600)
        try:
            status, summary = dns_sftp.read_result(config, delivery, manifest["serial"])
        except (ValidationError, OSError):
            status, summary = "invalid", LABELS["invalid"]
        if status not in {"installed", "already_installed", "failed", "pending", "invalid"}:
            status, summary = "invalid", LABELS["invalid"]
        with transaction.atomic():
            _claim_revision(Configuration.load().revision, changed=False)
            current = _attempt(path, manifest)
            if not current or current["delivery"] != delivery:
                raise ValidationError("DNS delivery changed; no installation confirmed.")
            if current["target"] != _target(Configuration.load()):
                raise ValidationError("NAS delivery destination changed; no installation confirmed.")
            attempt["status"] = status
            _save(path, attempt)
            if status in CONFIRMED:
                (path / ".pin").unlink(missing_ok=True)
        return status, summary


def delivery_states(config):
    if not config.dns_export_directory:
        return []
    generations = set(pending_generations(config.dns_export_directory))
    if config.dns_published_generation:
        generations.add(config.dns_published_generation)
    states = []
    for generation in sorted(generations, reverse=True):
        try:
            path, manifest = read_generation(config.dns_export_directory, generation)
            attempt = _attempt(path, manifest)
        except (ValidationError, OSError):
            states.append({"generation": generation, "summary": "Saved generation or delivery requires administrator review."})
            continue
        if attempt:
            target_matches = attempt["target"] == _target(config)
            states.append({
                **attempt, "target_matches": target_matches,
                "summary": LABELS[attempt["status"]] if target_matches
                else "Saved attempt belongs to a different NAS destination; deliver again before checking.",
            })
        else:
            states.append({"generation": generation, "summary": "Published locally; no saved SFTP attempt."})
    return states


def _revision(value):
    text = str(value)
    if not text.isascii() or not text.isdecimal() or len(text) > 10:
        raise ValidationError("Reload export previews before publishing.")
    return int(text)
