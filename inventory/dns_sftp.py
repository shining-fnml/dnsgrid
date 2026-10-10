"""SFTP-only delivery; credentials belong to the deployment, not the inventory."""

import ipaddress
import json
import os
import re
import stat
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError

from .dns_serial import validate_serial


def validate_destination(host, user, port):
    if not host and not user:
        return
    valid = False
    if isinstance(host, str):
        try:
            ipaddress.ip_address(host)
            valid = "%" not in host
        except ValueError:
            valid = len(host) <= 253 and all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                for part in host.split(".")
            )
    if (not valid or not isinstance(user, str)
            or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,63}", user)
            or type(port) is not int or not 1 <= port <= 65535):
        raise ValidationError("Provide a valid SFTP hostname, account and port, or leave host and user blank.")


def validate_generation(generation, serial):
    validate_serial(serial)
    if generation != f"dnsgrid-{serial}":
        raise ValidationError("Invalid DNS generation identifier.")


def validate_delivery(delivery, serial):
    validate_serial(serial)
    if not isinstance(delivery, str) or not re.fullmatch(
        rf"dnsgrid-{serial}-[0-9a-f]{{32}}", delivery
    ):
        raise ValidationError("Invalid NAS delivery identifier.")


def quote(path):
    """Escape both SFTP batch tokenization and its glob expansion."""
    path = str(path)
    if not path or any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise ValidationError("Invalid SFTP path.")
    return '"' + "".join("\\" + char if char in '\\\"' else char for char in path) + '"'


def validate_remote_path(path):
    if (not isinstance(path, str) or not path.startswith("/") or path == "/"
            or any(part in ("", ".", "..") for part in path.split("/")[1:])):
        raise ValidationError("SFTP directories must be absolute paths without traversal.")
    quote(path)


def _arguments(config):
    validate_destination(config.dns_sftp_host, config.dns_sftp_user, config.dns_sftp_port)
    if not config.dns_sftp_host:
        raise ValidationError("NAS SFTP delivery is disabled.")
    identity = settings.DNSGRID_DNS_SFTP_IDENTITY_FILE
    known_hosts = settings.DNSGRID_DNS_SFTP_KNOWN_HOSTS
    for path in (identity, known_hosts):
        if not path or not Path(path).is_absolute():
            raise ValidationError("Provision absolute SFTP identity and known_hosts paths.")
        quote(path)
    if any(char.isspace() or char in '\\\"' for char in known_hosts):
        raise ValidationError("The known_hosts path cannot contain whitespace, quotes or backslashes.")
    host = config.dns_sftp_host
    if ":" in host:
        host = f"[{host}]"
    return [
        "/usr/bin/sftp", "-F", "/dev/null", "-q", "-b", "-",
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "IdentitiesOnly=yes", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no",
        "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
        "-o", f"UserKnownHostsFile={known_hosts}", "-i", identity,
        "-P", str(config.dns_sftp_port), "--", f"{config.dns_sftp_user}@{host}",
    ]


def _run(config, batch, download=False):
    arguments = _arguments(config)
    if download:
        # Bound disk consumption as well as duration for an untrusted receipt.
        arguments[1:1] = ["-l", "64"]
    return subprocess.run(
        arguments, input=batch.encode("utf-8"),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        shell=False, timeout=120, check=False,
    ).returncode


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def deliver(config, path, manifest, delivery):
    validate_delivery(delivery, manifest["serial"])
    validate_generation(manifest["generation"], manifest["serial"])
    validate_remote_path(config.dns_sftp_inbox)
    remote = f"{config.dns_sftp_inbox}/{delivery}"
    partial = remote + ".partial"
    batch = [f"mkdir {quote(partial)}"]
    for zone in manifest["zones"]:
        name = zone["filename"]
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", name):
            raise ValidationError("Invalid zone filename.")
        batch.append(f"put {quote(path / name)} {quote(partial + '/' + name)}")
    batch.extend([
        f"put {quote(path / 'manifest.json')} {quote(partial + '/manifest.json')}",
        f"rename {quote(partial)} {quote(remote)}",
    ])
    try:
        code = _run(config, "\n".join(batch) + "\n")
    except subprocess.TimeoutExpired:
        return "unconfirmed", "Consegna non confermata: timeout SFTP. Controlla esito NAS prima di riprovare."
    except OSError:
        return "failure", "Impossibile avviare SFTP; controllare la configurazione locale."
    if code:
        return "unconfirmed", "Consegna non confermata: SFTP interrotto o fallito. Controlla esito NAS."
    return "delivered", "Consegnato, in attesa di elaborazione. I file non sono ancora confermati installati."


def read_result(config, delivery, serial):
    validate_delivery(delivery, serial)
    validate_remote_path(config.dns_sftp_outbox)
    with tempfile.TemporaryDirectory(prefix="dnsgrid-result-") as directory:
        path = Path(directory) / "result.json"
        batch = f"get {quote(config.dns_sftp_outbox + '/' + delivery + '.json')} {quote(path)}\n"
        try:
            if _run(config, batch, download=True):
                return "pending", "Esito non disponibile: consegnato o non confermato, in attesa di elaborazione."
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > 8192:
                    raise ValueError
                raw = stream.read(8193)
            if len(raw) > 8192:
                raise ValueError
            result = json.loads(raw, object_pairs_hook=_unique_object)
            timestamp = datetime.fromisoformat(result["timestamp"])
            if (type(result) is not dict
                    or set(result) != {"delivery", "serial", "status", "timestamp", "summary"}
                    or result["delivery"] != delivery or type(result["serial"]) is not int
                    or result["serial"] != serial
                    or result["status"] not in ("installed", "already_installed", "failed")
                    or timestamp.utcoffset() is None or timestamp.utcoffset().total_seconds() != 0
                    or not isinstance(result["summary"], str) or len(result["summary"]) > 512
                    or any(ord(char) < 32 or ord(char) == 127 for char in result["summary"])):
                raise ValueError
        except (subprocess.TimeoutExpired, OSError):
            return "pending", "Lettura esito NAS non confermata; riprovare il controllo."
        except (ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError):
            return "invalid", "Esito NAS non valido; nessuna installazione confermata."
    # Never display NAS-provided text, even from a structurally valid result.
    return result["status"], {
        "installed": "File installati sul NAS; caricamento delle zone non verificato.",
        "already_installed": "File già installati sul NAS; caricamento delle zone non verificato.",
        "failed": "Installazione NAS fallita; consultare la diagnostica locale protetta.",
    }[result["status"]]
