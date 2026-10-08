"""Fixed, noninteractive SSH request; remote output is deliberately not displayed."""

import ipaddress
import re
import subprocess
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError

from .dns_serial import validate_serial


def validate_destination(host, user, port):
    if not host and not user:
        return
    valid_host = False
    if isinstance(host, str):
        try:
            ipaddress.ip_address(host)
            valid_host = "%" not in host
        except ValueError:
            valid_host = len(host) <= 253 and all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in host.split(".")
            )
    if (
        not valid_host or not isinstance(user, str)
        or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,63}", user)
        or type(port) is not int or not 1 <= port <= 65535
    ):
        raise ValidationError("Provide a NAS hostname/IP, account name, and port 1..65535, or leave host and user blank.")


def validate_generation(generation, serial):
    validate_serial(serial)
    if generation != f"dnsgrid-{serial}":
        raise ValidationError("Invalid DNS generation identifier.")


def notify_nas(config, generation, serial):
    validate_generation(generation, serial)
    validate_destination(config.dns_nas_host, config.dns_nas_user, config.dns_nas_port)
    if not config.dns_nas_host:
        return "disabled", "NAS notification is disabled."
    identity = settings.DNSGRID_DNS_SSH_IDENTITY_FILE
    known_hosts = settings.DNSGRID_DNS_SSH_KNOWN_HOSTS
    if any(not path or "\x00" in path or not Path(path).is_absolute() for path in (identity, known_hosts)):
        return "failure", "Local publication succeeded; provision absolute SSH identity and known_hosts paths before retrying."
    arguments = [
        "/usr/bin/ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no", "-o", "ClearAllForwardings=yes",
        "-o", "ForwardAgent=no",
        "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
        "-o", f"UserKnownHostsFile={known_hosts}", "-i", identity,
        "-p", str(config.dns_nas_port), "-l", config.dns_nas_user,
        "--", config.dns_nas_host, f"dnsgrid-update {generation} {serial}",
    ]
    try:
        # Discard, rather than capture, untrusted output: bounded memory and no
        # private paths, credentials, terminal escapes or markup in UI/logs.
        result = subprocess.run(
            arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=120, check=False,
        )
    except subprocess.TimeoutExpired:
        return "unconfirmed", "Local publication succeeded; NAS update timed out and may have occurred. Retry this generation."
    except OSError:
        return "failure", "Local publication succeeded; SSH could not be started. Check deployment settings and retry."
    if result.returncode == 0:
        return "success", "NAS confirmed zone files installed (not proof that zones were loaded)."
    if result.returncode == 255 or result.returncode < 0:
        return "unconfirmed", "Local publication succeeded; SSH transport interrupted. NAS update may have occurred. Retry this generation."
    return "failure", "Local publication succeeded; NAS reported update failure. Review NAS-local diagnostics and retry."
