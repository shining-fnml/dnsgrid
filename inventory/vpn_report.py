"""Bounded, read-only comparison of VPN inventory with OpenVPN CCD files."""

import ipaddress
import os
import stat
from pathlib import Path

from django.conf import settings
from django.db import transaction

from .models import Configuration, Host

DEFAULT_CCD_DIR = "/etc/openvpn/ccd"
CCD_DEFAULT_FILE = "DEFAULT"
MAX_DIRECTORY_ENTRIES = 4096
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 8 * MAX_FILE_BYTES


def configured_paths():
    return Path(getattr(settings, "DNSGRID_VPN_CCD_DIR", DEFAULT_CCD_DIR))


def _source_error(error):
    if isinstance(error, FileNotFoundError):
        return "missing"
    if isinstance(error, NotADirectoryError):
        return "not a directory or contains a symlink"
    return f"unreadable ({error.strerror or error.__class__.__name__})"


def _open_directory(path):
    """Open each component without following symlinks, including parents."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open("/", flags)
    try:
        for component in Path(os.path.abspath(path)).parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_text(directory, name, remaining):
    """Never follow symlinks or block on special files; cap total read bytes."""
    if Path(name).name != name or name in (".", "..") or "\x00" in name:
        return None, "has an unsafe filename; not inspected", 0
    if remaining <= 0:
        return None, "not inspected: total read limit reached", 0
    descriptor = None
    try:
        if not stat.S_ISREG(os.stat(name, dir_fd=directory, follow_symlinks=False).st_mode):
            return None, "not a regular file; not inspected", 0
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory,
        )
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None, "not a regular file; not inspected", 0
        limit = min(MAX_FILE_BYTES + 1, remaining)
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            data = handle.read(limit)
            if len(data) >= limit:
                return None, "not inspected: file or total read limit reached", len(data)
        try:
            return data.decode("utf-8"), None, len(data)
        except UnicodeDecodeError:
            return None, "not valid UTF-8; not inspected", len(data)
    except OSError as error:
        return None, _source_error(error), 0
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _valid_ipv4(value):
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None


def parse_ccd(text):
    """Return active ``ifconfig-push`` argument lists."""
    pushes = []
    for line in text.splitlines():
        fields = line.strip().split()
        if fields and fields[0] == "ifconfig-push":
            pushes.append(fields[1:])
    return pushes


def _check_ccd(name, expected, text):
    pushes = parse_ccd(text)
    if not pushes:
        return "", [f"CCD file {name} has no ifconfig-push directive."]
    if len(pushes) > 1:
        return "", [f"CCD file {name} has {len(pushes)} ifconfig-push directives."]
    arguments = pushes[0]
    shown = " ".join(arguments)
    if len(arguments) != 2 or not all(_valid_ipv4(value) for value in arguments):
        return shown, [f"CCD file {name} has a malformed ifconfig-push: {shown!r}."]
    if arguments[0] != expected:
        return shown, [f"CCD file {name} pushes {arguments[0]}, expected {expected}."]
    return shown, []


@transaction.atomic
def build_vpn_report(config=None, hosts=None, ccd_dir=None):
    config = config if config is not None else Configuration.objects.get(pk=1)
    hosts = list(hosts if hosts is not None else Host.objects.select_related("site"))
    members = sorted((host for host in hosts if host.vpn), key=lambda host: host.name)
    expected = {host.name: host.vpn_address(config) for host in members}
    ccd_dir = Path(ccd_dir) if ccd_dir is not None else configured_paths()
    files, directory_error, descriptor = {}, None, None
    rows, remaining, inspection_errors = [], MAX_TOTAL_BYTES, 0
    try:
        try:
            descriptor = _open_directory(ccd_dir)
            with os.scandir(descriptor) as listing:
                for index, entry in enumerate(listing):
                    if index >= MAX_DIRECTORY_ENTRIES:
                        directory_error = f"more than {MAX_DIRECTORY_ENTRIES} entries; not inspected"
                        break
                    if entry.name != CCD_DEFAULT_FILE:
                        files[entry.name] = entry.is_file(follow_symlinks=False)
        except OSError as error:
            directory_error = _source_error(error)
        except ValueError:
            directory_error = "invalid directory path; not inspected"
        if directory_error:
            files = {}

        for host in members:
            name = host.name
            row = {
                "name": name, "short_name": host.vpn_short_name,
                "expected": expected[name], "ccd_value": "", "issues": [],
                "checked": directory_error is None,
            }
            if directory_error:
                row["ccd_value"] = "(not checked)"
            elif name not in files:
                row["issues"] = [f"CCD file {name} is missing."]
            else:
                text, error, used = _read_text(descriptor, name, remaining)
                remaining -= used
                if error:
                    row["checked"] = False
                    row["ccd_value"] = "(not checked)"
                    row["issues"] = [f"CCD file {name} is {error}."]
                    inspection_errors += 1
                else:
                    row["ccd_value"], row["issues"] = _check_ccd(name, expected[name], text)
            rows.append(row)
    finally:
        if descriptor is not None:
            os.close(descriptor)

    orphans = [
        {"name": name, "regular_file": regular}
        for name, regular in sorted(files.items()) if name not in expected
    ]
    issue_count = sum(len(row["issues"]) for row in rows) + len(orphans)
    issue_count += bool(directory_error)
    inconclusive = bool(directory_error or inspection_errors)
    return {
        "revision": config.revision,
        "sources": [{"label": "OpenVPN CCD directory", "path": str(ccd_dir), "error": directory_error}],
        "rows": rows, "ccd_orphans": orphans, "issue_count": issue_count,
        "inconclusive": inconclusive,
        "status": "inconclusive" if inconclusive else ("issues" if issue_count else "clean"),
        "aligned": issue_count == 0 and not inconclusive,
    }
