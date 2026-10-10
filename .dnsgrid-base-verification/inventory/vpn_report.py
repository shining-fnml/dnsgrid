"""Read-only VPN alignment report for the VPN center.

Compares dnsgrid's VPN members with the hosts file and the OpenVPN
client-config directory. This module only opens files for reading and
lists directories; it never creates, modifies, renames, or deletes files
and never reloads services. Nothing is auto-corrected.
"""

import ipaddress
import os
from pathlib import Path

from django.conf import settings

from .exporters import _inputs
from .models import VPN_SHORT_SUFFIX

DEFAULT_HOSTS_FILE = "/etc/hosts"
DEFAULT_CCD_DIR = "/etc/openvpn/ccd"
# OpenVPN's fallback client-config file, not a client.
CCD_DEFAULT_FILE = "DEFAULT"
MAX_FILE_BYTES = 1024 * 1024


def configured_paths():
    return (
        Path(getattr(settings, "DNSGRID_VPN_HOSTS_FILE", DEFAULT_HOSTS_FILE)),
        Path(getattr(settings, "DNSGRID_VPN_CCD_DIR", DEFAULT_CCD_DIR)),
    )


def _read_text(path):
    """Return (text, error) for a bounded, read-only text read."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        return None, "missing"
    except IsADirectoryError:
        return None, "not a regular file"
    except OSError as error:
        return None, f"unreadable ({error.strerror or error.__class__.__name__})"
    if len(data) > MAX_FILE_BYTES:
        return None, f"larger than {MAX_FILE_BYTES} bytes; not inspected"
    return data.decode("utf-8", errors="replace"), None


def _valid_ipv4(value):
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None


def parse_hosts(text):
    """Map VPN short names (without ``.vpn``) to [(line, ip)] entries.

    Only names ending in ``.vpn`` are VPN entries; every other name in the
    hosts file is out of scope and ignored.
    """
    suffix = "." + VPN_SHORT_SUFFIX
    entries = {}
    for number, line in enumerate(text.splitlines(), start=1):
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        address, names = fields[0], fields[1:]
        for name in names:
            name = name.lower()
            if name.endswith(suffix) and len(name) > len(suffix):
                entries.setdefault(name[: -len(suffix)], []).append((number, address))
    return entries


def parse_ccd(text):
    """Return the list of ``ifconfig-push`` argument lists in a CCD file."""
    pushes = []
    for line in text.splitlines():
        fields = line.strip().split()
        if not fields or fields[0].startswith(("#", ";")):
            continue
        if fields[0] == "ifconfig-push":
            pushes.append(fields[1:])
    return pushes


def _check_hosts(name, expected, hosts_entries):
    found = hosts_entries.get(name, [])
    if not found:
        return "", [f"{name}.{VPN_SHORT_SUFFIX} is missing from the hosts file."]
    addresses = sorted({address for _, address in found})
    shown = ", ".join(addresses)
    issues = []
    if len(found) > 1:
        lines = ", ".join(str(number) for number, _ in found)
        issues.append(f"{name}.{VPN_SHORT_SUFFIX} appears on multiple hosts-file lines ({lines}).")
    for number, address in found:
        if not _valid_ipv4(address):
            issues.append(f"Hosts-file line {number} has an invalid IPv4 address {address!r}.")
        elif address != expected:
            issues.append(f"Hosts-file line {number} maps to {address}, expected {expected}.")
    return shown, issues


def _check_ccd(name, expected, ccd_dir):
    text, error = _read_text(ccd_dir / name)
    if error == "missing":
        return "", [f"CCD file {name} is missing."]
    if error:
        return "", [f"CCD file {name} is {error}."]
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


def build_vpn_report(config=None, hosts=None, hosts_file=None, ccd_dir=None):
    default_hosts_file, default_ccd_dir = configured_paths()
    hosts_file = Path(hosts_file) if hosts_file is not None else default_hosts_file
    ccd_dir = Path(ccd_dir) if ccd_dir is not None else default_ccd_dir
    config, hosts = _inputs(config, hosts)
    members = [host for host in hosts if host.vpn]
    expected = {host.name: host.vpn_address(config) for host in members}

    sources = []
    hosts_text, hosts_error = _read_text(hosts_file)
    hosts_entries = parse_hosts(hosts_text) if hosts_error is None else {}
    sources.append({"label": "Hosts file", "path": str(hosts_file), "error": hosts_error})

    ccd_files, ccd_error = [], None
    try:
        with os.scandir(ccd_dir) as listing:
            ccd_files = sorted(
                (entry.name, entry.is_file()) for entry in listing
                if entry.name != CCD_DEFAULT_FILE
            )
    except FileNotFoundError:
        ccd_error = "missing"
    except NotADirectoryError:
        ccd_error = "not a directory"
    except OSError as error:
        ccd_error = f"unreadable ({error.strerror or error.__class__.__name__})"
    sources.append({"label": "OpenVPN CCD directory", "path": str(ccd_dir), "error": ccd_error})

    rows = []
    for host in members:
        name, address = host.name, expected[host.name]
        row = {
            "name": name, "short_name": host.vpn_short_name, "expected": address,
            "hosts_value": "", "ccd_value": "", "issues": [],
        }
        if hosts_error is None:
            row["hosts_value"], issues = _check_hosts(name, address, hosts_entries)
            row["issues"].extend(issues)
        else:
            row["hosts_value"] = "(not checked)"
        if ccd_error is None:
            row["ccd_value"], issues = _check_ccd(name, address, ccd_dir)
            row["issues"].extend(issues)
        else:
            row["ccd_value"] = "(not checked)"
        rows.append(row)

    hosts_orphans = [
        {
            "name": f"{name}.{VPN_SHORT_SUFFIX}",
            "lines": ", ".join(str(number) for number, _ in entries),
            "addresses": ", ".join(sorted({address for _, address in entries})),
        }
        for name, entries in sorted(hosts_entries.items()) if name not in expected
    ]
    ccd_orphans = [
        {"name": name, "regular_file": regular}
        for name, regular in ccd_files if name not in expected
    ]
    issue_count = sum(len(row["issues"]) for row in rows) + len(hosts_orphans) + len(ccd_orphans)
    issue_count += sum(1 for source in sources if source["error"])
    return {
        "revision": config.revision,
        "sources": sources,
        "rows": rows,
        "hosts_orphans": hosts_orphans,
        "ccd_orphans": ccd_orphans,
        "issue_count": issue_count,
        "aligned": issue_count == 0,
    }
