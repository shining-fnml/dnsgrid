"""NAS-side reservation application; runnable with Python's standard library only."""

import argparse
from datetime import datetime, timezone
import difflib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


SYNOWEBAPI = "/usr/syno/bin/synowebapi"
API = "SYNO.Network.DHCPServer.Reservation"


def validate_payload(payload):
    if not isinstance(payload, dict) or set(payload) != {"ifname", "reservationData"}:
        raise ValueError("Expected an export with only ifname and reservationData.")
    ifname = payload["ifname"]
    if not isinstance(ifname, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", ifname):
        raise ValueError("Invalid DSM interface name.")
    entries = payload["reservationData"]
    if not isinstance(entries, list):
        raise ValueError("reservationData must be a JSON array.")
    reservations = []
    macs, ips = set(), set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"mac", "ip", "hostname"}:
            raise ValueError("Each reservation must contain mac, ip, and hostname only.")
        mac, ip, hostname = entry["mac"], entry["ip"], entry["hostname"]
        if not isinstance(mac, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
            raise ValueError("Each reservation must have a colon-separated MAC address.")
        mac = mac.lower()
        if int(mac[:2], 16) & 1 or mac == "00:00:00:00:00:00":
            raise ValueError("Each MAC must be nonzero and unicast.")
        if not isinstance(ip, str):
            raise ValueError("Each reservation must have an IPv4 address.")
        ip = str(ipaddress.IPv4Address(ip))
        if not isinstance(hostname, str) or len(hostname) > 253 or any(
            ord(char) < 32 or ord(char) == 127 for char in hostname
        ):
            raise ValueError("Invalid reservation hostname.")
        if mac in macs or ip in ips:
            raise ValueError("Duplicate MAC or IP in reservation list.")
        macs.add(mac)
        ips.add(ip)
        reservations.append({"mac": mac, "ip": ip, "hostname": hostname})
    return {"ifname": ifname, "reservationData": reservations}


def current_payload(response, ifname):
    if not isinstance(response, dict) or response.get("success") is not True:
        raise ValueError("DSM reservation read failed.")
    try:
        lists = response["data"]["reservationList"]
    except (KeyError, TypeError) as error:
        raise ValueError("Missing DSM reservationList.") from error
    if not isinstance(lists, dict) or not isinstance(lists.get("ipv4"), list):
        raise ValueError("Missing DSM IPv4 reservation array.")
    if "ipv6" in lists and (not isinstance(lists["ipv6"], list) or lists["ipv6"]):
        raise ValueError("IPv6 reservations are unsupported; refusing to replace this interface.")
    reservations = []
    for entry in lists["ipv4"]:
        if not isinstance(entry, dict) or not {"clid", "ip", "hostname"} <= entry.keys():
            raise ValueError("Incomplete DSM reservation; refusing to omit it.")
        reservations.append({
            "mac": entry["clid"], "ip": entry["ip"], "hostname": entry["hostname"],
        })
    return validate_payload({"ifname": ifname, "reservationData": reservations})


def parse_response(output):
    # synowebapi prints a diagnostic line before its JSON response.
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", output):
        try:
            response, end = decoder.raw_decode(output, match.start())
        except ValueError:
            continue
        if isinstance(response, dict) and "success" in response and not output[end:].strip():
            return response
    raise ValueError("No complete DSM JSON response found.")


def call_api(method, ifname, reservations=None):
    args = [
        SYNOWEBAPI, "--exec", f"api={API}", f"method={method}",
        f"version={3 if method == 'get' else 2}", f"ifname={json.dumps(ifname)}",
    ]
    if method == "set":
        args.append("reservationData=" + json.dumps(reservations, separators=(",", ":")))
    result = subprocess.run(args, capture_output=True, text=True, check=True, timeout=120)
    response = parse_response(result.stdout)
    if response.get("success") is not True:
        raise ValueError(f"DSM Reservation.{method} failed: {response.get('error', 'unknown error')}")
    return response


def backup_reservations(directory, response, payload):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = Path(tempfile.mkdtemp(prefix=f"dsm-{payload['ifname']}-{stamp}-", dir=directory))
    for name, data in (("response.json", response), ("reservations.json", payload)):
        with os.fdopen(os.open(backup / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
            file.write(json.dumps(data, indent=2) + "\n")
            file.flush()
            os.fsync(file.fileno())
    return backup


def canonical_lines(payload):
    return [
        json.dumps(entry, sort_keys=True) + "\n"
        for entry in sorted(payload["reservationData"], key=lambda entry: entry["mac"])
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read, back up, and preview DSM IPv4 reservations locally; writes replace the full interface list.",
    )
    parser.add_argument("payload", type=Path, help="dnsgrid dsm-reservations-site-ID.json export")
    parser.add_argument("--backup-dir", type=Path, default=Path.cwd(), help="backup parent directory (default: current directory)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="read/backup/diff only (default)")
    mode.add_argument("--apply", action="store_true", help="ask for confirmation before writing")
    mode.add_argument("--yes", action="store_true", help="explicitly authorize writing without a prompt")
    options = parser.parse_args(argv)
    try:
        payload = validate_payload(json.loads(options.payload.read_text()))
        ifname = payload["ifname"]
        response = call_api("get", ifname)
        current = current_payload(response, ifname)
        backup = backup_reservations(options.backup_dir, response, current)
        print(f"Interface: {ifname}. Backup: {backup}")
        before, after = canonical_lines(current), canonical_lines(payload)
        print(f"Full-list replacement: {len(before)} current -> {len(after)} intended IPv4 reservations.")
        print("".join(difflib.unified_diff(before, after, fromfile="DSM current", tofile="dnsgrid intended")), end="")
        if not (options.apply or options.yes):
            print("Dry run: no changes applied. Use --apply (prompt) or --yes to write.")
            return 0
        if not options.yes:
            answer = input(f"Replace ALL reservations on {ifname}? [y/N] ").strip().lower()
            if answer != "y":
                print("Aborted: no changes applied.")
                return 0
        # Refuse stale previews, including newly added IPv6 reservations.
        latest = current_payload(call_api("get", ifname), ifname)
        if canonical_lines(latest) != before:
            raise ValueError("DSM reservations changed since preview; rerun and review.")
        call_api("set", ifname, payload["reservationData"])
        verified = current_payload(call_api("get", ifname), ifname)
        if canonical_lines(verified) != after:
            raise ValueError(f"Verification mismatch after writing; inspect DSM and backup at {backup}.")
        print("Applied and verified DSM IPv4 reservations.")
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, EOFError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
