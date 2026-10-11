"""Deterministic downloads and explicit local DNS zone publication."""

import json
import os
import subprocess
import stat
import tempfile
import time
from pathlib import Path

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import F

from .dsm import reservation_payload
from .models import Configuration, Host, Site
from .dns_serial import track_dns_content
from .dns_diagnostics import log

RNDC_TIMEOUT = 10
ZONE_CHECK_TIMEOUT = 10
VPN_ZONE = "vpn"


@transaction.atomic
def _inputs(config, hosts):
    # Match inventory services' write lock before reading the serial and hosts.
    # An atomic read alone is not a repeatable snapshot on every database.
    Configuration.objects.filter(pk=1).update(revision=F("revision"))
    config = config if config is not None else Configuration.load()
    hosts = list(hosts if hosts is not None else Host.objects.select_related("site"))
    hosts.sort(key=lambda host: (host.x, host.name, host.site_id))
    return config, hosts


def _group(host):
    return host.site.g


def _header(config, origin):
    return [
        f"$ORIGIN {origin}.",
        f"$TTL {config.ttl}",
        f"{origin}. IN SOA {config.soa_ns}. {config.soa_mailbox}. (",
        f"        {config.soa_serial}",
        f"        {config.soa_refresh}",
        f"        {config.soa_retry}",
        f"        {config.soa_expire}",
        f"        {config.soa_minimum}",
        ")",
    ]


def _dns_zones(config, hosts):
    hosts = sorted(hosts, key=lambda host: host.name)
    origin = config.lan_domain
    forward = _header(config, origin)
    forward.extend(
        f"{host.lan_fqdn(config)}. {config.ttl} A {host.lan_address(config)}" for host in hosts
    )
    forward.append(f"{origin}. NS {config.zone_ns}.")
    # Downloads retain their historical names; directory deposits use zone names.
    zones = {"forward.zone": (origin, "\n".join(forward) + "\n")}
    prefix = config.lan_prefix.split(".")
    groups = sorted(set(Site.objects.values_list("g", flat=True)) | {_group(host) for host in hosts})
    for group in groups:
        origin = f"{group}.{prefix[1]}.{prefix[0]}.in-addr.arpa"
        reverse = _header(config, origin)
        reverse.extend(
            f"{host.x}.{origin}. {config.ttl} PTR {host.lan_fqdn(config)}."
            for host in hosts if _group(host) == group
        )
        reverse.append(f"{origin}. NS {config.zone_ns}.")
        zones[f"reverse-{group}.zone"] = (origin, "\n".join(reverse) + "\n")
    origin = VPN_ZONE
    vpn = _header(config, origin)
    vpn.extend(
        f"{host.name}.{origin}. {config.ttl} A {host.vpn_address(config)}"
        for host in hosts if host.vpn
    )
    vpn.append(f"{origin}. NS {config.zone_ns}.")
    zones[f"{origin}.zone"] = (f"{origin}.zone", "\n".join(vpn) + "\n")
    return zones


def _run(command, timeout):
    started = time.monotonic()
    try:
        result = subprocess.run(
            command, shell=False, check=False, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, time.monotonic() - started
    return result.returncode, time.monotonic() - started


def _validate_zone(config, zone, path):
    result, elapsed = _run(
        [config.named_checkzone, f"{zone}.", str(path)], ZONE_CHECK_TIMEOUT,
    )
    log(
        "BIND zone validation succeeded" if result == 0 else "BIND zone validation failed",
        detail=result is not None, zone=zone, exit_status=result,
        elapsed_ms=round(elapsed * 1000),
    )
    return result == 0


def _reload(config):
    result, elapsed = _run([
        config.rndc, "-k", config.rndc_key, "-s", "127.0.0.1", "-p", "953", "reload",
    ], RNDC_TIMEOUT)
    log(
        "General RNDC reload command succeeded" if result == 0 else "General RNDC reload command failed",
        detail=result is not None, exit_status=result, elapsed_ms=round(elapsed * 1000),
        verification="external client resolution not checked",
    )
    return result == 0


@transaction.atomic
def publish_dns_zones(expected_revision):
    config, hosts = _inputs(None, None)
    from .dns_reset import ensure_ready
    ensure_ready(config.dns_export_directory)
    if str(config.revision) != expected_revision:
        raise ValidationError("Inventory changed. Reload export previews before publishing.")
    directory = config.dns_export_directory
    if not directory:
        raise ValidationError("Configure a DNS export directory in Settings before publishing.")
    if not Path(directory).is_absolute() or "\x00" in directory:
        raise ValidationError("The DNS export directory must be an absolute local path.")
    if not (config.named_checkzone and config.rndc and config.rndc_key):
        raise ValidationError("Configure named_checkzone, rndc, and rndc_key before publishing DNS zones.")
    for value in (config.named_checkzone, config.rndc, config.rndc_key):
        if "\x00" in value or not Path(value).is_absolute():
            raise ValidationError("BIND validator and RNDC paths must be absolute.")
    directory_path = Path(directory)
    try:
        directory_info = directory_path.lstat()
        real_directory = directory_path.resolve() == directory_path.absolute()
    except OSError as error:
        raise ValidationError("The BIND zone directory must be an existing real directory without symlinks.") from error
    if not stat.S_ISDIR(directory_info.st_mode) or not real_directory:
        raise ValidationError("The BIND zone directory must be a real directory without symlinks.")
    track_dns_content(config)
    zones = _dns_zones(config, hosts)
    filenames = [filename for filename, _ in zones.values()]
    if len(filenames) != len(set(filenames)):
        raise ValidationError("Forward and reverse zones must have distinct publication filenames.")
    if any(
        Path(filename).name != filename or filename in (".", "..", "manifest.json") or "\x00" in filename
        for filename in filenames
    ):
        raise ValidationError("Invalid DNS zone filename.")
    from .dns_publication import preflight_generation
    preflight_generation(config, zones)
    staged, errors = [], []
    for filename, content in zones.values():
        temporary = None
        try:
            target = directory_path / filename
            try:
                previous = target.lstat()
            except FileNotFoundError:
                previous = None
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="\n", dir=directory_path,
                prefix=".dnsgrid-", delete=False,
            ) as stream:
                temporary = stream.name
                stream.write(content)
                stream.flush()
                mode = 0o644
                if previous is not None and stat.S_ISREG(previous.st_mode):
                    mode = stat.S_IMODE(previous.st_mode) & 0o666
                    if os.fstat(stream.fileno()).st_gid != previous.st_gid:
                        os.fchown(stream.fileno(), -1, previous.st_gid)
                os.fchmod(stream.fileno(), mode)
                os.fsync(stream.fileno())
            zone_origin = VPN_ZONE if filename == f"{VPN_ZONE}.zone" else filename
            if not _validate_zone(config, zone_origin, temporary):
                errors.append((filename, "BIND zone validation failed; no zone files were installed."))
                break
            staged.append((filename, temporary, target))
            temporary = None
        except OSError as error:
            errors.append((filename, "Could not stage or validate the BIND zone file."))
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    errors.append((filename, "Could not remove a temporary BIND zone file."))
    written = []
    if not errors:
        for index, (filename, temporary, target) in enumerate(staged):
            try:
                os.replace(temporary, target)
                written.append(filename)
            except OSError:
                errors.append((filename, "Atomic BIND zone installation failed; RNDC reload skipped."))
                for _, pending, _ in staged[index + 1:]:
                    try:
                        os.unlink(pending)
                    except FileNotFoundError:
                        pass
                    except OSError:
                        errors.append((filename, "Could not remove a temporary BIND zone file."))
                break
            finally:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
                except OSError:
                    errors.append((filename, "Could not remove a temporary BIND zone file."))
    else:
        for filename, temporary, _ in staged:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            except OSError:
                errors.append((filename, "Could not remove a temporary BIND zone file."))
    if not errors:
        from .dns_publication import commit_generation
        try:
            commit_generation(config, zones)
        except ValidationError as error:
            errors.append(("generation manifest", "; ".join(error.messages)))
        except OSError:
            errors.append(("generation manifest", "Could not commit the immutable DNS generation."))
    if not errors and not _reload(config):
        errors.append(("RNDC reload", "The general RNDC reload failed or timed out; client resolution was not verified."))
    log("Local publication incomplete" if errors else "Local publication complete",
        generation=f"dnsgrid-{config.soa_serial}", files_written=len(written), failures=len(errors))
    return written, errors


def desired_gandi(config=None, hosts=None):
    config, hosts = _inputs(config, hosts)
    zone = config.gandi_zone.rstrip(".").lower()
    records = []
    for host in hosts:
        if not (host.vpn and host.public_export):
            continue
        fqdn = host.vpn_fqdn(config).rstrip(".").lower()
        if fqdn == zone:
            name = "@"
        elif fqdn.endswith("." + zone):
            name = fqdn[: -(len(zone) + 1)]
        else:
            raise ValueError("The VPN hostname must be inside the configured Gandi zone.")
        records.append({
            "rrset_name": name,
            "rrset_type": "A",
            "rrset_ttl": config.ttl,
            "rrset_values": [host.vpn_address(config)],
        })
    return records


@transaction.atomic
def build_exports(config=None, hosts=None):
    config, hosts = _inputs(config, hosts)
    result = {download: content for download, (_, content) in _dns_zones(config, hosts).items()}
    for site in Site.objects.order_by("id"):
        if site.dsm_ifname:
            result[f"dsm-reservations-site-{site.pk}.json"] = json.dumps(
                reservation_payload(config, site, hosts), indent=2,
            ) + "\n"
    result["gandi.json"] = json.dumps(desired_gandi(config, hosts), indent=2) + "\n"
    return result
