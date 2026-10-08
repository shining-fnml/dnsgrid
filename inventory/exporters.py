"""Deterministic downloads and explicit local DNS zone publication."""

import json
import os
import stat
import tempfile
from pathlib import Path

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import F

from .dsm import reservation_payload
from .models import Configuration, Host, Site
from .dns_serial import track_dns_content


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
    return zones


@transaction.atomic
def publish_dns_zones(expected_revision):
    config, hosts = _inputs(None, None)
    if str(config.revision) != expected_revision:
        raise ValidationError("Inventory changed. Reload export previews before publishing.")
    directory = config.dns_export_directory
    if not directory:
        raise ValidationError("Configure a DNS export directory in Settings before publishing.")
    if not Path(directory).is_absolute() or "\x00" in directory:
        raise ValidationError("The DNS export directory must be an absolute local path.")
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
    written, errors = [], []
    for filename, content in zones.values():
        temporary = None
        try:
            target = Path(directory) / filename
            try:
                previous = target.lstat()
            except FileNotFoundError:
                previous = None
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="\n", dir=directory,
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
            os.replace(temporary, target)
            written.append(filename)
        except OSError as error:
            errors.append((filename, str(error)))
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    errors.append((filename, f"Could not remove temporary file: {error}"))
    if not errors:
        from .dns_publication import commit_generation
        try:
            commit_generation(config, zones)
        except (OSError, ValidationError) as error:
            errors.append(("generation manifest", str(error)))
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
    vpn = [
        "# DNSGrid application-owned export; do not replace unrelated configuration.",
    ]
    vpn.extend(
        f"{host.vpn_address(config)} {host.vpn_short_name}"
        for host in hosts if host.vpn
    )
    result["vpn.hosts"] = "\n".join(vpn) + "\n"
    result["gandi.json"] = json.dumps(desired_gandi(config, hosts), indent=2) + "\n"
    return result
