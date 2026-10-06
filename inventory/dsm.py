"""Reservation-only DSM API payloads; no authentication or remote writes."""

import json
from urllib.parse import urlencode

from .models import Site, normalize_mac


def reservation_payload(config, site, hosts):
    """Build the complete reservation list for one site's DSM interface."""
    Site._meta.get_field("dsm_ifname").clean(site.dsm_ifname, site)
    if not site.dsm_ifname:
        raise ValueError("Configure the site's DSM DHCP interface before exporting.")
    reservations = []
    seen = set()
    for host in sorted(hosts, key=lambda host: (host.x, host.name, host.site_id)):
        if host.site_id != site.pk:
            continue
        mac = normalize_mac(host.mac)
        if not mac:
            continue
        if mac in seen:
            raise ValueError("DSM reservations must have unique MAC addresses.")
        seen.add(mac)
        reservations.append({
            "mac": mac, "ip": f"{config.lan_prefix}.{site.g}.{host.x}", "hostname": host.name,
        })
    return {"ifname": site.dsm_ifname, "reservationData": reservations}


def reservation_request(config, site, hosts):
    """Return form parameters for POST /webapi/entry.cgi using DSM's wrapper."""
    operation = {
        "api": "SYNO.Network.DHCPServer.Reservation", "method": "set", "version": 2,
        **reservation_payload(config, site, hosts),
    }
    return {
        "api": "SYNO.Entry.Request", "method": "request", "version": 1,
        "stop_when_error": "false", "mode": json.dumps("sequential"),
        "compound": json.dumps([operation], separators=(",", ":")),
    }


def reservation_form_body(config, site, hosts):
    return urlencode(reservation_request(config, site, hosts))
