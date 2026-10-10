"""Conservative LiveDNS reconciliation with durable, per-record ownership.

LiveDNS offers no conditional/ETag writes. Fresh reads reduce, but cannot eliminate,
the race with an external editor between a read and a write.
"""

import hashlib
import json
import os
import re
from urllib import error, parse, request

from django.db import transaction
from django.db.models import F

from .exporters import _inputs, desired_gandi
from .models import Configuration, GandiRecord


class GandiError(RuntimeError):
    """A safe-to-display failure, never containing credentials or response bodies."""


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GandiClient:
    base_url = "https://api.gandi.net/v5/livedns/"

    def __init__(self, config=None, timeout=15):
        config = config if config is not None else Configuration.load()
        self.token = os.environ.get("DNSGRID_GANDI_TOKEN") or config.gandi_token
        self.timeout = timeout
        if not self.token:
            raise GandiError("A Gandi API token is required.")
        if not isinstance(self.token, str) or "\r" in self.token or "\n" in self.token:
            raise GandiError("The Gandi API token contains invalid characters.")

    def _request(self, method, zone, name=None, record_type=None, record=None):
        if (not isinstance(zone, str)
                or not re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*", zone)
                or (name is not None and (
                    not isinstance(name, str)
                    or not re.fullmatch(r"@|[A-Za-z0-9_*-]+(?:\.[A-Za-z0-9_*-]+)*", name)
                ))
                or (record_type is not None and (
                    not isinstance(record_type, str)
                    or not re.fullmatch(r"[A-Z][A-Z0-9]*", record_type)
                ))):
            raise GandiError("Invalid Gandi resource identifier.")
        parts = ["domains", zone, "records"]
        if name is not None:
            parts.append(name)
        if record_type is not None:
            parts.append(record_type)
        # Reject dot segments outright: even percent-encoded dots can be normalized.
        if any(not isinstance(part, str) or not part or part in (".", "..")
               for part in parts):
            raise GandiError("Invalid Gandi resource identifier.")
        url = self.base_url + "/".join(parse.quote(part, safe="") for part in parts)
        try:
            body = None if record is None else json.dumps(record).encode("utf-8")
            headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            req = request.Request(url, data=body, headers=headers, method=method)
            with request.build_opener(_NoRedirect()).open(req, timeout=self.timeout) as response:
                data = response.read()
            return json.loads(data) if data else None
        except error.HTTPError as exc:
            raise GandiError(f"Gandi request failed (HTTP {exc.code}).") from None
        except (error.URLError, TimeoutError, OSError, TypeError, ValueError):
            raise GandiError("Gandi request failed or returned invalid JSON.") from None

    def list_rrsets(self, zone):
        return self._request("GET", zone)

    def create_rrset(self, zone, record):
        return self._request("POST", zone, record=record)

    def update_rrset(self, zone, name, record_type, record):
        return self._request("PUT", zone, name, record_type, record=record)

    def delete_rrset(self, zone, name, record_type):
        return self._request("DELETE", zone, name, record_type)


def _canonical(record):
    try:
        name = record["rrset_name"].rstrip(".").lower()
        record_type = record["rrset_type"].upper()
        ttl = record["rrset_ttl"]
        values = record["rrset_values"]
        if (not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 0
                or not isinstance(values, list)
                or not all(isinstance(value, str) for value in values)
                or not re.fullmatch(r"[A-Z][A-Z0-9]*", record_type)):
            raise ValueError
        return {
            "rrset_name": name,
            "rrset_type": record_type,
            "rrset_ttl": ttl,
            "rrset_values": sorted(values),
        }
    except (KeyError, TypeError, AttributeError, ValueError):
        raise GandiError("Gandi returned an invalid record set.") from None


def _ledger_record(record):
    return _canonical({
        "rrset_name": record.name,
        "rrset_type": record.record_type,
        "rrset_ttl": record.ttl,
        "rrset_values": record.values,
    })


def _remote(client, zone):
    records = client.list_rrsets(zone)
    if not isinstance(records, list):
        raise GandiError("Gandi returned an invalid record list.")
    result = {}
    for raw in records:
        record = _canonical(raw)
        key = (record["rrset_name"], record["rrset_type"])
        if key in result:
            raise GandiError("Gandi returned duplicate record sets.")
        result[key] = record
    return result


def _make_plan(config, hosts, client):
    desired = {
        (config.gandi_zone, record["rrset_name"], record["rrset_type"]): _canonical(record)
        for record in desired_gandi(config, hosts)
    }
    ledger = {
        (record.zone, record.name, record.record_type): _ledger_record(record)
        for record in GandiRecord.objects.all()
    }
    zones = sorted({config.gandi_zone} | {key[0] for key in ledger})
    remote = {zone: _remote(client, zone) for zone in zones}
    changes, conflicts = [], []
    for key in sorted(set(desired) | set(ledger)):
        zone, name, record_type = key
        before = remote[zone].get((name, record_type))
        owned = ledger.get(key)
        after = desired.get(key)
        other_types = [
            kind for remote_name, kind in remote[zone]
            if remote_name == name and kind != record_type
        ]
        # DNS permits A alongside TXT/MX; only CNAME (or an intended CNAME)
        # forbids other record types.
        collision = "CNAME" in other_types or (record_type == "CNAME" and other_types)
        if owned is None:
            if before is not None or collision:
                conflicts.append(f"Unmanaged record collision: {zone} / {name} / {record_type}.")
            elif after is not None:
                changes.append({"action": "create", "zone": zone, "name": name,
                                "type": record_type, "before": None, "after": after})
        elif before != owned:
            conflicts.append(f"Managed record changed remotely: {zone} / {name} / {record_type}.")
        elif after is not None and collision:
            conflicts.append(f"Conflicting remote record type: {zone} / {name} / {record_type}.")
        elif before != after:
            changes.append({"action": "delete" if after is None else "update",
                            "zone": zone, "name": name, "type": record_type,
                            "before": before, "after": after})
    plan = {"revision": config.revision, "changes": changes, "conflicts": conflicts}
    state = {
        "plan": plan,
        "remote": {zone: [records[key] for key in sorted(records)]
                   for zone, records in remote.items()},
        "ledger": [[*key, ledger[key]] for key in sorted(ledger)],
        "desired": [[*key, desired[key]] for key in sorted(desired)],
    }
    plan["fingerprint"] = hashlib.sha256(
        json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return plan


def plan_sync(config=None, hosts=None, client=None):
    config, hosts = _inputs(config, hosts)
    client = client if client is not None else GandiClient(config)
    return _make_plan(config, hosts, client)


def sync(config=None, hosts=None, client=None, *, expected_fingerprint):
    config, hosts = _inputs(config, hosts)
    client = client if client is not None else GandiClient(config)
    plan = _make_plan(config, hosts, client)
    if not expected_fingerprint or plan["fingerprint"] != expected_fingerprint:
        raise GandiError("The preview is stale. Generate and confirm a new preview.")
    if plan["conflicts"]:
        raise GandiError("Synchronization refused because the preview contains conflicts.")
    if not Configuration.objects.filter(pk=1, revision=plan["revision"]).exists():
        raise GandiError("Inventory changed. Generate and confirm a new preview.")
    for change in plan["changes"]:
        # UPDATE locks on SQLite too, unlike select_for_update. Each successful
        # operation commits its ledger before attempting another external write.
        with transaction.atomic():
            locked = Configuration.objects.filter(pk=1, revision=plan["revision"]).update(
                revision=F("revision")
            )
            if not locked:
                raise GandiError("Inventory changed. Generate and confirm a new preview.")
            zone, name, kind = change["zone"], change["name"], change["type"]
            owned = GandiRecord.objects.filter(zone=zone, name=name, record_type=kind).first()
            if (None if owned is None else _ledger_record(owned)) != change["before"]:
                raise GandiError("Ownership changed. Generate and confirm a new preview.")
            remote = _remote(client, zone)
            if remote.get((name, kind)) != change["before"] or (
                change["after"] is not None
                and any(remote_name == name and (
                    remote_kind == "CNAME" or kind == "CNAME"
                ) and remote_kind != kind for remote_name, remote_kind in remote)
            ):
                raise GandiError("Remote records changed. Generate and confirm a new preview.")
            if change["action"] == "delete":
                client.delete_rrset(zone, name, kind)
                owned.delete()
            else:
                after = change["after"]
                if change["action"] == "create":
                    client.create_rrset(zone, after)
                else:
                    client.update_rrset(zone, name, kind, after)
                GandiRecord.objects.update_or_create(
                    zone=zone, name=name, record_type=kind,
                    defaults={"ttl": after["rrset_ttl"], "values": after["rrset_values"]},
                )
    return plan
