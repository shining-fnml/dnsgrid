"""Versioned application data, deliberately separate from database backups."""

import ipaddress
import hashlib
import json

from django.core.exceptions import ValidationError
from django.db import transaction

from .models import MAX_PORTABLE_ID, MAX_SERIAL, Configuration, GandiRecord, Host, Site
from .services import _claim_revision
from .dns_serial import initial_serial, track_dns_content, validate_serial

FORMAT = "dnsgrid.application-data"
SCHEMA_VERSION = 1
MAX_BYTES = 8 * 1024 * 1024
MAX_LEDGER = 1024
MAX_ID = MAX_PORTABLE_ID
CONFIG_FIELDS = (
    "id", "lan_domain", "vpn_domain", "lan_prefix", "vpn_prefix", "gandi_zone",
    "ttl", "soa_ns", "soa_mailbox", "revision",
    "soa_refresh", "soa_retry", "soa_expire", "soa_minimum", "zone_ns",
    "soa_serial",
)
HOST_FIELDS = (
    "id", "name", "site_id", "row", "column", "category", "status",
    "vpn", "public_export", "mac", "notes",
)
SITE_FIELDS = ("id", "name", "g", "dsm_ifname")
LEDGER_FIELDS = ("id", "zone", "name", "record_type", "values", "ttl")
WARNINGS = (
    "This replaces all target settings, sites, hosts, and ownership records, not merges them.",
    "Use a trusted archive for the SAME Gandi domain and VPN control scope only. "
    "The ownership ledger grants the ability to update/delete matching provider records, "
    "including historical records no longer desired by any host.",
    "Never run source and destination as simultaneous Gandi writers. Stop the source first.",
    "No provider API calls are made by preview or restore. Existing provider conflict checks "
    "remain mandatory on the next Gandi preview/sync.",
    "No automatic DNS/DHCP/Gandi deployment is performed.",
    "Users, passwords, sessions, pending confirmations, tokens, environment secrets, and deployment settings are "
    "excluded. The destination's saved Gandi token is preserved.",
)


def _fail(message="Invalid application archive."):
    raise ValidationError(message)


def dumps(data):
    return json.dumps(data, sort_keys=True, ensure_ascii=True, indent=2, allow_nan=False) + "\n"


def fingerprint(data):
    return hashlib.sha256(dumps(data).encode("utf-8")).hexdigest()


def _fields(instance, fields):
    result = {field: getattr(instance, field) for field in fields}
    if "values" in result:
        result["values"] = sorted(result["values"])
    return result


@transaction.atomic
def snapshot(expected_revision=None):
    # SQLite's read transaction is a stable snapshot; on other backends the
    # singleton lock also excludes inventory changes and ledger checkpoints.
    config = Configuration.objects.select_for_update().get(pk=1)
    if expected_revision is not None and expected_revision != config.revision:
        _fail("Inventory changed. Reload export previews before downloading.")
    return {
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "configuration": _fields(config, CONFIG_FIELDS),
        "sites": [_fields(site, SITE_FIELDS) for site in Site.objects.order_by("id")],
        "hosts": [_fields(host, HOST_FIELDS) for host in Host.objects.order_by("id")],
        "gandi_records": [
            _fields(record, LEDGER_FIELDS) for record in GandiRecord.objects.order_by("id")
        ],
    }


def _object(value, fields, integer=(), boolean=(), arrays=()):
    if type(value) is not dict or set(value) != set(fields):
        _fail("Archive objects must contain exactly the documented fields.")
    for field in fields:
        expected = int if field in integer else bool if field in boolean else list if field in arrays else str
        if type(value[field]) is not expected:
            _fail(f"Invalid type for {field}.")
        if expected is str and (len(value[field]) > 4000 or "\x00" in value[field]):
            _fail(f"Invalid text for {field}.")
        if expected is str:
            try:
                value[field].encode("utf-8")
            except UnicodeError:
                _fail(f"Invalid UTF-8 text for {field}.")
    if "id" in fields and not 1 <= value["id"] <= MAX_ID:
        _fail("Object IDs must be positive JSON-safe integers no larger than 2**53 - 1.")


def _unique(items, key, label):
    values = [key(item) for item in items]
    if len(values) != len(set(values)):
        _fail(f"Duplicate {label}.")


def validate(data):
    """Validate entirely against the candidate dataset, never outgoing rows."""
    if type(data) is not dict or set(data) != {
        "format", "schema_version", "configuration", "sites", "hosts", "gandi_records",
    }:
        _fail("Unknown or missing archive fields.")
    if type(data["format"]) is not str or data["format"] != FORMAT:
        _fail("Unsupported archive format identifier.")
    if type(data["schema_version"]) is not int or data["schema_version"] != SCHEMA_VERSION:
        _fail("Unsupported archive schema version.")
    for field, limit in (("sites", 4), ("hosts", 127), ("gandi_records", MAX_LEDGER)):
        if type(data[field]) is not list or len(data[field]) > limit:
            _fail(f"Invalid or excessive {field} count.")
    raw_config = data["configuration"]
    if type(raw_config) is dict:
        # Retired deployment fields are accepted only for archive compatibility.
        raw_config = {
            field: value for field, value in raw_config.items()
            if field not in {"dns_nas_host", "dns_nas_user", "dns_nas_port"}
        }
    new_fields = ("soa_refresh", "soa_retry", "soa_expire", "soa_minimum", "zone_ns", "soa_serial")
    if type(raw_config) is dict and set(raw_config) in (
        set(CONFIG_FIELDS) - set(new_fields),
        set(CONFIG_FIELDS) - (set(new_fields) - {"soa_serial"}),
    ):
        defaults = Configuration()
        raw_config = {
            **raw_config,
            **{field: getattr(defaults, field) for field in new_fields},
            "zone_ns": raw_config["soa_ns"],
            "soa_refresh": 3600,
            "soa_retry": 900,
            "soa_minimum": min(raw_config["ttl"], 300) if type(raw_config["ttl"]) is int else 300,
            "soa_serial": raw_config.get("soa_serial", max(initial_serial(), raw_config["revision"])
                                        if type(raw_config["revision"]) is int else 0),
        }
    if type(raw_config) is dict and set(raw_config) == set(CONFIG_FIELDS) - {"soa_serial"}:
        raw_config = {**raw_config, "soa_serial": max(initial_serial(), raw_config["revision"])
                      if type(raw_config["revision"]) is int else 0}
    if type(raw_config) is dict and "soa_serial" in raw_config:
        validate_serial(raw_config["soa_serial"])
    _object(raw_config, CONFIG_FIELDS, integer=(
        "id", "revision", "ttl", "soa_refresh", "soa_retry", "soa_expire", "soa_minimum", "soa_serial",
    ))
    if data["configuration"]["id"] != 1:
        _fail("Configuration must have ID 1.")
    config = Configuration(**raw_config)
    config.clean_for_hosts([])
    sites = []
    for raw in data["sites"]:
        if type(raw) is dict and set(raw) == {"id", "name", "g"}:
            raw = {**raw, "dsm_ifname": ""}
        _object(raw, SITE_FIELDS, integer=("id", "g"))
        site = Site(**raw)
        site.clean()
        site.clean_fields()
        sites.append(site)
    if {site.pk for site in sites} != {1, 2, 3, 4} or len(sites) != 4:
        _fail("Archive must contain exactly the four fixed sites.")
    _unique(sites, lambda site: site.g, "site octet")
    _unique(sites, lambda site: site.name.casefold(), "site name")
    site_map = {site.pk: site for site in sites}
    hosts = []
    for raw in data["hosts"]:
        _object(raw, HOST_FIELDS, integer=("id", "site_id", "row", "column"),
                boolean=("vpn", "public_export"))
        if raw["site_id"] not in site_map:
            _fail("Host references an unknown site.")
        host = Host(**raw)
        host.site = site_map[host.site_id]
        # Normalize with the shared model rules, then validate field lengths.
        host.clean_for_inventory(config, hosts)
        host.clean_fields(exclude=["site"])
        hosts.append(host)
    config.clean_for_hosts(hosts)
    config.clean_fields()
    _unique(hosts, lambda host: host.pk, "host ID")
    _unique(hosts, lambda host: host.name, "host name")
    _unique(hosts, lambda host: (host.row, host.column), "host position")
    records = []
    for raw in data["gandi_records"]:
        _object(raw, LEDGER_FIELDS, integer=("id", "ttl"), arrays=("values",))
        if not 1 <= len(raw["values"]) <= 16 or any(type(value) is not str for value in raw["values"]):
            _fail("Owned A records require 1–16 IPv4 values.")
        try:
            for value in raw["values"]:
                ipaddress.IPv4Address(value)
        except (ValueError, ipaddress.AddressValueError):
            _fail("Owned A records require valid IPv4 addresses.")
        _unique(raw["values"], lambda value: value, "record value")
        record = GandiRecord(**raw)
        record.clean()
        record.clean_fields()
        if record.zone != config.gandi_zone:
            _fail("Ownership zone must match the incoming configured Gandi zone.")
        fqdn = record.zone if record.name == "@" else f"{record.name}.{record.zone}"
        # Only direct host labels within vpn_domain are controllable by exports.
        suffix = "." + config.vpn_domain
        if not fqdn.endswith(suffix) or "." in fqdn[:-len(suffix)] or len(fqdn) > 253:
            _fail("Ownership record is outside the incoming VPN host control scope.")
        records.append(record)
    _unique(records, lambda record: record.pk, "ownership ID")
    _unique(records, lambda record: (record.zone, record.name, record.record_type), "owned record")
    normalized = {
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "configuration": _fields(config, CONFIG_FIELDS),
        "sites": [_fields(site, SITE_FIELDS) for site in sorted(sites, key=lambda site: site.pk)],
        "hosts": [_fields(host, HOST_FIELDS) for host in sorted(hosts, key=lambda host: host.pk)],
        "gandi_records": [_fields(record, LEDGER_FIELDS) for record in sorted(records, key=lambda record: record.pk)],
    }
    if len(dumps(normalized).encode("utf-8")) > MAX_BYTES:
        _fail("Archive exceeds the 8 MiB pending-data limit.")
    return normalized


def loads(content):
    if type(content) is not bytes or len(content) > MAX_BYTES:
        _fail("Upload a UTF-8 JSON archive no larger than 8 MiB.")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail("Duplicate JSON object key.")
            result[key] = value
        return result

    try:
        data = json.loads(content.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda value: _fail("Nonfinite JSON number."))
        return validate(data)
    except (ValueError, UnicodeError, RecursionError, TypeError, OverflowError):
        _fail("Upload a valid bounded UTF-8 JSON archive.")


def diff(before, after):
    changes = []
    for field in CONFIG_FIELDS:
        if before["configuration"][field] != after["configuration"][field]:
            changes.append({"label": f"Setting {field}", "before": before["configuration"][field],
                            "after": after["configuration"][field]})
    for section in ("sites", "hosts", "gandi_records"):
        old = {item["id"]: item for item in before[section]}
        new = {item["id"]: item for item in after[section]}
        changes.append({"label": f"{section} count", "before": len(old), "after": len(new)})
        for pk in sorted(set(old) | set(new)):
            if old.get(pk) != new.get(pk):
                changes.append({"label": f"{section} ID {pk}",
                                "before": dumps(old[pk]) if pk in old else "Absent",
                                "after": dumps(new[pk]) if pk in new else "Removed"})
    return changes


@transaction.atomic
def restore(data, expected_revision, expected_fingerprint=None):
    data = validate(data)
    next_revision = max(expected_revision, data["configuration"]["revision"]) + 1
    if next_revision > MAX_SERIAL:
        _fail("Restoring would exceed the maximum inventory revision.")
    _claim_revision(expected_revision, changed=False)
    if expected_fingerprint is not None and fingerprint(snapshot()) != expected_fingerprint:
        _fail("Target data or ownership changed. Generate a fresh archive preview.")
    _claim_revision(expected_revision)
    current = Configuration.objects.get(pk=1)
    from .services import _dns_baseline
    current = _dns_baseline()
    previous_serial = current.soa_serial
    previous_hash = current.dns_content_hash
    # Delete dependents first, retain the fixed site rows and secret singleton.
    Host.objects.all().delete()
    GandiRecord.objects.all().delete()
    for raw in data["sites"]:
        Site.objects.update_or_create(pk=raw["id"], defaults={
            "name": raw["name"], "g": raw["g"], "dsm_ifname": raw["dsm_ifname"],
        })
    for field in CONFIG_FIELDS:
        if field != "id":
            setattr(current, field, data["configuration"][field])
    current.revision = next_revision
    current.soa_serial = max(previous_serial, current.soa_serial)
    current.dns_content_hash = previous_hash
    current.save(update_fields=[field for field in CONFIG_FIELDS if field != "id"])
    Host.objects.bulk_create([Host(**raw) for raw in data["hosts"]])
    GandiRecord.objects.bulk_create([GandiRecord(**raw) for raw in data["gandi_records"]])
    track_dns_content(current, seeded=current.soa_serial > previous_serial)
    return next_revision
