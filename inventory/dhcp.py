"""Explicit desired DHCP snapshots, with no DSM network side effects.

Retention is the newest 20 snapshots per site plus the latest, applied, downloaded,
last-attempt and last-failure pins (at most 25 snapshots). Result history is the
newest 50 receipts per site plus its last-attempt, last-failure and latest-applied
receipt pins (at most 53 rows). Fresh UUID attempts are never quota-blocked.
UUID retry idempotence is guaranteed within this retained receipt window only;
once a receipt expires, an unknown ID is treated as a fresh attempt if its
snapshot remains retained. Pending latest attempts are pinned. Runners must
preserve pending IDs and must not replay superseded expired attempts.
A runner must acknowledge a retained version; expired unknown versions fail closed.

Archive restore preserves fixed Site rows and operational DHCP metadata. Delivery
fails closed if the publication's subnet/interface differ from current
configuration; explicitly publish again after a mapping change. Retained exact
historical acknowledgements remain valid so durable runner queues can drain.

Optional report_id UUIDs distinguish recurring attempts. Known ID retries never
change receipt times or pointers. Legacy receipts without IDs are deduplicated
by publication/status; their same-version failure history remains conservatively
visible because ordering repeated attempts cannot be inferred safely.
"""

import hashlib
import ipaddress
import json
import secrets
import uuid

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import F

from .dsm import reservation_payload
from .models import (
    DNS_LABEL, Configuration, DHCPPublication, DHCPResult, DHCPState, Host, Site,
    normalize_prefix,
)
from .services import _claim_revision


SAFE_DIAGNOSTICS = frozenset({
    "invalid_response", "destructive_not_authorized", "dsm_drift", "dsm_failed",
    "verification_failed", "baseline_changed", "recovery_required", "mapping_mismatch",
})
RESULT_HISTORY_LIMIT = 50


def _lock_configuration():
    """Serialize machine operations without assuming an operator revision."""
    Configuration.objects.filter(pk=1).update(revision=F("revision"))
    return Configuration.load()


def checksum(payload):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _preview():
    config = Configuration.load()
    if normalize_prefix(config.lan_prefix) != config.lan_prefix:
        raise ValidationError("Invalid DHCP LAN prefix.")
    hosts = list(Host.objects.select_related("site"))
    rows = []
    for site in Site.objects.exclude(dsm_ifname=""):
        try:
            site.full_clean()
            payload = reservation_payload(config, site, hosts)
            network = ipaddress.IPv4Network(f"{config.lan_prefix}.{site.g}.0/24")
            seen_ips = set()
            for reservation in payload["reservationData"]:
                address = ipaddress.IPv4Address(reservation["ip"])
                if (address in seen_ips or address not in network
                        or address in (network.network_address, network.broadcast_address)):
                    raise ValidationError("Invalid or duplicate DHCP address.")
                seen_ips.add(address)
                if not DNS_LABEL.fullmatch(reservation["hostname"]):
                    raise ValidationError("Invalid DHCP hostname.")
        except (ValueError, ValidationError) as error:
            raise ValidationError(f"Invalid DHCP inventory for site {site.pk}.") from error
        state = DHCPState.objects.filter(site=site).select_related("latest").first()
        previous = state.latest if state else None
        count = len(payload["reservationData"])
        previous_count = len(previous.payload["reservationData"]) if previous else 0
        rows.append({
            "site_id": site.pk, "site_name": site.name,
            "subnet": f"{config.lan_prefix}.{site.g}.0/24",
            "payload": payload, "sha256": checksum(payload),
            "destructive": count == 0 or count * 2 < previous_count,
            "previous_version": previous.version if previous else None,
        })
    return rows


def preview(expected_revision):
    with transaction.atomic():
        _claim_revision(expected_revision, changed=False, reset_recovery=True)
        return _preview()


def publish(expected_revision, expected_preview, authorize_destructive=False):
    if type(authorize_destructive) is not bool:
        raise ValidationError("Destructive authorization must be an explicit checkbox.")
    with transaction.atomic():
        _claim_revision(expected_revision, changed=False, reset_recovery=True)
        rows = _preview()
        try:
            expected = json.dumps(expected_preview, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            raise ValidationError("Invalid DHCP preview.") from None
        if json.dumps(rows, sort_keys=True, separators=(",", ":")) != expected:
            raise ValidationError("Stale DHCP preview. Generate a fresh preview.")
        if any(row["destructive"] for row in rows) and not authorize_destructive:
            raise ValidationError("Explicit destructive authorization is required.")
        publications = []
        for row in rows:
            state, _ = DHCPState.objects.get_or_create(site_id=row["site_id"])
            current = state.latest
            if (current and current.sha256 == row["sha256"]
                    and current.subnet == row["subnet"]
                    and current.destructive_authorized == authorize_destructive):
                publications.append(current)
                continue
            publication = DHCPPublication.objects.create(
                site_id=row["site_id"], subnet=row["subnet"], payload=row["payload"],
                sha256=row["sha256"], destructive_authorized=authorize_destructive,
            )
            state.latest = publication
            state.save(update_fields=["latest"])
            _prune(state)
            publications.append(publication)
        return publications


def _prune(state):
    pins = {state.latest_id, state.applied_id, state.downloaded_id}
    for result_id in (state.last_attempt_id, state.last_failure_id, state.applied_receipt_id):
        if result_id:
            pins.add(DHCPResult.objects.get(pk=result_id).publication_id)
    newest = list(DHCPPublication.objects.filter(site_id=state.site_id).order_by(
        "-pk",
    ).values_list("pk", flat=True)[:20])
    DHCPPublication.objects.filter(site_id=state.site_id).exclude(
        pk__in=newest + [pk for pk in pins if pk is not None],
    ).delete()
    results = DHCPResult.objects.filter(publication__site_id=state.site_id)
    result_pins = [
        pk for pk in (state.last_attempt_id, state.last_failure_id, state.applied_receipt_id)
        if pk is not None
    ]
    recent = list(results.order_by("-pk").values_list("pk", flat=True)[:RESULT_HISTORY_LIMIT])
    results.exclude(pk__in=recent + result_pins).delete()


def envelope(publication):
    return {
        "schema_version": 1, "site_id": publication.site_id,
        "subnet": publication.subnet, "version": publication.version,
        "sha256": publication.sha256,
        "published_at": publication.published_at.isoformat(),
        "destructive_authorized": publication.destructive_authorized,
        "payload": publication.payload,
    }


def mapping_matches(publication):
    site = Site.objects.filter(pk=publication.site_id).first()
    config = Configuration.load()
    return bool(site and site.dsm_ifname
                and publication.payload["ifname"] == site.dsm_ifname
                and publication.subnet == f"{config.lan_prefix}.{site.g}.0/24")


def rotate_token(site_id, revoke=False):
    """Return a newly minted token once; only its SHA256 verifier is persisted."""
    with transaction.atomic():
        _lock_configuration()
        site = Site.objects.get(pk=site_id)
        state, _ = DHCPState.objects.get_or_create(site=site)
        token = "" if revoke else secrets.token_urlsafe(32)
        state.token_sha256 = hashlib.sha256(token.encode("ascii")).hexdigest() if token else ""
        state.save(update_fields=["token_sha256"])
        return token


def record_result(site_id, data):
    """Store receipt time, never trusting runner clocks or unfiltered diagnostics."""
    required = {"schema_version", "version", "sha256", "status"}
    if (not isinstance(data, dict) or not required <= data.keys()
            or data.keys() - required - {"diagnostic", "report_id"}
            or type(data["schema_version"]) is not int or data["schema_version"] != 1
            or not isinstance(data["version"], str) or len(data["version"]) > 100
            or not isinstance(data["sha256"], str) or len(data["sha256"]) != 64
            or not isinstance(data["status"], str)
            or data["status"] not in {"applied", "failed", "rejected"}
            or ("diagnostic" in data and not isinstance(data["diagnostic"], str))):
        raise ValidationError("Invalid DHCP result schema.")
    report_id = None
    if "report_id" in data:
        value = data["report_id"]
        try:
            if not isinstance(value, str):
                raise ValueError
            report_id = uuid.UUID(value)
            if not report_id.int or str(report_id) != value:
                raise ValueError
        except (ValueError, AttributeError):
            raise ValidationError("Invalid DHCP report ID.") from None
    with transaction.atomic():
        _lock_configuration()
        state = DHCPState.objects.select_for_update().get(site_id=site_id)
        publication = DHCPPublication.objects.filter(site_id=site_id, sha256=data["sha256"])
        publication = next((item for item in publication if item.version == data["version"]), None)
        if publication is None:
            raise ValidationError("Unknown or expired DHCP version.")
        supplied_diagnostic = data.get("diagnostic", "")
        diagnostic = (supplied_diagnostic if supplied_diagnostic in SAFE_DIAGNOSTICS
                      else "runner_reported_error" if supplied_diagnostic else "")
        if report_id is None:
            report = DHCPResult.objects.filter(
                publication=publication, report_id=None, status=data["status"],
            ).first()
            created = report is None
            if created:
                report = DHCPResult.objects.create(
                    publication=publication, report_id=None, status=data["status"],
                    diagnostic=diagnostic,
                )
        else:
            report = DHCPResult.objects.filter(
                publication=publication, report_id=report_id,
            ).first()
            created = report is None
            if created:
                report = DHCPResult.objects.create(
                    publication=publication, report_id=report_id,
                    status=data["status"], diagnostic=diagnostic,
                )
            elif report.status != data["status"] or report.diagnostic != diagnostic:
                raise ValidationError("Conflicting DHCP report ID.")
        if created:
            if not state.last_attempt_id or publication.pk >= state.last_attempt.publication_id:
                state.last_attempt = report
            if report.status == "applied":
                if not state.applied_id or publication.pk >= state.applied_id:
                    state.applied = publication
                    state.applied_receipt = report
            elif not state.last_failure_id or publication.pk >= state.last_failure.publication_id:
                state.last_failure = report
            state.save(update_fields=["last_attempt", "last_failure", "applied", "applied_receipt"])
            _prune(state)
        return report


@transaction.atomic
def status_rows():
    config = _lock_configuration()
    hosts = list(Host.objects.select_related("site"))
    rows = []
    for site in Site.objects.all():
        state = DHCPState.objects.filter(site=site).select_related(
            "latest", "applied", "downloaded", "last_attempt__publication", "last_failure__publication",
        ).first()
        latest = state.latest if state else None
        try:
            pending = (not latest
                       or checksum(reservation_payload(config, site, hosts)) != latest.sha256
                       or latest.subnet != f"{config.lan_prefix}.{site.g}.0/24")
        except (ValueError, ValidationError):
            pending = True
        rows.append({
            "site": site, "subnet": f"{config.lan_prefix}.{site.g}.0/24",
            "latest": latest, "applied": state.applied if state else None,
            "downloaded": state.downloaded if state else None,
            "last_attempt": state.last_attempt if state else None,
            "last_failure": state.last_failure if state else None,
            "contact": state.contacted_at if state else None,
            "download": state.downloaded_at if state else None,
            "last_seen": state.contacted_at if state else None,
            "last_downloaded_at": state.downloaded_at if state else None,
            "history": list(DHCPPublication.objects.filter(site=site).order_by("-pk")),
            "pending": pending,
            "status": ("unconfigured" if not site.dsm_ifname else "unpublished" if not latest
                       else "mapping_changed" if not mapping_matches(latest)
                       else state.last_attempt.status if state.last_attempt_id
                       and state.last_attempt.publication_id == latest.pk
                       and state.last_attempt.status != "applied"
                       else state.last_failure.status if state.last_failure_id
                       and state.last_failure.publication_id == latest.pk
                       and state.last_attempt_id and state.last_attempt.report_id is None
                       else "applied" if state.applied_id == latest.pk else "pending"),
        })
    return rows
