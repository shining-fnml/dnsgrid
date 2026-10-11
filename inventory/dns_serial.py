"""DNS content identity, independent of optimistic inventory revisions."""

import copy
import hashlib
import json
from datetime import datetime, timezone

from django.core.exceptions import ValidationError

MAX_SERIAL = 2**32 - 1


def initial_serial():
    serial = int(datetime.now(timezone.utc).timestamp())
    validate_serial(serial)
    return serial


def validate_serial(serial):
    if type(serial) is not int or not 0 <= serial <= MAX_SERIAL:
        raise ValidationError(
            "SOA serial must be an unsigned 32-bit integer (0..4294967295)."
        )


def compare_serial(candidate, previous):
    """Return RFC 1982 ordering, rejecting the undefined half-range distance."""
    validate_serial(candidate)
    validate_serial(previous)
    distance = (candidate - previous) & MAX_SERIAL
    if distance == 2**31:
        raise ValidationError(
            f"Ambiguous RFC 1982 serial comparison: {candidate} and {previous} differ by 2147483648."
        )
    return 0 if distance == 0 else 1 if distance < 2**31 else -1


def next_serial(previous):
    validate_serial(previous)
    today = initial_serial()
    validate_serial(today)
    if previous == MAX_SERIAL:
        raise ValidationError(
            "SOA serial uint32 range is exhausted. An administrator-coordinated migration is required."
        )
    result = max(today, previous + 1)
    validate_serial(result)
    if compare_serial(result, previous) != 1:
        raise ValidationError("Timestamp SOA serial would not advance under RFC 1982.")
    return result


def content_fingerprint(config):
    from .exporters import _dns_zones
    from .models import Host

    candidate = copy.copy(config)
    candidate.soa_serial = 0
    zones = sorted(_dns_zones(candidate, list(Host.objects.select_related("site"))).values())
    return hashlib.sha256(json.dumps(zones, ensure_ascii=True).encode("ascii")).hexdigest()


def track_dns_content(config, seeded=False):
    """Called under the singleton write lock, never by a GET."""
    from .models import Configuration

    validate_serial(config.soa_serial)
    fingerprint = content_fingerprint(config)
    if config.dns_content_hash and config.dns_content_hash != fingerprint and not seeded:
        config.soa_serial = next_serial(config.soa_serial)
    config.dns_content_hash = fingerprint
    Configuration.objects.filter(pk=1).update(
        soa_serial=config.soa_serial, dns_content_hash=fingerprint,
    )
    return config
