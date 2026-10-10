"""DNS content identity, independent of optimistic inventory revisions."""

import copy
import hashlib
import json
from datetime import date, datetime, timezone

from django.core.exceptions import ValidationError

MAX_SERIAL = 2**32 - 1


def initial_serial():
    return int(datetime.now(timezone.utc).strftime("%Y%m%d") + "00")


def validate_serial(serial):
    text = str(serial)
    try:
        if type(serial) is not int or len(text) != 10 or not 1 <= serial <= MAX_SERIAL:
            raise ValueError
        date(int(text[:4]), int(text[4:6]), int(text[6:8]))
    except ValueError as error:
        raise ValidationError(
            "SOA serial must be a real UTC YYYYMMDDnn date, counter 00..99, within uint32. "
            "Seed upward above the installed serial. Incompatible higher legacy serials "
            "require an administrator-coordinated DNS serial reset before migration."
        ) from error


def next_serial(previous):
    validate_serial(previous)
    today = initial_serial()
    validate_serial(today)
    if today > previous:
        return today
    if previous % 100 == 99:
        raise ValidationError(
            "SOA counter 99 is exhausted for its date. Wait until UTC passes that date; "
            "clock rollback or a future seed never permits a lower or fictitious date."
        )
    result = previous + 1
    validate_serial(result)
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
