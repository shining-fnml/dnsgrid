import copy

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import F

from .models import MAX_SERIAL, Configuration, Host, Site
from .dns_serial import compare_serial, content_fingerprint, initial_serial, track_dns_content, validate_serial


def _dns_baseline():
    config = Configuration.load()
    if not config.dns_content_hash:
        config.dns_content_hash = content_fingerprint(config)
        config.save(update_fields=["dns_content_hash"])
    return config


def _validate_position(row, column):
    if (
        type(row) is not int
        or type(column) is not int
        or not 0 <= row <= 15
        or not 0 <= column <= 7
        or (row == 0 and column == 0)
    ):
        raise ValidationError("Choose a nonreserved grid position within the grid.")


def plan_placement(row, column, exclude_host_id=None):
    _validate_position(row, column)
    occupants = {
        host.row: host
        for host in Host.objects.filter(column=column).exclude(pk=exclude_host_id)
    }
    shifts = []
    while row in occupants:
        if row == 15:
            raise ValidationError("There is no free position below this host in the column.")
        host = occupants[row]
        if host.static:
            raise ValidationError(f"Static host {host.name} cannot be shifted. Revoke static protection first.")
        shifts.append({
            "id": host.pk,
            "name": host.name,
            "from_row": row,
            "to_row": row + 1,
        })
        row += 1
    return shifts


def _claim_revision(expected_revision, changed=True, reset_recovery=False):
    if type(expected_revision) is not int or not 1 <= expected_revision <= MAX_SERIAL:
        raise ValidationError("Invalid or stale configuration revision.")
    if changed and expected_revision == MAX_SERIAL:
        raise ValidationError("The inventory revision has reached its maximum value.")
    updated = Configuration.objects.filter(pk=1, revision=expected_revision).update(
        revision=F("revision") + 1 if changed else F("revision")
    )
    if not updated:
        raise ValidationError("Stale configuration revision. Reload and try again.")
    if not reset_recovery:
        from .dns_reset import ensure_ready
        ensure_ready(Configuration.load().dns_export_directory)


def _host_values(host):
    return tuple(
        getattr(host, field.attname)
        for field in Host._meta.concrete_fields
        if not field.primary_key
    )


def validate_host_change(host, existing):
    if existing and existing.static and _host_values(existing) != _host_values(host):
        raise ValidationError("Static hosts are read-only. Revoke static protection as a separate operation first.")


def protect_static_addresses(current, candidate, sites):
    site_map = {site.pk: site for site in sites}
    for host in Host.objects.filter(static=True).select_related("site"):
        moved = copy.copy(host)
        moved.site = site_map[host.site_id]
        if host.lan_address(current) != moved.lan_address(candidate) or (
            host.vpn and host.vpn_address(current) != moved.vpn_address(candidate)
        ):
            raise ValidationError(f"Settings would change the IP address of static host {host.name}. Revoke static protection first.")


def preview_settings_addresses(candidate, sites, expected_revision):
    with transaction.atomic():
        _claim_revision(expected_revision, changed=False)
        protect_static_addresses(Configuration.load(), candidate, sites)


def preview_static_revocation(host_id, expected_revision):
    with transaction.atomic():
        _claim_revision(expected_revision, changed=False)
        host = Host.objects.filter(pk=host_id).first()
        if host is None or not host.static:
            raise ValidationError("This host is no longer static. Generate a fresh preview.")
        return host


def revoke_host_static(host_id, expected_revision):
    with transaction.atomic():
        _claim_revision(expected_revision, changed=False)
        try:
            host = Host.objects.get(pk=host_id)
        except Host.DoesNotExist as error:
            raise ValidationError("This host no longer exists.") from error
        if not host.static:
            raise ValidationError("This host is no longer static. Generate a fresh preview.")
        _claim_revision(expected_revision)
        Host.objects.filter(pk=host_id).update(static=False)
        host.static = False
        return host


def preview_host_change(host, expected_revision):
    with transaction.atomic():
        _claim_revision(expected_revision, changed=False)
        existing = Host.objects.filter(pk=host.pk).first() if host.pk else None
        if host.pk and existing is None:
            raise ValidationError("This host no longer exists.")
        host.full_clean(validate_unique=False, validate_constraints=False)
        host.validate_unique(exclude=["row", "column"])
        validate_host_change(host, existing)
        return plan_placement(host.row, host.column, exclude_host_id=host.pk)


def save_host(host, expected_revision):
    original_pk = host.pk
    try:
        with transaction.atomic():
            # Claim the singleton with a conditional UPDATE, not SQLite's ineffective row lock.
            _claim_revision(expected_revision, changed=False)
            _dns_baseline()
            host.full_clean(validate_constraints=False)
            existing = Host.objects.filter(pk=host.pk).first() if host.pk else None
            if host.pk and existing is None:
                raise ValidationError("This host no longer exists.")
            validate_host_change(host, existing)
            changed = existing is None or _host_values(existing) != _host_values(host)
            if not changed:
                return host
            shifts = plan_placement(host.row, host.column, exclude_host_id=host.pk)
            _claim_revision(expected_revision)
            # Free a moving host's old cell before applying descending shifts.
            if existing and (existing.row, existing.column) != (host.row, host.column):
                # Deleting/reinserting preserves the identity and never compacts its old column.
                Host.objects.filter(pk=host.pk).delete()
            for shift in reversed(shifts):
                Host.objects.filter(pk=shift["id"]).update(row=shift["to_row"])
            host.save(force_insert=existing is None or (
                existing.row, existing.column
            ) != (host.row, host.column))
            track_dns_content(Configuration.load())
            return host
    except IntegrityError as error:
        host.pk = original_pk
        raise ValidationError("The host conflicts with another inventory entry.") from error


def delete_host(host_id, expected_revision):
    with transaction.atomic():
        _claim_revision(expected_revision, changed=False)
        _dns_baseline()
        try:
            host = Host.objects.get(pk=host_id)
        except Host.DoesNotExist as error:
            raise ValidationError("This host no longer exists.") from error
        if host.static:
            raise ValidationError("Static hosts cannot be deleted. Revoke static protection first.")
        _claim_revision(expected_revision)
        host.delete()
        track_dns_content(Configuration.load())


def preview_host_delete(host_id, expected_revision):
    with transaction.atomic():
        _claim_revision(expected_revision, changed=False)
        host = Host.objects.filter(pk=host_id).select_related("site").first()
        if host is None:
            raise ValidationError("This host no longer exists.")
        if host.static:
            raise ValidationError("Static hosts cannot be deleted. Revoke static protection first.")
        return host


def _plan_host_move(host_id, direction):
    if direction not in ("up", "down"):
        raise ValidationError("Choose Move up or Move down.")
    try:
        host = Host.objects.select_related("site").get(pk=host_id)
    except Host.DoesNotExist as error:
        raise ValidationError("This host no longer exists.") from error
    if host.static:
        raise ValidationError("Static hosts cannot be moved. Revoke static protection first.")
    target = host.x + (-1 if direction == "up" else 1)
    column, row = divmod(target, 16)
    _validate_position(row, column)
    if Host.objects.filter(row=row, column=column).exists():
        raise ValidationError("The destination cell is occupied. Quick moves never shift other hosts.")
    candidate = copy.copy(host)
    candidate.row, candidate.column = row, column
    return host, candidate


def preview_host_move(host_id, direction, expected_revision):
    with transaction.atomic():
        _claim_revision(expected_revision, changed=False)
        host, candidate = _plan_host_move(host_id, direction)
        return host, candidate, Configuration.load()


def move_host(host_id, direction, expected_revision):
    try:
        with transaction.atomic():
            _claim_revision(expected_revision, changed=False)
            _dns_baseline()
            _, candidate = _plan_host_move(host_id, direction)
            _claim_revision(expected_revision)
            candidate.save(update_fields=["row", "column"])
            track_dns_content(Configuration.load())
            return candidate
    except IntegrityError as error:
        raise ValidationError("The destination conflicts with another inventory entry.") from error


CONFIG_FIELDS = (
    "lan_domain", "vpn_domain", "lan_prefix", "vpn_prefix", "gandi_zone",
    "gandi_token", "ttl", "soa_ns", "soa_mailbox",
    "soa_refresh", "soa_retry", "soa_expire", "soa_minimum", "zone_ns", "dns_export_directory",
    "named_checkzone", "rndc", "rndc_key",
    "gandi_token_expires_on", "gandi_token_warning_days",
)


def update_settings(config_data, site_data, expected_revision):
    if (
        not isinstance(config_data, dict)
        or not isinstance(site_data, (list, tuple))
        or any(not isinstance(data, dict) for data in site_data)
    ):
        raise ValidationError("Provide configuration and four site dictionaries.")
    try:
        with transaction.atomic():
            _claim_revision(expected_revision, changed=False)
            current = _dns_baseline()
            if set(config_data) - set(CONFIG_FIELDS) - {"soa_serial"}:
                raise ValidationError("Unknown configuration field.")
            serial = config_data.get("soa_serial", current.soa_serial)
            validate_serial(serial)
            serial_order = compare_serial(serial, current.soa_serial)
            if serial_order < 0:
                raise ValidationError("SOA serial must not decrease under RFC 1982.")
            candidate = Configuration(
                pk=1, revision=current.revision, soa_serial=serial,
                dns_content_hash=current.dns_content_hash,
                dns_published_generation=current.dns_published_generation,
                **{field: config_data.get(field, getattr(current, field)) for field in CONFIG_FIELDS},
            )
            if not candidate.gandi_token or (
                candidate.gandi_token != current.gandi_token
                and "gandi_token_expires_on" not in config_data
            ):
                candidate.gandi_token_expires_on = None
            candidate.full_clean(validate_unique=False)
            if (
                len(site_data) != 4
                or any(set(data) not in (
                    {"id", "name", "g"}, {"id", "name", "g", "dsm_ifname"},
                ) for data in site_data)
                or any(type(data["id"]) is not int for data in site_data)
                or {data["id"] for data in site_data} != {1, 2, 3, 4}
                or set(Site.objects.values_list("id", flat=True)) != {1, 2, 3, 4}
            ):
                raise ValidationError("Settings must contain exactly the four fixed sites.")
            originals = {site.pk: site for site in Site.objects.all()}
            sites = [Site(**{
                **data, "dsm_ifname": data.get("dsm_ifname", originals[data["id"]].dsm_ifname),
            }) for data in site_data]
            for site in sites:
                site.full_clean(validate_unique=False, validate_constraints=False)
            if len({site.name.casefold() for site in sites}) != 4:
                raise ValidationError("Site names must be unique.")
            if len({site.g for site in sites}) != 4:
                raise ValidationError("Site octets must be unique.")
            protect_static_addresses(current, candidate, sites)
            changed = serial != current.soa_serial or any(
                getattr(candidate, field) != getattr(current, field) for field in CONFIG_FIELDS
            ) or any(
                (site.name, site.g, site.dsm_ifname) != (
                    originals[site.pk].name, originals[site.pk].g, originals[site.pk].dsm_ifname,
                )
                for site in sites
            )
            if changed:
                _claim_revision(expected_revision)
                candidate.revision = expected_revision + 1
                candidate.save(force_update=True, update_fields=(*CONFIG_FIELDS, "revision", "soa_serial"))
                for site in sites:
                    site.save(update_fields=["name", "g", "dsm_ifname"])
                track_dns_content(candidate, seeded=serial_order > 0)
            return candidate
    except IntegrityError as error:
        raise ValidationError("The settings conflict with existing inventory data.") from error


def lower_dns_serial(expected_revision, expected_serial, baseline, confirmed=False):
    if confirmed is not True:
        raise ValidationError("Administrator confirmation that no DNS server loaded the legacy serials is required.")
    validate_serial(expected_serial)
    validate_serial(baseline)
    directory = Configuration.load().dns_export_directory
    with transaction.atomic():
        _claim_revision(expected_revision, changed=False)
        current = Configuration.load()
        if current.dns_export_directory != directory:
            raise ValidationError("DNS export directory changed. Generate a new baseline preview.")
        if current.soa_serial != expected_serial:
            raise ValidationError("SOA serial changed. Generate a new baseline preview.")
        if baseline >= current.soa_serial or baseline > initial_serial():
            raise ValidationError("The baseline must lower the stored serial to a Unix timestamp no later than now.")
        _claim_revision(expected_revision)
        _reset_dns_tracking(current, baseline)
        return Configuration.load()


def _reset_dns_tracking(current, baseline):
    Configuration.objects.filter(pk=1).update(
        soa_serial=baseline, dns_content_hash=content_fingerprint(current),
        dns_published_generation="",
    )
