import copy
import uuid
from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, OperationalError, transaction
from django.db.models import F
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from .exporters import build_exports, publish_dns_zones
from .forms import ArchiveUploadForm, ConfigurationForm, HostForm, HostMoveForm
from .models import Configuration, Host, Site
from .services import (
    delete_host, move_host, plan_placement, preview_host_move, save_host, update_settings,
)

COLUMNS = (
    "Networking", "Peripherals", "Bare metal", "Virtual servers",
    "Console desktops", "TV desktops", "Laptops", "Phones",
)
HOST_FIELDS = ("name", "row", "column", "category", "status", "vpn", "public_export", "mac", "notes")
CONFIG_FIELDS = (
    "lan_domain", "vpn_domain", "lan_prefix", "vpn_prefix", "gandi_zone",
    "ttl", "soa_ns", "soa_mailbox",
    "soa_refresh", "soa_retry", "soa_expire", "soa_minimum", "zone_ns", "dns_export_directory",
)


def operator(view):
    @never_cache
    @login_required
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_staff:
            raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapped


def _errors(error):
    if isinstance(error, ValidationError):
        return "; ".join(error.messages)
    return "The operation could not complete. Reload and retry; no inventory changes were saved."


def _pending(request, kind, payload, revision, changes, title, **context):
    nonce = uuid.uuid4().hex
    request.session["pending"] = {
        "nonce": nonce, "kind": kind, "payload": payload, "revision": revision,
    }
    return render(request, "inventory/confirm.html", {
        "nonce": nonce, "title": title, "changes": changes, **context,
    })


def _host_from_payload(payload):
    fields = {key: payload[key] for key in HOST_FIELDS}
    fields["site_id"] = payload["site_id"]
    host = get_object_or_404(Host, pk=payload["id"]) if payload.get("id") else Host()
    for key, value in fields.items():
        setattr(host, key, value)
    return host


def _address_summary(host, config):
    return (
        f"Cell ({host.row}, {host.column}), x={host.x}\n"
        f"LAN {host.lan_fqdn(config)} → {host.lan_address(config)}\n"
        f"VPN {host.vpn_fqdn(config)} → {host.vpn_address(config)}"
    )


@operator
def grid(request):
    config = Configuration.load()
    hosts = {host.x: host for host in Host.objects.select_related("site")}
    rows = []
    for row in range(16):
        cells = []
        for column in range(8):
            x = 16 * column + row
            host = hosts.get(x)
            cells.append({
                "row": row, "column": column, "x": x, "host": host,
                "lan": host.lan_address(config) if host else "",
                "vpn": host.vpn_address(config) if host and host.vpn else "",
            })
        rows.append({"index": row, "cells": cells})
    return render(request, "inventory/grid.html", {
        "rows": rows, "columns": COLUMNS, "count": len(hosts),
        "sites": Site.objects.order_by("id"),
    })


@operator
def host_edit(request, host_id=None):
    config = Configuration.load()
    host = get_object_or_404(Host, pk=host_id) if host_id else None
    initial = {key: getattr(host, key) for key in HOST_FIELDS} if host else {
        "row": request.GET.get("row", 1), "column": request.GET.get("column", 0),
        "status": Host.Status.RUNNING,
    }
    initial.update(revision=config.revision, site=host.site_id if host else 1)
    form = HostForm(request.POST or None, initial=initial)
    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        payload = {key: data[key] for key in HOST_FIELDS}
        payload.update(site_id=data["site"].pk, id=host_id)
        candidate = _host_from_payload(payload)
        try:
            if data["revision"] != config.revision:
                raise ValidationError("Inventory changed. Reload this form before previewing.")
            candidate.full_clean(validate_unique=False, validate_constraints=False)
            candidate.validate_unique(exclude=["row", "column"])
            shifts = plan_placement(candidate.row, candidate.column, exclude_host_id=host_id)
            changes = []
            if host:
                changes.append({
                    "label": host.name, "before": _address_summary(host, config),
                    "after": _address_summary(candidate, config),
                })
            else:
                changes.append({
                    "label": candidate.name, "before": "Empty",
                    "after": _address_summary(candidate, config),
                })
            for shift in shifts:
                shifted = Host.objects.select_related("site").get(pk=shift["id"])
                before = _address_summary(shifted, config)
                shifted.row = shift["to_row"]
                changes.append({"label": shifted.name, "before": before, "after": _address_summary(shifted, config)})
            for field in ("site", "category", "status", "vpn", "public_export", "mac", "notes"):
                before = str(getattr(host, field)) if host else "—"
                after = str(getattr(candidate, field))
                if before != after:
                    changes.append({"label": field, "before": before, "after": after})
            payload.update({key: getattr(candidate, key) for key in HOST_FIELDS})
            return _pending(request, "host", payload, config.revision, changes, "Confirm host and grid changes")
        except ValidationError as error:
            form.add_error(None, _errors(error))
    moves = []
    if host:
        for direction, label, target in (
            ("up", "Move up", host.x - 1), ("down", "Move down", host.x + 1),
        ):
            if 1 <= target <= 127 and not Host.objects.filter(
                column=target // 16, row=target % 16,
            ).exists():
                moves.append({"direction": direction, "label": label, "target": target})
    return render(request, "inventory/form.html", {
        "form": form, "title": "Edit host" if host else "Insert host", "host": host,
        "moves": moves, "revision": config.revision,
    })


@operator
@require_POST
def host_move(request, host_id):
    form = HostMoveForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Choose Move up or Move down and provide a valid inventory revision.")
        return redirect("host-edit", host_id=host_id)
    data = form.cleaned_data
    try:
        host, candidate, config = preview_host_move(host_id, data["direction"], data["revision"])
    except (ValidationError, IntegrityError, OperationalError) as error:
        messages.error(request, _errors(error))
        return redirect("host-edit", host_id=host_id)
    return _pending(request, "move", {"id": host.pk, "direction": data["direction"]},
                    config.revision, [{
                        "label": host.name, "before": _address_summary(host, config),
                        "after": _address_summary(candidate, config),
                    }], "Confirm saved host move (no other hosts move)")


@operator
@require_POST
def host_delete(request, host_id):
    config = Configuration.load()
    host = get_object_or_404(Host, pk=host_id)
    return _pending(request, "delete", {"id": host.pk}, config.revision, [{
        "label": host.name, "before": host.lan_address(config),
        "after": "Removed from inventory and exports; other cells are not compacted.",
    }], "Confirm manual deletion")


@operator
def configuration(request):
    from .archives import WARNINGS
    config = Configuration.load()
    sites = list(Site.objects.order_by("id"))
    initial = {key: getattr(config, key) for key in CONFIG_FIELDS}
    initial["revision"] = config.revision
    initial["soa_serial"] = config.revision
    form = ConfigurationForm(request.POST or None, initial=initial, sites=sites)
    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        candidate = copy.copy(config)
        config_data = {key: data[key] for key in CONFIG_FIELDS}
        config_data["soa_serial"] = data["soa_serial"]
        config_data["gandi_token"] = (
            "" if data["clear_token"] else data["gandi_token"] or config.gandi_token
        )
        for key, value in config_data.items():
            if key == "soa_serial":
                continue
            setattr(candidate, key, value)
        site_data = [{
            "id": site.pk, "name": data[f"site_{site.pk}_name"], "g": data[f"site_{site.pk}_g"],
            "dsm_ifname": data[f"site_{site.pk}_dsm_ifname"],
        } for site in sites]
        try:
            if data["revision"] != config.revision:
                raise ValidationError("Inventory changed. Reload this form before previewing.")
            if data["soa_serial"] < config.revision:
                raise ValidationError("SOA serial must not decrease.")
            candidate.full_clean()
            if len({site["g"] for site in site_data}) != 4:
                raise ValidationError("Each of the four sites must have a distinct octet.")
            if len({site["name"].strip().lower() for site in site_data}) != 4:
                raise ValidationError("Each site must have a distinct name.")
            changes = [{
                "label": key, "before": getattr(config, key), "after": getattr(candidate, key),
            } for key in CONFIG_FIELDS if getattr(config, key) != getattr(candidate, key)]
            if data["soa_serial"] != config.revision:
                changes.append({"label": "SOA serial", "before": config.revision, "after": data["soa_serial"]})
            if config.gandi_token != candidate.gandi_token:
                changes.append({"label": "Gandi token", "before": "Hidden", "after": "Set" if candidate.gandi_token else "Removed"})
            for site, new in zip(sites, site_data):
                if site.name != new["name"] or site.g != new["g"]:
                    changes.append({
                        "label": f"Site {site.pk}", "before": f"{site.name} (g={site.g})",
                        "after": f"{new['name']} (g={new['g']})",
                    })
                if site.dsm_ifname != new["dsm_ifname"]:
                    changes.append({
                        "label": f"Site {site.pk} DSM DHCP interface",
                        "before": site.dsm_ifname or "Not configured",
                        "after": new["dsm_ifname"] or "Not configured",
                    })
            for host in Host.objects.select_related("site"):
                moved = copy.copy(host)
                moved.site = Site(id=host.site_id, **{
                    key: value for key, value in site_data[host.site_id - 1].items() if key != "id"
                })
                before = f"{host.lan_address(config)} / {host.vpn_address(config)}"
                after = f"{moved.lan_address(candidate)} / {moved.vpn_address(candidate)}"
                if before != after:
                    changes.append({"label": host.name, "before": before, "after": after})
            return _pending(request, "settings", {"config": config_data, "sites": site_data},
                            config.revision, changes, "Confirm global settings")
        except ValidationError as error:
            form.add_error(None, _errors(error))
    return render(request, "inventory/form.html", {
        "form": form, "title": "Global settings", "settings_page": True,
        "token_saved": bool(config.gandi_token),
        "archive_form": ArchiveUploadForm(initial={"revision": config.revision}, auto_id="archive_%s"),
        "archive_warnings": WARNINGS,
    })


@operator
@require_POST
def confirm(request):
    pending = request.session.get("pending")
    if not pending or request.POST.get("nonce") != pending["nonce"]:
        if pending and pending["kind"] == "archive":
            request.session.pop("pending", None)
        messages.error(request, "This confirmation expired. Generate a new preview.")
        return redirect("grid")
    try:
        payload = pending["payload"]
        revision = pending["revision"]
        if pending["kind"] == "host":
            save_host(_host_from_payload(payload), expected_revision=revision)
        elif pending["kind"] == "move":
            move_host(payload["id"], payload["direction"], expected_revision=revision)
        elif pending["kind"] == "delete":
            delete_host(payload["id"], expected_revision=revision)
        elif pending["kind"] == "settings":
            update_settings(payload["config"], payload["sites"], expected_revision=revision)
        elif pending["kind"] == "gandi":
            from .gandi import sync
            sync(expected_fingerprint=payload["fingerprint"])
        elif pending["kind"] == "archive":
            from .archives import restore
            if request.POST.get("replace_ack") != "yes" or request.POST.get("ledger_ack") != "yes":
                raise ValidationError("Replacement and trusted same-scope ownership acknowledgments are required.")
            restore(payload["data"], expected_revision=revision,
                    expected_fingerprint=payload["target_fingerprint"])
        else:
            raise ValidationError("Unknown confirmation.")
    except (ValidationError, IntegrityError, OperationalError) as error:
        messages.error(request, _errors(error))
    except RuntimeError:
        messages.error(request, "Gandi sync could not complete. Generate a fresh preview to reconcile any completed changes.")
    else:
        messages.success(request, "Changes applied.")
    request.session.pop("pending", None)
    return redirect("exports" if pending["kind"] == "gandi" else "grid")


@operator
@require_POST
def cancel(request):
    request.session.pop("pending", None)
    messages.info(request, "Preview canceled. No changes applied.")
    return redirect("grid")


@operator
def archive_download(request):
    from .archives import dumps, snapshot
    revision = request.GET.get("revision", "")
    if not revision.isascii() or not revision.isdecimal() or len(revision) > 10:
        return HttpResponse("Provide the export preview revision.", status=400)
    try:
        data = snapshot(expected_revision=int(revision))
    except ValidationError:
        return HttpResponse("Inventory changed. Reload export previews before downloading.", status=409)
    response = HttpResponse(dumps(data), content_type="application/json; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="dnsgrid-archive-v1.json"'
    return response


@operator
def archive_upload(request):
    from .archives import MAX_BYTES, MAX_SERIAL, WARNINGS, diff, fingerprint, loads, snapshot
    current = snapshot()
    revision = current["configuration"]["revision"]
    form = ArchiveUploadForm(request.POST or None, request.FILES or None, initial={"revision": revision})
    if request.method == "POST":
        request.session.pop("pending", None)
        if form.is_valid():
            try:
                if form.cleaned_data["revision"] != revision:
                    raise ValidationError("Inventory changed. Reload before previewing the archive.")
                upload = form.cleaned_data["archive"]
                if upload.size > MAX_BYTES:
                    raise ValidationError("Archive exceeds the 8 MiB upload limit.")
                candidate = loads(upload.read(MAX_BYTES + 1))
                next_revision = max(revision, candidate["configuration"]["revision"]) + 1
                if next_revision > MAX_SERIAL:
                    raise ValidationError("Restoring would exceed the maximum SOA serial.")
                changes = diff(current, candidate)
                changes.append({"label": "Resulting SOA serial", "before": revision, "after": next_revision})
                payload = {"data": candidate, "target_fingerprint": fingerprint(current)}
                return _pending(request, "archive", payload, revision, changes,
                                "Confirm application-data replacement", archive=True, warnings=WARNINGS)
            except ValidationError as error:
                form.add_error(None, _errors(error))
    return render(request, "inventory/form.html", {
        "form": form, "title": "Restore application archive", "archive_page": True,
        "warnings": WARNINGS,
    })


@operator
def exports(request):
    with transaction.atomic():
        Configuration.objects.filter(pk=1).update(revision=F("revision"))
        config = Configuration.load()
        artifacts = build_exports(config=config)
    return render(request, "inventory/exports.html", {
        "artifacts": artifacts, "revision": config.revision,
        "dns_export_directory": config.dns_export_directory,
    })


@operator
@require_POST
def dns_publish(request):
    try:
        written, errors = publish_dns_zones(request.POST.get("revision"))
    except (ValidationError, IntegrityError, OperationalError) as error:
        messages.error(request, _errors(error))
    else:
        if written:
            messages.success(request, "DNS zone files written: " + ", ".join(written))
        for filename, error in errors:
            messages.error(request, f"DNS zone write failed for {filename}: {error}")
    return redirect("exports")


@operator
def download(request, filename):
    with transaction.atomic():
        Configuration.objects.filter(pk=1).update(revision=F("revision"))
        config = Configuration.load()
        if request.GET.get("revision", str(config.revision)) != str(config.revision):
            return HttpResponse("Inventory changed. Reload export previews before downloading.", status=409)
        artifacts = build_exports(config=config)
    if filename not in artifacts:
        from django.http import Http404
        raise Http404
    response = HttpResponse(artifacts[filename], content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@operator
@require_GET
def vpn_report(request):
    from .vpn_report import build_vpn_report
    return render(request, "inventory/vpn_report.html", {"report": build_vpn_report()})


@operator
@require_POST
def gandi_preview(request):
    from .gandi import plan_sync
    try:
        plan = plan_sync()
    except (RuntimeError, ValidationError):
        messages.error(request, "Could not preview Gandi. Check the configured zone, token, and network connection.")
        return redirect("exports")
    if plan["conflicts"]:
        return render(request, "inventory/gandi.html", {"plan": plan})
    changes = [{
        "label": f"{item['action']} {item['name']}.{item['zone']}",
        "before": item["before"], "after": item["after"],
    } for item in plan["changes"]]
    return _pending(request, "gandi", {"fingerprint": plan["fingerprint"]},
                    plan["revision"], changes, "Confirm Gandi LiveDNS sync")
