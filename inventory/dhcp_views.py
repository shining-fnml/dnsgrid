"""Explicit operator publication, separate from the NAS machine API."""

import secrets

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db import IntegrityError, OperationalError
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_POST

from . import dhcp
from .models import DHCPPublication
from .views import _errors, operator


@operator
@require_POST
def preview(request):
    try:
        revision = int(request.POST.get("revision", ""))
        rows = dhcp.preview(revision)
    except (ValueError, ValidationError, IntegrityError, OperationalError) as error:
        messages.error(request, _errors(error))
        return redirect("exports")
    nonce = secrets.token_urlsafe(32)
    request.session["dhcp_preview"] = {
        "revision": revision, "rows": rows, "nonce": nonce,
    }
    return render(request, "inventory/dhcp_confirm.html", {
        "rows": rows, "nonce": nonce, "revision": revision,
    })


@operator
@require_POST
def publish(request):
    pending = request.session.get("dhcp_preview")
    if not pending or not secrets.compare_digest(
        request.POST.get("nonce", "").encode("utf-8"), pending["nonce"].encode("ascii"),
    ):
        messages.error(request, "Generate a fresh DHCP publication preview before confirming.")
        return redirect("exports")
    try:
        dhcp.publish(
            pending["revision"], pending["rows"],
            authorize_destructive=request.POST.get("authorize_destructive") == "yes",
        )
    except (ValidationError, IntegrityError, OperationalError) as error:
        messages.error(request, _errors(error))
    else:
        request.session.pop("dhcp_preview", None)
        messages.success(
            request, "DHCP snapshots published. NAS appliances must pull and report application; "
            "publication does not write to DSM or reload DNS.",
        )
    return redirect("dhcp-status")


@operator
@require_GET
def status(request):
    return render(request, "inventory/dhcp_status.html", {"rows": dhcp.status_rows()})


@operator
@require_GET
def download(request, site_id, publication_id):
    publication = get_object_or_404(DHCPPublication, pk=publication_id, site_id=site_id)
    response = JsonResponse(publication.payload)
    response["Content-Disposition"] = (
        f'attachment; filename="dsm-reservations-site-{site_id}-publication-{publication_id}.json"'
    )
    response["X-DNSGrid-Version"] = publication.version
    response["X-DNSGrid-SHA256"] = publication.sha256
    return response
