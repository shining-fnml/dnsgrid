"""Read-only credential disclosure authorized exclusively by the VPN peer."""

from ipaddress import IPv4Address

from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_variables

from .gandi_credentials import CredentialError, effective_expiry, effective_token, expiry_status
from .models import Configuration, Host


def _response(data, status=200):
    response = JsonResponse(data, status=status)
    response["Cache-Control"] = "private, no-store"
    response["Pragma"] = "no-cache"
    response["Expires"] = "0"
    return response


def _authorized(peer, config):
    if not isinstance(peer, str):
        return False
    try:
        address = IPv4Address(peer)
        matches = [
            host for host in Host.objects.select_related("site")
            if IPv4Address(host.vpn_address(config)) == address
        ]
    except (ValueError, TypeError):
        return False
    return len(matches) == 1 and matches[0].vpn and matches[0].public_export


@csrf_exempt
@sensitive_variables()
def pat(request):
    if request.method != "GET":
        response = _response({"error": "method_not_allowed"}, 405)
        response["Allow"] = "GET"
        return response
    # A read transaction keeps the configuration and host mapping in one snapshot
    # on SQLite, without the revision UPDATE used by mutation services.
    with transaction.atomic():
        config = Configuration.objects.select_for_update().filter(pk=1).first()
        if config is None:
            return _response({"error": "configuration_unavailable"}, 503)
        if not _authorized(request.META.get("REMOTE_ADDR"), config):
            return _response({"error": "unauthorized"}, 403)
        try:
            token = effective_token(config)
            expires_on = effective_expiry(config)
        except CredentialError:
            return _response({"error": "credential_unavailable"}, 503)
        if expiry_status(expires_on, config.gandi_token_warning_days) == "expired":
            return _response({"error": "credential_expired"}, 503)
        return _response({
            "token": token,
            "expires_on": expires_on.isoformat() if expires_on else None,
        })
