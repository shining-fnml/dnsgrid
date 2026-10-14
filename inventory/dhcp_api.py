import hashlib
import hmac
import json

from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import HttpResponse, JsonResponse, UnreadablePostError
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from .dhcp import _lock_configuration, envelope, mapping_matches, record_result
from .models import DHCPState


def _response(data=None, status=200):
    response = JsonResponse(data, status=status) if data is not None else HttpResponse(status=status)
    response["Cache-Control"] = "private, no-store"
    response["Vary"] = "Authorization"
    return response


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member.")
        result[key] = value
    return result


def _authenticate(request, site_id):
    # Authentication deliberately ignores cookies and sessions.
    authorization = request.META.get("HTTP_AUTHORIZATION", "")
    state = DHCPState.objects.select_for_update().filter(site_id=site_id).first()
    token = authorization[7:] if authorization.startswith("Bearer ") else ""
    if not token or len(token) > 256 or not token.isascii():
        return None
    supplied = hashlib.sha256(token.encode("ascii")).hexdigest()
    if not state or not state.token_sha256 or not hmac.compare_digest(state.token_sha256, supplied):
        return None
    state.contacted_at = timezone.now()
    state.save(update_fields=["contacted_at"])
    return state


def latest(request, site_id):
    if request.method != "GET":
        response = _response({"error": "method_not_allowed"}, 405)
        response["Allow"] = "GET"
        return response
    with transaction.atomic():
        _lock_configuration()
        state = _authenticate(request, site_id)
        if state is None:
            return _response({"error": "unauthorized"}, 401)
        if not state.latest_id:
            return _response({"error": "no_publication"}, 404)
        publication = state.latest
        if not mapping_matches(publication):
            return _response({"error": "mapping_changed"}, 409)
        etag = f'"{publication.version}"'
        matches = request.META.get("HTTP_IF_NONE_MATCH", "").split(",")
        not_modified = any(value.strip() in (etag, "*") for value in matches)
        if not not_modified:
            state.downloaded = publication
            state.downloaded_at = timezone.now()
            state.save(update_fields=["downloaded", "downloaded_at"])
        response = _response(None, 304) if not_modified else _response(envelope(publication))
        response["ETag"] = etag
        return response


@csrf_exempt
def result(request, site_id):
    if request.method != "POST":
        response = _response({"error": "method_not_allowed"}, 405)
        response["Allow"] = "POST"
        return response
    with transaction.atomic():
        _lock_configuration()
        if _authenticate(request, site_id) is None:
            return _response({"error": "unauthorized"}, 401)
        length = request.META.get("CONTENT_LENGTH", "")
        if length:
            try:
                size = int(length)
            except (TypeError, ValueError):
                return _response({"error": "invalid_content_length"}, 400)
            if size < 0:
                return _response({"error": "invalid_content_length"}, 400)
            if size > 4096:
                return _response({"error": "payload_too_large"}, 413)
        if request.content_type != "application/json":
            return _response({"error": "unsupported_media_type"}, 415)
        try:
            raw = request.read(4097)
            if len(raw) > 4096:
                return _response({"error": "payload_too_large"}, 413)
            data = json.loads(raw, object_pairs_hook=_unique_object)
            report = record_result(site_id, data)
        except (ValueError, UnicodeError, ValidationError, UnreadablePostError, RecursionError):
            return _response({"error": "invalid_result"}, 400)
        return _response({"status": report.status})
