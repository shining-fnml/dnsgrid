"""Shared effective credential resolution and administrator-declared expiry."""

import os
import re
from datetime import date, datetime, timezone


class CredentialError(ValueError):
    """Fixed diagnostics only; never include credential values."""


def token_source():
    return "environment" if os.environ.get("DNSGRID_GANDI_TOKEN") else "database"


def effective_token(config):
    token = os.environ.get("DNSGRID_GANDI_TOKEN") or config.gandi_token
    if not token:
        raise CredentialError("A Gandi API token is required.")
    if not isinstance(token, str) or not re.fullmatch(r"[\x21-\x7e]{1,512}", token):
        raise CredentialError("The Gandi API token contains invalid characters.")
    return token


def effective_expiry(config):
    if token_source() == "environment":
        value = os.environ.get("DNSGRID_GANDI_TOKEN_EXPIRES_ON", "")
        if not value:
            return None
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
            raise CredentialError("Invalid Gandi token expiration metadata.")
        try:
            return date.fromisoformat(value)
        except ValueError:
            raise CredentialError("Invalid Gandi token expiration metadata.") from None
    value = config.gandi_token_expires_on
    if value is not None and type(value) is not date:
        raise CredentialError("Invalid Gandi token expiration metadata.")
    return value


def expiry_status(expires_on, warning_days, today=None):
    today = today if today is not None else datetime.now(timezone.utc).date()
    if expires_on is None:
        return "unknown"
    remaining = (expires_on - today).days
    if remaining <= 0:
        return "expired"
    return "expiring" if remaining <= warning_days else "valid"


def credential_summary(config):
    summary = {"source": token_source(), "status": "unavailable", "expires_on": None}
    try:
        effective_token(config)
        summary["expires_on"] = effective_expiry(config)
        summary["status"] = expiry_status(summary["expires_on"], config.gandi_token_warning_days)
    except CredentialError:
        pass
    return summary
