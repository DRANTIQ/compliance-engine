"""Detect Azure credential / authentication failures from collector and verify payloads."""

from __future__ import annotations

from typing import Any

_AZURE_AUTH_MARKERS = (
    "invalid_client",
    "invalid_client_secret",
    "unauthorized_client",
    "aadsts7000215",
    "aadsts7000222",
    "aadsts700016",
    "authenticationfailed",
    "clientauthenticationerror",
    "authentication failed",
    "invalid credential",
    "azure ad token request failed",
    "invalid_grant",
)


def is_azure_auth_error_text(text: str) -> bool:
    lower = (text or "").lower()
    return any(marker in lower for marker in _AZURE_AUTH_MARKERS)


def is_azure_auth_failure(error: dict[str, Any] | None) -> bool:
    if not error:
        return False
    if error.get("auth_failure") is True:
        return True
    combined = " ".join(
        str(error.get(key, ""))
        for key in ("type", "message", "error")
    )
    return is_azure_auth_error_text(combined)


def collection_errors_indicate_auth_failure(errors: list[dict[str, Any]]) -> bool:
    if not errors:
        return False
    auth_hits = 0
    for entry in errors:
        combined = f"{entry.get('type', '')} {entry.get('error', '')}"
        if is_azure_auth_error_text(combined):
            auth_hits += 1
    return auth_hits == len(errors)


def verify_failure_is_auth(*, message: str, status_code: int | None = None) -> bool:
    if status_code in (401, 403):
        return True
    return is_azure_auth_error_text(message)
