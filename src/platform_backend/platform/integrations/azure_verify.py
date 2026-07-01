"""Verify Azure service principal access to a subscription (stdlib HTTP — no Azure SDK)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

AZURE_MGMT_SCOPE = "https://management.azure.com/.default"
SUBSCRIPTION_API_VERSION = "2022-12-01"


class AzureVerificationError(Exception):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _post_form(url: str, fields: dict[str, str]) -> dict:
    body = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise AzureVerificationError(
            f"Azure AD token request failed: {detail or exc.reason}",
            status_code=exc.code,
        ) from exc
    except urllib.error.URLError as exc:
        raise AzureVerificationError(f"Azure AD token request failed: {exc.reason}") from exc


def _get_json(url: str, access_token: str) -> dict:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise AzureVerificationError(
            f"Azure subscription lookup failed: {detail or exc.reason}",
            status_code=exc.code,
        ) from exc
    except urllib.error.URLError as exc:
        raise AzureVerificationError(f"Azure subscription lookup failed: {exc.reason}") from exc


def fetch_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    payload = _post_form(
        token_url,
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": AZURE_MGMT_SCOPE,
        },
    )
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise AzureVerificationError("Azure AD token response missing access_token")
    return token


def verify_subscription_access(
    *,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    subscription_id: str,
) -> dict:
    """Return subscription metadata when Reader (or higher) access is valid."""
    token = fetch_access_token(tenant_id, client_id, client_secret)
    sub_url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"?api-version={SUBSCRIPTION_API_VERSION}"
    )
    sub = _get_json(sub_url, token)
    return {
        "valid": True,
        "subscription_id": sub.get("subscriptionId", subscription_id),
        "display_name": sub.get("displayName"),
        "tenant_id": sub.get("tenantId", tenant_id),
        "state": sub.get("state"),
    }
