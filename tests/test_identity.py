"""Unit tests for identity abstraction."""

from __future__ import annotations

from uuid import UUID

import pytest
from fastapi import HTTPException

from platform_backend.identity.models import PlatformPrincipal
from platform_backend.identity.providers.dev_header import resolve_dev_header_principal


class DummyRequest:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers


def test_dev_header_resolves_tenant_admin() -> None:
    tenant = "54abf846-1d4c-49f9-9115-2f4f882a2cd2"
    principal = resolve_dev_header_principal(
        DummyRequest({"X-Tenant-ID": tenant})
    )
    assert principal.tenant_id == UUID(tenant)
    assert principal.role == "tenant_admin"
    assert principal.auth_mode == "dev_header"


def test_dev_header_viewer_role() -> None:
    tenant = "54abf846-1d4c-49f9-9115-2f4f882a2cd2"
    principal = resolve_dev_header_principal(
        DummyRequest({"X-Tenant-ID": tenant, "X-Role": "viewer"})
    )
    assert principal.role == "viewer"


def test_dev_header_rejects_invalid_role() -> None:
    tenant = "54abf846-1d4c-49f9-9115-2f4f882a2cd2"
    with pytest.raises(HTTPException) as exc:
        resolve_dev_header_principal(
            DummyRequest({"X-Tenant-ID": tenant, "X-Role": "hacker"})
        )
    assert exc.value.status_code == 400


def test_write_roles_exclude_viewer() -> None:
    from platform_backend.identity.models import WRITE_ROLES

    assert "viewer" not in WRITE_ROLES
    assert "tenant_admin" in WRITE_ROLES
