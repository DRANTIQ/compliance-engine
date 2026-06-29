"""Tests for workspace slug generation."""

from __future__ import annotations

from platform_backend.identity.slug import (
    slugify_workspace_name,
    validate_slug,
    validate_workspace_name,
)


def test_slugify_workspace_name() -> None:
    assert slugify_workspace_name("Acme Inc") == "acme-inc"
    assert slugify_workspace_name("Acme Security") == "acme-security"
    assert slugify_workspace_name("Foo & Bar LLC") == "foo-bar-llc"


def test_validate_workspace_name() -> None:
    assert validate_workspace_name("A") is not None
    assert validate_workspace_name("Acme") is None


def test_validate_slug_reserved() -> None:
    assert validate_slug("admin") is not None
    assert validate_slug("acme-corp") is None


def test_slugify_strips_punctuation() -> None:
    assert slugify_workspace_name("  Hello!!! World  ") == "hello-world"
