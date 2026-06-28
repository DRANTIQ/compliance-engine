"""Shared pytest fixtures and CI-safe default environment."""

from __future__ import annotations

import os

import pytest


def pytest_configure() -> None:
    # Unit tests call get_settings() but CI has no .env file.
    os.environ.setdefault(
        "DATABASE_URL",
        "postgresql://ci:ci@127.0.0.1:5432/postgres?sslmode=require",
    )
    os.environ.setdefault("EXTERNAL_ID_ENCRYPTION_KEY", "ci-test-encryption-key")
    os.environ.setdefault("SUPABASE_URL", "https://ci.example.supabase.co")


@pytest.fixture(autouse=True)
def _reset_settings_cache() -> None:
    from platform_backend.config.settings import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
