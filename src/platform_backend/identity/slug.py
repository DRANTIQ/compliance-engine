from __future__ import annotations

import re

RESERVED_SLUGS = frozenset({
    "admin",
    "api",
    "app",
    "www",
    "drantiq",
    "support",
    "help",
    "status",
    "billing",
    "login",
    "signup",
    "onboarding",
    "welcome",
    "internal",
    "test",
    "demo",
    "null",
    "undefined",
})

MIN_SLUG_LENGTH = 3
MAX_SLUG_LENGTH = 48
MAX_SLUG_ATTEMPTS = 5


def slugify_workspace_name(name: str) -> str:
    """Convert workspace name to URL slug (server-side only)."""
    text = name.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = re.sub(r"-+", "-", text).strip("-")
    if len(text) > MAX_SLUG_LENGTH:
        text = text[:MAX_SLUG_LENGTH].rstrip("-")
    return text


def validate_workspace_name(name: str) -> str | None:
    cleaned = name.strip()
    if len(cleaned) < 2:
        return "workspace name must be at least 2 characters"
    if len(cleaned) > 100:
        return "workspace name must be at most 100 characters"
    return None


def validate_slug(slug: str) -> str | None:
    if len(slug) < MIN_SLUG_LENGTH:
        return "workspace name is too short"
    if len(slug) > MAX_SLUG_LENGTH:
        return "workspace name produces a slug that is too long"
    if slug in RESERVED_SLUGS:
        return "workspace name is reserved"
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug):
        return "workspace name contains invalid characters"
    return None


def slug_candidates(base_slug: str) -> list[str]:
    candidates = [base_slug]
    for i in range(2, MAX_SLUG_ATTEMPTS + 2):
        candidates.append(f"{base_slug}-{i}")
    return candidates[:MAX_SLUG_ATTEMPTS]
