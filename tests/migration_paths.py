"""Resolve generated migration SQL paths (CI-safe without platform-db sibling checkout)."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def migration_sql_path(filename: str) -> Path:
    generated = REPO_ROOT / "generated" / "migrations" / filename
    if generated.is_file():
        return generated
    sibling = REPO_ROOT.parent / "platform-db" / "migrations" / filename
    if sibling.is_file():
        return sibling
    return generated
