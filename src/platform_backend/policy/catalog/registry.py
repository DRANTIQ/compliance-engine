from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from platform_backend.config.settings import Settings, get_settings
from platform_backend.policy.catalog.loader import load_policy_index
from platform_backend.policy.catalog.models import PolicyDefinition


def resolve_catalog_path(settings: Settings | None = None) -> Path:
    cfg = settings or get_settings()
    catalog_path = Path(cfg.policy_catalog_path)
    if not catalog_path.is_absolute():
        repo_root = Path(__file__).resolve().parents[4]
        catalog_path = repo_root / catalog_path
    return catalog_path


@lru_cache
def get_policy_catalog() -> dict[str, PolicyDefinition]:
    return load_policy_index(resolve_catalog_path())


def get_policy_definition(policy_id: str) -> PolicyDefinition | None:
    return get_policy_catalog().get(policy_id)
