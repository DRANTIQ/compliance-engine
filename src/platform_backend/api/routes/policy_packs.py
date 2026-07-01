from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from platform_backend.api.deps import get_settings_dep
from platform_backend.config.settings import Settings
from platform_backend.identity.deps import get_principal
from platform_backend.identity.models import PlatformPrincipal
from platform_backend.policy.catalog.loader import load_policy_packs
from platform_backend.policy.catalog.registry import resolve_catalog_path

router = APIRouter(prefix="/v1/policy-packs", tags=["policy-packs"])


class PolicyPackSummary(BaseModel):
    pack_id: str
    display_title: str
    description: str | None = None
    check_count: int = Field(description="Number of security checks in this pack")


def _packs_paths(settings: Settings) -> list[Path]:
    catalog = resolve_catalog_path(settings)
    packs_dir = catalog.parent / "packs"
    paths = [packs_dir / "aws.yaml"]
    azure_path = packs_dir / "azure.yaml"
    if azure_path.is_file():
        paths.append(azure_path)
    return paths


@router.get(
    "",
    response_model=list[PolicyPackSummary],
    summary="List policy packs",
    description="Drantiq security check bundles grouped by domain (identity, storage, network, …).",
    responses={200: {"description": "Policy pack list"}},
)
async def list_policy_packs(
    _principal: PlatformPrincipal = Depends(get_principal),
    settings: Settings = Depends(get_settings_dep),
) -> list[PolicyPackSummary]:
    packs: list[dict] = []
    for path in _packs_paths(settings):
        packs.extend(load_policy_packs(path))
    out: list[PolicyPackSummary] = []
    for pack in packs:
        if pack.get("pack_id") in {"pack_aws_core", "pack_azure_core"}:
            continue
        policy_ids = pack.get("policy_ids") or []
        out.append(
            PolicyPackSummary(
                pack_id=str(pack["pack_id"]),
                display_title=str(pack.get("display_title") or pack["pack_id"]),
                description=pack.get("description"),
                check_count=len(policy_ids),
            )
        )
    return sorted(out, key=lambda p: p.pack_id)
