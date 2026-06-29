from __future__ import annotations

import logging
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from platform_backend.api.deps import get_db_pool
from platform_backend.config.settings import Settings, get_settings
from platform_backend.db.pool import DatabasePool
from platform_backend.identity.deps import get_principal
from platform_backend.identity.models import PlatformPrincipal
from platform_backend.platform.repositories.workspace import WorkspaceRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/billing", tags=["billing"])

VALID_PLANS = frozenset({"trial", "starter", "growth", "enterprise"})


class SubscriptionResponse(BaseModel):
    plan: str
    trial_end: str | None = None
    workspace_status: str


class BillingWebhookEvent(BaseModel):
    tenant_id: str
    plan: str = Field(description="trial | starter | growth | enterprise")
    trial_end: datetime | None = None


async def get_workspace_repo(db: DatabasePool = Depends(get_db_pool)) -> WorkspaceRepository:
    return WorkspaceRepository(db)


async def verify_billing_webhook(
    settings: Settings = Depends(get_settings),
    webhook_secret: str | None = Header(default=None, alias="X-Billing-Webhook-Secret"),
) -> None:
    expected = settings.billing_webhook_secret.strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="billing webhook is not configured",
        )
    if webhook_secret != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid webhook secret")


@router.get(
    "/subscription",
    response_model=SubscriptionResponse,
    summary="Current subscription",
    description="Returns plan and trial end for the current workspace.",
)
async def get_subscription(
    principal: PlatformPrincipal = Depends(get_principal),
    repo: WorkspaceRepository = Depends(get_workspace_repo),
) -> SubscriptionResponse:
    row = await repo.get_workspace(principal.tenant_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workspace not found")
    trial_end = row.get("trial_end")
    return SubscriptionResponse(
        plan=row.get("plan", "trial"),
        trial_end=trial_end.isoformat() if isinstance(trial_end, datetime) else None,
        workspace_status=row["status"],
    )


@router.post(
    "/webhook",
    summary="Billing provider webhook (stub)",
    description="Updates workspace plan from billing provider events.",
    include_in_schema=False,
)
async def billing_webhook(
    body: BillingWebhookEvent,
    repo: WorkspaceRepository = Depends(get_workspace_repo),
    _: None = Depends(verify_billing_webhook),
) -> dict[str, str]:
    if body.plan not in VALID_PLANS:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="invalid plan")

    row = await repo.update_plan(
        UUID(body.tenant_id),
        plan=body.plan,
        trial_end=body.trial_end,
    )
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workspace not found")

    logger.info(
        "billing.updated tenant_id=%s plan=%s",
        body.tenant_id,
        body.plan,
        extra={"audit": True, "event": "billing.updated"},
    )
    return {"status": "ok"}
