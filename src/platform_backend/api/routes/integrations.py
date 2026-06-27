from __future__ import annotations

import re
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from platform_backend.api.deps import get_integration_service, get_tenant_id, require_write_access
from platform_backend.identity.models import PlatformPrincipal
from platform_backend.platform.services.scan_service import IntegrationService

router = APIRouter(prefix="/v1/integrations", tags=["integrations"])

AWS_ACCOUNT_PATTERN = re.compile(r"^[0-9]{12}$")


class AwsIntegrationCreate(BaseModel):
    account_id: str = Field(min_length=12, max_length=12)
    role_arn: str = Field(min_length=20)
    external_id: str = Field(min_length=8)
    regions: list[str] = Field(min_length=1)

    @field_validator("account_id")
    @classmethod
    def validate_account_id(cls, value: str) -> str:
        if not AWS_ACCOUNT_PATTERN.match(value):
            raise ValueError("account_id must be a 12-digit AWS account id")
        return value

    @field_validator("regions")
    @classmethod
    def validate_regions(cls, value: list[str]) -> list[str]:
        cleaned = [r.strip() for r in value if r.strip()]
        if not cleaned:
            raise ValueError("regions must not be empty")
        return cleaned


class IntegrationResponse(BaseModel):
    id: str
    tenant_id: str
    provider: str
    account_id: str
    role_arn: str
    regions: list[str]
    status: str
    created_at: str
    updated_at: str


@router.post("/aws", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED)
async def register_aws_integration(
    body: AwsIntegrationCreate,
    principal: PlatformPrincipal = Depends(require_write_access),
    service: IntegrationService = Depends(get_integration_service),
) -> IntegrationResponse:
    tenant_id = principal.tenant_id
    try:
        row = await service.register_aws(
            tenant_id,
            account_id=body.account_id,
            role_arn=body.role_arn,
            external_id=body.external_id,
            regions=body.regions,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        if "unique" in str(exc).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="integration already exists for this account",
            ) from exc
        raise
    return IntegrationResponse(**row)


@router.get("", response_model=list[IntegrationResponse])
async def list_integrations(
    tenant_id: UUID = Depends(get_tenant_id),
    service: IntegrationService = Depends(get_integration_service),
) -> list[IntegrationResponse]:
    rows = await service.list(tenant_id)
    return [IntegrationResponse(**r) for r in rows]
