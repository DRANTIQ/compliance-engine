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
AZURE_GUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class AwsIntegrationCreate(BaseModel):
    account_id: str = Field(min_length=12, max_length=12, description="12-digit AWS account ID", examples=["387957186076"])
    role_arn: str = Field(
        min_length=20,
        description="Customer IAM role ARN the hub account can AssumeRole into",
        examples=["arn:aws:iam::387957186076:role/SteampipeReadRole"],
    )
    external_id: str = Field(min_length=8, description="STS external ID (encrypted at rest, min 8 chars)")
    regions: list[str] = Field(min_length=1, description="AWS regions to scan", examples=[["us-east-1"]])

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


class AzureIntegrationCreate(BaseModel):
    subscription_id: str = Field(
        description="Azure subscription GUID to scan",
        examples=["11111111-2222-3333-4444-555555555555"],
    )
    azure_tenant_id: str = Field(
        description="Entra ID (Azure AD) tenant GUID",
        examples=["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
    )
    azure_client_id: str = Field(
        description="Service principal application (client) id",
        examples=["ffffffff-1111-2222-3333-444444444444"],
    )
    client_secret: str = Field(
        min_length=8,
        description="Service principal client secret (encrypted at rest, never returned)",
    )
    locations: list[str] = Field(
        min_length=1,
        description="Azure locations to scan",
        examples=[["eastus", "westeurope"]],
    )

    @field_validator("subscription_id", "azure_tenant_id", "azure_client_id")
    @classmethod
    def validate_guid(cls, value: str) -> str:
        if not AZURE_GUID_PATTERN.match(value):
            raise ValueError("must be a valid GUID")
        return value.lower()

    @field_validator("locations")
    @classmethod
    def validate_locations(cls, value: list[str]) -> list[str]:
        cleaned = [loc.strip().lower() for loc in value if loc.strip()]
        if not cleaned:
            raise ValueError("locations must not be empty")
        return cleaned


class IntegrationResponse(BaseModel):
    id: str
    tenant_id: str
    provider: str
    account_id: str
    role_arn: str | None = Field(
        default=None,
        description="AWS IAM role ARN (null for Azure integrations)",
    )
    azure_tenant_id: str | None = Field(default=None, description="Entra tenant id (Azure only)")
    azure_client_id: str | None = Field(default=None, description="Service principal client id (Azure only)")
    regions: list[str]
    status: str = Field(description="active | invalid | disabled")
    created_at: str
    updated_at: str


class IntegrationVerifyResponse(BaseModel):
    valid: bool
    provider: str
    subscription_id: str | None = None
    display_name: str | None = None
    tenant_id: str | None = None
    state: str | None = None
    message: str | None = None


class AzureRotateSecretRequest(BaseModel):
    client_secret: str = Field(
        min_length=8,
        description="New service principal client secret (encrypted at rest, never returned)",
    )


@router.post(
    "/aws",
    response_model=IntegrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register AWS integration",
    description=(
        "Connect a customer AWS account via cross-account IAM role + external ID. "
        "Requires **tenant_admin** or **super_admin**.\n\n"
        "Customer must trust the hub account and grant read-only permissions. "
        "`external_id` is stored encrypted and never returned in responses.\n\n"
        "- **409** — integration already exists for this account\n"
        "- **400** — validation error (account_id, regions, external_id length)"
    ),
    responses={201: {"description": "Integration created"}, 409: {"description": "Duplicate account"}},
)
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


@router.post(
    "/azure",
    response_model=IntegrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register Azure integration",
    description=(
        "Connect an Azure subscription via a customer-owned service principal. "
        "Requires **tenant_admin** or **super_admin**.\n\n"
        "`client_secret` is stored encrypted and never returned in responses.\n\n"
        "- **409** — integration already exists for this subscription\n"
        "- **400** — validation error"
    ),
    responses={201: {"description": "Integration created"}, 409: {"description": "Duplicate subscription"}},
)
async def register_azure_integration(
    body: AzureIntegrationCreate,
    principal: PlatformPrincipal = Depends(require_write_access),
    service: IntegrationService = Depends(get_integration_service),
) -> IntegrationResponse:
    tenant_id = principal.tenant_id
    try:
        row = await service.register_azure(
            tenant_id,
            subscription_id=body.subscription_id,
            azure_tenant_id=body.azure_tenant_id,
            azure_client_id=body.azure_client_id,
            client_secret=body.client_secret,
            locations=body.locations,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        if "unique" in str(exc).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="integration already exists for this subscription",
            ) from exc
        raise
    return IntegrationResponse(**row)


@router.get(
    "",
    response_model=list[IntegrationResponse],
    summary="List cloud integrations",
    description="All AWS and Azure integrations for the authenticated tenant. Use `id` when calling **POST /v1/scans**.",
    responses={200: {"description": "Integration list (may be empty)"}},
)
async def list_integrations(
    tenant_id: UUID = Depends(get_tenant_id),
    service: IntegrationService = Depends(get_integration_service),
) -> list[IntegrationResponse]:
    rows = await service.list(tenant_id)
    return [IntegrationResponse(**r) for r in rows]


@router.post(
    "/{integration_id}/verify",
    response_model=IntegrationVerifyResponse,
    summary="Verify integration credentials",
    description=(
        "Test that stored credentials can access the cloud account. "
        "Currently supported for **Azure** service principals (Reader on subscription)."
    ),
    responses={
        200: {"description": "Verification result"},
        404: {"description": "Integration not found"},
        400: {"description": "Provider does not support verify"},
    },
)
async def verify_integration(
    integration_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    service: IntegrationService = Depends(get_integration_service),
) -> IntegrationVerifyResponse:
    try:
        result = await service.verify_azure(tenant_id, integration_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return IntegrationVerifyResponse(**result)


@router.post(
    "/{integration_id}/rotate-secret",
    response_model=IntegrationResponse,
    summary="Rotate Azure client secret",
    description=(
        "Update the stored Azure service principal client secret without recreating the integration. "
        "Verifies the new secret against Azure before saving and sets status to **active** on success."
    ),
    responses={
        200: {"description": "Secret rotated"},
        404: {"description": "Integration not found"},
        400: {"description": "Validation or verification failed"},
    },
)
async def rotate_azure_secret(
    integration_id: UUID,
    body: AzureRotateSecretRequest,
    principal: PlatformPrincipal = Depends(require_write_access),
    service: IntegrationService = Depends(get_integration_service),
) -> IntegrationResponse:
    tenant_id = principal.tenant_id
    try:
        row = await service.rotate_azure_secret(
            tenant_id,
            integration_id,
            client_secret=body.client_secret,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return IntegrationResponse(**row)
