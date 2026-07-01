from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from platform_backend.api.deps import get_db_pool, get_scan_service, get_tenant_id, require_write_access
from platform_backend.api.schemas.customer_experience import FixPriorityItem, ScanRiskSummaryResponse
from platform_backend.identity.models import PlatformPrincipal
from platform_backend.compliance.frameworks import CUSTOMER_PRIMARY_FRAMEWORK
from platform_backend.compliance.repository import ComplianceRepository
from platform_backend.db.pool import DatabasePool
from platform_backend.assets.repositories.resources import AssetRepository
from platform_backend.findings.experience import build_fix_priorities, build_risk_summary
from platform_backend.findings.repository import FindingsRepository
from platform_backend.platform.repositories.scan_insights import ScanInsightsRepository
from platform_backend.platform.services.scan_service import ScanService

router = APIRouter(prefix="/v1/scans", tags=["scans"])


class ScanCreate(BaseModel):
    integration_id: UUID = Field(description="UUID from GET /v1/integrations")


class ScanResponse(BaseModel):
    id: str
    tenant_id: str
    integration_id: str
    status: str
    trace_id: str
    started_at: str | None = None
    completed_at: str | None = None
    created_at: str
    updated_at: str


class ScanDetailResponse(ScanResponse):
    account_id: str | None = None
    collection_status: str | None = None
    provider: str | None = None
    error: dict | None = None


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create scan and enqueue collection",
    description=(
        "Starts a new security scan for the given integration. Enqueues a job on "
        "`platform:collect.aws`; workers collect AWS inventory to S3, ingest assets, "
        "evaluate policies, and compute security assessment score.\n\n"
        "Requires **tenant_admin** or **super_admin**. Poll **GET /v1/scans/{id}** until "
        "status is `completed`, `completed_with_errors`, or `failed` before reading findings."
    ),
    responses={201: {"description": "Scan queued"}, 404: {"description": "Integration not found"}},
)
async def create_scan(
    body: ScanCreate,
    principal: PlatformPrincipal = Depends(require_write_access),
    service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    tenant_id = principal.tenant_id
    try:
        row = await service.create_scan(tenant_id, body.integration_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return ScanResponse(**row)


@router.get(
    "/{scan_id}/timeline",
    summary="Scan event timeline",
    description="Append-only collection/policy events for the scan (from `assets.collection_events`).",
    responses={200: {"description": "Timeline events"}, 404: {"description": "Scan not found"}},
)
async def get_scan_timeline(
    scan_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    service: ScanService = Depends(get_scan_service),
) -> list[dict]:
    timeline = await service.get_scan_timeline(tenant_id, scan_id)
    if timeline is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return timeline


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Get scan by ID",
    description="Scan status, account_id, collection sub-status, and error payload if failed.",
    responses={200: {"description": "Scan detail"}, 404: {"description": "Scan not found"}},
)
async def get_scan(
    scan_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    service: ScanService = Depends(get_scan_service),
) -> ScanDetailResponse:
    row = await service.get_scan(tenant_id, scan_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return ScanDetailResponse(**row)


@router.get(
    "",
    response_model=list[ScanResponse],
    summary="List scans",
    description="Recent scans for the tenant, newest first.",
    responses={200: {"description": "Scan list"}},
)
async def list_scans(
    tenant_id: UUID = Depends(get_tenant_id),
    service: ScanService = Depends(get_scan_service),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[ScanResponse]:
    rows = await service.list_scans(tenant_id, limit=limit, offset=offset)
    return [ScanResponse(**r) for r in rows]


async def get_scan_insights_repo(db: DatabasePool = Depends(get_db_pool)) -> ScanInsightsRepository:
    return ScanInsightsRepository(db)


async def get_compliance_repo(db: DatabasePool = Depends(get_db_pool)) -> ComplianceRepository:
    return ComplianceRepository(db)


async def get_findings_repo(db: DatabasePool = Depends(get_db_pool)) -> FindingsRepository:
    return FindingsRepository(db)


async def get_assets_repo(db: DatabasePool = Depends(get_db_pool)) -> AssetRepository:
    return AssetRepository(db)


@router.get(
    "/{scan_id}/risk-summary",
    response_model=ScanRiskSummaryResponse,
    summary="Scan risk summary",
    description=(
        "Customer decision API: severity counts, security score, and top risks with "
        "affected resources and why each issue matters."
    ),
    responses={200: {"description": "Risk summary"}, 404: {"description": "Scan not found"}},
)
async def get_scan_risk_summary(
    scan_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    service: ScanService = Depends(get_scan_service),
    findings: FindingsRepository = Depends(get_findings_repo),
    assets: AssetRepository = Depends(get_assets_repo),
    compliance: ComplianceRepository = Depends(get_compliance_repo),
    framework_id: str = Query(default=CUSTOMER_PRIMARY_FRAMEWORK),
    top_n: int = Query(default=5, ge=1, le=20),
) -> ScanRiskSummaryResponse:
    scan = await service.get_scan(tenant_id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")

    rows = await findings.list_findings(tenant_id, scan_id, limit=500, offset=0)
    comp = await compliance.get_scan_compliance(
        tenant_id, scan_id, framework_id, customer_visible_only=True
    )
    score = comp.get("score") if comp else None
    resource_total = await assets.count(tenant_id, scan_id)
    summary = build_risk_summary(
        rows,
        compliance_score=score,
        top_n=top_n,
        resource_total=resource_total,
    )
    return ScanRiskSummaryResponse(**summary)


@router.get(
    "/{scan_id}/fix-priorities",
    response_model=list[FixPriorityItem],
    summary="Prioritized fix list",
    description=(
        "What to fix first for a scan. Sorted by severity, internet exposure, "
        "data sensitivity, framework impact, and estimated fix time."
    ),
    responses={200: {"description": "Prioritized fixes"}, 404: {"description": "Scan not found"}},
)
async def get_scan_fix_priorities(
    scan_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    service: ScanService = Depends(get_scan_service),
    findings: FindingsRepository = Depends(get_findings_repo),
    limit: int = Query(default=20, ge=1, le=500),
) -> list[FixPriorityItem]:
    scan = await service.get_scan(tenant_id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")

    rows = await findings.list_failures(tenant_id, scan_id, limit=500)
    priorities = build_fix_priorities(rows, limit=limit)
    return [FixPriorityItem(**item) for item in priorities]


@router.get(
    "/{scan_id}/compliance",
    summary="Security assessment summary",
    description=(
        "Weighted security assessment score and check summary for the scan. "
        "Same data as the compliance framework endpoint, compact shape."
    ),
    responses={200: {"description": "Compliance summary"}, 404: {"description": "Scan or compliance results not found"}},
)
async def get_scan_compliance_summary(
    scan_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    service: ScanService = Depends(get_scan_service),
    compliance: ComplianceRepository = Depends(get_compliance_repo),
    framework_id: str = Query(default=CUSTOMER_PRIMARY_FRAMEWORK),
) -> dict:
    scan = await service.get_scan(tenant_id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    result = await compliance.get_scan_compliance(
        tenant_id, scan_id, framework_id, customer_visible_only=True
    )
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="compliance results not found for scan",
        )
    return result


@router.get(
    "/{scan_id}/inventory-completeness",
    summary="Inventory completeness score",
    description="Ops metric: expected vs collected resource types for the scan.",
    responses={200: {"description": "Completeness report"}, 404: {"description": "Scan not found"}},
)
async def get_inventory_completeness(
    scan_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    service: ScanService = Depends(get_scan_service),
    insights: ScanInsightsRepository = Depends(get_scan_insights_repo),
) -> dict:
    scan = await service.get_scan(tenant_id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return await insights.inventory_completeness(tenant_id, scan_id)


@router.get(
    "/{scan_id}/policy-coverage",
    summary="Policy evaluation coverage",
    description="Which YAML policies were evaluated vs skipped for this scan.",
    responses={200: {"description": "Policy coverage report"}, 404: {"description": "Scan not found"}},
)
async def get_policy_coverage(
    scan_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    service: ScanService = Depends(get_scan_service),
    insights: ScanInsightsRepository = Depends(get_scan_insights_repo),
) -> dict:
    scan = await service.get_scan(tenant_id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return await insights.policy_coverage(tenant_id, scan_id)
