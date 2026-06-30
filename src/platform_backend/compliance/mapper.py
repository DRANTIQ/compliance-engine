from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP
from typing import Any
from uuid import UUID

from platform_backend.compliance.repository import ComplianceRepository, ControlAggregate
from platform_backend.compliance.frameworks import (
    CUSTOMER_PRIMARY_FRAMEWORK,
    SCAN_FRAMEWORK_IDS,
)
from platform_backend.db.pool import DatabasePool


def _aggregate_control(
    control: dict[str, Any],
    findings_by_policy: dict[str, list[dict[str, Any]]],
) -> ControlAggregate:
    mapped_policy_ids = list(control.get("mapped_policy_ids") or [])
    assessment_type = control["assessment_type"]
    customer_title = control.get("display_title") or control["title"]

    if assessment_type == "manual":
        return ControlAggregate(
            framework_id=control["framework_id"],
            control_id=control["control_id"],
            title=customer_title,
            domain=control.get("domain"),
            severity=control["severity"],
            assessment_type=assessment_type,
            mapped_policy_ids=mapped_policy_ids,
            status="manual",
            fail_count=0,
            pass_count=0,
            finding_ids=[],
            evidence={"assessment": "manual"},
        )

    if not mapped_policy_ids:
        return ControlAggregate(
            framework_id=control["framework_id"],
            control_id=control["control_id"],
            title=customer_title,
            domain=control.get("domain"),
            severity=control["severity"],
            assessment_type=assessment_type,
            mapped_policy_ids=[],
            status="not_assessed",
            fail_count=0,
            pass_count=0,
            finding_ids=[],
            evidence={"reason": "no_policy_mapping"},
        )

    fail_count = 0
    pass_count = 0
    finding_ids: list[str] = []
    evidence: dict[str, Any] = {"policies": {}}
    has_error = False

    for policy_id in mapped_policy_ids:
        policy_findings = findings_by_policy.get(policy_id, [])
        policy_fail = sum(1 for f in policy_findings if f["result"] == "fail")
        policy_pass = sum(1 for f in policy_findings if f["result"] == "pass")
        policy_error = sum(1 for f in policy_findings if f["result"] == "error")
        fail_count += policy_fail
        pass_count += policy_pass
        has_error = has_error or policy_error > 0
        evidence["policies"][policy_id] = {
            "fail": policy_fail,
            "pass": policy_pass,
            "error": policy_error,
            "findings": policy_findings,
        }
        finding_ids.extend(f["id"] for f in policy_findings if f["result"] == "fail")

    if not any(findings_by_policy.get(pid) for pid in mapped_policy_ids):
        status = "not_assessed"
    elif fail_count > 0:
        status = "fail"
    elif has_error:
        status = "error"
    else:
        status = "pass"

    return ControlAggregate(
        framework_id=control["framework_id"],
        control_id=control["control_id"],
        title=customer_title,
        domain=control.get("domain"),
        severity=control["severity"],
        assessment_type=assessment_type,
        mapped_policy_ids=mapped_policy_ids,
        status=status,
        fail_count=fail_count,
        pass_count=pass_count,
        finding_ids=finding_ids,
        evidence=evidence,
    )


def _compute_score(aggregates: list[ControlAggregate]) -> tuple[Decimal, dict[str, int]]:
    pass_count = sum(1 for a in aggregates if a.status == "pass")
    fail_count = sum(1 for a in aggregates if a.status == "fail")
    not_assessed_count = sum(1 for a in aggregates if a.status == "not_assessed")
    manual_count = sum(1 for a in aggregates if a.status == "manual")
    error_count = sum(1 for a in aggregates if a.status == "error")
    total = len(aggregates)

    assessed = pass_count + fail_count + error_count
    if assessed == 0:
        score = Decimal("0.00")
    else:
        score = (Decimal(pass_count) / Decimal(assessed) * Decimal("100")).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )

    return score, {
        "pass": pass_count,
        "fail": fail_count,
        "not_assessed": not_assessed_count,
        "manual": manual_count,
        "error": error_count,
        "total": total,
    }


class ComplianceMapper:
    def __init__(self, db: DatabasePool) -> None:
        self._repo = ComplianceRepository(db)

    async def map_scan(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        framework_id: str | None = None,
    ) -> dict[str, Any]:
        """Map findings to compliance frameworks. Returns primary customer framework summary."""
        if framework_id:
            return await self._map_single_framework(tenant_id, scan_id, framework_id)

        primary: dict[str, Any] | None = None
        for fid in SCAN_FRAMEWORK_IDS:
            framework = await self._repo.get_framework(fid, customer_visible_only=False)
            if not framework:
                continue
            summary = await self._map_single_framework(tenant_id, scan_id, fid)
            if fid == CUSTOMER_PRIMARY_FRAMEWORK:
                primary = summary
        if not primary:
            raise LookupError(f"framework not found: {CUSTOMER_PRIMARY_FRAMEWORK}")
        return primary

    async def _map_single_framework(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        framework_id: str,
    ) -> dict[str, Any]:
        framework = await self._repo.get_framework(framework_id, customer_visible_only=False)
        if not framework:
            raise LookupError(f"framework not found: {framework_id}")

        controls = await self._repo.list_controls(framework_id)
        findings_by_policy = await self._repo.get_findings_by_policy(tenant_id, scan_id)

        aggregates: list[ControlAggregate] = []
        for control in controls:
            aggregate = _aggregate_control(control, findings_by_policy)
            aggregates.append(aggregate)
            await self._repo.upsert_control_result(tenant_id, scan_id, aggregate)

        score, summary = _compute_score(aggregates)
        await self._repo.upsert_scan_score(
            tenant_id,
            scan_id,
            framework_id,
            score=score,
            pass_count=summary["pass"],
            fail_count=summary["fail"],
            not_assessed_count=summary["not_assessed"],
            manual_count=summary["manual"],
            error_count=summary["error"],
            total_controls=summary["total"],
        )

        return {
            "framework_id": framework_id,
            "scan_id": str(scan_id),
            "score": float(score),
            "summary": summary,
        }
