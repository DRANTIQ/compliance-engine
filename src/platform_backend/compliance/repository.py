from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from uuid import UUID

from platform_backend.db.pool import DatabasePool


@dataclass(frozen=True)
class ControlAggregate:
    framework_id: str
    control_id: str
    title: str
    domain: str | None
    severity: str
    assessment_type: str
    mapped_policy_ids: list[str]
    status: str
    fail_count: int
    pass_count: int
    finding_ids: list[str]
    evidence: dict[str, Any]


class ComplianceRepository:
    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def get_framework(self, framework_id: str) -> dict[str, Any] | None:
        row = await self._db.fetchrow_global(
            """
            SELECT framework_id, title, provider, version_label, enabled
            FROM compliance_v2.frameworks
            WHERE framework_id = $1 AND enabled = true
            """,
            framework_id,
        )
        return dict(row) if row else None

    async def list_controls(self, framework_id: str) -> list[dict[str, Any]]:
        rows = await self._db.fetch_global(
            """
            SELECT c.framework_id, c.control_id, c.control_ref, c.title, c.domain,
                   c.severity, c.assessment_type,
                   COALESCE(
                     array_agg(pm.policy_id ORDER BY pm.policy_id)
                       FILTER (WHERE pm.policy_id IS NOT NULL),
                     '{}'
                   ) AS mapped_policy_ids
            FROM compliance_v2.controls c
            LEFT JOIN compliance_v2.policy_mappings pm
              ON pm.framework_id = c.framework_id AND pm.control_id = c.control_id
            WHERE c.framework_id = $1 AND c.enabled = true
            GROUP BY c.framework_id, c.control_id, c.control_ref, c.title,
                     c.domain, c.severity, c.assessment_type
            ORDER BY c.control_id
            """,
            framework_id,
        )
        return [dict(row) for row in rows]

    async def get_findings_by_policy(
        self, tenant_id: UUID, scan_id: UUID
    ) -> dict[str, list[dict[str, Any]]]:
        rows = await self._db.fetch(
            tenant_id,
            """
            SELECT id, policy_id, resource_id, result, severity, title, evidence
            FROM findings.findings
            WHERE tenant_id = $1 AND scan_id = $2
            ORDER BY policy_id, resource_id
            """,
            tenant_id,
            scan_id,
        )
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            grouped[row["policy_id"]].append(
                {
                    "id": str(row["id"]),
                    "resource_id": row["resource_id"],
                    "result": row["result"],
                    "severity": row["severity"],
                    "title": row["title"],
                    "evidence": row["evidence"]
                    if isinstance(row["evidence"], dict)
                    else json.loads(row["evidence"]),
                }
            )
        return grouped

    async def upsert_control_result(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        aggregate: ControlAggregate,
    ) -> None:
        await self._db.execute(
            tenant_id,
            """
            INSERT INTO compliance_v2.control_results (
              tenant_id, scan_id, framework_id, control_id, status, severity, title, domain,
              mapped_policy_ids, fail_count, pass_count, finding_ids, evidence
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::uuid[], $13::jsonb)
            ON CONFLICT (tenant_id, scan_id, framework_id, control_id) DO UPDATE
              SET status = EXCLUDED.status,
                  severity = EXCLUDED.severity,
                  title = EXCLUDED.title,
                  domain = EXCLUDED.domain,
                  mapped_policy_ids = EXCLUDED.mapped_policy_ids,
                  fail_count = EXCLUDED.fail_count,
                  pass_count = EXCLUDED.pass_count,
                  finding_ids = EXCLUDED.finding_ids,
                  evidence = EXCLUDED.evidence,
                  evaluated_at = now()
            """,
            tenant_id,
            scan_id,
            aggregate.framework_id,
            aggregate.control_id,
            aggregate.status,
            aggregate.severity,
            aggregate.title,
            aggregate.domain,
            aggregate.mapped_policy_ids,
            aggregate.fail_count,
            aggregate.pass_count,
            [UUID(fid) for fid in aggregate.finding_ids],
            json.dumps(aggregate.evidence),
        )

    async def upsert_scan_score(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        framework_id: str,
        *,
        score: Decimal,
        pass_count: int,
        fail_count: int,
        not_assessed_count: int,
        manual_count: int,
        error_count: int,
        total_controls: int,
    ) -> None:
        await self._db.execute(
            tenant_id,
            """
            INSERT INTO compliance_v2.scan_scores (
              tenant_id, scan_id, framework_id, score, pass_count, fail_count,
              not_assessed_count, manual_count, error_count, total_controls
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (tenant_id, scan_id, framework_id) DO UPDATE
              SET score = EXCLUDED.score,
                  pass_count = EXCLUDED.pass_count,
                  fail_count = EXCLUDED.fail_count,
                  not_assessed_count = EXCLUDED.not_assessed_count,
                  manual_count = EXCLUDED.manual_count,
                  error_count = EXCLUDED.error_count,
                  total_controls = EXCLUDED.total_controls,
                  evaluated_at = now()
            """,
            tenant_id,
            scan_id,
            framework_id,
            score,
            pass_count,
            fail_count,
            not_assessed_count,
            manual_count,
            error_count,
            total_controls,
        )

    async def get_scan_compliance(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        framework_id: str,
    ) -> dict[str, Any] | None:
        framework = await self.get_framework(framework_id)
        if not framework:
            return None

        score_row = await self._db.fetchrow(
            tenant_id,
            """
            SELECT score, pass_count, fail_count, not_assessed_count, manual_count,
                   error_count, total_controls, evaluated_at
            FROM compliance_v2.scan_scores
            WHERE tenant_id = $1 AND scan_id = $2 AND framework_id = $3
            """,
            tenant_id,
            scan_id,
            framework_id,
        )
        if not score_row:
            return None

        control_rows = await self._db.fetch(
            tenant_id,
            """
            SELECT control_id, status, severity, title, domain, mapped_policy_ids,
                   fail_count, pass_count, finding_ids, evidence, evaluated_at
            FROM compliance_v2.control_results
            WHERE tenant_id = $1 AND scan_id = $2 AND framework_id = $3
            ORDER BY control_id
            """,
            tenant_id,
            scan_id,
            framework_id,
        )

        controls = []
        for row in control_rows:
            evidence = row["evidence"]
            controls.append(
                {
                    "control_id": row["control_id"],
                    "status": row["status"],
                    "severity": row["severity"],
                    "title": row["title"],
                    "domain": row["domain"],
                    "mapped_policy_ids": list(row["mapped_policy_ids"] or []),
                    "fail_count": row["fail_count"],
                    "pass_count": row["pass_count"],
                    "finding_ids": [str(fid) for fid in (row["finding_ids"] or [])],
                    "evidence": evidence
                    if isinstance(evidence, dict)
                    else json.loads(evidence),
                    "evaluated_at": row["evaluated_at"].isoformat(),
                }
            )

        return {
            "framework_id": framework_id,
            "framework_title": framework["title"],
            "version_label": framework["version_label"],
            "scan_id": str(scan_id),
            "score": float(score_row["score"]),
            "summary": {
                "pass": score_row["pass_count"],
                "fail": score_row["fail_count"],
                "not_assessed": score_row["not_assessed_count"],
                "manual": score_row["manual_count"],
                "error": score_row["error_count"],
                "total": score_row["total_controls"],
            },
            "evaluated_at": score_row["evaluated_at"].isoformat(),
            "controls": controls,
        }

    async def list_frameworks(self) -> list[dict[str, Any]]:
        rows = await self._db.fetch_global(
            """
            SELECT framework_id, title, provider, version_label
            FROM compliance_v2.frameworks
            WHERE enabled = true
            ORDER BY framework_id
            """
        )
        return [dict(row) for row in rows]
