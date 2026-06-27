from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from platform_backend.db.pool import DatabasePool

AWS_STARTER_RESOURCE_TYPES = frozenset(
    {
        "identity.user",
        "storage.bucket",
        "compute.instance",
    }
)


class ScanInsightsRepository:
    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def inventory_completeness(self, tenant_id: UUID, scan_id: UUID) -> dict[str, Any]:
        rows = await self._db.fetch(
            tenant_id,
            """
            SELECT resource_type, COUNT(*) AS count
            FROM assets.resources
            WHERE tenant_id = $1 AND scan_id = $2
            GROUP BY resource_type
            ORDER BY resource_type
            """,
            tenant_id,
            scan_id,
        )
        collected = {row["resource_type"]: row["count"] for row in rows}
        expected = sorted(AWS_STARTER_RESOURCE_TYPES)
        present = [t for t in expected if t in collected]
        score = round(len(present) / len(expected) * 100, 2) if expected else 0.0

        return {
            "scan_id": str(scan_id),
            "resource_count": sum(collected.values()),
            "resource_types": collected,
            "expected_types": expected,
            "missing_types": [t for t in expected if t not in collected],
            "completeness_score": score,
        }

    async def policy_coverage(self, tenant_id: UUID, scan_id: UUID) -> dict[str, Any]:
        eval_row = await self._db.fetchrow(
            tenant_id,
            """
            SELECT policies_run, findings_count, fail_count, status, completed_at
            FROM findings.evaluation_runs
            WHERE tenant_id = $1 AND scan_id = $2
            """,
            tenant_id,
            scan_id,
        )
        result_rows = await self._db.fetch(
            tenant_id,
            """
            SELECT result, COUNT(*) AS count
            FROM findings.findings
            WHERE tenant_id = $1 AND scan_id = $2
            GROUP BY result
            """,
            tenant_id,
            scan_id,
        )
        by_result = {row["result"]: row["count"] for row in result_rows}
        policy_rows = await self._db.fetch(
            tenant_id,
            """
            SELECT policy_id, result, COUNT(*) AS count
            FROM findings.findings
            WHERE tenant_id = $1 AND scan_id = $2
            GROUP BY policy_id, result
            ORDER BY policy_id
            """,
            tenant_id,
            scan_id,
        )
        by_policy: dict[str, dict[str, int]] = {}
        for row in policy_rows:
            by_policy.setdefault(row["policy_id"], {})[row["result"]] = row["count"]

        return {
            "scan_id": str(scan_id),
            "evaluation_status": eval_row["status"] if eval_row else None,
            "policies_evaluated": eval_row["policies_run"] if eval_row else 0,
            "findings_total": eval_row["findings_count"] if eval_row else 0,
            "fail_count": eval_row["fail_count"] if eval_row else 0,
            "by_result": by_result,
            "by_policy": by_policy,
        }
