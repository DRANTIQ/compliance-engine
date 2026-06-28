from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from platform_backend.db.pool import DatabasePool
from platform_backend.policy.catalog.models import PolicyDefinition
from platform_backend.policy.engine.evaluator import build_evidence, evaluate_policy_logic


class FindingsRepository:
    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def start_evaluation_run(self, tenant_id: UUID, scan_id: UUID) -> UUID:
        row = await self._db.fetchrow(
            tenant_id,
            """
            INSERT INTO findings.evaluation_runs (tenant_id, scan_id, status)
            VALUES ($1, $2, 'running')
            ON CONFLICT (tenant_id, scan_id) DO UPDATE
              SET status = 'running',
                  policies_run = 0,
                  findings_count = 0,
                  fail_count = 0,
                  error = NULL,
                  started_at = now(),
                  completed_at = NULL
            RETURNING id
            """,
            tenant_id,
            scan_id,
        )
        return row["id"]

    async def complete_evaluation_run(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        *,
        policies_run: int,
        findings_count: int,
        fail_count: int,
        status: str = "completed",
        error: dict[str, Any] | None = None,
    ) -> None:
        await self._db.execute(
            tenant_id,
            """
            UPDATE findings.evaluation_runs
            SET status = $3,
                policies_run = $4,
                findings_count = $5,
                fail_count = $6,
                error = $7::jsonb,
                completed_at = now()
            WHERE tenant_id = $1 AND scan_id = $2
            """,
            tenant_id,
            scan_id,
            status,
            policies_run,
            findings_count,
            fail_count,
            json.dumps(error) if error else None,
        )

    async def upsert_finding(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        *,
        policy: PolicyDefinition,
        resource_id: str,
        resource_type: str,
        result: str,
        evidence: dict[str, Any],
    ) -> None:
        status = "open" if result == "fail" else "resolved"
        await self._db.execute(
            tenant_id,
            """
            INSERT INTO findings.findings (
              tenant_id, scan_id, policy_id, resource_id, resource_type,
              result, status, severity, title, description, evidence
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)
            ON CONFLICT (tenant_id, scan_id, policy_id, resource_id) DO UPDATE
              SET result = EXCLUDED.result,
                  status = EXCLUDED.status,
                  severity = EXCLUDED.severity,
                  title = EXCLUDED.title,
                  description = EXCLUDED.description,
                  evidence = EXCLUDED.evidence,
                  evaluated_at = now()
            """,
            tenant_id,
            scan_id,
            policy.policy_id,
            resource_id,
            resource_type,
            result,
            status,
            policy.severity,
            policy.title,
            policy.description,
            json.dumps(evidence),
        )

    async def list_findings(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        *,
        result: str | None = None,
        policy_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses = ["tenant_id = $1", "scan_id = $2"]
        params: list[Any] = [tenant_id, scan_id]
        idx = 3

        if result:
            clauses.append(f"result = ${idx}")
            params.extend([result])
            idx += 1
        if policy_id:
            clauses.append(f"policy_id = ${idx}")
            params.extend([policy_id])
            idx += 1
        if status:
            clauses.append(f"status = ${idx}")
            params.extend([status])
            idx += 1

        params.extend([limit, offset])
        query = f"""
            SELECT id, policy_id, resource_id, resource_type, result, status, severity,
                   title, description, evidence, evaluated_at, created_at
            FROM findings.findings
            WHERE {" AND ".join(clauses)}
            ORDER BY severity, policy_id, resource_id
            LIMIT ${idx} OFFSET ${idx + 1}
        """
        rows = await self._db.fetch(tenant_id, query, *params)
        return [self._public(row) for row in rows]

    async def list_failures(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        *,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        return await self.list_findings(
            tenant_id,
            scan_id,
            result="fail",
            limit=limit,
            offset=0,
        )

    async def list_by_resource(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        resource_id: str,
        *,
        result: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses = ["tenant_id = $1", "scan_id = $2", "resource_id = $3"]
        params: list[Any] = [tenant_id, scan_id, resource_id]
        idx = 4
        if result:
            clauses.append(f"result = ${idx}")
            params.append(result)
            idx += 1
        params.append(limit)
        query = f"""
            SELECT id, policy_id, resource_id, resource_type, result, status, severity,
                   title, description, evidence, evaluated_at, created_at
            FROM findings.findings
            WHERE {" AND ".join(clauses)}
            ORDER BY severity, policy_id
            LIMIT ${idx}
        """
        rows = await self._db.fetch(tenant_id, query, *params)
        return [self._public(row) for row in rows]

    async def list_by_policy(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        policy_id: str,
        *,
        result: str = "fail",
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        return await self.list_findings(
            tenant_id,
            scan_id,
            result=result,
            policy_id=policy_id,
            limit=limit,
            offset=0,
        )

    async def get_finding(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        finding_id: UUID,
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            tenant_id,
            """
            SELECT id, policy_id, resource_id, resource_type, result, status, severity,
                   title, description, evidence, evaluated_at, created_at
            FROM findings.findings
            WHERE tenant_id = $1 AND scan_id = $2 AND id = $3
            """,
            tenant_id,
            scan_id,
            finding_id,
        )
        return self._public(row) if row else None

    async def count_by_result(self, tenant_id: UUID, scan_id: UUID) -> dict[str, int]:
        rows = await self._db.fetch(
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
        return {row["result"]: row["count"] for row in rows}

    @staticmethod
    def _public(row: Any) -> dict[str, Any]:
        evidence = row["evidence"]
        return {
            "id": str(row["id"]),
            "policy_id": row["policy_id"],
            "resource_id": row["resource_id"],
            "resource_type": row["resource_type"],
            "result": row["result"],
            "status": row["status"],
            "severity": row["severity"],
            "title": row["title"],
            "description": row["description"],
            "evidence": evidence if isinstance(evidence, dict) else json.loads(evidence),
            "evaluated_at": row["evaluated_at"].isoformat(),
            "created_at": row["created_at"].isoformat(),
        }


async def evaluate_scan(
    assets: list[dict[str, Any]],
    policies: list[PolicyDefinition],
    repo: FindingsRepository,
    tenant_id: UUID,
    scan_id: UUID,
) -> tuple[int, int, int]:
    policies_run = 0
    findings_count = 0
    fail_count = 0

    for policy in policies:
        policies_run += 1
        matched = [asset for asset in assets if policy.matches_asset(asset)]
        for asset in matched:
            try:
                failed = evaluate_policy_logic(asset, policy.logic)
                result = "fail" if failed else "pass"
            except Exception as exc:
                result = "error"
                failed = True
                evidence = {"error": str(exc)}
            else:
                evidence = build_evidence(asset, policy.evidence_fields)

            await repo.upsert_finding(
                tenant_id,
                scan_id,
                policy=policy,
                resource_id=asset["resource_id"],
                resource_type=asset["resource_type"],
                result=result,
                evidence=evidence,
            )
            findings_count += 1
            if result == "fail":
                fail_count += 1

    return policies_run, findings_count, fail_count
