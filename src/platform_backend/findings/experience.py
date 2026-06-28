"""Customer-facing finding presentation — action-oriented API payloads."""

from __future__ import annotations

from typing import Any

from platform_backend.findings.presentation import enrich_finding, remediation_for_finding
from platform_backend.policy.catalog.registry import get_policy_definition

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

RESOURCE_TYPE_LABEL: dict[str, str] = {
    "storage.bucket": "S3 bucket",
    "storage.filesystem": "EFS file system",
    "network.vpc": "VPC",
    "network.security_group": "Security group",
    "network.nacl": "Network ACL",
    "governance.trail": "CloudTrail trail",
    "governance.config": "AWS Config",
    "governance.hub": "Security Hub",
    "identity.account": "Account setting",
    "identity.user": "IAM user",
    "identity.certificate": "IAM certificate",
    "compute.instance": "EC2 instance",
    "database.instance": "RDS instance",
    "security.key": "KMS key",
}

DATA_SENSITIVE_TYPES = frozenset({"storage.bucket", "storage.filesystem", "database.instance"})


def resource_type_label(resource_type: str) -> str:
    return RESOURCE_TYPE_LABEL.get(resource_type, resource_type.replace(".", " "))


def affected_resource_name(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence") or {}
    props = evidence.get("properties") if isinstance(evidence.get("properties"), dict) else evidence
    if not isinstance(props, dict):
        props = {}
    name = (
        props.get("name")
        or props.get("bucket_name")
        or props.get("trail_name")
        or props.get("vpc_id")
        or props.get("id")
    )
    if isinstance(name, str) and name:
        return name
    tail = finding.get("resource_id", "").split("/")[-1]
    return tail if tail else finding.get("resource_id", "unknown")


def parse_framework_mappings(mappings: list[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for raw in mappings:
        text = raw.strip()
        if text.startswith("CIS "):
            out.append({"framework": "CIS AWS v6", "control": text.removeprefix("CIS ").strip()})
        elif text.startswith("SOC2 "):
            out.append({"framework": "SOC 2", "control": text.removeprefix("SOC2 ").strip()})
        else:
            parts = text.split(" ", 1)
            if len(parts) == 2:
                out.append({"framework": parts[0], "control": parts[1]})
            else:
                out.append({"framework": text, "control": ""})
    return out


def _internet_exposed(finding: dict[str, Any]) -> bool:
    if finding.get("resource_type") != "storage.bucket":
        return False
    evidence = finding.get("evidence") or {}
    props = evidence.get("properties") if isinstance(evidence.get("properties"), dict) else evidence
    if not isinstance(props, dict):
        return False
    for key in (
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
        "public_access_block_enabled",
    ):
        if props.get(key) is False:
            return True
    if props.get("is_public") is True or props.get("public") is True:
        return True
    return finding.get("severity") == "critical" and finding.get("policy_id", "").startswith("AWS_S3_")


def fix_priority_sort_key(finding: dict[str, Any], remediation: dict[str, Any]) -> tuple:
    sev = SEVERITY_ORDER.get(finding.get("severity", ""), 99)
    exposure = 0 if _internet_exposed(finding) else 1
    sensitivity = 0 if finding.get("resource_type") in DATA_SENSITIVE_TYPES else 1
    has_framework = 0 if remediation.get("framework_mappings") else 1
    minutes = remediation.get("estimated_fix_minutes") or 99
    return (sev, exposure, sensitivity, has_framework, minutes)


def customer_remediation(remediation: dict[str, Any]) -> dict[str, Any]:
    return {
        "summary": remediation.get("fix_summary"),
        "headline": remediation.get("headline"),
        "risk_summary": remediation.get("risk_summary"),
        "business_impact": remediation.get("business_impact"),
        "estimated_minutes": remediation.get("estimated_fix_minutes"),
        "estimated_fix_minutes": remediation.get("estimated_fix_minutes"),
        "aws_console_steps": [],
        "aws_cli": remediation.get("aws_cli"),
        "terraform": remediation.get("terraform"),
        "cloudformation": remediation.get("cloudformation"),
        "framework_mappings": remediation.get("framework_mappings") or [],
    }


def enrich_customer_finding(finding: dict[str, Any], *, include_priority: bool = False) -> dict[str, Any]:
    base = enrich_finding(finding)
    rem = base["remediation"]
    display = rem.get("headline") or finding.get("title")
    out: dict[str, Any] = {
        **base,
        "display_title": display,
        "plain_language_title": display,
        "technical_title": finding.get("title"),
        "affected_resource": affected_resource_name(finding),
        "resource_type_label": resource_type_label(finding.get("resource_type", "")),
        "risk": rem.get("risk_summary") or finding.get("description"),
        "business_impact": rem.get("business_impact"),
        "frameworks": parse_framework_mappings(rem.get("framework_mappings") or []),
        "remediation": customer_remediation(rem),
    }
    if include_priority:
        out["priority_rank"] = fix_priority_sort_key(finding, rem)
    return out


def build_risk_summary(
    findings: list[dict[str, Any]],
    *,
    compliance_score: float | None,
    top_n: int = 5,
) -> dict[str, Any]:
    fails = [f for f in findings if f.get("result") == "fail"]
    severity_counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for f in fails:
        sev = f.get("severity", "medium")
        if sev in severity_counts:
            severity_counts[sev] += 1

    pairs = [(f, enrich_customer_finding(f)) for f in fails]
    pairs.sort(key=lambda p: fix_priority_sort_key(p[0], p[1]["remediation"]))

    seen_policies: set[str] = set()
    top_risks: list[dict[str, Any]] = []
    for finding, item in pairs:
        if finding["policy_id"] in seen_policies:
            continue
        seen_policies.add(finding["policy_id"])
        rem = item["remediation"]
        top_risks.append(
            {
                "finding_id": finding["id"],
                "policy_id": finding["policy_id"],
                "title": item["display_title"],
                "technical_title": item["technical_title"],
                "severity": finding["severity"],
                "affected_resource": item["affected_resource"],
                "resource_type": item["resource_type_label"],
                "why_it_matters": item["risk"],
                "business_impact": item["business_impact"],
                "estimated_fix_minutes": rem.get("estimated_minutes"),
            }
        )
        if len(top_risks) >= top_n:
            break

    return {
        "score": compliance_score,
        "total_findings": len(fails),
        **severity_counts,
        "top_risks": top_risks,
    }


def build_fix_priorities(findings: list[dict[str, Any]], *, limit: int = 20) -> list[dict[str, Any]]:
    fails = [f for f in findings if f.get("result") == "fail"]
    pairs = [(f, enrich_customer_finding(f)) for f in fails]
    pairs.sort(key=lambda p: fix_priority_sort_key(p[0], p[1]["remediation"]))

    out: list[dict[str, Any]] = []
    for rank, (finding, item) in enumerate(pairs[:limit], start=1):
        rem = item["remediation"]
        out.append(
            {
                "rank": rank,
                "finding_id": finding["id"],
                "policy_id": finding["policy_id"],
                "display_title": item["display_title"],
                "technical_title": item["technical_title"],
                "severity": finding["severity"],
                "affected_resource": item["affected_resource"],
                "resource_id": finding["resource_id"],
                "resource_type": item["resource_type_label"],
                "why_it_matters": item["risk"],
                "business_impact": item["business_impact"],
                "estimated_fix_minutes": rem.get("estimated_minutes"),
                "frameworks": item["frameworks"],
                "internet_exposed": _internet_exposed(finding),
                "data_sensitive": finding.get("resource_type") in DATA_SENSITIVE_TYPES,
            }
        )
    return out


def build_resource_risk(findings: list[dict[str, Any]], resource_id: str) -> dict[str, Any]:
    related = [f for f in findings if f.get("resource_id") == resource_id and f.get("result") == "fail"]
    if not related:
        return {
            "resource_id": resource_id,
            "risk_level": "healthy",
            "finding_count": 0,
            "findings": [],
            "display_titles": [],
        }

    severities = [SEVERITY_ORDER.get(f.get("severity", ""), 99) for f in related]
    min_sev = min(severities)
    risk_level = {0: "critical", 1: "high", 2: "medium", 3: "low", 4: "info"}.get(min_sev, "medium")

    items = []
    titles: list[str] = []
    for f in sorted(related, key=lambda x: fix_priority_sort_key(x, remediation_for_finding(x))):
        item = enrich_customer_finding(f)
        titles.append(item["display_title"])
        items.append(
            {
                "finding_id": f["id"],
                "policy_id": f["policy_id"],
                "display_title": item["display_title"],
                "technical_title": item["technical_title"],
                "severity": f["severity"],
                "remediation_summary": item["remediation"].get("summary"),
            }
        )

    return {
        "resource_id": resource_id,
        "risk_level": risk_level,
        "finding_count": len(related),
        "findings": items,
        "display_titles": titles,
    }


def build_affected_resources(findings: list[dict[str, Any]], policy_id: str) -> dict[str, Any]:
    policy = get_policy_definition(policy_id)
    related = [f for f in findings if f.get("policy_id") == policy_id and f.get("result") == "fail"]
    resources = []
    for f in related:
        item = enrich_customer_finding(f)
        resources.append(
            {
                "finding_id": f["id"],
                "resource_id": f["resource_id"],
                "affected_resource": item["affected_resource"],
                "resource_type": item["resource_type_label"],
                "severity": f["severity"],
                "display_title": item["display_title"],
            }
        )
    return {
        "policy_id": policy_id,
        "policy_title": policy.title if policy else policy_id,
        "display_title": (policy.remediation.headline if policy and policy.remediation else None)
        or (policy.title if policy else policy_id),
        "affected_count": len(resources),
        "resources": resources,
    }
