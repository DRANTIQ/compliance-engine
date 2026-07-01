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

SEVERITY_RISK_BASE: dict[str, int] = {
    "critical": 92,
    "high": 72,
    "medium": 48,
    "low": 28,
    "info": 12,
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

AZURE_RESOURCE_TYPE_LABEL: dict[str, str] = {
    "storage.bucket": "Storage account",
    "network.security_group": "Network security group",
    "network.vpc": "Virtual network",
    "governance.hub": "Microsoft Defender for Cloud",
    "identity.account": "Azure subscription",
    "compute.instance": "Virtual machine",
    "database.instance": "Database server",
    "security.key": "Key Vault",
}

DATA_SENSITIVE_TYPES = frozenset({"storage.bucket", "storage.filesystem", "database.instance"})
IDENTITY_RESOURCE_TYPES = frozenset({"identity.user", "identity.account", "identity.certificate"})
LOGGING_POLICY_PREFIXES = ("AWS_LOG_", "AWS_S3_003", "AWS_S3_004", "AWS_CMP_003")
ENCRYPTION_POLICY_IDS = frozenset(
    {
        "AWS_S3_001",
        "AWS_RDS_001",
        "AWS_EFS_001",
        "AWS_NET_001",
        "AWS_EC2_006",
        "AWS_EC2_007",
        "AWS_EC2_008",
        "AWS_CMP_011",
        "AZURE_STG_001",
        "AZURE_STG_002",
        "AZURE_CMP_002",
        "AZURE_DB_002",
        "AZURE_KV_001",
        "AZURE_KV_002",
    }
)


def _policy_provider(policy_id: str) -> str:
    if policy_id.startswith("AZURE_"):
        return "azure"
    return "aws"


def resource_type_label(resource_type: str, *, policy_id: str | None = None) -> str:
    provider = _policy_provider(policy_id) if policy_id else "aws"
    if provider == "azure":
        return AZURE_RESOURCE_TYPE_LABEL.get(resource_type, resource_type.replace(".", " "))
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


def parse_framework_mappings(
    mappings: list[str],
    *,
    customer_visible: bool = True,
) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for raw in mappings:
        text = raw.strip()
        if customer_visible and text.upper().startswith("CIS "):
            continue
        if text.startswith("CIS "):
            out.append({"framework": "CIS AWS v6", "control": text.removeprefix("CIS ").strip()})
        elif text.startswith("SOC2 "):
            out.append({"framework": "SOC 2", "control": text.removeprefix("SOC2 ").strip()})
        elif text.startswith("NIST "):
            out.append({"framework": "NIST 800-53", "control": text.removeprefix("NIST ").strip()})
        else:
            parts = text.split(" ", 1)
            if len(parts) == 2:
                out.append({"framework": parts[0], "control": parts[1]})
            else:
                out.append({"framework": text, "control": ""})
    return out


def _internet_exposed(finding: dict[str, Any]) -> bool:
    policy_id = finding.get("policy_id", "")
    if policy_id.startswith("AZURE_STG_003"):
        evidence = finding.get("evidence") or {}
        props = evidence.get("properties") if isinstance(evidence.get("properties"), dict) else evidence
        if isinstance(props, dict) and props.get("allow_blob_public_access") is True:
            return True
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


def _publicly_accessible(finding: dict[str, Any]) -> bool:
    if _internet_exposed(finding):
        return True
    evidence = finding.get("evidence") or {}
    props = evidence.get("properties") if isinstance(evidence.get("properties"), dict) else evidence
    if isinstance(props, dict) and props.get("public") is True:
        return True
    policy_id = finding.get("policy_id", "")
    return policy_id.startswith(
        ("AWS_EC2_011", "AWS_EC2_012", "AWS_EC2_013", "AWS_CMP_013", "AWS_CMP_014",
         "AZURE_NET_001", "AZURE_NET_002", "AZURE_CMP_001", "AZURE_DB_001")
    )


def _identity_exposure(finding: dict[str, Any]) -> bool:
    if finding.get("resource_type") in IDENTITY_RESOURCE_TYPES:
        return True
    policy_id = finding.get("policy_id", "")
    return policy_id.startswith(("AWS_IAM_", "AZURE_ID_"))


def _why_badges(finding: dict[str, Any], signals: dict[str, Any]) -> list[dict[str, str]]:
    badges: list[dict[str, str]] = []
    if signals["internet_exposed"]:
        badges.append({"id": "internet_exposed", "label": "Internet exposed"})
    if signals["data_sensitive"]:
        badges.append({"id": "sensitive_data", "label": "Sensitive data"})
    if signals["publicly_accessible"]:
        badges.append({"id": "public_resource", "label": "Public resource"})
    if signals["identity_exposure"]:
        badges.append({"id": "identity_exposure", "label": "Identity exposure"})
    policy_id = finding.get("policy_id", "")
    if policy_id.startswith(LOGGING_POLICY_PREFIXES):
        badges.append({"id": "insufficient_logging", "label": "Insufficient logging"})
    if policy_id in ENCRYPTION_POLICY_IDS or "encrypt" in policy_id.lower():
        badges.append({"id": "no_encryption", "label": "No encryption"})
    return badges


def compute_risk_signals(finding: dict[str, Any]) -> dict[str, Any]:
    """Composite risk signals — extensible schema for Wiz-style prioritization."""
    score = SEVERITY_RISK_BASE.get(finding.get("severity", ""), 45)
    internet = _internet_exposed(finding)
    sensitive = finding.get("resource_type") in DATA_SENSITIVE_TYPES
    publicly_accessible = _publicly_accessible(finding)
    identity_exposure = _identity_exposure(finding)
    if internet:
        score = min(100, score + 12)
    if sensitive:
        score = min(100, score + 8)
    if publicly_accessible and not internet:
        score = min(100, score + 6)
    if identity_exposure:
        score = min(100, score + 5)
    evidence = finding.get("evidence") or {}
    confidence = "high" if isinstance(evidence, dict) and evidence else "medium"

    # Reserved for future scoring — values default false until assessed.
    business_critical = False
    lateral_movement = False
    blast_radius = False

    signals = {
        "risk_score": score,
        "internet_exposed": internet,
        "data_sensitive": sensitive,
        "confidence": confidence,
        "publicly_accessible": publicly_accessible,
        "identity_exposure": identity_exposure,
        "business_critical": business_critical,
        "lateral_movement": lateral_movement,
        "blast_radius": blast_radius,
        "assessed": {
            "business_critical": False,
            "lateral_movement": False,
            "blast_radius": False,
        },
    }
    signals["why_badges"] = _why_badges(finding, signals)
    return signals


def build_related_resources(
    resource_id: str,
    relationships: list[dict[str, Any]],
    *,
    assets_by_id: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Relationship graph edges for a finding's primary resource (not an attack path)."""
    assets_by_id = assets_by_id or {}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rel in relationships:
        peer = (
            rel["to_resource_id"]
            if rel.get("from_resource_id") == resource_id
            else rel.get("from_resource_id")
        )
        if not peer or peer == resource_id or peer in seen:
            continue
        seen.add(peer)
        asset = assets_by_id.get(peer, {})
        props = asset.get("properties") if isinstance(asset.get("properties"), dict) else {}
        name = (
            props.get("name")
            or props.get("instance_id")
            or props.get("role_name")
            or peer.split("/")[-1]
        )
        out.append(
            {
                "resource_id": peer,
                "resource_name": str(name),
                "resource_type": str(asset.get("resource_type") or ""),
                "relationship_type": str(rel.get("relationship_type") or "related"),
            }
        )
    return out


def fix_priority_sort_key(finding: dict[str, Any], remediation: dict[str, Any]) -> tuple:
    signals = compute_risk_signals(finding)
    score_rank = -signals["risk_score"]
    sev = SEVERITY_ORDER.get(finding.get("severity", ""), 99)
    exposure = 0 if signals["internet_exposed"] else 1
    sensitivity = 0 if signals["data_sensitive"] else 1
    has_framework = 0 if remediation.get("framework_mappings") else 1
    minutes = remediation.get("estimated_fix_minutes") or 99
    return (score_rank, sev, exposure, sensitivity, has_framework, minutes)


def customer_remediation(remediation: dict[str, Any]) -> dict[str, Any]:
    raw_mappings = remediation.get("framework_mappings") or []
    customer_mappings = [m for m in raw_mappings if not str(m).strip().upper().startswith("CIS ")]
    return {
        "summary": remediation.get("fix_summary"),
        "headline": remediation.get("headline"),
        "risk_summary": remediation.get("risk_summary"),
        "business_impact": remediation.get("business_impact"),
        "estimated_minutes": remediation.get("estimated_fix_minutes"),
        "estimated_fix_minutes": remediation.get("estimated_fix_minutes"),
        "aws_console_steps": [],
        "aws_cli": remediation.get("aws_cli"),
        "azure_cli": remediation.get("azure_cli"),
        "azure_portal_steps": remediation.get("azure_portal_steps") or [],
        "terraform": remediation.get("terraform"),
        "cloudformation": remediation.get("cloudformation"),
        "framework_mappings": customer_mappings,
    }


def enrich_customer_finding(finding: dict[str, Any], *, include_priority: bool = False) -> dict[str, Any]:
    base = enrich_finding(finding)
    rem = base["remediation"]
    policy = get_policy_definition(finding.get("policy_id", ""))
    display = (
        policy.customer_display_title()
        if policy
        else rem.get("headline") or finding.get("title") or finding.get("policy_id") or "Security finding"
    )
    technical = finding.get("title") or finding.get("policy_id") or "Finding"
    customer_mappings = [m for m in (rem.get("framework_mappings") or []) if not str(m).strip().upper().startswith("CIS ")]
    risk_signals = compute_risk_signals(finding)
    out: dict[str, Any] = {
        **base,
        "display_title": display,
        "plain_language_title": display,
        "technical_title": technical,
        "affected_resource": affected_resource_name(finding),
        "resource_type_label": resource_type_label(
            finding.get("resource_type", ""),
            policy_id=finding.get("policy_id"),
        ),
        "risk": rem.get("risk_summary") or finding.get("description"),
        "business_impact": rem.get("business_impact"),
        "frameworks": parse_framework_mappings(customer_mappings, customer_visible=True),
        "remediation": customer_remediation(rem),
        "policy_version": policy.version if policy else "1.0.0",
        "risk_signals": risk_signals,
    }
    if include_priority:
        out["priority_rank"] = fix_priority_sort_key(finding, rem)
    return out


def build_resource_inventory_stats(
    findings: list[dict[str, Any]],
    *,
    resource_total: int,
) -> dict[str, int]:
    """Distinct resources with at least one failing finding vs clean inventory."""
    at_risk_ids = {f["resource_id"] for f in findings if f.get("result") == "fail" and f.get("resource_id")}
    at_risk = len(at_risk_ids)
    protected = max(0, resource_total - at_risk)
    return {
        "cloud_resources": resource_total,
        "resources_at_risk": at_risk,
        "resources_protected": protected,
    }


def build_risk_summary(
    findings: list[dict[str, Any]],
    *,
    compliance_score: float | None,
    top_n: int = 5,
    resource_total: int | None = None,
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
        signals = item.get("risk_signals") or compute_risk_signals(finding)
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
                "estimated_fix_minutes": rem.get("estimated_fix_minutes") or rem.get("estimated_minutes"),
                "risk_score": signals["risk_score"],
            }
        )
        if len(top_risks) >= top_n:
            break

    result: dict[str, Any] = {
        "score": compliance_score,
        "total_findings": len(fails),
        **severity_counts,
        "top_risks": top_risks,
    }
    if resource_total is not None:
        result.update(build_resource_inventory_stats(findings, resource_total=resource_total))
    return result


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
                "estimated_fix_minutes": rem.get("estimated_fix_minutes") or rem.get("estimated_minutes"),
                "frameworks": item["frameworks"],
                "internet_exposed": _internet_exposed(finding),
                "data_sensitive": finding.get("resource_type") in DATA_SENSITIVE_TYPES,
                "risk_score": compute_risk_signals(finding)["risk_score"],
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
        "display_title": policy.customer_display_title() if policy else policy_id,
        "affected_count": len(resources),
        "resources": resources,
    }
