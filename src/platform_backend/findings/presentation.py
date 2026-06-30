from __future__ import annotations

from typing import Any

from platform_backend.policy.catalog.models import PolicyDefinition, PolicyRemediation
from platform_backend.policy.catalog.registry import get_policy_definition


def _resource_context(finding: dict[str, Any]) -> dict[str, str]:
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
    if not isinstance(name, str) or not name:
        tail = finding.get("resource_id", "").split("/")[-1]
        name = tail if tail else "RESOURCE"

    region = props.get("region") if isinstance(props.get("region"), str) else "us-east-1"
    if region == "global":
        region = "us-east-1"

    return {
        "resource_name": str(name),
        "bucket_name": str(props.get("bucket_name") or props.get("name") or name),
        "trail_name": str(props.get("trail_name") or props.get("name") or name),
        "region": str(region),
        "account_id": str(props.get("account_id") or ""),
    }


def render_template(template: str | None, ctx: dict[str, str]) -> str | None:
    if not template:
        return None
    out = template
    for key, value in ctx.items():
        out = out.replace("{" + key + "}", value)
    return out


def remediation_for_finding(
    finding: dict[str, Any],
    policy: PolicyDefinition | None = None,
) -> dict[str, Any]:
    pol = policy or get_policy_definition(finding.get("policy_id", ""))
    if not pol:
        minutes = {"critical": 5, "high": 5, "medium": 3, "low": 2}.get(finding.get("severity", ""), 3)
        return {
            "headline": finding.get("title"),
            "risk_summary": finding.get("description"),
            "business_impact": "This misconfiguration may lead to unauthorized access or compliance failure.",
            "fix_summary": "Review the affected resource in AWS and apply the recommended security control.",
            "estimated_fix_minutes": minutes,
            "framework_mappings": [],
            "aws_cli": None,
            "terraform": None,
            "cloudformation": None,
        }

    rem: PolicyRemediation = pol.effective_remediation()
    ctx = _resource_context(finding)
    return {
        "headline": rem.headline or pol.customer_display_title(),
        "risk_summary": rem.risk_summary or pol.description,
        "business_impact": rem.business_impact,
        "fix_summary": rem.fix_summary,
        "estimated_fix_minutes": rem.estimated_fix_minutes,
        "framework_mappings": list(rem.framework_mappings),
        "aws_cli": render_template(rem.aws_cli, ctx),
        "terraform": render_template(rem.terraform, ctx),
        "cloudformation": render_template(rem.cloudformation, ctx),
    }


def enrich_finding(finding: dict[str, Any], *, customer_visible: bool = False) -> dict[str, Any]:
    out = dict(finding)
    pol = get_policy_definition(finding.get("policy_id", ""))
    rem = remediation_for_finding(finding, pol)
    if customer_visible and pol:
        rem = dict(rem)
        rem["framework_mappings"] = list(pol.effective_remediation().customer_framework_mappings())
    out["remediation"] = rem
    display = pol.customer_display_title() if pol else rem.get("headline") or finding.get("title")
    out["display_title"] = display
    out["technical_title"] = finding.get("title")
    if customer_visible:
        out["policy_id"] = finding.get("policy_id")
    return out
