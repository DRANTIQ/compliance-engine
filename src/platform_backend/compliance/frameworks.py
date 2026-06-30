"""Commercial compliance framework identifiers (ADR-015)."""

from __future__ import annotations

CUSTOMER_PRIMARY_FRAMEWORK = "drantiq_security_assessment_v1"
INTERNAL_PARITY_FRAMEWORK = "cis_aws_v6"
NIST_AWS_FRAMEWORK = "nist_800_53_rev5_aws"
SOC2_AWS_FRAMEWORK = "soc2_aws"

# Computed on every scan — CIS kept for engineering parity, not customer API.
SCAN_FRAMEWORK_IDS: tuple[str, ...] = (
    CUSTOMER_PRIMARY_FRAMEWORK,
    INTERNAL_PARITY_FRAMEWORK,
    NIST_AWS_FRAMEWORK,
    SOC2_AWS_FRAMEWORK,
)
