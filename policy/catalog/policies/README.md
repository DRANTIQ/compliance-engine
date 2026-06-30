# YAML policy definitions (AWS_S3_001, …)

Logic only — no framework mappings here. See `mappings/`.

Each policy includes:

- `display_title` — customer-safe headline (ADR-015)
- `title` — engineering / technical title
- `pack_id` — product pack (`packs/aws.yaml`)
- `remediation.framework_mappings` — NIST / SOC2 (customer-visible where allowed)

Engineering lineage (parity notes) lives in `infra-state-docs` only — not in this catalog.
