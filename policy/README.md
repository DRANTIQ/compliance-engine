# policy

Unified Policy Library + YAML DSL evaluator.

| Path | Purpose |
|------|---------|
| `catalog/aws_cspm_v1.yaml` | **Master catalog** — 35 policies, IDs, CIS control, collector, status |
| `catalog/policies/` | One YAML per **implemented** policy (`AWS_*`) |
| `catalog/mappings/cis_aws_v6.yaml` | CIS AWS v6 framework mappings |
| `engine/` | Evaluator (fail_when, field_check, compound) |

Deployment: `policy-worker` on EKS.

See POLICY_LIBRARY.md in infra-state-docs.
