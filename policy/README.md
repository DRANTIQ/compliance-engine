# policy

Unified Policy Library + YAML DSL evaluator.

| Path | Purpose |
|------|---------|
| `catalog/policies/` | One YAML per policy (`AWS_S3_001.yaml`) |
| `catalog/mappings/` | Framework control mappings (separate from policy logic) |
| `engine/` | Evaluator (fail_when, field_check, compound) |

Deployment: `policy-worker` on EKS.

See POLICY_LIBRARY.md in infra-state-docs.
