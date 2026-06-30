# Framework mappings (CIS, SOC2, NIST, …)

| File | Purpose |
|------|---------|
| `mappings/cis_aws_v6.yaml` | **35** `policy_id` → CIS `control_id` mappings (locked) |
| `mappings/nist_800_53_rev5.yaml` | NIST Moderate baseline subset (P4) |
| `mappings/soc2_aws.yaml` | SOC 2 TSC AWS technical mapping — **85** policies (P5 W4) |
| `aws_cspm_v1.yaml` | Master catalog — all policy metadata and `status` |

Regenerate DB migration after catalog edits:

```bash
python scripts/build_policy_catalog.py
cd ../platform-db && python scripts/migrate.py
```
