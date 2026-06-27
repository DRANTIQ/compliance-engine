# Framework mappings (CIS, SOC2, NIST, …)

| File | Purpose |
|------|---------|
| `mappings/cis_aws_v6.yaml` | **35** `policy_id` → CIS `control_id` mappings (locked) |
| `aws_cspm_v1.yaml` | Master catalog — all policy metadata and `status` |

Regenerate DB migration after catalog edits:

```bash
python scripts/build_policy_catalog.py
cd ../platform-db && python scripts/migrate.py
```
