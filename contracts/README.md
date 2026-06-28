# OpenAPI contract

**Source of truth:** live schema from running FastAPI app.

Generate:

```bash
python scripts/export_openapi.py
```

Outputs `contracts/openapi.json` (full spec with Supabase auth docs).

**Interactive docs:** http://localhost:8090/docs

The legacy `openapi.yaml` stub is deprecated — use `/openapi.json` or the export script.
