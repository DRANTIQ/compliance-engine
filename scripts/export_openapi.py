#!/usr/bin/env python3
"""Export OpenAPI schema to contracts/openapi.json for CI and Postman import."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from platform_backend.api.main import app  # noqa: E402

OUT = ROOT / "contracts" / "openapi.json"


def main() -> int:
    schema = app.openapi()
    OUT.write_text(json.dumps(schema, indent=2), encoding="utf-8")
    paths = len(schema.get("paths", {}))
    print(f"Wrote {OUT} ({paths} paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
