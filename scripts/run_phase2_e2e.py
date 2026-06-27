#!/usr/bin/env python3
"""Phase 2 E2E: scan -> collect -> ingest -> policy evaluate -> GET findings."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

API_BASE = os.environ.get("API_BASE", "http://localhost:8090")
TENANT_ID = os.environ.get("TENANT_ID", "")
INTEGRATION_ID = os.environ.get("INTEGRATION_ID", "")
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "90"))


def _request(method: str, path: str, body: dict | None = None) -> dict | list:
    headers = {"X-Tenant-ID": TENANT_ID, "Content-Type": "application/json"}
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(f"{API_BASE}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def main() -> int:
    if not TENANT_ID:
        print("Set TENANT_ID", file=sys.stderr)
        return 1

    if not INTEGRATION_ID:
        integrations = _request("GET", "/v1/integrations")
        if not integrations:
            print("No integrations; register one first", file=sys.stderr)
            return 1
        integration_id = integrations[0]["id"]
    else:
        integration_id = INTEGRATION_ID

    scan = _request("POST", "/v1/scans", {"integration_id": integration_id})
    scan_id = scan["id"]
    print(f"scan created: {scan_id} status={scan['status']}")

    deadline = time.time() + POLL_SECONDS
    status = scan["status"]
    while time.time() < deadline:
        detail = _request("GET", f"/v1/scans/{scan_id}")
        status = detail["status"]
        print(f"  status={status}")
        if status in ("completed", "completed_with_errors", "failed"):
            break
        time.sleep(2)

    if status not in ("completed", "completed_with_errors"):
        print(f"FAIL: scan ended with {status}", file=sys.stderr)
        return 1

    assets = _request("GET", f"/v1/assets?scan_id={scan_id}")
    print(f"assets: {len(assets)}")

    findings = _request("GET", f"/v1/findings?scan_id={scan_id}")
    print(f"findings (all): {len(findings)}")

    fail_findings = _request("GET", f"/v1/findings?scan_id={scan_id}&result=fail")
    print(f"findings (fail): {len(fail_findings)}")
    for finding in fail_findings[:5]:
        print(f"  - {finding['policy_id']} {finding['resource_id']} ({finding['severity']})")

    if len(assets) < 1:
        print("FAIL: expected assets", file=sys.stderr)
        return 1
    if len(fail_findings) < 1:
        print("FAIL: expected at least one failing finding (AWS_IAM_005 on mock-admin)", file=sys.stderr)
        return 1

    print("Phase 2 E2E passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
