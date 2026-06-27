#!/usr/bin/env python3
"""Phase 3 E2E: scan pipeline + CIS compliance API + asset search."""

from __future__ import annotations

import json
import os
import sys
import time
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
    print(f"scan created: {scan_id}")

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

    compliance = _request("GET", f"/v1/compliance/frameworks/cis_aws_v6/scans/{scan_id}")
    print(f"CIS score: {compliance['score']}")
    print(f"CIS summary: {compliance['summary']}")
    assert compliance["summary"]["total"] == 35, "expected 35 CIS controls"

    scan_compliance = _request("GET", f"/v1/scans/{scan_id}/compliance")
    assert scan_compliance["framework_id"] == "cis_aws_v6"

    completeness = _request("GET", f"/v1/scans/{scan_id}/inventory-completeness")
    print(f"inventory completeness: {completeness['completeness_score']}%")
    if completeness["completeness_score"] < 100:
        print("FAIL: expected full inventory completeness for mock scan", file=sys.stderr)
        return 1

    coverage = _request("GET", f"/v1/scans/{scan_id}/policy-coverage")
    print(f"policy coverage: {coverage['policies_evaluated']} policies, fail={coverage['fail_count']}")

    search = _request("GET", f"/v1/assets/search?scan_id={scan_id}&q=mock-admin")
    print(f"asset search hits: {len(search)}")
    if len(search) < 1:
        print("FAIL: asset search should find mock-admin IAM user", file=sys.stderr)
        return 1

    fail_controls = [c for c in compliance["controls"] if c["status"] == "fail"]
    if not fail_controls:
        print("FAIL: expected at least one failing CIS control (2.9)", file=sys.stderr)
        return 1
    print(f"failing controls: {[c['control_id'] for c in fail_controls]}")

    print("Phase 3 E2E passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
