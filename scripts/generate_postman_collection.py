#!/usr/bin/env python3
"""Generate Platform V2 Postman collection."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

AUTH_PREREQUEST = [
    'const authMode = pm.environment.get("authMode") || "supabase";',
    'const url = pm.request.url.toString();',
    'if (pm.variables.get("skipPlatformAuth") === "true") { return; }',
    'if (url.includes("/health") || url.includes("/ready") || url.includes("/auth/v1/token")) { return; }',
    "const baseUrl = pm.environment.get('baseUrl');",
    'if (!baseUrl) { throw new Error("Select Platform V2 — Local environment before sending requests."); }',
    'pm.request.headers.upsert({ key: "Accept", value: "application/json" });',
    'if (["POST", "PUT", "PATCH"].includes(pm.request.method)) {',
    "  const body = pm.request.body;",
    '  if (body && body.mode === "raw" && body.raw) {',
    '    pm.request.headers.upsert({ key: "Content-Type", value: "application/json" });',
    "  }",
    "}",
    'if (authMode === "supabase") {',
    '  const isAdmin = pm.variables.get("requestRole") === "super_admin";',
    '  const tokenKey = isAdmin ? "adminSupabaseToken" : "supabaseToken";',
    '  const token = pm.environment.get(tokenKey);',
    '  if (!token) {',
    '    throw new Error("Run Authentication > Login (" + (isAdmin ? "super_admin" : "tenant_admin") + ") first.");',
    "  }",
    '  pm.request.auth = { type: "bearer", bearer: [{ key: "token", value: token, type: "string" }] };',
    "} else {",
    '  pm.request.auth = { type: "noauth" };',
    '  const tenantId = pm.environment.get("tenantId");',
    '  if (!tenantId) throw new Error("Set tenantId in environment.");',
    '  const role = pm.variables.get("requestRole") || pm.environment.get("role") || "tenant_admin";',
    '  pm.request.headers.upsert({ key: "X-Tenant-ID", value: tenantId });',
    '  pm.request.headers.upsert({ key: "X-Role", value: role });',
    "}",
]

COL_TEST = [
    'pm.test("Response time under 30s", function () {',
    "  pm.expect(pm.response.responseTime).to.be.below(30000);",
    "});",
]


def supabase_login(
    name: str,
    email_var: str,
    password_var: str,
    token_var: str,
    desc: str = "",
) -> dict:
    tests = [
        'pm.test("Login OK", () => pm.response.to.have.status(200));',
        "const body = pm.response.json();",
        f'pm.environment.set("{token_var}", body.access_token);',
        'if (body.refresh_token) { pm.environment.set("supabaseRefreshToken", body.refresh_token); }',
        'if (body.user && body.user.id) { pm.environment.set("authSubject", body.user.id); }',
        f'console.log("Saved {token_var}, expires_in", body.expires_in);',
    ]
    return {
        "name": name,
        "description": desc,
        "event": [
            {
                "listen": "prerequest",
                "script": {"type": "text/javascript", "exec": ['pm.variables.set("skipPlatformAuth", "true");']},
            },
            {
                "listen": "test",
                "script": {
                    "type": "text/javascript",
                    "exec": ['pm.variables.unset("skipPlatformAuth");'] + tests,
                },
            },
        ],
        "request": {
            "auth": {"type": "noauth"},
            "method": "POST",
            "header": [
                {"key": "apikey", "value": "{{supabaseAnonKey}}", "type": "text"},
                {"key": "Content-Type", "value": "application/json", "type": "text"},
            ],
            "body": {
                "mode": "raw",
                "raw": json.dumps(
                    {"email": f"{{{{{email_var}}}}}", "password": f"{{{{{password_var}}}}}"},
                    indent=2,
                ),
            },
            "url": "{{supabaseUrl}}/auth/v1/token?grant_type=password",
        },
    }


def req(
    name: str,
    method: str,
    path: str,
    desc: str = "",
    body: dict | None = None,
    query: list[dict] | None = None,
    tests: list[str] | None = None,
    role: str | None = None,
) -> dict:
    url: dict = {
        "raw": "{{baseUrl}}" + path
        + ("?" + "&".join(f"{q['key']}={q['value']}" for q in query) if query else ""),
        "host": ["{{baseUrl}}"],
        "path": [p for p in path.strip("/").split("/") if p],
    }
    if query:
        url["query"] = query
    item: dict = {
        "name": name,
        "request": {
            "method": method,
            "header": [],
            "url": url,
            "description": desc,
        },
    }
    if body is not None:
        item["request"]["body"] = {"mode": "raw", "raw": json.dumps(body, indent=2)}
    events: list[dict] = []
    if role:
        events.append(
            {
                "listen": "prerequest",
                "script": {
                    "type": "text/javascript",
                    "exec": [f'pm.variables.set("requestRole", "{role}");'],
                },
            }
        )
        events.append(
            {
                "listen": "test",
                "script": {
                    "type": "text/javascript",
                    "exec": ['pm.variables.unset("requestRole");'] + (tests or []),
                },
            }
        )
    elif tests:
        events.append({"listen": "test", "script": {"type": "text/javascript", "exec": tests}})
    if events:
        item["event"] = events
    return item


def folder(name: str, desc: str, items: list[dict], folder_events: list[dict] | None = None) -> dict:
    f: dict = {"name": name, "description": desc, "item": items}
    if folder_events:
        f["event"] = folder_events
    return f


save_scan = [
    'pm.test("Status 200", () => pm.response.to.have.status(200));',
    "const scans = pm.response.json();",
    'pm.test("Has scans", () => pm.expect(scans.length).to.be.above(0));',
    'const completed = scans.find(s => ["completed", "completed_with_errors"].includes(s.status));',
    "const pick = completed || scans[0];",
    'pm.environment.set("scanId", pick.id);',
    'console.log("scanId=", pick.id, "status=", pick.status);',
]

save_integration = [
    'pm.test("Status 200", () => pm.response.to.have.status(200));',
    "const ints = pm.response.json();",
    'if (ints.length) pm.environment.set("integrationId", ints[0].id);',
]

save_finding = [
    'pm.test("Status 200", () => pm.response.to.have.status(200));',
    "const rows = pm.response.json();",
    'pm.test("Has findings", () => pm.expect(rows.length).to.be.above(0));',
    'pm.environment.set("findingId", rows[0].id);',
    'if (rows[0].policy_id) pm.environment.set("policyId", rows[0].policy_id);',
    'if (rows[0].resource_id) pm.environment.set("resourceId", rows[0].resource_id);',
]

save_asset = [
    'pm.test("Status 200", () => pm.response.to.have.status(200));',
    "const rows = pm.response.json();",
    'if (rows.length) pm.environment.set("resourceId", rows[0].resource_id);',
]

create_scan_test = [
    'pm.test("Status 201", () => pm.response.to.have.status(201));',
    "const body = pm.response.json();",
    'pm.environment.set("scanId", body.id);',
    'console.log("Started scan", body.id, body.status);',
]

save_me = [
    'pm.test("Status 200", () => pm.response.to.have.status(200));',
    "const me = pm.response.json();",
    'if (me.tenant_id) pm.environment.set("tenantId", me.tenant_id);',
    'console.log("role=", me.role, "tenant=", me.tenant_id);',
]

admin_folder_prerequest = [
    {
        "listen": "prerequest",
        "script": {
            "type": "text/javascript",
            "exec": [
                'pm.variables.set("requestRole", pm.environment.get("adminRole") || "super_admin");'
            ],
        },
    },
    {
        "listen": "test",
        "script": {"type": "text/javascript", "exec": ['pm.variables.unset("requestRole");']},
    },
]

collection = {
    "info": {
        "_postman_id": "p2v2-api-collection-001",
        "name": "Platform V2 API",
        "description": (
            "End-to-end Postman collection for Platform V2 (compliance-engine API on :8090).\n\n"
            "## Setup\n"
            "1. Import collection + `environments/Platform-V2-Local.postman_environment.json`.\n"
            "2. Select **Platform V2 — Local** environment.\n"
            "3. Start stack: `scripts/start_platform_v2.ps1`.\n"
            "4. Run **E2E Read Workflow** (existing scan) or **E2E Write Workflow** (new scan).\n\n"
            "## Auth (default: Supabase)\n"
            "1. Run **Authentication > Login (tenant_admin)** — saves `supabaseToken`\n"
            "2. For admin routes, run **Login (super_admin)** — saves `adminSupabaseToken`\n"
            "3. E2E workflows include login steps automatically\n\n"
            "Set `authMode=dev_headers` to use X-Tenant-ID + X-Role instead.\n\n"
            "OpenAPI: {{baseUrl}}/docs"
        ),
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    "event": [
        {"listen": "prerequest", "script": {"type": "text/javascript", "exec": AUTH_PREREQUEST}},
        {"listen": "test", "script": {"type": "text/javascript", "exec": COL_TEST}},
    ],
    "item": [
        folder(
            "Authentication",
            "Supabase email/password login. Tokens saved to environment (expire ~1h — re-run when 401).",
            [
                supabase_login(
                    "Login (tenant_admin)",
                    "userEmail",
                    "userPassword",
                    "supabaseToken",
                    "admin@drantiq.local — platform-ui tenant admin",
                ),
                supabase_login(
                    "Login (super_admin)",
                    "adminEmail",
                    "adminPassword",
                    "adminSupabaseToken",
                    "ops@drantiq.local — admin-ui super admin",
                ),
                supabase_login(
                    "Login (viewer)",
                    "viewerEmail",
                    "viewerPassword",
                    "viewerSupabaseToken",
                    "user@drantiq.local — read-only",
                ),
            ],
        ),
        folder(
            "E2E Read Workflow",
            "Supabase login then full read path. Picks latest completed scan.",
            [
                supabase_login(
                    "0. Login (tenant_admin)",
                    "userEmail",
                    "userPassword",
                    "supabaseToken",
                ),
                req("1. Health", "GET", "/health", tests=['pm.test("healthy", () => pm.response.to.have.status(200));']),
                req("2. Ready", "GET", "/ready", tests=['pm.test("ready", () => pm.response.to.have.status(200));']),
                req("3. GET /v1/me", "GET", "/v1/me", tests=save_me),
                req("4. List integrations", "GET", "/v1/integrations", tests=save_integration),
                req(
                    "5. List scans",
                    "GET",
                    "/v1/scans",
                    query=[{"key": "limit", "value": "20"}],
                    tests=save_scan,
                ),
                req("6. Get scan detail", "GET", "/v1/scans/{{scanId}}"),
                req("7. Scan timeline", "GET", "/v1/scans/{{scanId}}/timeline"),
                req(
                    "8. List assets",
                    "GET",
                    "/v1/assets",
                    query=[{"key": "scan_id", "value": "{{scanId}}"}],
                    tests=save_asset,
                ),
                req(
                    "9. Search assets",
                    "GET",
                    "/v1/assets/search",
                    query=[
                        {"key": "scan_id", "value": "{{scanId}}"},
                        {"key": "q", "value": "aws"},
                    ],
                ),
                req(
                    "10. List findings (fail)",
                    "GET",
                    "/v1/findings",
                    query=[
                        {"key": "scan_id", "value": "{{scanId}}"},
                        {"key": "result", "value": "fail"},
                        {"key": "limit", "value": "50"},
                    ],
                    tests=save_finding,
                ),
                req(
                    "11. Get finding",
                    "GET",
                    "/v1/findings/{{findingId}}",
                    query=[{"key": "scan_id", "value": "{{scanId}}"}],
                ),
                req(
                    "11b. Risk summary",
                    "GET",
                    "/v1/scans/{{scanId}}/risk-summary",
                ),
                req(
                    "11c. Fix priorities",
                    "GET",
                    "/v1/scans/{{scanId}}/fix-priorities",
                ),
                req(
                    "12. Scan compliance summary",
                    "GET",
                    "/v1/scans/{{scanId}}/compliance",
                    query=[{"key": "framework_id", "value": "{{frameworkId}}"}],
                ),
                req(
                    "13. Compliance framework detail",
                    "GET",
                    "/v1/compliance/frameworks/{{frameworkId}}/scans/{{scanId}}",
                ),
                req("14. Inventory completeness", "GET", "/v1/scans/{{scanId}}/inventory-completeness"),
                req("15. Policy coverage", "GET", "/v1/scans/{{scanId}}/policy-coverage"),
                supabase_login(
                    "16. Login (super_admin)",
                    "adminEmail",
                    "adminPassword",
                    "adminSupabaseToken",
                ),
                req(
                    "17. Admin overview",
                    "GET",
                    "/v1/admin/overview",
                    role="super_admin",
                    tests=['pm.test("200", () => pm.response.to.have.status(200));'],
                ),
            ],
        ),
        folder(
            "E2E Write Workflow",
            "Login, trigger scan, poll until complete (~60s real AWS).",
            [
                supabase_login(
                    "0. Login (tenant_admin)",
                    "userEmail",
                    "userPassword",
                    "supabaseToken",
                ),
                req("1. Health", "GET", "/health"),
                req("2. List integrations", "GET", "/v1/integrations", tests=save_integration),
                req(
                    "3. Create scan",
                    "POST",
                    "/v1/scans",
                    body={"integration_id": "{{integrationId}}"},
                    tests=create_scan_test,
                ),
                req(
                    "4. Poll scan status",
                    "GET",
                    "/v1/scans/{{scanId}}",
                    desc="Re-run until status is completed or failed.",
                    tests=[
                        "const s = pm.response.json().status;",
                        'console.log("scan status:", s);',
                    ],
                ),
                req(
                    "5. List findings after scan",
                    "GET",
                    "/v1/findings",
                    query=[
                        {"key": "scan_id", "value": "{{scanId}}"},
                        {"key": "result", "value": "fail"},
                    ],
                ),
            ],
        ),
        folder(
            "Health",
            "",
            [
                req("GET /health", "GET", "/health"),
                req("GET /ready", "GET", "/ready"),
            ],
        ),
        folder("Identity", "", [req("GET /v1/me", "GET", "/v1/me")]),
        folder(
            "Integrations",
            "",
            [
                req("List integrations", "GET", "/v1/integrations", tests=save_integration),
                req(
                    "Register AWS integration",
                    "POST",
                    "/v1/integrations/aws",
                    body={
                        "account_id": "{{awsAccountId}}",
                        "role_arn": "{{awsRoleArn}}",
                        "external_id": "{{awsExternalId}}",
                        "regions": ["us-east-1"],
                    },
                    tests=['pm.test("201 or 409", () => pm.expect([201, 409]).to.include(pm.response.code));'],
                ),
            ],
        ),
        folder(
            "Scans",
            "",
            [
                req(
                    "List scans",
                    "GET",
                    "/v1/scans",
                    query=[{"key": "limit", "value": "50"}],
                    tests=save_scan,
                ),
                req(
                    "Create scan",
                    "POST",
                    "/v1/scans",
                    body={"integration_id": "{{integrationId}}"},
                    tests=create_scan_test,
                ),
                req("Get scan", "GET", "/v1/scans/{{scanId}}"),
                req("Scan timeline", "GET", "/v1/scans/{{scanId}}/timeline"),
                req(
                    "Scan compliance",
                    "GET",
                    "/v1/scans/{{scanId}}/compliance",
                    query=[{"key": "framework_id", "value": "{{frameworkId}}"}],
                ),
                req("Inventory completeness", "GET", "/v1/scans/{{scanId}}/inventory-completeness"),
                req("Policy coverage", "GET", "/v1/scans/{{scanId}}/policy-coverage"),
                req(
                    "Risk summary",
                    "GET",
                    "/v1/scans/{{scanId}}/risk-summary",
                    desc="Customer decision API — severity counts and top risks.",
                ),
                req(
                    "Fix priorities",
                    "GET",
                    "/v1/scans/{{scanId}}/fix-priorities",
                    desc="What to fix first — sorted by severity and exposure.",
                ),
            ],
        ),
        folder(
            "Assets",
            "",
            [
                req(
                    "List assets",
                    "GET",
                    "/v1/assets",
                    query=[
                        {"key": "scan_id", "value": "{{scanId}}"},
                        {"key": "limit", "value": "100"},
                    ],
                    tests=save_asset,
                ),
                req(
                    "Search assets",
                    "GET",
                    "/v1/assets/search",
                    query=[
                        {"key": "scan_id", "value": "{{scanId}}"},
                        {"key": "q", "value": "admin"},
                    ],
                ),
                req(
                    "Get asset",
                    "GET",
                    "/v1/assets/{{resourceId}}",
                    query=[{"key": "scan_id", "value": "{{scanId}}"}],
                ),
                req(
                    "Asset relationships",
                    "GET",
                    "/v1/assets/{{resourceId}}/relationships",
                    query=[{"key": "scan_id", "value": "{{scanId}}"}],
                ),
                req(
                    "Resource risk",
                    "GET",
                    "/v1/assets/{{resourceId}}/risk",
                    query=[{"key": "scan_id", "value": "{{scanId}}"}],
                    desc="All findings affecting this resource.",
                ),
            ],
        ),
        folder(
            "Findings",
            "",
            [
                req(
                    "List findings",
                    "GET",
                    "/v1/findings",
                    query=[
                        {"key": "scan_id", "value": "{{scanId}}"},
                        {"key": "limit", "value": "100"},
                    ],
                    tests=save_finding,
                ),
                req(
                    "List failures only",
                    "GET",
                    "/v1/findings",
                    query=[
                        {"key": "scan_id", "value": "{{scanId}}"},
                        {"key": "result", "value": "fail"},
                    ],
                ),
                req(
                    "Get finding",
                    "GET",
                    "/v1/findings/{{findingId}}",
                    query=[{"key": "scan_id", "value": "{{scanId}}"}],
                ),
                req(
                    "Finding affected resources",
                    "GET",
                    "/v1/findings/{{findingId}}/affected-resources",
                    query=[{"key": "scan_id", "value": "{{scanId}}"}],
                ),
            ],
        ),
        folder(
            "Policies",
            "",
            [
                req(
                    "Policy affected resources",
                    "GET",
                    "/v1/policies/{{policyId}}/affected-resources",
                    query=[{"key": "scan_id", "value": "{{scanId}}"}],
                ),
            ],
        ),
        folder(
            "Compliance",
            "",
            [
                req("List frameworks", "GET", "/v1/compliance/frameworks"),
                req(
                    "Scan compliance matrix",
                    "GET",
                    "/v1/compliance/frameworks/{{frameworkId}}/scans/{{scanId}}",
                ),
            ],
        ),
        folder(
            "Admin (super_admin)",
            "Requires super_admin role.",
            [
                req("Overview", "GET", "/v1/admin/overview", role="super_admin"),
                req("List tenants", "GET", "/v1/admin/tenants", role="super_admin"),
                req("Get tenant", "GET", "/v1/admin/tenants/{{tenantId}}", role="super_admin"),
                req(
                    "Create tenant",
                    "POST",
                    "/v1/admin/tenants",
                    role="super_admin",
                    body={"name": "Postman Test Tenant", "slug": "postman-test-tenant"},
                    tests=['pm.test("201 or 409", () => pm.expect([201, 409]).to.include(pm.response.code));'],
                ),
                req(
                    "Update tenant",
                    "PATCH",
                    "/v1/admin/tenants/{{tenantId}}",
                    role="super_admin",
                    body={"status": "active"},
                ),
                req(
                    "List memberships",
                    "GET",
                    "/v1/admin/tenants/{{tenantId}}/memberships",
                    role="super_admin",
                ),
                req(
                    "Create membership",
                    "POST",
                    "/v1/admin/tenants/{{tenantId}}/memberships",
                    role="super_admin",
                    body={
                        "auth_issuer": "{{authIssuer}}",
                        "auth_subject": "00000000-0000-0000-0000-000000000001",
                        "email": "postman@example.com",
                        "role": "viewer",
                    },
                    tests=['pm.test("201 or 409", () => pm.expect([201, 409]).to.include(pm.response.code));'],
                ),
                req(
                    "List tenant integrations",
                    "GET",
                    "/v1/admin/tenants/{{tenantId}}/integrations",
                    role="super_admin",
                    tests=save_integration,
                ),
                req(
                    "List tenant scans",
                    "GET",
                    "/v1/admin/tenants/{{tenantId}}/scans",
                    role="super_admin",
                    query=[{"key": "limit", "value": "20"}],
                    tests=save_scan,
                ),
                req(
                    "Admin list all scans",
                    "GET",
                    "/v1/admin/scans",
                    role="super_admin",
                    query=[{"key": "limit", "value": "50"}],
                ),
                req(
                    "Admin list failed scans",
                    "GET",
                    "/v1/admin/scans",
                    role="super_admin",
                    query=[
                        {"key": "status", "value": "failed"},
                        {"key": "limit", "value": "50"},
                    ],
                ),
                req(
                    "Admin create scan",
                    "POST",
                    "/v1/admin/tenants/{{tenantId}}/scans",
                    role="super_admin",
                    body={"integration_id": "{{integrationId}}"},
                    tests=create_scan_test,
                ),
            ],
            folder_events=admin_folder_prerequest,
        ),
    ],
}

out = ROOT / "postman" / "Platform-V2-API.postman_collection.json"
out.write_text(json.dumps(collection, indent=2), encoding="utf-8")
count = sum(len(f["item"]) for f in collection["item"])
print(f"Wrote {out} ({count} requests)")
