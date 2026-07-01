# Drantiq — Azure subscription onboarding

**Audience:** Customer security / cloud / platform engineers  
**Goal:** Connect your Azure subscription to Drantiq with **read-only** service principal access  
**Time:** ~15–20 minutes  
**App:** [https://app.drantiq.ai](https://app.drantiq.ai)

**Public docs:** [https://drantiq.ai/docs/azure-onboarding](https://drantiq.ai/docs/azure-onboarding)

---

## What you are setting up

Drantiq assesses your Azure environment for security misconfigurations. We **never modify** your resources.

Access model:

```
Drantiq platform
        │
        │  Service Principal (client id + secret)
        ▼
Your Entra ID tenant
        │
        └── Reader on target subscription
```

You create **one app registration / service principal** in **your** tenant. Drantiq uses it to collect inventory and evaluate security controls.

| Item | Who owns it |
|------|-------------|
| App registration & service principal | **Your** Entra ID tenant |
| Client secret | **Your** tenant (rotate per your policy) |
| Role assignment (Reader) | **Your** subscription |
| Scan results | Your Drantiq workspace |

---

## Prerequisites

- Azure subscription administrator or ability to create app registrations and assign roles
- **Subscription ID** (GUID)
- **Entra tenant ID** (GUID)
- Drantiq workspace with **tenant admin** access
- Outbound HTTPS from Drantiq to `login.microsoftonline.com` and `management.azure.com`

---

## Values you will need

| Field | Example | Where to find it |
|-------|---------|------------------|
| **Subscription ID** | `11111111-2222-3333-4444-555555555555` | Azure Portal → Subscriptions |
| **Tenant ID** | `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee` | Entra ID → Overview |
| **Client ID** | `ffffffff-1111-2222-3333-444444444444` | App registration → Overview |
| **Client secret** | _(you create)_ | App registration → Certificates & secrets |
| **Locations** | `eastus`, `westeurope` | Regions to include in collection |

---

## Step 1 — Register an application

1. Open **Microsoft Entra ID** → **App registrations** → **New registration**
2. Name: `DrantiqReadOnly` (or your standard)
3. Supported account types: **Single tenant**
4. Register and copy the **Application (client) ID** and **Directory (tenant) ID**

---

## Step 2 — Create a client secret

1. Open the app → **Certificates & secrets** → **New client secret**
2. Copy the **Value** immediately (shown once)
3. Store in your password manager — you will paste it into Drantiq once

---

## Step 3 — Assign Reader on the subscription

1. Open **Subscriptions** → select the target subscription
2. **Access control (IAM)** → **Add role assignment**
3. Role: **Reader**
4. Assign access to: **User, group, or service principal**
5. Select the `DrantiqReadOnly` service principal
6. Save

> For Key Vault and Defender checks in later releases, Drantiq may document additional narrow read roles. MVP collection uses **Reader** on the subscription.

---

## Step 4 — Connect in Drantiq

1. Sign in to Drantiq → **Integrations** → **Add Azure**
2. Enter subscription ID, tenant ID, client ID, client secret, and locations
3. Optional: **Verify connection** (calls `POST /v1/integrations/{id}/verify`)
4. Run your first **security assessment** from **Scans**

### API (tenant admin token required)

```http
POST /v1/integrations/azure
Content-Type: application/json

{
  "subscription_id": "11111111-2222-3333-4444-555555555555",
  "azure_tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "azure_client_id": "ffffffff-1111-2222-3333-444444444444",
  "client_secret": "your-client-secret",
  "locations": ["eastus", "westeurope"]
}
```

The client secret is **encrypted at rest** and never returned in API responses.

---

## Rotating the client secret

1. Create a new secret in Entra ID
2. Re-register the integration in Drantiq with the new secret (or use a future rotate API)
3. Revoke the old secret in Azure

---

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| Verify returns `invalid client secret` | Wrong secret or expired secret |
| Verify returns subscription lookup failed (403) | Reader role not assigned on subscription |
| Scan stays queued | Collector worker not listening on `platform:collect.azure` (ops) |

---

## Security notes

- Treat the client secret like a password — minimum length 8 characters; prefer long random values
- Use a dedicated service principal per Drantiq workspace / environment
- Drantiq does not require contributor or owner roles for assessment
