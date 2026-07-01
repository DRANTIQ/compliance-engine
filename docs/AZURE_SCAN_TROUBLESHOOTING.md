# Azure scan troubleshooting (internal)

**Audience:** Drantiq support, engineering, customer success  
**Customer-facing summary:** [AZURE_SUBSCRIPTION_ONBOARDING.md](./AZURE_SUBSCRIPTION_ONBOARDING.md) · [Public onboarding](https://drantiq.ai/docs/azure-onboarding)

Use this when a client reports an Azure scan showing **Completed with errors**, partial collection, or missing Defender controls.

---

## Microsoft.Security not registered (Defender for Cloud)

### What the client sees

- Scan status: **Completed with errors** (not failed)
- Resource count may be **> 0** (other collectors succeeded)
- Compliance score may still appear; **Defender-related controls** may show **not assessed**
- In **admin-ui**: scan timeline / manifest errors include something like:

```json
{
  "type": "ResourceNotFoundError",
  "plugin": "azure.defender",
  "error": "Please register to Microsoft.Security in order to view your security status"
}
```

### Root cause

The Azure subscription has **not registered the `Microsoft.Security` resource provider**. Drantiq’s Defender collector calls the Azure Security Center pricing API; Azure returns this error when Defender for Cloud was never enabled on that subscription.

This is a **customer Azure configuration** issue, not a Drantiq platform outage or broken integration.

### Is the scan usable?

| Item | Expected behavior |
|------|-------------------|
| Scan overall | **Yes** — collection finishes; ingest and policy evaluation run |
| Status `completed_with_errors` | **Correct** — one optional plugin reported an error |
| Storage, network, IAM-style checks | Should evaluate if those resources were collected |
| **AZURE_DEF_001** (Defender Standard) | Usually **not assessed** — no pricing data collected |

Do **not** treat this the same as a **failed** scan (0 resources, hard collector crash).

### What to tell the client

> Your Azure scan completed successfully for most resource types. Microsoft Defender for Cloud is not enabled on this subscription, so we could not collect Defender pricing data. That is why the scan shows “completed with errors” and Defender controls may be marked not assessed.
>
> This does not mean Drantiq lost access to your subscription. To include Defender checks, register Microsoft Defender for Cloud on the subscription (see steps below), then run a new scan.

### Fix (customer action)

**Option A — Azure Portal**

1. Open **Microsoft Defender for Cloud** → **Get started** / enable on the subscription, **or**
2. **Subscriptions** → select subscription → **Resource providers** → register **`Microsoft.Security`**

**Option B — Azure CLI**

```bash
az account set --subscription "<subscription-id>"
az provider register --namespace Microsoft.Security
az provider show --namespace Microsoft.Security --query registrationState
```

Wait until `registrationState` is `Registered` (can take several minutes), then **re-run the scan**.

### Optional hardening (future onboarding)

Recommend registering `Microsoft.Security` during onboarding if the client wants full Defender coverage. **Reader** on the subscription is still sufficient for Drantiq; no Contributor role is required to register the provider (subscription admin may be needed).

---

## Quick diagnosis checklist

| Symptom | Check | Likely cause |
|---------|-------|----------------|
| `completed_with_errors`, resources > 0, defender error in manifest | Admin scan timeline / S3 manifest `errors[]` | Microsoft.Security not registered (this doc) |
| Scan **failed**, 0 resources | Collector logs on EC2 | Collector bug or auth failure — engineering |
| Verify connection fails | `POST /integrations/{id}/verify` | Wrong secret, missing Reader role |
| Integration status **invalid** | Scan failed with auth error | Expired/wrong secret — `POST .../rotate-secret` or app **Fix connection** |
| Scan stuck **queued** | Redis `platform:collect.azure` depth | Collector worker not running |
| Compliance 404 right after scan | Policy worker / ingest timing | Deploy ingest fix; retry compliance tab |

---

## Where to look in Drantiq

| Tool | Path / API |
|------|------------|
| **admin-ui** | Tenant → scan detail → timeline / errors |
| **API** | `GET /v1/admin/tenants/{tenant_id}/scans/{scan_id}` |
| **Manifest** | S3 URI on `collection.completed` event → `errors`, `resource_count`, `status` |

---

## Related

- Collector plugin: `platform-collectors` → `plugins/azure/defender_collect.py`
- Policy: `AZURE_DEF_001` in compliance-engine policy catalog
- Customer onboarding: [AZURE_SUBSCRIPTION_ONBOARDING.md](./AZURE_SUBSCRIPTION_ONBOARDING.md)
