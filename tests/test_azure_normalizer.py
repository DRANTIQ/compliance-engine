"""Unit tests for Azure bronze normalization."""

from __future__ import annotations

from uuid import UUID

from platform_backend.assets.ingest.normalizer import normalize_bronze

TENANT = UUID("54abf846-1d4c-49f9-9115-2f4f882a2cd2")
SCAN = UUID("11111111-1111-1111-1111-111111111111")
INTEGRATION = UUID("22222222-2222-2222-2222-222222222222")
SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"


def test_normalize_azure_storage_account() -> None:
    storage_id = (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/mock-rg/"
        "providers/Microsoft.Storage/storageAccounts/mockstore"
    )
    bronze = {
        "provider_type": "azure_storage_account",
        "resource_type": "storage.bucket",
        "collected_at": "2026-06-30T00:00:00+00:00",
        "items": [
            {
                "id": storage_id,
                "name": "mockstore",
                "location": "eastus",
                "subscription_id": SUBSCRIPTION,
                "enable_https_traffic_only": True,
                "minimum_tls_version": "TLS1_2",
                "allow_blob_public_access": False,
                "supports_https_traffic_only": True,
            }
        ],
    }
    resources, _ = normalize_bronze(
        bronze,
        tenant_id=TENANT,
        scan_id=SCAN,
        integration_id=INTEGRATION,
        account_id=SUBSCRIPTION,
    )
    assert len(resources) == 1
    row = resources[0]
    assert row["provider"] == "azure"
    assert row["provider_type"] == "azure_storage_account"
    assert row["resource_type"] == "storage.bucket"
    assert row["resource_id"].endswith("/storageAccounts/mockstore")
    assert row["properties"]["enable_https_traffic_only"] is True
    assert row["properties"]["min_tls_1_2"] is True
    assert row["region"] == "eastus"


def test_normalize_azure_network_security_group() -> None:
    nsg_id = (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/mock-rg/"
        "providers/Microsoft.Network/networkSecurityGroups/mock-nsg"
    )
    bronze = {
        "provider_type": "azure_network_security_group",
        "resource_type": "network.security_group",
        "collected_at": "2026-06-30T00:00:00+00:00",
        "items": [
            {
                "id": nsg_id,
                "name": "mock-nsg",
                "location": "eastus",
                "resource_group": "mock-rg",
                "AllowsSshFromInternet": True,
                "AllowsRdpFromInternet": False,
                "AllowsUnrestrictedAdminPorts": True,
            }
        ],
    }
    resources, _ = normalize_bronze(
        bronze,
        tenant_id=TENANT,
        scan_id=SCAN,
        integration_id=INTEGRATION,
        account_id=SUBSCRIPTION,
    )
    assert resources[0]["properties"]["allows_ssh_from_internet_ipv4"] is True
    assert resources[0]["properties"]["allows_unrestricted_admin_ports_ipv4"] is True


def test_normalize_azure_vm_relationships() -> None:
    vnet_id = (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/mock-rg/"
        "providers/Microsoft.Network/virtualNetworks/mock-vnet"
    )
    nsg_id = (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/mock-rg/"
        "providers/Microsoft.Network/networkSecurityGroups/mock-nsg"
    )
    vm_id = (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/mock-rg/"
        "providers/Microsoft.Compute/virtualMachines/mock-vm"
    )
    bronze = {
        "provider_type": "azure_virtual_machine",
        "resource_type": "compute.instance",
        "collected_at": "2026-06-30T00:00:00+00:00",
        "items": [
            {
                "id": vm_id,
                "name": "mock-vm",
                "location": "eastus",
                "resource_group": "mock-rg",
                "has_public_ip": False,
                "os_disk_encrypted": True,
                "vnet_id": vnet_id,
                "network_security_group_ids": [nsg_id],
            }
        ],
    }
    resources, relationships = normalize_bronze(
        bronze,
        tenant_id=TENANT,
        scan_id=SCAN,
        integration_id=INTEGRATION,
        account_id=SUBSCRIPTION,
    )
    assert resources[0]["provider"] == "azure"
    assert resources[0]["properties"]["has_public_ip"] is False
    rel_types = {(r["from_resource_id"], r["to_resource_id"], r["relationship_type"]) for r in relationships}
    assert (vm_id, vnet_id, "member_of") in rel_types
    assert (vm_id, nsg_id, "protected_by") in rel_types


def test_normalize_azure_subscription_identity() -> None:
    bronze = {
        "provider_type": "azure_subscription",
        "resource_type": "identity.account",
        "collected_at": "2026-06-30T00:00:00+00:00",
        "items": [
            {
                "subscription_id": SUBSCRIPTION,
                "owner_role_assignment_count": 4,
                "too_many_owners": True,
            }
        ],
    }
    resources, _ = normalize_bronze(
        bronze,
        tenant_id=TENANT,
        scan_id=SCAN,
        integration_id=INTEGRATION,
        account_id=SUBSCRIPTION,
    )
    assert resources[0]["resource_id"] == f"/subscriptions/{SUBSCRIPTION}"
    assert resources[0]["properties"]["too_many_owners"] is True


def test_normalize_azure_defender_and_keyvault() -> None:
    kv_id = (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/mock-rg/"
        "providers/Microsoft.KeyVault/vaults/mock-kv"
    )
    kv_bronze = {
        "provider_type": "azure_key_vault",
        "resource_type": "security.key",
        "collected_at": "2026-06-30T00:00:00+00:00",
        "items": [
            {
                "id": kv_id,
                "name": "mock-kv",
                "location": "eastus",
                "resource_group": "mock-rg",
                "enable_soft_delete": True,
                "enable_purge_protection": False,
            }
        ],
    }
    defender_bronze = {
        "provider_type": "azure_defender",
        "resource_type": "governance.hub",
        "collected_at": "2026-06-30T00:00:00+00:00",
        "items": [
            {
                "subscription_id": SUBSCRIPTION,
                "defender_standard_enabled": True,
                "standard_plan_count": 2,
            }
        ],
    }
    kv_rows, _ = normalize_bronze(
        kv_bronze,
        tenant_id=TENANT,
        scan_id=SCAN,
        integration_id=INTEGRATION,
        account_id=SUBSCRIPTION,
    )
    defender_rows, _ = normalize_bronze(
        defender_bronze,
        tenant_id=TENANT,
        scan_id=SCAN,
        integration_id=INTEGRATION,
        account_id=SUBSCRIPTION,
    )
    assert kv_rows[0]["properties"]["enable_soft_delete"] is True
    assert defender_rows[0]["properties"]["defender_standard_enabled"] is True


def test_normalize_azure_database_servers() -> None:
    sql_id = (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/mock-rg/providers/Microsoft.Sql/servers/mock-sql"
    )
    bronze = {
        "provider_type": "azure_sql_server",
        "resource_type": "database.instance",
        "collected_at": "2026-06-30T00:00:00+00:00",
        "items": [
            {
                "id": sql_id,
                "name": "mock-sql",
                "location": "eastus",
                "resource_group": "mock-rg",
                "public_network_access": "Disabled",
                "minimal_tls_version": "1.2",
                "kind": "sql_server",
            }
        ],
    }
    resources, _ = normalize_bronze(
        bronze,
        tenant_id=TENANT,
        scan_id=SCAN,
        integration_id=INTEGRATION,
        account_id=SUBSCRIPTION,
    )
    props = resources[0]["properties"]
    assert props["publicly_accessible"] is False
    assert props["tls_enforced"] is True
