from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from platform_backend.config.settings import Settings
from platform_backend.platform.models.collection_job import (
    AwsCollectionJob,
    AzureCollectionJob,
    parse_collection_job,
)
from tests.migration_paths import migration_sql_path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "contracts" / "collection.job.schema.json"


def test_migration_027_azure_integrations_exists() -> None:
    migration = migration_sql_path("027_azure_integrations.sql")
    assert migration.is_file()
    text = migration.read_text(encoding="utf-8")
    assert "integrations_provider_check" in text
    assert "azure_tenant_id" in text
    assert "027_azure_integrations" in text


def test_collect_queue_for_provider() -> None:
    settings = Settings(
        DATABASE_URL="postgresql://u:p@localhost:5432/db?sslmode=require",
        COLLECT_QUEUE_KEY="platform:collect.aws",
        COLLECT_AZURE_QUEUE_KEY="platform:collect.azure",
    )
    assert settings.collect_queue_for_provider("aws") == "platform:collect.aws"
    assert settings.collect_queue_for_provider("azure") == "platform:collect.azure"


def test_parse_azure_collection_job() -> None:
    job = parse_collection_job(
        {
            "provider": "azure",
            "job_id": str(uuid4()),
            "scan_id": str(uuid4()),
            "tenant_id": str(uuid4()),
            "integration_id": str(uuid4()),
            "collection_run_id": str(uuid4()),
            "account_id": "11111111-2222-3333-4444-555555555555",
            "azure_tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "azure_client_id": "ffffffff-1111-2222-3333-444444444444",
            "azure_client_secret": "secret",
            "regions": ["eastus"],
            "s3_bucket": "bucket",
            "s3_prefix": "platform-v2/tenants/t/scans/s/azure/sub",
            "plugins": ["azure.storage"],
        }
    )
    assert isinstance(job, AzureCollectionJob)


def test_parse_aws_collection_job_legacy_payload() -> None:
    job = parse_collection_job(
        {
            "job_id": str(uuid4()),
            "scan_id": str(uuid4()),
            "tenant_id": str(uuid4()),
            "integration_id": str(uuid4()),
            "collection_run_id": str(uuid4()),
            "account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/X",
            "external_id": "ext",
            "regions": ["us-east-1"],
            "s3_bucket": "bucket",
            "s3_prefix": "prefix",
            "plugins": ["aws.s3"],
        }
    )
    assert isinstance(job, AwsCollectionJob)


@pytest.mark.skipif(not SCHEMA_PATH.is_file(), reason="collection.job.schema.json missing")
def test_collection_job_schema_documents_azure() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert "AzureCollectionJob" in schema.get("$defs", {})
    assert "AwsCollectionJob" in schema.get("$defs", {})
