"""Collection job payloads pushed to Redis collect queues."""

from __future__ import annotations

import json
from typing import Any, Literal, Union
from uuid import UUID

from pydantic import BaseModel, Field

AWS_ACCOUNT_ID_PATTERN = r"^[0-9]{12}$"
AZURE_GUID_PATTERN = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class CollectionJobBase(BaseModel):
    job_id: UUID
    scan_id: UUID
    tenant_id: UUID
    integration_id: UUID
    collection_run_id: UUID
    account_id: str
    regions: list[str] = Field(min_length=1)
    s3_bucket: str
    s3_prefix: str
    trace_id: UUID | None = None


class AwsCollectionJob(CollectionJobBase):
    provider: Literal["aws"] = "aws"
    account_id: str = Field(pattern=AWS_ACCOUNT_ID_PATTERN)
    role_arn: str
    external_id: str
    plugins: list[str] = Field(default_factory=list)


class AzureCollectionJob(CollectionJobBase):
    provider: Literal["azure"] = "azure"
    account_id: str = Field(description="Azure subscription id", pattern=AZURE_GUID_PATTERN)
    azure_tenant_id: str = Field(pattern=AZURE_GUID_PATTERN)
    azure_client_id: str = Field(pattern=AZURE_GUID_PATTERN)
    azure_client_secret: str = Field(min_length=1)
    plugins: list[str] = Field(default_factory=list)


CollectionJob = Union[AwsCollectionJob, AzureCollectionJob]


def parse_collection_job(raw: str | dict[str, Any]) -> AwsCollectionJob | AzureCollectionJob:
    data = json.loads(raw) if isinstance(raw, str) else raw
    provider = data.get("provider", "aws")
    if provider == "azure":
        return AzureCollectionJob.model_validate(data)
    return AwsCollectionJob.model_validate(data)
