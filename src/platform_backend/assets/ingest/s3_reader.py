from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import url2pathname

import boto3
from botocore.exceptions import ClientError

from platform_backend.config.settings import Settings, get_settings


def _uri_to_path(uri: str) -> Path:
    parsed = urlparse(uri)
    return Path(url2pathname(parsed.path))


class SnapshotReader:
    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._s3 = None
        if not self._settings.use_local_storage:
            self._s3 = boto3.client("s3", region_name=self._settings.s3_region)

    def read_json(self, uri: str) -> dict[str, Any]:
        if uri.startswith("file:"):
            path = _uri_to_path(uri)
            if not path.is_absolute() and self._settings.use_local_storage:
                path = Path(self._settings.local_storage_path) / path
            return json.loads(path.read_text(encoding="utf-8"))
        if uri.startswith("s3://"):
            _, rest = uri.split("s3://", 1)
            bucket, key = rest.split("/", 1)
            try:
                obj = self._s3.get_object(Bucket=bucket, Key=key)  # type: ignore[union-attr]
            except ClientError as exc:
                raise FileNotFoundError(uri) from exc
            return json.loads(obj["Body"].read())
        raise ValueError(f"unsupported uri: {uri}")

    def read_manifest_and_bronze(self, manifest_uri: str, manifest: dict[str, Any]) -> list[dict[str, Any]]:
        if manifest_uri.startswith("file:"):
            base_dir = _uri_to_path(manifest_uri).parent
            return [
                json.loads((base_dir / entry["path"]).read_text(encoding="utf-8"))
                for entry in manifest.get("files", [])
            ]

        base_uri = manifest_uri.rsplit("/", 1)[0]
        return [self.read_json(f"{base_uri}/{entry['path']}") for entry in manifest.get("files", [])]
