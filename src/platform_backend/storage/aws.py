from __future__ import annotations

import boto3

from platform_backend.config.settings import Settings, get_settings


def s3_client(settings: Settings | None = None):
    cfg = settings or get_settings()
    kwargs: dict = {"region_name": cfg.s3_region or cfg.aws_default_region}
    if cfg.aws_access_key_id and cfg.aws_secret_access_key:
        kwargs["aws_access_key_id"] = cfg.aws_access_key_id
        kwargs["aws_secret_access_key"] = cfg.aws_secret_access_key
        if cfg.aws_session_token:
            kwargs["aws_session_token"] = cfg.aws_session_token
    return boto3.client("s3", **kwargs)
