from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field(alias="DATABASE_URL")
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    s3_bucket: str = Field(default="steampipe-data-storage", alias="S3_BUCKET")
    s3_region: str = Field(default="us-east-1", alias="S3_REGION")
    s3_prefix: str = Field(default="platform-v2", alias="S3_PREFIX")

    collect_queue_key: str = Field(default="platform:collect.aws", alias="COLLECT_QUEUE_KEY")
    platform_events_key: str = Field(default="platform:events", alias="PLATFORM_EVENTS_KEY")
    policy_queue_key: str = Field(default="platform:policy.evaluate", alias="POLICY_QUEUE_KEY")
    policy_catalog_path: str = Field(
        default="policy/catalog/policies", alias="POLICY_CATALOG_PATH"
    )
    external_id_encryption_key: str = Field(default="", alias="EXTERNAL_ID_ENCRYPTION_KEY")

    use_local_storage: bool = Field(default=False, alias="USE_LOCAL_STORAGE")
    local_storage_path: str = Field(default="./local/snapshots", alias="LOCAL_STORAGE_PATH")

    aws_access_key_id: str = Field(default="", alias="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: str = Field(default="", alias="AWS_SECRET_ACCESS_KEY")
    aws_session_token: str = Field(default="", alias="AWS_SESSION_TOKEN")
    aws_default_region: str = Field(default="us-east-1", alias="AWS_DEFAULT_REGION")

    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8090, alias="API_PORT")
    cors_origins: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174",
        alias="CORS_ORIGINS",
    )

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")
    dev_tenant_header_auth: bool = Field(default=True, alias="DEV_TENANT_HEADER_AUTH")

    rate_limit_per_minute: int = Field(default=120, alias="RATE_LIMIT_PER_MINUTE")
    api_docs_enabled: bool = Field(default=True, alias="API_DOCS_ENABLED")
    sentry_dsn: str = Field(default="", alias="SENTRY_DSN")

    oidc_enabled: bool = Field(default=False, alias="OIDC_ENABLED")
    oidc_issuer: str = Field(default="", alias="OIDC_ISSUER")
    oidc_audience: str = Field(default="authenticated", alias="OIDC_AUDIENCE")
    oidc_jwks_uri: str = Field(default="", alias="OIDC_JWKS_URI")
    oidc_jwt_secret: str = Field(default="", alias="OIDC_JWT_SECRET")
    supabase_url: str = Field(default="", alias="SUPABASE_URL")

    @property
    def jwt_auth_enabled(self) -> bool:
        return self.oidc_enabled or bool(self.oidc_jwt_secret)

    @property
    def effective_oidc_issuer(self) -> str:
        if self.oidc_issuer:
            return self.oidc_issuer.rstrip("/")
        if self.supabase_url:
            return f"{self.supabase_url.rstrip('/')}/auth/v1"
        return ""

    @field_validator("database_url")
    @classmethod
    def require_sslmode(cls, value: str) -> str:
        if "sslmode=" not in value and "ssl=" not in value:
            raise ValueError("DATABASE_URL must include sslmode=require for production safety")
        return value

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
