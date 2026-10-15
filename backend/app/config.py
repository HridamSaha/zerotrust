"""Application configuration loaded from environment variables."""

from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings. Secrets must come from environment / .env — never hardcode production values."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "ZeroTrust Access Control"
    app_env: str = "development"
    debug: bool = True
    api_prefix: str = "/api"

    secret_key: str = Field(default="change-me-to-a-long-random-string")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    cors_origins: str = "http://localhost:5173"

    database_url: str = (
        "postgresql+psycopg://zerotrust:zerotrust_dev_password@localhost:5433/zerotrust"
    )

    risk_low_max: int = 24
    risk_medium_max: int = 49
    risk_high_max: int = 74

    auth_rate_limit_requests: int = 10
    auth_rate_limit_window_seconds: int = 60

    demo_admin_email: str = "admin@zerotrust.demo"
    demo_admin_password: str = "AdminDemo!234"
    demo_user_email: str = "user@zerotrust.demo"
    demo_user_password: str = "UserDemo!234"

    @field_validator("secret_key")
    @classmethod
    def warn_weak_secret(cls, value: str) -> str:
        if value in {"", "change-me-to-a-long-random-string"}:
            # Allowed in development; production deployments must override.
            return value
        if len(value) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return value

    @property
    def cors_origin_list(self) -> List[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def is_development(self) -> bool:
        return self.app_env.lower() in {"development", "dev", "test"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
