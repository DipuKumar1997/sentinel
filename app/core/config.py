"""Centralized application configuration.

All configuration is loaded from environment variables (see .env.example).
Never hardcode secrets here.
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "SentinelMail AI"
    APP_ENV: str = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    SECRET_KEY: str = "CHANGE_ME_dev_only_do_not_use_in_prod"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    DATABASE_URL: str = "postgresql+asyncpg://sentinel:sentinel_dev_password@localhost:5432/sentinelmail"

    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    EVIDENCE_STORAGE_BACKEND: str = "local"
    EVIDENCE_STORAGE_PATH: str = "/data/evidence"
    MAX_UPLOAD_SIZE_MB: int = 25

    RATE_LIMIT_PER_MINUTE: int = 60

    VIRUSTOTAL_API_KEY: str | None = None
    ABUSEIPDB_API_KEY: str | None = None
    IPINFO_TOKEN: str | None = None

    @property
    def max_upload_size_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
