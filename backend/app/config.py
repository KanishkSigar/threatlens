"""
ThreatLens Configuration
Loads settings from environment variables with sensible defaults.
"""

import secrets
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # App
    APP_NAME: str = "ThreatLens"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Security
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./threatlens.db"

    # Optional API Keys
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance to avoid re-reading env on every request."""
    return Settings()
