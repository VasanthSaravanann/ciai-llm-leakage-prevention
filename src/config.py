import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # API settings
    API_TITLE: str = "CIAI – LLM Data Leakage Prevention"
    API_VERSION: str = "0.1.0"
    API_KEY_NAME: str = "X-API-KEY"
    # In production, set API_KEY via the environment variable `API_KEY` or .env file
    API_KEY: str = os.getenv("API_KEY", "ciai-dev-key")
    # Support multiple API keys (comma-separated) for staging/rotation
    API_KEYS: str = os.getenv("API_KEYS", "")

    # Request limits / hardening
    MAX_REQUEST_SIZE: int = int(os.getenv("MAX_REQUEST_SIZE", "100000"))
    MAX_B64_RECURSION: int = int(os.getenv("MAX_B64_RECURSION", "3"))

    # Database settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./data/ciai_audit.db")

    # SMTP settings for alerts
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASS: str = os.getenv("SMTP_PASS", "")
    ALERT_RECIPIENT: str = os.getenv("ALERT_RECIPIENT", "")

    # Detection settings
    PRESIDIO_MODEL: str = os.getenv("PRESIDIO_MODEL", "en_core_web_sm")
    # Redis / Celery
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")

    # Auth (JWT)
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

    # Data governance
    RETENTION_DAYS: int = int(os.getenv("RETENTION_DAYS", "90"))

    class Config:
        env_file = ".env"


settings = Settings()

# Helper: parsed list of API keys
def get_api_keys():
    keys = []
    raw = getattr(settings, "API_KEYS", "")
    if raw:
        keys = [k.strip() for k in raw.split(",") if k.strip()]
    # include the single API_KEY for backward compatibility
    if settings.API_KEY and settings.API_KEY not in keys:
        keys.append(settings.API_KEY)
    return keys
