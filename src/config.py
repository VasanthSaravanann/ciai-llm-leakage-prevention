import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # API settings
    API_TITLE: str = "CIAI – LLM Data Leakage Prevention"
    API_VERSION: str = "0.1.0"
    API_KEY_NAME: str = "X-API-KEY"
    API_KEY: str = "ciai-dev-key"  # Change this in production!

    # Database settings
    DATABASE_URL: str = "sqlite:///./data/ciai_audit.db"

    # SMTP settings for alerts
    SMTP_SERVER: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASS: str = os.getenv("SMTP_PASS", "")
    ALERT_RECIPIENT: str = os.getenv("ALERT_RECIPIENT", "")

    # Detection settings
    PRESIDIO_MODEL: str = "en_core_web_sm"

    class Config:
        env_file = ".env"


settings = Settings()
