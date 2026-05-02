"""Santhosh AI — Configuration Settings"""
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    APP_NAME: str = "Santhosh AI"
    VERSION: str = "2.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = "santhosh-ai-secret-change-in-production"
    API_KEY: Optional[str] = None
    LLM_ENABLED: bool = True
    ANTHROPIC_API_KEY: Optional[str] = None
    MAX_UPLOAD_SIZE_MB: int = 500
    SCAN_TIMEOUT_SECONDS: int = 300
    UPLOAD_DIR: str = "/tmp/santhosh_uploads"
    REPORT_DIR: str = "/tmp/santhosh_reports"
    DATABASE_URL: str = "sqlite:///./santhosh.db"
    REDIS_URL: Optional[str] = None
    ALLOWED_ORIGINS: list = ["*"]

    class Config:
        env_file = ".env"
