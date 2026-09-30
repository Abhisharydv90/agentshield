from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    ENV: Literal["dev", "staging", "prod"] = "dev"
    LOG_LEVEL: str = "INFO"
    SERVICE_NAME: str = "agentshield"

    DATABASE_URL: str = "postgresql+asyncpg://postgres:REPLACE_ME@localhost:5432/agentshield"
    REDIS_URL: str = "redis://localhost:6379/0"

    UPSTREAM_URL: str = "https://api.openai.com"
    UPSTREAM_KEY: str = "sk-REPLACE_ME"
    UPSTREAM_TIMEOUT: float = 30.0

    JUDGE_URL: str = "https://generativelanguage.googleapis.com"
    JUDGE_KEY: str = "AIzaSy-REPLACE_ME"
    JUDGE_MODEL: str = "gemini-3.5-flash"
    JUDGE_TIMEOUT: float = 5.0  # Gemini can be a bit slower on the free tier
    JUDGE_CACHE_TTL: int = 300
    JUDGE_ENFORCE: bool = False

    INJECTION_ENFORCE: bool = False
    INJECTION_SIM_THRESHOLD: float = 0.87

    PII_ENFORCE: bool = False
    PII_VAULT_TTL: int = 900
    PII_ENTITIES: str = "EMAIL_ADDRESS,PHONE_NUMBER,CREDIT_CARD,US_SSN,IBAN_CODE,PERSON"

    PINECONE_KEY: str | None = None
    PINECONE_INDEX: str | None = None

    DEFAULT_TENANT: str = "default"

    SECRET_KEY: str = "dev-secret-change-me-in-prod"

    KILL_INJECTION: bool = False
    KILL_PII: bool = False
    KILL_JUDGE: bool = False

    # --- Email (Resend) ---
    RESEND_API_KEY: str = ""
    RESEND_FROM: str = "onboarding@resend.dev"
    APP_BASE_URL: str = "http://localhost:3000"

    # --- Auth hardening ---
    LOCKOUT_THRESHOLD: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15
    PASSWORD_RESET_TTL_MINUTES: int = 30
    EMAIL_VERIFICATION_TTL_HOURS: int = 24

settings = Settings()