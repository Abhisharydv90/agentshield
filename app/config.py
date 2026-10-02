from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central AgentShield configuration.

    Security rule:
    - Development may use local defaults.
    - Staging/production must explicitly provide security-sensitive values.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    # ---------------------------------------------------------
    # Application
    # ---------------------------------------------------------

    ENV: Literal["dev", "staging", "prod"] = "dev"
    LOG_LEVEL: str = "INFO"
    SERVICE_NAME: str = "agentshield"

    # ---------------------------------------------------------
    # Database
    # ---------------------------------------------------------

    DATABASE_URL: str = (
        "postgresql+asyncpg://postgres:postgres"
        "@localhost:5432/agentshield"
    )

    DATABASE_REQUIRE_SSL: bool = False

    # ---------------------------------------------------------
    # Redis
    # ---------------------------------------------------------

    REDIS_URL: str = "redis://localhost:6379/0"

    # ---------------------------------------------------------
    # Upstream LLM
    # ---------------------------------------------------------

    UPSTREAM_URL: str = "https://api.openai.com"
    UPSTREAM_KEY: str = ""
    UPSTREAM_TIMEOUT: float = Field(default=30.0, gt=0, le=300)

    # ---------------------------------------------------------
    # LLM Judge
    # ---------------------------------------------------------

    JUDGE_URL: str = "https://generativelanguage.googleapis.com"
    JUDGE_KEY: str = ""
    JUDGE_MODEL: str = "gemini-3.5-flash"
    JUDGE_TIMEOUT: float = Field(default=5.0, gt=0, le=60)
    JUDGE_CACHE_TTL: int = Field(default=300, ge=0, le=86400)

    # Security enforcement defaults to TRUE.
    JUDGE_ENFORCE: bool = True

    # ---------------------------------------------------------
    # Injection detection
    # ---------------------------------------------------------

    INJECTION_ENFORCE: bool = True
    INJECTION_SIM_THRESHOLD: float = Field(
        default=0.87,
        ge=0.0,
        le=1.0,
    )

    # ---------------------------------------------------------
    # PII protection
    # ---------------------------------------------------------

    PII_ENFORCE: bool = True
    PII_VAULT_TTL: int = Field(
        default=900,
        ge=60,
        le=86400,
    )

    PII_ENTITIES: str = (
        "EMAIL_ADDRESS,"
        "PHONE_NUMBER,"
        "CREDIT_CARD,"
        "US_SSN,"
        "IBAN_CODE,"
        "PERSON"
    )

    # ---------------------------------------------------------
    # Vector provider
    # ---------------------------------------------------------

    PINECONE_KEY: str | None = None
    PINECONE_INDEX: str | None = None

    # ---------------------------------------------------------
    # Tenant
    # ---------------------------------------------------------

    DEFAULT_TENANT: str = "default"

    # ---------------------------------------------------------
    # Cryptographic secret
    # ---------------------------------------------------------

    SECRET_KEY: str = ""

    # ---------------------------------------------------------
    # Kill switches
    #
    # IMPORTANT:
    # Kill switches disable a feature safely.
    # They must NEVER silently convert a security decision into ALLOW.
    # ---------------------------------------------------------

    KILL_INJECTION: bool = False
    KILL_PII: bool = False
    KILL_JUDGE: bool = False

    # ---------------------------------------------------------
    # Email
    # ---------------------------------------------------------

    RESEND_API_KEY: str = ""
    RESEND_FROM: str = "onboarding@resend.dev"
    APP_BASE_URL: str = "http://localhost:3000"

    # ---------------------------------------------------------
    # Authentication
    # ---------------------------------------------------------

    LOCKOUT_THRESHOLD: int = Field(
        default=5,
        ge=1,
        le=100,
    )

    LOCKOUT_DURATION_MINUTES: int = Field(
        default=15,
        ge=1,
        le=1440,
    )

    PASSWORD_RESET_TTL_MINUTES: int = Field(
        default=30,
        ge=5,
        le=1440,
    )

    EMAIL_VERIFICATION_TTL_HOURS: int = Field(
        default=24,
        ge=1,
        le=168,
    )

    SESSION_TTL_HOURS: int = Field(
        default=24 * 7,
        ge=1,
        le=24 * 30,
    )

    # ---------------------------------------------------------
    # Trusted origins
    # ---------------------------------------------------------

    CORS_ORIGINS: str = (
        "http://localhost:3000,"
        "http://127.0.0.1:3000"
    )

    # ---------------------------------------------------------
    # Rate limiting
    # ---------------------------------------------------------

    RATE_LIMIT_FAIL_OPEN: bool = False
    TRUSTED_PROXY_IPS: str = ""
    TRUSTED_HOSTS: str = ""
    MAX_REQUEST_BODY_BYTES: int = Field(
        default=2 * 1024 * 1024,
        ge=64 * 1024,
        le=16 * 1024 * 1024,
    )

    # ---------------------------------------------------------
    # Validators
    # ---------------------------------------------------------

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, value: str) -> str:
        value = value.strip()

        if not value:
            return value

        if len(value) < 32:
            raise ValueError(
                "SECRET_KEY must contain at least 32 characters."
            )

        return value

    @field_validator("CORS_ORIGINS")
    @classmethod
    def normalize_origins(cls, value: str) -> str:
        origins = []

        for origin in value.split(","):
            origin = origin.strip().rstrip("/")

            if origin:
                origins.append(origin)

        return ",".join(origins)

    @model_validator(mode="after")
    def validate_environment(self) -> "Settings":
        """
        Prevent accidental insecure production configuration.
        """

        # Parse proxy networks at startup so malformed trust configuration
        # cannot silently degrade into an unexpected runtime policy.
        for network in self.TRUSTED_PROXY_IPS.split(","):
            network = network.strip()
            if network:
                try:
                    ipaddress.ip_network(network, strict=False)
                except ValueError as exc:
                    raise ValueError(
                        f"Invalid TRUSTED_PROXY_IPS entry: {network}"
                    ) from exc

        if self.ENV in {"staging", "prod"}:
            if not self.SECRET_KEY:
                raise ValueError(
                    "SECRET_KEY must be explicitly configured "
                    "in staging/production."
                )

            if self.SECRET_KEY.lower() in {
                "dev-secret-change-me-in-prod",
                "change-me",
                "secret",
            }:
                raise ValueError(
                    "Unsafe SECRET_KEY detected."
                )

            if self.DATABASE_URL.startswith(
                "postgresql+asyncpg://postgres:postgres@localhost"
            ):
                raise ValueError(
                    "Local development DATABASE_URL cannot be used "
                    "in staging/production."
                )

            self.DATABASE_REQUIRE_SSL = True

            trusted_hosts = [
                value.strip()
                for value in self.TRUSTED_HOSTS.split(",")
                if value.strip()
            ]
            if not trusted_hosts:
                raise ValueError(
                    "TRUSTED_HOSTS must be explicitly configured in staging/production."
                )
            if any(host == "*" for host in trusted_hosts):
                raise ValueError(
                    "Wildcard TRUSTED_HOSTS is not permitted in staging/production."
                )

            origins = self.cors_origins
            if not origins:
                raise ValueError(
                    "CORS_ORIGINS must be explicitly configured in staging/production."
                )
            if any(
                origin.startswith(("http://localhost", "http://127.0.0.1"))
                for origin in origins
            ):
                raise ValueError(
                    "Development CORS origins are not permitted in staging/production."
                )

            if not self.REDIS_URL.lower().startswith("rediss://"):
                raise ValueError(
                    "REDIS_URL must use rediss:// in staging/production."
                )

        return self

    @property
    def trusted_hosts(self) -> list[str]:
        return [
            value.strip()
            for value in self.TRUSTED_HOSTS.split(",")
            if value.strip()
        ]

    @property
    def trusted_proxy_ips(self) -> list[str]:
        return [
            value.strip()
            for value in self.TRUSTED_PROXY_IPS.split(",")
            if value.strip()
        ]

    @property
    def cors_origins(self) -> list[str]:
        return [
            origin
            for origin in self.CORS_ORIGINS.split(",")
            if origin
        ]


settings = Settings()