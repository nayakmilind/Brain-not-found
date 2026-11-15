from __future__ import annotations

import base64
import binascii
from urllib.parse import urlsplit

from pydantic import AnyHttpUrl, EmailStr, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: SecretStr
    redis_url: SecretStr
    master_kek_b64: SecretStr
    hmac_pepper_b64: SecretStr
    jwt_secret_b64: SecretStr
    log_level: str = "INFO"
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    login_failure_threshold: int = 5
    login_backoff_base_seconds: int = 1
    login_backoff_max_seconds: int = 900
    cookie_secure: bool = True
    source_max_bytes: int = 5_242_880
    source_fetch_timeout_seconds: int = 10
    source_max_redirects: int = 3
    extraction_max_characters: int = 2_000_000
    extraction_max_pdf_pages: int = 100
    extraction_max_docx_uncompressed_bytes: int = 20_000_000
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: SecretStr | None = None
    smtp_password: SecretStr | None = None
    smtp_from: EmailStr | None = None
    assistant_enabled: bool = False
    assistant_base_url: AnyHttpUrl | None = None
    assistant_api_key: SecretStr | None = None
    assistant_model: str | None = None

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().startswith("postgresql+asyncpg://"):
            raise ValueError("DATABASE_URL must use the postgresql+asyncpg scheme")
        return value

    @field_validator("redis_url")
    @classmethod
    def validate_redis_url(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().startswith(("redis://", "rediss://")):
            raise ValueError("REDIS_URL must use the redis or rediss scheme")
        return value

    @field_validator("master_kek_b64", "hmac_pepper_b64", "jwt_secret_b64")
    @classmethod
    def validate_key_material(cls, value: SecretStr) -> SecretStr:
        try:
            decoded = base64.b64decode(value.get_secret_value(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Key material must be valid base64") from exc
        if len(decoded) != 32:
            raise ValueError("Key material must decode to exactly 32 bytes")
        return value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("LOG_LEVEL must be a standard logging level")
        return normalized

    @field_validator(
        "access_token_minutes",
        "refresh_token_days",
        "login_failure_threshold",
        "login_backoff_base_seconds",
        "login_backoff_max_seconds",
        "source_max_bytes",
        "source_fetch_timeout_seconds",
        "source_max_redirects",
        "extraction_max_characters",
        "extraction_max_pdf_pages",
        "extraction_max_docx_uncompressed_bytes",
        "smtp_port",
    )
    @classmethod
    def validate_positive_security_setting(cls, value: int) -> int:
        if value < 1:
            raise ValueError("Security durations and thresholds must be positive")
        return value

    @model_validator(mode="after")
    def validate_security_ranges(self) -> Settings:
        if self.login_backoff_max_seconds < self.login_backoff_base_seconds:
            raise ValueError(
                "LOGIN_BACKOFF_MAX_SECONDS must be at least LOGIN_BACKOFF_BASE_SECONDS"
            )
        if self.smtp_port > 65535:
            raise ValueError("SMTP_PORT must be a valid TCP port")
        return self

    @field_validator("smtp_host", "smtp_from", mode="before")
    @classmethod
    def normalize_optional_smtp_text(cls, value: str | None) -> str | None:
        return None if value == "" else value

    @field_validator("smtp_username", "smtp_password", mode="before")
    @classmethod
    def normalize_optional_smtp_secret(
        cls, value: SecretStr | str | None
    ) -> SecretStr | str | None:
        return None if value == "" else value

    @model_validator(mode="after")
    def validate_smtp_settings(self) -> Settings:
        smtp_has_credentials = self.smtp_username is not None or self.smtp_password is not None
        if smtp_has_credentials and (self.smtp_username is None or self.smtp_password is None):
            raise ValueError("SMTP_USERNAME and SMTP_PASSWORD must be configured together")
        if (self.smtp_host is None) != (self.smtp_from is None):
            raise ValueError("SMTP_HOST and SMTP_FROM must be configured together")
        if smtp_has_credentials and self.smtp_host is None:
            raise ValueError("SMTP_HOST and SMTP_FROM are required when SMTP credentials are set")
        return self

    @field_validator("assistant_base_url", "assistant_model", mode="before")
    @classmethod
    def normalize_optional_assistant_text(
        cls,
        value: AnyHttpUrl | str | None,
    ) -> AnyHttpUrl | str | None:
        return None if value == "" else value

    @field_validator("assistant_api_key", mode="before")
    @classmethod
    def normalize_optional_assistant_secret(
        cls,
        value: SecretStr | str | None,
    ) -> SecretStr | str | None:
        return None if value == "" else value

    @model_validator(mode="after")
    def validate_assistant_settings(self) -> Settings:
        configured = (
            self.assistant_base_url is not None,
            self.assistant_api_key is not None,
            self.assistant_model is not None,
        )
        if any(configured) and not all(configured):
            raise ValueError(
                "ASSISTANT_BASE_URL, ASSISTANT_API_KEY, and ASSISTANT_MODEL "
                "must be configured together"
            )
        if self.assistant_enabled and not all(configured):
            raise ValueError(
                "Assistant provider settings are required when ASSISTANT_ENABLED is true"
            )
        if self.assistant_base_url is not None and self.assistant_base_url.scheme != "https":
            raise ValueError("ASSISTANT_BASE_URL must use HTTPS")
        if self.assistant_base_url is not None:
            parsed_url = urlsplit(str(self.assistant_base_url))
            has_url_credentials = parsed_url.username is not None or parsed_url.password is not None
            if has_url_credentials or parsed_url.query or parsed_url.fragment:
                raise ValueError(
                    "ASSISTANT_BASE_URL must not include credentials, query parameters, "
                    "or fragments"
                )
        if self.assistant_model is not None and not self.assistant_model.strip():
            raise ValueError("ASSISTANT_MODEL cannot be empty")
        return self
