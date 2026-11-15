import base64

import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import Settings


def key_material(byte: bytes) -> SecretStr:
    return SecretStr(base64.b64encode(byte * 32).decode("ascii"))


def test_settings_accept_valid_local_service_urls() -> None:
    settings = Settings(
        _env_file=None,
        database_url=SecretStr("postgresql+asyncpg://user:pass@localhost/db"),
        redis_url=SecretStr("redis://localhost:6379/0"),
        master_kek_b64=key_material(b"k"),
        hmac_pepper_b64=key_material(b"h"),
        jwt_secret_b64=key_material(b"j"),
        log_level="debug",
    )

    assert settings.log_level == "DEBUG"
    assert settings.database_url.get_secret_value().startswith("postgresql+asyncpg://")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("database_url", "postgresql://localhost/db"),
        ("redis_url", "http://localhost"),
        ("log_level", "VERBOSE"),
        ("master_kek_b64", "not-base64"),
        ("hmac_pepper_b64", "YQ=="),
        ("login_backoff_base_seconds", 901),
        ("source_max_bytes", 0),
        ("source_fetch_timeout_seconds", 0),
        ("source_max_redirects", 0),
        ("extraction_max_characters", 0),
        ("extraction_max_pdf_pages", 0),
        ("extraction_max_docx_uncompressed_bytes", 0),
        ("smtp_port", 65536),
    ],
)
def test_settings_reject_invalid_values(field: str, value: object) -> None:
    values: dict[str, object] = {
        "database_url": SecretStr("postgresql+asyncpg://user:pass@localhost/db"),
        "redis_url": SecretStr("redis://localhost:6379/0"),
        "master_kek_b64": key_material(b"k"),
        "hmac_pepper_b64": key_material(b"h"),
        "jwt_secret_b64": key_material(b"j"),
        "log_level": "INFO",
    }
    values[field] = value

    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)


@pytest.mark.parametrize(
    ("smtp_values", "message"),
    [
        ({"smtp_host": "smtp.example.com"}, "SMTP_HOST and SMTP_FROM"),
        ({"smtp_username": SecretStr("user")}, "must be configured together"),
        (
            {
                "smtp_host": "smtp.example.com",
                "smtp_from": "sender@example.com",
                "smtp_password": SecretStr("password"),
            },
            "must be configured together",
        ),
    ],
)
def test_settings_reject_incomplete_smtp_configuration(
    smtp_values: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        Settings(
            _env_file=None,
            database_url=SecretStr("postgresql+asyncpg://test:test@localhost/db"),
            redis_url=SecretStr("redis://localhost:6379/0"),
            master_kek_b64=key_material(b"k"),
            hmac_pepper_b64=key_material(b"h"),
            jwt_secret_b64=key_material(b"j"),
            **smtp_values,
        )


def test_settings_accept_complete_starttls_configuration() -> None:
    settings = Settings(
        _env_file=None,
        database_url=SecretStr("postgresql+asyncpg://test:test@localhost/db"),
        redis_url=SecretStr("redis://localhost:6379/0"),
        master_kek_b64=key_material(b"k"),
        hmac_pepper_b64=key_material(b"h"),
        jwt_secret_b64=key_material(b"j"),
        smtp_host="smtp.example.com",
        smtp_from="sender@example.com",
        smtp_username=SecretStr("user"),
        smtp_password=SecretStr("password"),
    )
    assert settings.smtp_host == "smtp.example.com"
    assert str(settings.smtp_from) == "sender@example.com"


def test_assistant_provider_is_disabled_by_default() -> None:
    settings = Settings(
        _env_file=None,
        database_url=SecretStr("postgresql+asyncpg://user:pass@localhost/db"),
        redis_url=SecretStr("redis://localhost:6379/0"),
        master_kek_b64=key_material(b"k"),
        hmac_pepper_b64=key_material(b"h"),
        jwt_secret_b64=key_material(b"j"),
    )

    assert settings.assistant_enabled is False
    assert settings.assistant_base_url is None


@pytest.mark.parametrize(
    "values",
    [
        {"assistant_enabled": True},
        {"assistant_base_url": "https://llm.example.test/v1"},
        {
            "assistant_enabled": True,
            "assistant_base_url": "http://llm.example.test/v1",
            "assistant_api_key": SecretStr("synthetic-key"),
            "assistant_model": "synthetic-model",
        },
        {
            "assistant_enabled": True,
            "assistant_base_url": "https://user:password@llm.example.test/v1",
            "assistant_api_key": SecretStr("synthetic-key"),
            "assistant_model": "synthetic-model",
        },
        {
            "assistant_enabled": True,
            "assistant_base_url": "https://llm.example.test/v1",
            "assistant_api_key": SecretStr("synthetic-key"),
            "assistant_model": " ",
        },
    ],
)
def test_assistant_provider_rejects_incomplete_or_insecure_configuration(
    values: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            database_url=SecretStr("postgresql+asyncpg://user:pass@localhost/db"),
            redis_url=SecretStr("redis://localhost:6379/0"),
            master_kek_b64=key_material(b"k"),
            hmac_pepper_b64=key_material(b"h"),
            jwt_secret_b64=key_material(b"j"),
            **values,
        )
