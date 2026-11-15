import pytest
from cryptography.exceptions import InvalidTag

from app.core.crypto import (
    constant_time_equal,
    decrypt_value,
    encrypt_value,
    hmac_value,
    new_data_key,
    unwrap_data_key,
    wrap_data_key,
)


def test_field_encryption_and_wrapping_round_trip() -> None:
    kek = b"k" * 32
    aad = b"synthetic-user-context"
    data_key = new_data_key()
    wrapped_key = wrap_data_key(data_key, kek, aad)
    encrypted_value = encrypt_value("demo@example.com", data_key, aad)

    unwrapped_key = unwrap_data_key(wrapped_key, kek, aad)

    assert unwrapped_key == data_key
    assert decrypt_value(encrypted_value, unwrapped_key, aad) == "demo@example.com"
    assert b"demo@example.com" not in encrypted_value


def test_authenticated_encryption_rejects_wrong_context() -> None:
    key = new_data_key()
    encrypted_value = encrypt_value("masked data", key, b"user-a")

    with pytest.raises(InvalidTag):
        decrypt_value(encrypted_value, key, b"user-b")


def test_crypto_helpers_reject_malformed_payloads() -> None:
    with pytest.raises(ValueError, match="Encrypted field is malformed"):
        decrypt_value(b"short", b"k" * 32, b"context")
    with pytest.raises(ValueError, match="Wrapped data key is malformed"):
        unwrap_data_key(b"short", b"k" * 32, b"context")


def test_hmac_is_deterministic_and_pepper_bound() -> None:
    first = hmac_value("email:demo@example.com", b"a" * 32)

    assert first == hmac_value("email:demo@example.com", b"a" * 32)
    assert first != hmac_value("email:demo@example.com", b"b" * 32)
    assert constant_time_equal(first, first)
    assert not constant_time_equal(first, "0" * 64)
