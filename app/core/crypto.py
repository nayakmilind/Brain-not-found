import base64
import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def decode_key(value: str) -> bytes:
    key = base64.b64decode(value, validate=True)
    if len(key) != 32:
        raise ValueError("Encryption and HMAC keys must be 32 bytes")
    return key


def new_data_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encrypt_value(value: str, data_key: bytes, associated_data: bytes) -> bytes:
    return encrypt_bytes(value.encode("utf-8"), data_key, associated_data)


def encrypt_bytes(value: bytes, data_key: bytes, associated_data: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(data_key).encrypt(nonce, value, associated_data)


def decrypt_value(payload: bytes, data_key: bytes, associated_data: bytes) -> str:
    return decrypt_bytes(payload, data_key, associated_data).decode("utf-8")


def decrypt_bytes(payload: bytes, data_key: bytes, associated_data: bytes) -> bytes:
    if len(payload) < 13:
        raise ValueError("Encrypted field is malformed")
    nonce, ciphertext = payload[:12], payload[12:]
    return AESGCM(data_key).decrypt(nonce, ciphertext, associated_data)


def wrap_data_key(data_key: bytes, kek: bytes, associated_data: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(kek).encrypt(nonce, data_key, associated_data)


def unwrap_data_key(payload: bytes, kek: bytes, associated_data: bytes) -> bytes:
    if len(payload) < 13:
        raise ValueError("Wrapped data key is malformed")
    nonce, ciphertext = payload[:12], payload[12:]
    return AESGCM(kek).decrypt(nonce, ciphertext, associated_data)


def hmac_value(value: str, pepper: bytes) -> str:
    return hmac.new(pepper, value.encode("utf-8"), hashlib.sha256).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
