import secrets
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from uuid import UUID

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_password_hasher = PasswordHasher()
_JWT_ISSUER = "privacy-shield-ai"
_JWT_AUDIENCE = "privacy-shield-ai"


class InvalidAccessToken(Exception):
    pass


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


@lru_cache(maxsize=1)
def _dummy_password_hash() -> str:
    return hash_password(secrets.token_urlsafe(32))


def verify_password(password: str, encoded_hash: str | None) -> bool:
    hash_to_check = encoded_hash or _dummy_password_hash()
    try:
        return _password_hasher.verify(hash_to_check, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def create_access_token(
    user_id: UUID,
    signing_key: bytes,
    lifetime: timedelta,
    *,
    now: datetime | None = None,
) -> tuple[str, datetime]:
    issued_at = now or datetime.now(UTC)
    expires_at = issued_at + lifetime
    payload = {
        "sub": str(user_id),
        "iat": issued_at,
        "exp": expires_at,
        "jti": secrets.token_urlsafe(16),
        "iss": _JWT_ISSUER,
        "aud": _JWT_AUDIENCE,
    }
    return jwt.encode(payload, signing_key, algorithm="HS256"), expires_at


def decode_access_token(token: str, signing_key: bytes) -> UUID:
    try:
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["HS256"],
            audience=_JWT_AUDIENCE,
            issuer=_JWT_ISSUER,
            options={"require": ["sub", "iat", "exp", "jti"]},
        )
        return UUID(payload["sub"])
    except (jwt.InvalidTokenError, ValueError, KeyError) as exc:
        raise InvalidAccessToken from exc


def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)
