from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.crypto import decode_key, decrypt_value, unwrap_data_key
from app.core.security import InvalidAccessToken, decode_access_token, verify_password
from app.db.models.auth import RefreshToken, User
from app.main import create_app
from app.modules.auth.router import CSRF_COOKIE, REFRESH_COOKIE
from app.modules.auth.service import AuthService, InvalidCredentials

TEST_EMAIL = "Avery.Example@example.com"
TEST_PASSWORD = "synthetic-personal-password"


@pytest.fixture
async def auth_client(
    auth_settings: Settings,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    app = create_app(auth_settings)
    async with app.router.lifespan_context(app):
        app.state.session_factory = auth_session_factory
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            yield client


async def _load_user(
    session_factory: async_sessionmaker[AsyncSession],
) -> User:
    async with session_factory() as session:
        return (await session.execute(select(User))).scalar_one()


async def test_register_encrypts_email_and_hashes_password(
    auth_client: AsyncClient,
    auth_session_factory: async_sessionmaker[AsyncSession],
    auth_settings: Settings,
) -> None:
    response = await auth_client.post(
        "/v1/auth/register",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )

    assert response.status_code == 201
    user_id = UUID(response.json()["user_id"])
    assert (
        decode_access_token(
            response.json()["access_token"],
            decode_key(auth_settings.jwt_secret_b64.get_secret_value()),
        )
        == user_id
    )

    user = await _load_user(auth_session_factory)
    assert user.id == user_id
    assert user.email_hash != TEST_EMAIL.casefold()
    assert TEST_EMAIL.casefold().encode() not in user.email_enc
    assert user.password_hash != TEST_PASSWORD
    assert user.password_hash.startswith("$argon2id$")
    assert verify_password(TEST_PASSWORD, user.password_hash)
    assert auth_client.cookies.get(REFRESH_COOKIE)
    assert auth_client.cookies.get(CSRF_COOKIE)
    auth_cookies = response.headers.get_list("set-cookie")
    assert any(
        "psai_refresh=" in cookie and "Path=/v1/auth" in cookie and "HttpOnly" in cookie
        for cookie in auth_cookies
    )
    assert any(
        "psai_csrf=" in cookie and "Path=/" in cookie and "HttpOnly" not in cookie
        for cookie in auth_cookies
    )

    data_key = unwrap_data_key(
        user.dek_wrapped,
        decode_key(auth_settings.master_kek_b64.get_secret_value()),
        b"user-dek:" + user.id.bytes,
    )
    assert (
        decrypt_value(
            user.email_enc,
            data_key,
            b"user-email:" + user.id.bytes,
        )
        == TEST_EMAIL.casefold()
    )

    async with auth_session_factory() as session:
        token = (await session.execute(select(RefreshToken))).scalar_one()
    assert token.token_hash != auth_client.cookies.get(REFRESH_COOKIE)
    assert len(token.token_hash) == 64


async def test_duplicate_registration_and_login(
    auth_client: AsyncClient,
) -> None:
    first = await auth_client.post(
        "/v1/auth/register",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    duplicate = await auth_client.post(
        "/v1/auth/register",
        json={"email": TEST_EMAIL.casefold(), "password": TEST_PASSWORD},
    )
    login = await auth_client.post(
        "/v1/auth/login",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )

    assert first.status_code == 201
    assert duplicate.status_code == 409
    assert login.status_code == 200
    assert login.json()["token_type"] == "bearer"


async def test_refresh_rotates_and_reuse_revokes_the_token_family(
    auth_client: AsyncClient,
) -> None:
    registered = await auth_client.post(
        "/v1/auth/register",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    assert registered.status_code == 201
    old_refresh = auth_client.cookies.get(REFRESH_COOKIE)
    csrf_token = auth_client.cookies.get(CSRF_COOKIE)
    assert old_refresh is not None
    assert csrf_token is not None

    rotated = await auth_client.post(
        "/v1/auth/refresh",
        headers={"X-CSRF-Token": csrf_token},
    )
    assert rotated.status_code == 200
    new_refresh = auth_client.cookies.get(REFRESH_COOKIE)
    new_csrf = auth_client.cookies.get(CSRF_COOKIE)
    assert new_refresh is not None and new_refresh != old_refresh
    assert new_csrf is not None

    auth_client.cookies.set(REFRESH_COOKIE, old_refresh, path="/v1/auth")
    reused = await auth_client.post(
        "/v1/auth/refresh",
        headers={"X-CSRF-Token": new_csrf},
    )
    assert reused.status_code == 401

    auth_client.cookies.set(REFRESH_COOKIE, new_refresh, path="/v1/auth")
    family_revoked = await auth_client.post(
        "/v1/auth/refresh",
        headers={"X-CSRF-Token": new_csrf},
    )
    assert family_revoked.status_code == 401


async def test_refresh_requires_csrf_proof(auth_client: AsyncClient) -> None:
    await auth_client.post(
        "/v1/auth/register",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )

    response = await auth_client.post("/v1/auth/refresh")

    assert response.status_code == 403


async def test_refresh_rejects_missing_or_unknown_token(
    auth_client: AsyncClient,
) -> None:
    auth_client.cookies.set(CSRF_COOKIE, "csrf-test", path="/")
    missing = await auth_client.post(
        "/v1/auth/refresh",
        headers={"X-CSRF-Token": "csrf-test"},
    )
    auth_client.cookies.set(REFRESH_COOKIE, "unknown-token", path="/v1/auth")
    unknown = await auth_client.post(
        "/v1/auth/refresh",
        headers={"X-CSRF-Token": "csrf-test"},
    )

    assert missing.status_code == 401
    assert unknown.status_code == 401


async def test_logout_revokes_refresh_token_and_clears_cookies(
    auth_client: AsyncClient,
) -> None:
    await auth_client.post(
        "/v1/auth/register",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    csrf_token = auth_client.cookies.get(CSRF_COOKIE)
    assert csrf_token is not None

    response = await auth_client.post(
        "/v1/auth/logout",
        headers={"X-CSRF-Token": csrf_token},
    )

    assert response.status_code == 204
    assert any(
        "psai_refresh" in value and "Max-Age=0" in value
        for value in response.headers.get_list("set-cookie")
    )
    assert auth_client.cookies.get(REFRESH_COOKIE) is None


async def test_failed_logins_apply_exponential_lockout(
    auth_client: AsyncClient,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    await auth_client.post(
        "/v1/auth/register",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    first_failure = await auth_client.post(
        "/v1/auth/login",
        json={"email": TEST_EMAIL, "password": "wrong-personal-password"},
    )
    second_failure = await auth_client.post(
        "/v1/auth/login",
        json={"email": TEST_EMAIL, "password": "wrong-personal-password"},
    )
    correct_during_lockout = await auth_client.post(
        "/v1/auth/login",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )

    user = await _load_user(auth_session_factory)
    locked_until = user.locked_until
    assert locked_until is not None
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=UTC)
    assert locked_until > datetime.now(UTC)
    assert user.failed_login_attempts == 2
    assert [first_failure.status_code, second_failure.status_code] == [401, 401]
    assert correct_during_lockout.status_code == 401

    async with auth_session_factory() as session:
        user = (await session.execute(select(User))).scalar_one()
        user.locked_until = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
    third_failure = await auth_client.post(
        "/v1/auth/login",
        json={"email": TEST_EMAIL, "password": "wrong-personal-password"},
    )
    user = await _load_user(auth_session_factory)
    locked_until = user.locked_until
    assert locked_until is not None
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=UTC)
    backoff_seconds = (locked_until - datetime.now(UTC)).total_seconds()
    assert third_failure.status_code == 401
    assert user.failed_login_attempts == 3
    assert 100 < backoff_seconds <= 120


async def test_login_unknown_email_uses_generic_error(
    auth_client: AsyncClient,
) -> None:
    response = await auth_client.post(
        "/v1/auth/login",
        json={"email": "unknown@example.com", "password": TEST_PASSWORD},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


async def test_validation_errors_do_not_echo_password(auth_client: AsyncClient) -> None:
    secret_input = "pw-needle"
    response = await auth_client.post(
        "/v1/auth/register",
        json={"email": "valid@example.com", "password": secret_input},
    )

    assert response.status_code == 422
    assert secret_input not in response.text
    assert response.json()["title"] == "Request validation failed"


async def test_service_registration_and_login_issue_tokens(
    auth_settings: Settings,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    service = AuthService(auth_settings)
    async with auth_session_factory() as session:
        registered = await service.register(session, TEST_EMAIL, TEST_PASSWORD)
    async with auth_session_factory() as session:
        logged_in = await service.login(session, TEST_EMAIL, TEST_PASSWORD)

    assert registered.user_id == logged_in.user_id
    assert registered.refresh_token != logged_in.refresh_token
    assert (
        decode_access_token(
            logged_in.access_token,
            decode_key(auth_settings.jwt_secret_b64.get_secret_value()),
        )
        == registered.user_id
    )


async def test_expired_refresh_token_is_revoked(
    auth_settings: Settings,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    service = AuthService(auth_settings)
    async with auth_session_factory() as session:
        tokens = await service.register(session, TEST_EMAIL, TEST_PASSWORD)

    async with auth_session_factory() as session:
        refresh_token = (await session.execute(select(RefreshToken))).scalar_one()
        refresh_token.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    async with auth_session_factory() as session:
        with pytest.raises(InvalidCredentials):
            await service.refresh(session, tokens.refresh_token)

    async with auth_session_factory() as session:
        refresh_token = (await session.execute(select(RefreshToken))).scalar_one()
        assert refresh_token.revoked_at is not None


def test_access_token_rejects_invalid_signature(auth_settings: Settings) -> None:
    signing_key = decode_key(auth_settings.jwt_secret_b64.get_secret_value())

    with pytest.raises(InvalidAccessToken):
        decode_access_token("not-a-jwt", signing_key)
