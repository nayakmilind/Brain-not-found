from __future__ import annotations

import smtplib
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import dns.asyncresolver
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.ssrf_guard import FetchRejected, FetchResult, SafeFetcher
from app.db.models.auth import User
from app.db.models.source import OwnershipChallenge, Source
from app.modules.ownership.email import (
    OTPMailer,
    SMTPDeliveryError,
    SMTPNotConfigured,
)
from app.modules.ownership.service import (
    ChallengeAlreadyActive,
    ChallengeAttemptsExceeded,
    ChallengeExpired,
    EmailDomainMismatch,
    InvalidOwnershipMethod,
    InvalidOwnershipProof,
    OwnershipNotFound,
    OwnershipService,
    VerificationUnavailable,
)
from app.modules.sources.service import SourceService

TEST_PASSWORD = "synthetic-personal-password"


@pytest.fixture
async def ownership_client(auth_app: FastAPI) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=auth_app),
        base_url="http://testserver",
    ) as client:
        yield client


class FixtureFetcher(SafeFetcher):
    def __init__(self, body: bytes = b"") -> None:
        super().__init__()
        self.body = body
        self.urls: list[str] = []
        self.error: Exception | None = None

    async def fetch(self, url: str) -> FetchResult:
        self.urls.append(url)
        if self.error is not None:
            raise self.error
        return FetchResult(
            url=url,
            status_code=200,
            headers={"content-type": "text/html"},
            body=self.body,
        )


class FixtureMailer:
    def __init__(self) -> None:
        self.messages: list[tuple[str, str]] = []

    async def send_otp(self, recipient: str, otp: str) -> None:
        self.messages.append((recipient, otp))


async def _register(client: AsyncClient, email: str) -> tuple[str, UUID]:
    response = await client.post(
        "/v1/auth/register",
        json={"email": email, "password": TEST_PASSWORD},
    )
    assert response.status_code == 201
    data = response.json()
    return data["access_token"], UUID(data["user_id"])


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _accept_consent(client: AsyncClient, token: str) -> None:
    response = await client.post(
        "/v1/consent/accept",
        headers=_headers(token),
        json={"version": "2026-03", "accepted": True},
    )
    assert response.status_code == 200


async def _create_url(
    client: AsyncClient,
    token: str,
    url: str = "https://example.com/profile",
) -> UUID:
    response = await client.post(
        "/v1/sources",
        headers=_headers(token),
        json={"kind": "URL", "label": "Synthetic profile", "uri": url},
    )
    assert response.status_code == 201
    return UUID(response.json()["id"])


async def _load_user_source(
    session_factory: async_sessionmaker[AsyncSession],
    user_id: UUID,
    source_id: UUID,
) -> tuple[User, Source]:
    async with session_factory() as session:
        user = await session.get(User, user_id)
        source = await session.get(Source, source_id)
        assert user is not None
        assert source is not None
        return user, source


async def test_bio_token_challenge_is_masked_hashed_and_user_scoped(
    ownership_client: AsyncClient,
    auth_app: FastAPI,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    fetcher = FixtureFetcher()
    auth_app.state.safe_fetcher = fetcher
    token, user_id = await _register(ownership_client, "bio.owner@example.com")
    await _accept_consent(ownership_client, token)
    source_id = await _create_url(ownership_client, token)

    revoked = await ownership_client.post(
        "/v1/consent/revoke",
        headers=_headers(token),
    )
    assert revoked.status_code == 200
    blocked_challenge = await ownership_client.post(
        f"/v1/sources/{source_id}/ownership/challenge",
        headers=_headers(token),
        json={"method": "BIO_TOKEN"},
    )
    assert blocked_challenge.status_code == 403
    assert fetcher.urls == []
    await _accept_consent(ownership_client, token)

    challenge_response = await ownership_client.post(
        f"/v1/sources/{source_id}/ownership/challenge",
        headers=_headers(token),
        json={"method": "BIO_TOKEN"},
    )
    assert challenge_response.status_code == 200
    challenge_data = challenge_response.json()
    challenge_id = UUID(challenge_data["challenge_id"])
    challenge_token = challenge_data["token"]
    assert challenge_token.startswith("shield-verify-")
    assert "Remove the token" in challenge_data["instructions"]

    second_challenge = await ownership_client.post(
        f"/v1/sources/{source_id}/ownership/challenge",
        headers=_headers(token),
        json={"method": "BIO_TOKEN"},
    )
    assert second_challenge.status_code == 409
    email_without_smtp = await ownership_client.post(
        f"/v1/sources/{source_id}/ownership/challenge",
        headers=_headers(token),
        json={"method": "EMAIL_OTP", "email": "owner@example.com"},
    )
    assert email_without_smtp.status_code == 503

    async with auth_session_factory() as session:
        challenge = await session.get(OwnershipChallenge, challenge_id)
        assert challenge is not None
        assert challenge.token_hash != challenge_token
        assert challenge_token.encode() not in challenge.token_hash.encode()

    wrong_proof = await ownership_client.post(
        f"/v1/sources/{source_id}/ownership/verify",
        headers=_headers(token),
        json={"challenge_id": str(challenge_id), "proof": "incorrect"},
    )
    assert wrong_proof.status_code == 400

    fetcher.body = f"<div>{challenge_token}</div>".encode()
    verified = await ownership_client.post(
        f"/v1/sources/{source_id}/ownership/verify",
        headers=_headers(token),
        json={"challenge_id": str(challenge_id)},
    )
    assert verified.status_code == 200
    assert verified.json() == {"verified": True, "ownership_status": "VERIFIED"}
    assert fetcher.urls == ["https://example.com/profile"]
    async with auth_session_factory() as session:
        source = await session.get(Source, source_id)
        assert source is not None
        assert source.ownership_status == "VERIFIED"
        assert (
            await SourceService(auth_app.state.settings).require_scannable(
                session,
                user_id,
                source_id,
            )
        ).ownership_status == "VERIFIED"

    repeat = await ownership_client.post(
        f"/v1/sources/{source_id}/ownership/challenge",
        headers=_headers(token),
        json={"method": "BIO_TOKEN"},
    )
    assert repeat.status_code == 200
    assert repeat.json()["ownership_status"] == "VERIFIED"
    assert repeat.json()["challenge_id"] is None


async def test_bio_parser_ignores_script_and_verification_is_bounded(
    ownership_client: AsyncClient,
    auth_app: FastAPI,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    fetcher = FixtureFetcher()
    auth_app.state.safe_fetcher = fetcher
    token, user_id = await _register(ownership_client, "attempts@example.com")
    await _accept_consent(ownership_client, token)
    source_id = await _create_url(ownership_client, token)

    async with auth_session_factory() as session:
        user, _ = await _load_user_source(auth_session_factory, user_id, source_id)
        service = OwnershipService(auth_app.state.settings, fetcher)
        challenge, challenge_token, _ = await service.create_challenge(
            session,
            user,
            source_id=source_id,
            method="BIO_TOKEN",
            email=None,
        )
        assert challenge is not None
        assert challenge_token is not None
        challenge_id = challenge.id

        fetcher.body = f"<script>{challenge_token}</script>".encode()
        with pytest.raises(InvalidOwnershipProof):
            await service.verify(
                session,
                user,
                source_id=source_id,
                challenge_id=challenge_id,
                proof=None,
            )
        fetcher.body = b"<div>no token</div>"
        for _ in range(4):
            with pytest.raises(InvalidOwnershipProof):
                await service.verify(
                    session,
                    user,
                    source_id=source_id,
                    challenge_id=challenge_id,
                    proof=None,
                )
        with pytest.raises(ChallengeAttemptsExceeded):
            await service.verify(
                session,
                user,
                source_id=source_id,
                challenge_id=challenge_id,
                proof=None,
            )

        challenge = await session.get(OwnershipChallenge, challenge_id)
        assert challenge is not None
        challenge.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        challenge.attempts = 0
        await session.commit()
        with pytest.raises(ChallengeExpired):
            await service.verify(
                session,
                user,
                source_id=source_id,
                challenge_id=challenge_id,
                proof=None,
            )


async def test_meta_tag_dns_and_email_ownership_methods(
    ownership_client: AsyncClient,
    auth_session_factory: async_sessionmaker[AsyncSession],
    auth_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, user_id = await _register(ownership_client, "multi.owner@example.com")
    await _accept_consent(ownership_client, token)
    meta_id = await _create_url(
        ownership_client,
        token,
        "https://site.example.com/meta",
    )
    dns_id = await _create_url(
        ownership_client,
        token,
        "https://site.example.com/dns",
    )
    email_id = await _create_url(
        ownership_client,
        token,
        "https://blog.example.com/email",
    )
    user, _ = await _load_user_source(auth_session_factory, user_id, meta_id)
    settings_with_smtp = auth_settings.model_copy(
        update={
            "smtp_host": "smtp.example.com",
            "smtp_from": "noreply@example.com",
            "smtp_username": SecretStr("smtp-user"),
            "smtp_password": SecretStr("smtp-pass"),
        }
    )

    fetcher = FixtureFetcher()
    service = OwnershipService(settings_with_smtp, fetcher)
    async with auth_session_factory() as session:
        meta_challenge, meta_token, _ = await service.create_challenge(
            session,
            user,
            source_id=meta_id,
            method="META_TAG",
            email=None,
        )
        assert meta_challenge is not None
        assert meta_token is not None
        fetcher.body = f'<meta name="privacy-shield-verification" content="{meta_token}">'.encode()
        assert await service.verify(
            session,
            user,
            source_id=meta_id,
            challenge_id=meta_challenge.id,
            proof=None,
        )

        dns_challenge, dns_token, _ = await service.create_challenge(
            session,
            user,
            source_id=dns_id,
            method="DNS_TXT",
            email=None,
        )
        assert dns_challenge is not None
        assert dns_token is not None

        class TXTRecord:
            strings = [dns_token.encode()]

        async def fake_resolve(name: str, record_type: str, lifetime: int) -> list[TXTRecord]:
            assert name == "_privacy-shield-verification.site.example.com"
            assert record_type == "TXT"
            assert lifetime == 3
            return [TXTRecord()]

        monkeypatch.setattr(dns.asyncresolver, "resolve", fake_resolve)
        assert await service.verify(
            session,
            user,
            source_id=dns_id,
            challenge_id=dns_challenge.id,
            proof=None,
        )

        mailer = FixtureMailer()
        email_service = OwnershipService(settings_with_smtp, fetcher, mailer)
        email_challenge, returned_token, _ = await email_service.create_challenge(
            session,
            user,
            source_id=email_id,
            method="EMAIL_OTP",
            email="owner@example.com",
        )
        assert email_challenge is not None
        assert returned_token is None
        assert len(mailer.messages) == 1
        recipient, otp = mailer.messages[0]
        assert recipient == "owner@example.com"
        assert len(otp) == 6 and otp.isdigit()
        assert await email_service.verify(
            session,
            user,
            source_id=email_id,
            challenge_id=email_challenge.id,
            proof=otp,
        )


async def test_ownership_validation_expiry_unavailability_and_self_declare(
    ownership_client: AsyncClient,
    auth_session_factory: async_sessionmaker[AsyncSession],
    auth_settings: Settings,
) -> None:
    fetcher = FixtureFetcher()
    token, user_id = await _register(ownership_client, "source.owner@example.com")
    await _accept_consent(ownership_client, token)
    url_id = await _create_url(ownership_client, token)
    text_response = await ownership_client.post(
        "/v1/sources",
        headers=_headers(token),
        json={"kind": "TEXT", "label": "Pasted", "content": "Synthetic text"},
    )
    assert text_response.status_code == 201
    text_id = UUID(text_response.json()["id"])
    user, _ = await _load_user_source(auth_session_factory, user_id, url_id)
    service = OwnershipService(auth_settings, fetcher)

    async with auth_session_factory() as session:
        with pytest.raises(InvalidOwnershipMethod):
            await service.create_challenge(
                session,
                user,
                source_id=url_id,
                method="SELF_DECLARE",
                email=None,
            )
        with pytest.raises(InvalidOwnershipMethod):
            await service.create_challenge(
                session,
                user,
                source_id=text_id,
                method="BIO_TOKEN",
                email=None,
            )
        with pytest.raises(EmailDomainMismatch):
            await service.create_challenge(
                session,
                user,
                source_id=url_id,
                method="EMAIL_OTP",
                email="owner@attacker.net",
            )
        with pytest.raises(SMTPNotConfigured):
            await service.create_challenge(
                session,
                user,
                source_id=url_id,
                method="EMAIL_OTP",
                email="owner@example.com",
            )
        with pytest.raises(InvalidOwnershipMethod):
            await service.create_challenge(
                session,
                user,
                source_id=url_id,
                method="UNKNOWN",
                email=None,
            )
        challenge, _, _ = await service.create_challenge(
            session,
            user,
            source_id=url_id,
            method="BIO_TOKEN",
            email=None,
        )
        assert challenge is not None
        with pytest.raises(ChallengeAlreadyActive):
            await service.create_challenge(
                session,
                user,
                source_id=url_id,
                method="META_TAG",
                email=None,
            )
        fetcher.error = FetchRejected("blocked")
        with pytest.raises(VerificationUnavailable):
            await service.verify(
                session,
                user,
                source_id=url_id,
                challenge_id=challenge.id,
                proof=None,
            )
        fetcher.error = None

        declared, returned_token, already = await service.create_challenge(
            session,
            user,
            source_id=text_id,
            method="SELF_DECLARE",
            email=None,
        )
        assert declared is None
        assert returned_token is None
        assert already is True
        with pytest.raises(OwnershipNotFound):
            await service.verify(
                session,
                user,
                source_id=url_id,
                challenge_id=UUID(int=0),
                proof=None,
            )
        assert (
            await SourceService(auth_settings).require_scannable(
                session,
                user_id,
                text_id,
            )
        ).ownership_status == "SELF_DECLARED"


async def test_smtp_sender_uses_starttls_and_surfaces_delivery_errors(
    auth_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unconfigured = OTPMailer(auth_settings)
    with pytest.raises(SMTPNotConfigured):
        await unconfigured.send_otp("person@example.com", "123456")

    settings = auth_settings.model_copy(
        update={
            "smtp_host": "smtp.example.com",
            "smtp_from": "sender@example.com",
            "smtp_username": SecretStr("user"),
            "smtp_password": SecretStr("password"),
        }
    )
    calls: list[tuple[str, Any]] = []

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            calls.append(("connect", (host, port, timeout)))

        def __enter__(self) -> FakeSMTP:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def starttls(self, *, context: object) -> None:
            calls.append(("starttls", context))

        def login(self, username: str, password: str) -> None:
            calls.append(("login", (username, password)))

        def send_message(self, message: object) -> None:
            calls.append(("send", message))

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    await OTPMailer(settings).send_otp("person@example.com", "123456")
    assert calls[0] == ("connect", ("smtp.example.com", 587, 10))
    assert calls[1][0] == "starttls"
    assert calls[2] == ("login", ("user", "password"))
    assert calls[3][0] == "send"

    class FailingSMTP(FakeSMTP):
        def starttls(self, *, context: object) -> None:
            raise smtplib.SMTPException("synthetic SMTP failure")

    monkeypatch.setattr(smtplib, "SMTP", FailingSMTP)
    with pytest.raises(SMTPDeliveryError):
        await OTPMailer(settings).send_otp("person@example.com", "123456")
