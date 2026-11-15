from __future__ import annotations

import re
import secrets
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from uuid import UUID

import dns.asyncresolver
import dns.exception
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.crypto import (
    constant_time_equal,
    decode_key,
    decrypt_value,
    hmac_value,
    unwrap_data_key,
)
from app.core.ssrf_guard import FetchRejected, SafeFetcher, parse_http_url
from app.db.models.auth import User
from app.db.models.source import OwnershipChallenge, Source
from app.modules.consent.service import require_current_consent
from app.modules.ownership import repository
from app.modules.ownership.email import OTPMailer, SMTPDeliveryError, SMTPNotConfigured
from app.modules.sources.repository import get_source

CHALLENGE_TTL = timedelta(minutes=15)
MAX_CHALLENGE_ATTEMPTS = 5
_BIO_TOKEN_PATTERN = re.compile(r"shield-verify-[A-Za-z0-9_-]+")
_DNS_LABEL = "_privacy-shield-verification"


class OwnershipNotFound(Exception):
    pass


class InvalidOwnershipMethod(ValueError):
    pass


class ChallengeAlreadyActive(ValueError):
    pass


class ChallengeExpired(ValueError):
    pass


class ChallengeAttemptsExceeded(ValueError):
    pass


class InvalidOwnershipProof(ValueError):
    pass


class EmailDomainMismatch(ValueError):
    pass


class VerificationUnavailable(Exception):
    pass


class _BioParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._hidden_depth = 0
        self.text: list[str] = []

    def handle_starttag(self, tag: str, _attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "noscript"}:
            self._hidden_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript"} and self._hidden_depth:
            self._hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._hidden_depth == 0:
            self.text.append(data)


class _MetaTagParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.values: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "meta":
            return
        attributes = {key.lower(): value for key, value in attrs}
        name = attributes.get("name")
        if name is not None and name.lower() == "privacy-shield-verification":
            content = attributes.get("content")
            if content is not None:
                self.values.append(content)


class OwnershipService:
    def __init__(
        self,
        settings: Settings,
        fetcher: SafeFetcher,
        mailer: OTPMailer | None = None,
    ) -> None:
        self._settings = settings
        self._fetcher = fetcher
        self._mailer = mailer or OTPMailer(settings)
        self._kek = decode_key(settings.master_kek_b64.get_secret_value())
        self._pepper = decode_key(settings.hmac_pepper_b64.get_secret_value())

    async def create_challenge(
        self,
        session: AsyncSession,
        user: User,
        *,
        source_id: UUID,
        method: str,
        email: str | None,
    ) -> tuple[OwnershipChallenge | None, str | None, bool]:
        source = await self._owned_source(
            session,
            source_id,
            user.id,
            for_update=True,
        )
        await require_current_consent(session, user.id)
        if source.status != "ACTIVE":
            raise InvalidOwnershipMethod
        if method not in {"BIO_TOKEN", "META_TAG", "DNS_TXT", "EMAIL_OTP", "SELF_DECLARE"}:
            raise InvalidOwnershipMethod
        if method == "SELF_DECLARE":
            if source.kind == "URL":
                raise InvalidOwnershipMethod
            source.ownership_status = "SELF_DECLARED"
            await session.commit()
            return None, None, True
        if source.kind != "URL" or source.uri_enc is None:
            raise InvalidOwnershipMethod
        if source.ownership_status == "VERIFIED":
            return None, None, True
        uri = self._decrypt_uri(user, source)
        _, host, _ = self._host(uri)
        if method == "EMAIL_OTP":
            if email is None:
                raise InvalidOwnershipMethod
            self._validate_email_domain(email, host)
            if self._settings.smtp_host is None or self._settings.smtp_from is None:
                raise SMTPNotConfigured
        elif email is not None:
            raise InvalidOwnershipMethod
        now = datetime.now(UTC)
        await repository.delete_stale_challenges(session, source.id, now)
        if await repository.get_active_challenge(session, source.id, now) is not None:
            raise ChallengeAlreadyActive

        token = self._new_token(method)
        challenge = await repository.create_challenge(
            session,
            source_id=source.id,
            method=method,
            token_hash=hmac_value(f"ownership:{token}", self._pepper),
            expires_at=now + CHALLENGE_TTL,
        )
        source.ownership_status = "PENDING"
        await session.commit()
        if method == "EMAIL_OTP":
            try:
                await self._mailer.send_otp(email or "", token)
            except (SMTPNotConfigured, SMTPDeliveryError):
                await repository.delete_challenge(session, challenge, source)
                raise
        return challenge, token if method != "EMAIL_OTP" else None, False

    async def verify(
        self,
        session: AsyncSession,
        user: User,
        *,
        source_id: UUID,
        challenge_id: UUID,
        proof: str | None,
    ) -> bool:
        challenge = await repository.get_challenge(
            session,
            challenge_id=challenge_id,
            source_id=source_id,
            user_id=user.id,
            for_update=True,
        )
        if challenge is None:
            raise OwnershipNotFound
        if challenge.verified_at is not None:
            return True
        if _as_utc(challenge.expires_at) <= datetime.now(UTC):
            raise ChallengeExpired
        if challenge.attempts >= MAX_CHALLENGE_ATTEMPTS:
            raise ChallengeAttemptsExceeded

        challenge.attempts += 1
        await repository.save_challenge_attempt(session)
        passed = await self._evaluate_proof(session, user, challenge, source_id, proof)
        if not passed:
            raise InvalidOwnershipProof

        current = await repository.get_challenge(
            session,
            challenge_id=challenge_id,
            source_id=source_id,
            user_id=user.id,
            for_update=True,
        )
        source = await self._owned_source(session, source_id, user.id)
        if current is None:
            raise OwnershipNotFound
        if current.verified_at is not None:
            return True
        if _as_utc(current.expires_at) <= datetime.now(UTC):
            raise ChallengeExpired
        await repository.mark_verified(session, current, source, datetime.now(UTC))
        return True

    async def _evaluate_proof(
        self,
        session: AsyncSession,
        user: User,
        challenge: OwnershipChallenge,
        source_id: UUID,
        proof: str | None,
    ) -> bool:
        if challenge.method == "EMAIL_OTP":
            if proof is None or re.fullmatch(r"\d{6}", proof) is None:
                return False
            return self._matches_token(proof, challenge.token_hash)
        if proof is not None:
            return False
        source = await self._owned_source(session, source_id, user.id)
        if source.uri_enc is None:
            raise OwnershipNotFound
        uri = self._decrypt_uri(user, source)
        try:
            if challenge.method == "DNS_TXT":
                host = self._host(uri)[1]
                candidates = await self._dns_candidates(host)
            else:
                result = await self._fetcher.fetch(uri)
                candidates = self._http_candidates(challenge.method, result.body)
        except (FetchRejected, VerificationUnavailable) as error:
            raise VerificationUnavailable from error
        return any(self._matches_token(candidate, challenge.token_hash) for candidate in candidates)

    async def _dns_candidates(self, host: str) -> list[str]:
        try:
            records = await dns.asyncresolver.resolve(
                f"{_DNS_LABEL}.{host}",
                "TXT",
                lifetime=3,
            )
        except (dns.exception.DNSException, OSError, TimeoutError) as error:
            raise VerificationUnavailable from error
        candidates: list[str] = []
        for record in records:
            try:
                candidates.append(b"".join(record.strings).decode("utf-8"))
            except UnicodeDecodeError:
                continue
        return candidates

    def _http_candidates(self, method: str, content: bytes) -> list[str]:
        decoded = content.decode("utf-8", errors="replace")
        if method == "BIO_TOKEN":
            bio_parser = _BioParser()
            bio_parser.feed(decoded)
            visible_text = " ".join(bio_parser.text)
            return _BIO_TOKEN_PATTERN.findall(visible_text)
        if method == "META_TAG":
            meta_parser = _MetaTagParser()
            meta_parser.feed(decoded)
            return meta_parser.values
        raise InvalidOwnershipMethod

    def _matches_token(self, candidate: str, token_hash: str) -> bool:
        candidate_hash = hmac_value(f"ownership:{candidate}", self._pepper)
        return constant_time_equal(candidate_hash, token_hash)

    def _decrypt_uri(self, user: User, source: Source) -> str:
        if source.uri_enc is None:
            raise OwnershipNotFound
        data_key = unwrap_data_key(
            user.dek_wrapped,
            self._kek,
            b"user-dek:" + user.id.bytes,
        )
        return decrypt_value(
            source.uri_enc,
            data_key,
            b"source-uri:" + source.id.bytes,
        )

    def _host(self, uri: str) -> tuple[str, str, int]:
        return parse_http_url(uri)

    def _validate_email_domain(self, email: str, host: str) -> None:
        try:
            address = email.rsplit("@", 1)
            domain = address[1].encode("idna").decode("ascii").lower()
        except (IndexError, UnicodeError) as error:
            raise EmailDomainMismatch from error
        labels = host.split(".")
        allowed_domains = {host}
        if len(labels) > 2:
            allowed_domains.add(".".join(labels[1:]))
        if domain not in allowed_domains:
            raise EmailDomainMismatch

    def _new_token(self, method: str) -> str:
        if method == "BIO_TOKEN":
            return f"shield-verify-{secrets.token_urlsafe(24)}"
        if method == "EMAIL_OTP":
            return f"{secrets.randbelow(1_000_000):06d}"
        return secrets.token_urlsafe(32)

    async def _owned_source(
        self,
        session: AsyncSession,
        source_id: UUID,
        user_id: UUID,
        *,
        for_update: bool = False,
    ) -> Source:
        source = await get_source(session, source_id, user_id, for_update=for_update)
        if source is None:
            raise OwnershipNotFound
        return source


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
