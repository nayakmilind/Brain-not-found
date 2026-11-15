from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.crypto import decode_key, hmac_value
from app.db.models.consent import Consent
from app.modules.consent import repository

CONSENT_VERSION = "2026-03"
CONSENT_SCOPE: dict[str, bool] = {
    "assess_only_my_own_sources": True,
    "never_request_platform_credentials": True,
    "scores_are_estimates_not_safety_guarantees": True,
}
CONSENT_STATEMENTS: tuple[str, ...] = (
    "Only submit URLs, pasted text, and files that belong to you or that you are "
    "authorized to assess.",
    "URL ownership checks may make bounded public HTTP or DNS requests. We respect "
    "robots.txt and do not bypass platform protections.",
    "We never ask for social-media passwords or credentials. Pasted text and "
    "uploaded files are not fetched.",
    "Source labels, URLs, and submitted contents are encrypted before storage; "
    "avoid submitting passwords or other secrets.",
    "Findings and scores are estimates. A clean report does not prove that you "
    "have no public exposure.",
)


class UnsupportedConsentVersion(ValueError):
    pass


class ConsentNotAccepted(ValueError):
    pass


class ConsentService:
    def __init__(self, settings: Settings) -> None:
        self._pepper = decode_key(settings.hmac_pepper_b64.get_secret_value())

    async def current(self, session: AsyncSession, user_id: UUID) -> Consent | None:
        return await repository.get_active_consent(session, user_id, CONSENT_VERSION)

    async def status(self, session: AsyncSession, user_id: UUID) -> Consent | None:
        return await self.current(session, user_id)

    async def accept(
        self,
        session: AsyncSession,
        *,
        user_id: UUID,
        version: str,
        accepted: bool,
        client_ip: str,
    ) -> Consent:
        if version != CONSENT_VERSION:
            raise UnsupportedConsentVersion
        if not accepted:
            raise ConsentNotAccepted
        current = await self.current(session, user_id)
        if current is not None:
            return current
        return await repository.create_consent(
            session,
            user_id=user_id,
            version=CONSENT_VERSION,
            scope=CONSENT_SCOPE.copy(),
            ip_hash=hmac_value(f"consent-ip:{client_ip}", self._pepper),
        )

    async def revoke(
        self,
        session: AsyncSession,
        user_id: UUID,
    ) -> tuple[bool, datetime | None]:
        now = datetime.now(UTC)
        revoked = await repository.revoke_active_consents(session, user_id, now)
        return revoked, now if revoked else None


async def require_current_consent(
    session: AsyncSession,
    user_id: UUID,
) -> Consent:
    consent = await repository.get_active_consent(session, user_id, CONSENT_VERSION)
    if consent is None:
        raise ConsentNotAccepted
    return consent
