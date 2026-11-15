from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.consent import Consent


async def get_active_consent(
    session: AsyncSession,
    user_id: UUID,
    version: str,
) -> Consent | None:
    result = await session.execute(
        select(Consent)
        .where(
            Consent.user_id == user_id,
            Consent.version == version,
            Consent.revoked_at.is_(None),
        )
        .order_by(Consent.accepted_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def create_consent(
    session: AsyncSession,
    *,
    user_id: UUID,
    version: str,
    scope: dict[str, bool],
    ip_hash: str,
) -> Consent:
    consent = Consent(
        id=uuid4(),
        user_id=user_id,
        version=version,
        scope_json=scope,
        ip_hash=ip_hash,
    )
    session.add(consent)
    await session.commit()
    await session.refresh(consent)
    return consent


async def revoke_active_consents(
    session: AsyncSession,
    user_id: UUID,
    revoked_at: datetime,
) -> bool:
    active_result = await session.execute(
        select(Consent.id)
        .where(
            Consent.user_id == user_id,
            Consent.revoked_at.is_(None),
        )
        .limit(1)
    )
    has_active = active_result.scalar_one_or_none() is not None
    if not has_active:
        await session.commit()
        return False
    await session.execute(
        update(Consent)
        .where(Consent.user_id == user_id, Consent.revoked_at.is_(None))
        .values(revoked_at=revoked_at)
    )
    await session.commit()
    return True
