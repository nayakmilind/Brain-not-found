from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.source import OwnershipChallenge, Source


async def get_active_challenge(
    session: AsyncSession,
    source_id: UUID,
    now: datetime,
) -> OwnershipChallenge | None:
    result = await session.execute(
        select(OwnershipChallenge)
        .where(
            OwnershipChallenge.source_id == source_id,
            OwnershipChallenge.verified_at.is_(None),
            OwnershipChallenge.expires_at > now,
            OwnershipChallenge.attempts < 5,
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


async def delete_stale_challenges(
    session: AsyncSession,
    source_id: UUID,
    now: datetime,
) -> None:
    await session.execute(
        delete(OwnershipChallenge)
        .where(
            OwnershipChallenge.source_id == source_id,
            (OwnershipChallenge.expires_at <= now) | (OwnershipChallenge.attempts >= 5),
            OwnershipChallenge.verified_at.is_(None),
        )
        .execution_options(synchronize_session=False)
    )


async def create_challenge(
    session: AsyncSession,
    *,
    source_id: UUID,
    method: str,
    token_hash: str,
    expires_at: datetime,
) -> OwnershipChallenge:
    challenge = OwnershipChallenge(
        id=uuid4(),
        source_id=source_id,
        method=method,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    session.add(challenge)
    await session.commit()
    await session.refresh(challenge)
    return challenge


async def get_challenge(
    session: AsyncSession,
    *,
    challenge_id: UUID,
    source_id: UUID,
    user_id: UUID,
    for_update: bool = False,
) -> OwnershipChallenge | None:
    statement = (
        select(OwnershipChallenge)
        .join(Source, Source.id == OwnershipChallenge.source_id)
        .where(
            OwnershipChallenge.id == challenge_id,
            OwnershipChallenge.source_id == source_id,
            Source.user_id == user_id,
        )
    )
    if for_update:
        statement = statement.with_for_update()
    result = await session.execute(statement)
    return result.scalar_one_or_none()


async def save_challenge_attempt(session: AsyncSession) -> None:
    await session.commit()


async def mark_verified(
    session: AsyncSession,
    challenge: OwnershipChallenge,
    source: Source,
    verified_at: datetime,
) -> None:
    challenge.verified_at = verified_at
    source.ownership_status = "VERIFIED"
    await session.execute(
        delete(OwnershipChallenge).where(
            OwnershipChallenge.source_id == source.id,
            OwnershipChallenge.id != challenge.id,
        )
    )
    await session.commit()


async def delete_challenge(
    session: AsyncSession,
    challenge: OwnershipChallenge,
    source: Source,
) -> None:
    await session.delete(challenge)
    source.ownership_status = "UNVERIFIED"
    await session.commit()
