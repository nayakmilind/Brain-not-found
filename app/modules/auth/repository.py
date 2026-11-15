from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.auth import RefreshToken, User


async def get_user_by_email_hash(
    session: AsyncSession,
    email_hash: str,
    *,
    for_update: bool = False,
) -> User | None:
    statement = select(User).where(User.email_hash == email_hash)
    if for_update:
        statement = statement.with_for_update()
    result = await session.execute(statement)
    return result.scalar_one_or_none()


async def get_user_by_id(
    session: AsyncSession,
    user_id: UUID,
    *,
    for_update: bool = False,
) -> User | None:
    statement = select(User).where(User.id == user_id)
    if for_update:
        statement = statement.with_for_update()
    result = await session.execute(statement)
    return result.scalar_one_or_none()


async def get_refresh_token(
    session: AsyncSession,
    token_hash: str,
    *,
    for_update: bool = False,
) -> RefreshToken | None:
    statement = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    if for_update:
        statement = statement.with_for_update()
    result = await session.execute(statement)
    return result.scalar_one_or_none()


def add_user(session: AsyncSession, user: User) -> None:
    session.add(user)


def add_refresh_token(
    session: AsyncSession,
    *,
    user_id: UUID,
    token_hash: str,
    family_id: UUID,
    expires_at: datetime,
) -> RefreshToken:
    refresh_token = RefreshToken(
        id=uuid4(),
        user_id=user_id,
        token_hash=token_hash,
        family_id=family_id,
        expires_at=expires_at,
    )
    session.add(refresh_token)
    return refresh_token


async def revoke_refresh_family(
    session: AsyncSession,
    family_id: UUID,
    revoked_at: datetime,
) -> None:
    await session.execute(
        update(RefreshToken)
        .where(
            RefreshToken.family_id == family_id,
            RefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=revoked_at)
    )
