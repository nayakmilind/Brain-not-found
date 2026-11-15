from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.source import Source


async def list_sources(
    session: AsyncSession,
    user_id: UUID,
    *,
    limit: int,
    offset: int,
) -> list[Source]:
    result = await session.execute(
        select(Source)
        .where(Source.user_id == user_id)
        .order_by(Source.created_at.desc(), Source.id)
        .limit(limit)
        .offset(offset)
    )
    return list(result.scalars().all())


async def get_source(
    session: AsyncSession,
    source_id: UUID,
    user_id: UUID,
    *,
    for_update: bool = False,
) -> Source | None:
    statement = select(Source).where(
        Source.id == source_id,
        Source.user_id == user_id,
    )
    if for_update:
        statement = statement.with_for_update()
    result = await session.execute(statement)
    return result.scalar_one_or_none()


async def add_source(session: AsyncSession, source: Source) -> Source:
    session.add(source)
    await session.commit()
    await session.refresh(source)
    return source


async def delete_source(session: AsyncSession, source: Source) -> None:
    await session.delete(source)
    await session.commit()
