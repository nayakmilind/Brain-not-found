from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.finding import Finding


async def replace_for_scan(
    session: AsyncSession,
    scan_id: UUID,
    findings: Sequence[Finding],
) -> None:
    await session.execute(delete(Finding).where(Finding.scan_id == scan_id))
    session.add_all(findings)


async def list_for_scan(
    session: AsyncSession,
    scan_id: UUID,
    *,
    limit: int,
    cursor: UUID | None,
    category: str | None,
    evidence_class: str | None,
) -> list[Finding]:
    statement = select(Finding).where(Finding.scan_id == scan_id)
    if cursor is not None:
        statement = statement.where(Finding.id > cursor)
    if category is not None:
        statement = statement.where(Finding.category == category)
    if evidence_class is not None:
        statement = statement.where(Finding.evidence_class == evidence_class)
    statement = statement.order_by(Finding.id).limit(limit + 1)
    result = await session.execute(statement)
    return list(result.scalars().all())
