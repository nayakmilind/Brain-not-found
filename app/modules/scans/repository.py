from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.scan import Scan, ScanDeadLetter, ScanEvent, ScanSource
from app.db.models.source import Source


async def get_scan(
    session: AsyncSession,
    scan_id: UUID,
    *,
    user_id: UUID | None = None,
    for_update: bool = False,
) -> Scan | None:
    statement = select(Scan).where(Scan.id == scan_id)
    if user_id is not None:
        statement = statement.where(Scan.user_id == user_id)
    if for_update:
        statement = statement.with_for_update()
    result = await session.execute(statement)
    return result.scalar_one_or_none()


async def get_scan_by_idempotency_key(
    session: AsyncSession,
    user_id: UUID,
    key_hash: str,
    *,
    for_update: bool = False,
) -> Scan | None:
    statement = select(Scan).where(
        Scan.user_id == user_id,
        Scan.idempotency_key_hash == key_hash,
    )
    if for_update:
        statement = statement.with_for_update()
    result = await session.execute(statement)
    return result.scalar_one_or_none()


async def get_sources(
    session: AsyncSession,
    user_id: UUID,
    source_ids: list[UUID],
) -> list[Source]:
    result = await session.execute(
        select(Source).where(
            Source.user_id == user_id,
            Source.id.in_(source_ids),
        )
    )
    return list(result.scalars().all())


async def get_sources_for_scan(
    session: AsyncSession,
    scan: Scan,
) -> list[Source]:
    result = await session.execute(
        select(Source)
        .join(ScanSource, ScanSource.source_id == Source.id)
        .where(ScanSource.scan_id == scan.id, Source.user_id == scan.user_id)
    )
    return list(result.scalars().all())


async def source_records_for_scan(
    session: AsyncSession,
    scan: Scan,
) -> list[tuple[Source, ScanSource]]:
    result = await session.execute(
        select(Source, ScanSource)
        .join(ScanSource, ScanSource.source_id == Source.id)
        .where(ScanSource.scan_id == scan.id, Source.user_id == scan.user_id)
    )
    return list(result.all())


async def update_scan_source(
    session: AsyncSession,
    scan_id: UUID,
    source_id: UUID,
    *,
    fetch_status: str,
    content_hash: str | None,
    fetched_at: datetime | None,
) -> None:
    result = await session.execute(
        select(ScanSource).where(
            ScanSource.scan_id == scan_id,
            ScanSource.source_id == source_id,
        )
    )
    scan_source = result.scalar_one_or_none()
    if scan_source is None:
        return
    scan_source.fetch_status = fetch_status
    scan_source.content_hash = content_hash
    scan_source.fetched_at = fetched_at
    await session.commit()


async def has_failed_sources(session: AsyncSession, scan_id: UUID) -> bool:
    result = await session.execute(
        select(ScanSource.scan_id)
        .where(
            ScanSource.scan_id == scan_id,
            ScanSource.fetch_status == "FAILED",
        )
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


async def add_scan(
    session: AsyncSession,
    scan: Scan,
    source_ids: list[UUID],
) -> Scan:
    session.add(scan)
    await session.flush()
    session.add_all(ScanSource(scan_id=scan.id, source_id=source_id) for source_id in source_ids)
    append_event(
        session,
        scan,
        message="Scan queued; source content has not been processed.",
    )
    await session.commit()
    await session.refresh(scan)
    return scan


def append_event(session: AsyncSession, scan: Scan, *, message: str) -> None:
    scan.event_sequence += 1
    session.add(
        ScanEvent(
            scan_id=scan.id,
            sequence=scan.event_sequence,
            status=scan.status,
            stage_checkpoint=scan.stage_checkpoint,
            message=message,
        )
    )


async def events_after(
    session: AsyncSession,
    scan_id: UUID,
    sequence: int,
    *,
    limit: int = 100,
) -> list[ScanEvent]:
    result = await session.execute(
        select(ScanEvent)
        .where(ScanEvent.scan_id == scan_id, ScanEvent.sequence > sequence)
        .order_by(ScanEvent.sequence)
        .limit(limit)
    )
    return list(result.scalars().all())


async def pending_scan_jobs(
    session: AsyncSession,
    *,
    limit: int,
) -> list[tuple[UUID, int]]:
    result = await session.execute(
        select(Scan.id, Scan.queue_generation)
        .where(Scan.status == "QUEUED")
        .order_by(Scan.created_at, Scan.id)
        .limit(limit)
    )
    return [(scan_id, generation) for scan_id, generation in result.all()]


async def mark_enqueue_failed(session: AsyncSession, scan: Scan) -> None:
    await session.refresh(scan, with_for_update=True)
    if scan.status == "QUEUED" and scan.stage_checkpoint == "QUEUED":
        scan.status = "FAILED"
        scan.error_code = "QUEUE_UNAVAILABLE"
        scan.finished_at = datetime.now(UTC)
        append_event(
            session,
            scan,
            message="Scan could not be queued; retry with the same key.",
        )
    await session.commit()


async def reset_enqueue_failure(session: AsyncSession, scan: Scan) -> None:
    scan.status = "QUEUED"
    scan.error_code = None
    scan.finished_at = None
    scan.queue_generation += 1
    append_event(session, scan, message="Queue retry requested.")
    await session.commit()


async def add_dead_letter(
    session: AsyncSession,
    scan: Scan,
    *,
    attempts: int,
    error_code: str,
) -> None:
    scan.status = "FAILED"
    scan.error_code = error_code
    scan.attempts = attempts
    scan.finished_at = datetime.now(UTC)
    session.add(
        ScanDeadLetter(
            scan_id=scan.id,
            attempts=attempts,
            error_code=error_code,
        )
    )
    append_event(session, scan, message="Scan failed after the configured worker retries.")
    await session.commit()
