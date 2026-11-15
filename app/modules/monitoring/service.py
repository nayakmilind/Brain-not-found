from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.db.models.auth import User
from app.db.models.finding import Finding
from app.db.models.monitoring import MonitorJob, MonitorSource, ScanDiff
from app.db.models.scan import Scan
from app.db.models.scoring import RiskScore
from app.db.models.source import Source
from app.modules.consent.repository import get_active_consent
from app.modules.consent.service import CONSENT_VERSION, ConsentNotAccepted
from app.modules.monitoring.schemas import (
    MonitorCadence,
    MonitoringResponse,
    MonitoringTimelineResponse,
    ScanDiffResponse,
)
from app.modules.scans.queue import ScanJobQueue
from app.modules.scans.repository import get_scan, get_sources_for_scan
from app.modules.scans.schemas import ScanCreateRequest
from app.modules.scans.service import (
    ScanIdempotencyConflict,
    ScanNotFound,
    ScanQueueUnavailable,
    ScanService,
)
from app.modules.sources.service import SourceNotFound, SourceNotScannable, SourceService

MAX_MONITOR_JOBS_PER_DISPATCH = 50
MAX_DIFF_FINDINGS = 50_000
MAX_ALERT_DETAILS = 200
_CADENCE_DELAYS = {"DAILY": timedelta(days=1), "WEEKLY": timedelta(days=7)}


class MonitoringNotFound(Exception):
    pass


class MonitoringNotReady(Exception):
    pass


class MonitoringAlreadyExists(Exception):
    pass


class MonitoringService:
    def __init__(
        self,
        settings: Settings,
        queue: ScanJobQueue | None = None,
    ) -> None:
        self._settings = settings
        self._scans = ScanService(settings, queue) if queue is not None else None
        self._sources = SourceService(settings)

    async def create(
        self,
        session: AsyncSession,
        user_id: UUID,
        scan_id: UUID,
        cadence: MonitorCadence,
    ) -> MonitoringResponse:
        scan = await get_scan(session, scan_id, user_id=user_id)
        if scan is None:
            raise ScanNotFound
        if scan.status != "DONE" or scan.result_state != "GENERATED":
            raise MonitoringNotReady
        if await get_active_consent(session, user_id, CONSENT_VERSION) is None:
            raise ConsentNotAccepted
        existing = (
            await session.execute(
                select(MonitorJob).where(
                    MonitorJob.user_id == user_id,
                    MonitorJob.baseline_scan_id == scan_id,
                    MonitorJob.active.is_(True),
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise MonitoringAlreadyExists

        sources = await get_sources_for_scan(session, scan)
        if not sources:
            raise SourceNotScannable
        for source in sources:
            await self._sources.require_scannable(session, user_id, source.id)

        now = datetime.now(UTC)
        monitor = MonitorJob(
            id=uuid4(),
            user_id=user_id,
            baseline_scan_id=scan_id,
            last_scan_id=scan_id,
            cadence=cadence,
            next_run_at=now + _CADENCE_DELAYS[cadence],
            active=True,
        )
        session.add(monitor)
        await session.flush()
        session.add_all(
            MonitorSource(monitor_job_id=monitor.id, source_id=source.id) for source in sources
        )
        await session.commit()
        await session.refresh(monitor)
        return MonitoringResponse.model_validate(monitor)

    async def timeline(
        self,
        session: AsyncSession,
        user_id: UUID,
        monitor_id: UUID,
    ) -> MonitoringTimelineResponse:
        monitor = (
            await session.execute(
                select(MonitorJob).where(
                    MonitorJob.id == monitor_id,
                    MonitorJob.user_id == user_id,
                )
            )
        ).scalar_one_or_none()
        if monitor is None:
            raise MonitoringNotFound
        diffs = list(
            (
                await session.execute(
                    select(ScanDiff)
                    .where(ScanDiff.monitor_job_id == monitor_id)
                    .order_by(ScanDiff.created_at.desc(), ScanDiff.id.desc())
                    .limit(100)
                )
            ).scalars()
        )
        return MonitoringTimelineResponse(
            monitor=MonitoringResponse.model_validate(monitor),
            diffs=[
                ScanDiffResponse(
                    id=diff.id,
                    from_scan_id=diff.from_scan_id,
                    to_scan_id=diff.to_scan_id,
                    added=diff.added_json,
                    removed=diff.removed_json,
                    new_exposure_count=len(diff.added_json),
                    score_delta=diff.score_delta,
                    truncated=diff.truncated,
                    created_at=diff.created_at,
                )
                for diff in diffs
            ],
        )

    async def dispatch_due(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        now: datetime | None = None,
    ) -> int:
        if self._scans is None:
            raise ValueError("A scan queue is required to dispatch scheduled monitoring")
        current_time = now or datetime.now(UTC)
        async with session_factory() as session:
            due_ids = list(
                (
                    await session.execute(
                        select(MonitorJob.id)
                        .where(
                            MonitorJob.active.is_(True),
                            MonitorJob.pending_scan_id.is_(None),
                            MonitorJob.next_run_at <= current_time,
                        )
                        .order_by(MonitorJob.next_run_at, MonitorJob.id)
                        .limit(MAX_MONITOR_JOBS_PER_DISPATCH)
                    )
                ).scalars()
            )

        dispatched = 0
        for monitor_id in due_ids:
            async with session_factory() as session:
                monitor = (
                    await session.execute(
                        select(MonitorJob).where(MonitorJob.id == monitor_id).with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    monitor is None
                    or not monitor.active
                    or monitor.pending_scan_id is not None
                    or _as_utc(monitor.next_run_at) > current_time
                ):
                    continue
                user = await session.get(User, monitor.user_id)
                if user is None or user.deleted_at is not None:
                    monitor.active = False
                    monitor.pause_reason = "SOURCE_NOT_ELIGIBLE"
                    await session.commit()
                    continue
                if await get_active_consent(session, monitor.user_id, CONSENT_VERSION) is None:
                    monitor.active = False
                    monitor.pause_reason = "CONSENT_REVOKED"
                    await session.commit()
                    continue

                source_ids = list(
                    (
                        await session.execute(
                            select(MonitorSource.source_id)
                            .join(Source, Source.id == MonitorSource.source_id)
                            .where(
                                MonitorSource.monitor_job_id == monitor.id,
                                Source.user_id == monitor.user_id,
                                Source.status == "ACTIVE",
                                Source.ownership_status.in_(("VERIFIED", "SELF_DECLARED")),
                            )
                            .order_by(MonitorSource.source_id)
                        )
                    ).scalars()
                )
                all_monitored_source_ids = list(
                    (
                        await session.execute(
                            select(MonitorSource.source_id).where(
                                MonitorSource.monitor_job_id == monitor.id
                            )
                        )
                    ).scalars()
                )
                if not source_ids or set(source_ids) != set(all_monitored_source_ids):
                    monitor.active = False
                    monitor.pause_reason = "SOURCE_NOT_ELIGIBLE"
                    await session.commit()
                    continue

                scheduled_scan_id = uuid4()
                cadence = monitor.cadence
                monitor.pending_scan_id = scheduled_scan_id
                monitor.next_run_at = current_time + _CADENCE_DELAYS[cadence]
                request = ScanCreateRequest(source_ids=source_ids, mode="STANDARD")
                idempotency_key = f"monitor:{monitor.id}:{int(current_time.timestamp())}"
                try:
                    await self._scans.create(
                        session,
                        user,
                        request,
                        idempotency_key,
                        scan_id=scheduled_scan_id,
                        monitor_job_id=monitor.id,
                    )
                except ConsentNotAccepted:
                    await session.rollback()
                    await _pause_monitor(session_factory, monitor_id, "CONSENT_REVOKED")
                except (SourceNotFound, SourceNotScannable):
                    await session.rollback()
                    await _pause_monitor(session_factory, monitor_id, "SOURCE_NOT_ELIGIBLE")
                except (ScanQueueUnavailable, ScanIdempotencyConflict):
                    await session.rollback()
                    await _retry_monitor_soon(session_factory, monitor_id, current_time)
                else:
                    dispatched += 1
        return dispatched

    async def complete_scheduled_scan(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        scan_id: UUID,
    ) -> None:
        async with session_factory() as session:
            scan = await session.get(Scan, scan_id)
            if scan is None or scan.monitor_job_id is None:
                return
            monitor = (
                await session.execute(
                    select(MonitorJob)
                    .where(
                        MonitorJob.id == scan.monitor_job_id,
                        MonitorJob.pending_scan_id == scan.id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if monitor is None:
                return
            if scan.status == "CANCELLED" and scan.error_code == "CONSENT_REVOKED":
                monitor.active = False
                monitor.pause_reason = "CONSENT_REVOKED"
                monitor.pending_scan_id = None
                await session.commit()
                return
            if (
                scan.status != "DONE"
                or scan.result_state != "GENERATED"
                or scan.error_code == "PARTIAL_SOURCE_FAILURE"
            ):
                monitor.pending_scan_id = None
                await session.commit()
                return

            previous_scan_id = monitor.last_scan_id or monitor.baseline_scan_id
            current_findings = await _findings_for_diff(session, scan.id)
            previous_findings = await _findings_for_diff(session, previous_scan_id)
            old_by_key = {_finding_key(finding): finding for finding in previous_findings}
            new_by_key = {_finding_key(finding): finding for finding in current_findings}
            added_findings = [
                new_by_key[key] for key in sorted(new_by_key.keys() - old_by_key.keys())
            ]
            removed_findings = [
                old_by_key[key] for key in sorted(old_by_key.keys() - new_by_key.keys())
            ]
            score_delta = await _score_delta(session, previous_scan_id, scan.id)
            truncated = (
                len(current_findings) > MAX_DIFF_FINDINGS
                or len(previous_findings) > MAX_DIFF_FINDINGS
                or len(added_findings) > MAX_ALERT_DETAILS
                or len(removed_findings) > MAX_ALERT_DETAILS
            )
            session.add(
                ScanDiff(
                    id=uuid4(),
                    monitor_job_id=monitor.id,
                    from_scan_id=previous_scan_id,
                    to_scan_id=scan.id,
                    added_json=[
                        _masked_finding(item) for item in added_findings[:MAX_ALERT_DETAILS]
                    ],
                    removed_json=[
                        _masked_finding(item) for item in removed_findings[:MAX_ALERT_DETAILS]
                    ],
                    score_delta=score_delta,
                    truncated=truncated,
                )
            )
            monitor.last_scan_id = scan.id
            monitor.pending_scan_id = None
            await session.commit()


async def _findings_for_diff(session: AsyncSession, scan_id: UUID) -> list[Finding]:
    result = await session.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.id)
        .limit(MAX_DIFF_FINDINGS + 1)
    )
    return list(result.scalars())


def _finding_key(finding: Finding) -> tuple[str, str, str]:
    return (str(finding.source_id), finding.type, finding.value_hmac)


def _masked_finding(finding: Finding) -> dict[str, object]:
    return {
        "finding_id": str(finding.id),
        "source_id": str(finding.source_id),
        "type": finding.type,
        "masked_preview": finding.masked_preview,
        "evidence_class": finding.evidence_class,
        "confidence": finding.confidence,
    }


async def _score_delta(session: AsyncSession, previous_scan_id: UUID, current_scan_id: UUID) -> int:
    old_score = await session.scalar(
        select(RiskScore.total).where(RiskScore.scan_id == previous_scan_id)
    )
    new_score = await session.scalar(
        select(RiskScore.total).where(RiskScore.scan_id == current_scan_id)
    )
    if old_score is None or new_score is None:
        return 0
    return int(new_score) - int(old_score)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def _pause_monitor(
    session_factory: async_sessionmaker[AsyncSession],
    monitor_id: UUID,
    reason: str,
) -> None:
    async with session_factory() as session:
        monitor = await session.get(MonitorJob, monitor_id, with_for_update=True)
        if monitor is not None:
            monitor.active = False
            monitor.pending_scan_id = None
            monitor.pause_reason = reason
            await session.commit()


async def _retry_monitor_soon(
    session_factory: async_sessionmaker[AsyncSession],
    monitor_id: UUID,
    now: datetime,
) -> None:
    async with session_factory() as session:
        monitor = await session.get(MonitorJob, monitor_id, with_for_update=True)
        if monitor is not None:
            monitor.pending_scan_id = None
            monitor.next_run_at = now + timedelta(minutes=5)
            await session.commit()
