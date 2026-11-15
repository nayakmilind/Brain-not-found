from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.crypto import decode_key, hmac_value
from app.db.models.auth import User
from app.db.models.scan import Scan, ScanEvent
from app.modules.consent.repository import get_active_consent
from app.modules.consent.service import CONSENT_VERSION, require_current_consent
from app.modules.scans import repository
from app.modules.scans.queue import QueueUnavailable, ScanJobQueue
from app.modules.scans.schemas import ScanCreateRequest
from app.modules.sources.service import SourceNotFound, SourceService

TERMINAL_STATUSES = frozenset({"DONE", "FAILED", "CANCELLED"})
PIPELINE_STAGES = ("FETCHING", "ANALYZING", "SCORING", "RECOMMENDING")
CHECKPOINT_RANK = {
    "QUEUED": 0,
    "FETCHING": 1,
    "ANALYZING": 2,
    "SCORING": 3,
    "RECOMMENDING": 4,
    "DONE": 5,
}
STAGE_MESSAGES = {
    "FETCHING": "Retrieving eligible URL sources and loading declared source content.",
    "ANALYZING": "Detecting exposures from extracted content; masked findings are persisted.",
    "SCORING": "Building the exposure graph and explainable risk score.",
    "RECOMMENDING": "Calculating playbook recommendations and simulated score gains.",
}


class ScanNotFound(Exception):
    pass


class ScanIdempotencyConflict(Exception):
    pass


class ScanQueueUnavailable(Exception):
    pass


class ScanService:
    def __init__(self, settings: Settings, queue: ScanJobQueue) -> None:
        self._settings = settings
        self._pepper = decode_key(settings.hmac_pepper_b64.get_secret_value())
        self._queue = queue
        self._sources = SourceService(settings)

    async def create(
        self,
        session: AsyncSession,
        user: User,
        request: ScanCreateRequest,
        idempotency_key: str,
        *,
        scan_id: UUID | None = None,
        monitor_job_id: UUID | None = None,
    ) -> Scan:
        await require_current_consent(session, user.id)
        key_hash = hmac_value(
            f"scan-idempotency:{user.id}:{idempotency_key}",
            self._pepper,
        )
        fingerprint = self._request_fingerprint(request)
        existing = await repository.get_scan_by_idempotency_key(
            session,
            user.id,
            key_hash,
            for_update=True,
        )
        if existing is not None:
            return await self._reuse(session, existing, fingerprint)

        await self._validate_sources(session, user.id, request.source_ids)
        scan = Scan(
            id=scan_id or uuid4(),
            user_id=user.id,
            mode=request.mode,
            idempotency_key_hash=key_hash,
            request_fingerprint=fingerprint,
            monitor_job_id=monitor_job_id,
        )
        try:
            await repository.add_scan(session, scan, request.source_ids)
        except IntegrityError:
            await session.rollback()
            existing = await repository.get_scan_by_idempotency_key(
                session,
                user.id,
                key_hash,
                for_update=True,
            )
            if existing is None:
                raise
            return await self._reuse(session, existing, fingerprint)

        await self._enqueue(session, scan)
        return scan

    async def _reuse(
        self,
        session: AsyncSession,
        scan: Scan,
        fingerprint: str,
    ) -> Scan:
        if scan.request_fingerprint != fingerprint:
            raise ScanIdempotencyConflict
        if scan.status == "FAILED" and scan.error_code == "QUEUE_UNAVAILABLE":
            await repository.reset_enqueue_failure(session, scan)
            await self._enqueue(session, scan)
        return scan

    async def _enqueue(self, session: AsyncSession, scan: Scan) -> None:
        try:
            await self._queue.enqueue_scan(scan.id, scan.queue_generation)
        except QueueUnavailable as error:
            await repository.mark_enqueue_failed(session, scan)
            raise ScanQueueUnavailable from error

    async def _validate_sources(
        self,
        session: AsyncSession,
        user_id: UUID,
        source_ids: list[UUID],
    ) -> None:
        sources = await repository.get_sources(session, user_id, source_ids)
        if len(sources) != len(source_ids):
            raise SourceNotFound
        for source_id in source_ids:
            await self._sources.require_scannable(session, user_id, source_id)

    @staticmethod
    def _request_fingerprint(request: ScanCreateRequest) -> str:
        canonical_request = json.dumps(
            {
                "mode": request.mode,
                "source_ids": sorted(str(source_id) for source_id in request.source_ids),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()

    async def get(
        self,
        session: AsyncSession,
        user_id: UUID,
        scan_id: UUID,
    ) -> Scan:
        scan = await repository.get_scan(session, scan_id, user_id=user_id)
        if scan is None:
            raise ScanNotFound
        return scan

    async def cancel(
        self,
        session: AsyncSession,
        user_id: UUID,
        scan_id: UUID,
    ) -> Scan:
        scan = await repository.get_scan(
            session,
            scan_id,
            user_id=user_id,
            for_update=True,
        )
        if scan is None:
            raise ScanNotFound
        if scan.status not in TERMINAL_STATUSES:
            scan.status = "CANCELLED"
            scan.error_code = None
            scan.finished_at = datetime.now(UTC)
            repository.append_event(
                session,
                scan,
                message="Scan cancellation requested.",
            )
            await session.commit()
            await session.refresh(scan)
        return scan

    async def events_after(
        self,
        session: AsyncSession,
        scan_id: UUID,
        sequence: int,
    ) -> list[ScanEvent]:
        return await repository.events_after(session, scan_id, sequence)


async def run_scan_pipeline(
    session_factory: async_sessionmaker[AsyncSession],
    scan_id: UUID,
    *,
    stage_runner: Callable[[str], Awaitable[None]],
    attempt_number: int = 1,
) -> None:
    for stage in PIPELINE_STAGES:
        async with session_factory() as session:
            scan = await repository.get_scan(session, scan_id, for_update=True)
            if scan is None or scan.status in TERMINAL_STATUSES:
                return
            consent = await get_active_consent(session, scan.user_id, CONSENT_VERSION)
            if consent is None:
                scan.status = "CANCELLED"
                scan.error_code = "CONSENT_REVOKED"
                scan.finished_at = datetime.now(UTC)
                repository.append_event(
                    session,
                    scan,
                    message="Consent is no longer active; scan cancelled.",
                )
                await session.commit()
                return
            sources = await repository.get_sources_for_scan(session, scan)
            if not sources or any(
                source.status != "ACTIVE"
                or source.ownership_status not in {"VERIFIED", "SELF_DECLARED"}
                for source in sources
            ):
                scan.status = "FAILED"
                scan.error_code = "SOURCE_NOT_ELIGIBLE"
                scan.finished_at = datetime.now(UTC)
                repository.append_event(
                    session,
                    scan,
                    message="A source is no longer eligible; scan failed.",
                )
                await session.commit()
                return
            if CHECKPOINT_RANK.get(scan.stage_checkpoint, -1) >= CHECKPOINT_RANK[stage]:
                continue
            scan.status = stage
            scan.attempts = max(scan.attempts, attempt_number)
            if scan.started_at is None:
                scan.started_at = datetime.now(UTC)
            repository.append_event(session, scan, message=STAGE_MESSAGES[stage])
            await session.commit()

        await stage_runner(stage)

        async with session_factory() as session:
            scan = await repository.get_scan(session, scan_id, for_update=True)
            if scan is None or scan.status in TERMINAL_STATUSES:
                return
            scan.stage_checkpoint = stage
            repository.append_event(
                session,
                scan,
                message=f"{stage.title()} checkpoint saved.",
            )
            await session.commit()

    async with session_factory() as session:
        scan = await repository.get_scan(session, scan_id, for_update=True)
        if scan is None or scan.status in TERMINAL_STATUSES:
            return
        scan.status = "DONE"
        scan.stage_checkpoint = "DONE"
        scan.attempts = max(scan.attempts, attempt_number)
        scan.finished_at = datetime.now(UTC)
        has_failures = await repository.has_failed_sources(session, scan_id)
        scan.error_code = "PARTIAL_SOURCE_FAILURE" if has_failures else None
        if scan.result_state == "GENERATED":
            message = (
                (
                    "Some sources could not be processed; masked findings, exposure graph, "
                    "risk score, and recommendations are available."
                )
                if has_failures
                else (
                    "Detection, exposure graph, and risk score complete; masked findings "
                    "and recommendations are available."
                )
            )
        else:
            message = (
                "Some sources could not be processed; no findings or score were generated."
                if has_failures
                else "Extraction complete; no findings or score were generated."
            )
        repository.append_event(
            session,
            scan,
            message=message,
        )
        await session.commit()


async def dead_letter_scan(
    session_factory: async_sessionmaker[AsyncSession],
    scan_id: UUID,
    *,
    attempts: int,
    error_code: str,
) -> None:
    async with session_factory() as session:
        scan = await repository.get_scan(session, scan_id, for_update=True)
        if scan is None or scan.status in TERMINAL_STATUSES:
            return
        await repository.add_dead_letter(
            session,
            scan,
            attempts=attempts,
            error_code=error_code,
        )
