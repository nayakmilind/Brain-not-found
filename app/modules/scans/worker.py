from __future__ import annotations

import os
from typing import Any, cast
from uuid import UUID

import structlog
from arq import Retry
from arq.connections import ArqRedis, RedisSettings
from arq.cron import cron
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings
from app.core.logging import configure_logging
from app.core.ssrf_guard import SafeFetcher
from app.modules.monitoring.service import MonitoringService
from app.modules.scans import repository
from app.modules.scans.queue import ArqScanQueue, QueueUnavailable
from app.modules.scans.service import dead_letter_scan, run_scan_pipeline
from app.pipeline.runner import ScanContentPipeline

logger = structlog.get_logger(__name__)
MAX_JOB_TRIES = 3


async def startup(ctx: dict[str, Any]) -> None:
    settings = Settings()
    configure_logging(settings.log_level)
    engine = create_async_engine(
        settings.database_url.get_secret_value(),
        pool_pre_ping=True,
    )
    ctx["db_engine"] = engine
    ctx["session_factory"] = async_sessionmaker(engine, expire_on_commit=False)
    ctx["settings"] = settings
    ctx["safe_fetcher"] = SafeFetcher(
        max_bytes=settings.source_max_bytes,
        timeout_seconds=settings.source_fetch_timeout_seconds,
        max_redirects=settings.source_max_redirects,
    )


async def shutdown(ctx: dict[str, Any]) -> None:
    engine = cast(AsyncEngine, ctx["db_engine"])
    await engine.dispose()


async def dispatch_pending_scans(ctx: dict[str, Any]) -> None:
    session_factory = cast(
        async_sessionmaker[AsyncSession],
        ctx["session_factory"],
    )
    pool = cast(ArqRedis, ctx["redis"])
    async with session_factory() as session:
        pending = await repository.pending_scan_jobs(session, limit=100)
    queue = ArqScanQueue(pool)
    for scan_id, generation in pending:
        try:
            await queue.enqueue_scan(scan_id, generation)
        except QueueUnavailable as error:
            logger.warning(
                "scan_dispatch_failed",
                scan_id=str(scan_id),
                error_type=type(error).__name__,
            )
            break


async def dispatch_due_monitors(ctx: dict[str, Any]) -> None:
    session_factory = cast(async_sessionmaker[AsyncSession], ctx["session_factory"])
    pool = cast(ArqRedis, ctx["redis"])
    settings = cast(Settings, ctx["settings"])
    await MonitoringService(settings, ArqScanQueue(pool)).dispatch_due(session_factory)


async def run_scan(ctx: dict[str, Any], scan_id: str) -> None:
    parsed_scan_id = UUID(scan_id)
    settings = cast(Settings, ctx["settings"])
    session_factory = cast(
        async_sessionmaker[AsyncSession],
        ctx["session_factory"],
    )
    attempt = int(ctx.get("job_try", 1))
    try:
        safe_fetcher = cast(SafeFetcher, ctx["safe_fetcher"])
        pipeline = ScanContentPipeline(
            session_factory,
            parsed_scan_id,
            settings,
            safe_fetcher,
        )
        await run_scan_pipeline(
            session_factory,
            parsed_scan_id,
            stage_runner=pipeline.run_stage,
            attempt_number=attempt,
        )
    except Exception as error:
        logger.warning(
            "scan_job_failed",
            scan_id=str(parsed_scan_id),
            attempt=attempt,
            error_type=type(error).__name__,
        )
        if attempt < MAX_JOB_TRIES:
            raise Retry(defer=min(2 ** (attempt - 1), 30)) from error
        await dead_letter_scan(
            session_factory,
            parsed_scan_id,
            attempts=attempt,
            error_code="WORKER_RETRIES_EXHAUSTED",
        )
        await MonitoringService(settings).complete_scheduled_scan(session_factory, parsed_scan_id)
        return
    await MonitoringService(settings).complete_scheduled_scan(session_factory, parsed_scan_id)


class WorkerSettings:
    functions = [run_scan]
    cron_jobs = [
        cron(
            dispatch_due_monitors,
            minute={0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55},
            run_at_startup=True,
        ),
        cron(
            dispatch_pending_scans,
            second={0, 10, 20, 30, 40, 50},
            run_at_startup=True,
        ),
    ]
    redis_settings = RedisSettings.from_dsn(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    on_startup = startup
    on_shutdown = shutdown
    max_jobs = 10
    max_tries = MAX_JOB_TRIES
    retry_jobs = True
    job_timeout = 60
    keep_result = 3600
