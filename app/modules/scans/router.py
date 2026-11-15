from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.db.models.auth import User
from app.db.session import get_db_session
from app.modules.auth.dependencies import get_current_user
from app.modules.consent.service import ConsentNotAccepted
from app.modules.scans import repository
from app.modules.scans.queue import ScanJobQueue
from app.modules.scans.schemas import ScanCreateRequest, ScanResponse
from app.modules.scans.service import (
    ScanIdempotencyConflict,
    ScanNotFound,
    ScanQueueUnavailable,
    ScanService,
)
from app.modules.sources.service import SourceNotFound, SourceNotScannable

router = APIRouter(prefix="/v1/scans", tags=["scans"])


def get_scan_service(request: Request) -> ScanService:
    settings: Settings = request.app.state.settings
    queue: ScanJobQueue = request.app.state.scan_queue
    return ScanService(settings, queue)


@router.post("", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: ScanCreateRequest,
    idempotency_key: Annotated[
        str,
        Header(
            alias="Idempotency-Key",
            min_length=8,
            max_length=128,
            pattern=r"^[A-Za-z0-9._~:-]+$",
        ),
    ],
    service: Annotated[ScanService, Depends(get_scan_service)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> ScanResponse:
    try:
        scan = await service.create(session, user, payload, idempotency_key)
    except ConsentNotAccepted as error:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Current consent is required to start a scan",
        ) from error
    except SourceNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or more sources were not found",
        ) from error
    except SourceNotScannable as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Every URL source must be verified before scanning",
        ) from error
    except ScanIdempotencyConflict as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Idempotency-Key was already used with a different request",
        ) from error
    except ScanQueueUnavailable as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The scan queue is unavailable; retry with the same Idempotency-Key",
            headers={"Retry-After": "2"},
        ) from error
    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    service: Annotated[ScanService, Depends(get_scan_service)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> ScanResponse:
    try:
        scan = await service.get(session, user.id, scan_id)
    except ScanNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        ) from error
    return ScanResponse.model_validate(scan)


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    scan_id: UUID,
    service: Annotated[ScanService, Depends(get_scan_service)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> ScanResponse:
    try:
        scan = await service.cancel(session, user.id, scan_id)
    except ScanNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        ) from error
    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}/events")
async def scan_events(
    scan_id: UUID,
    request: Request,
    service: Annotated[ScanService, Depends(get_scan_service)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
    last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
) -> StreamingResponse:
    try:
        after = int(last_event_id or "0")
        if after < 0:
            raise ValueError
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Last-Event-ID must be a non-negative integer",
        ) from error
    try:
        await service.get(session, user.id, scan_id)
    except ScanNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        ) from error

    session_factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory

    async def stream() -> AsyncIterator[str]:
        nonlocal after
        while not await request.is_disconnected():
            async with session_factory() as stream_session:
                events = await service.events_after(stream_session, scan_id, after)
                scan = await repository.get_scan(stream_session, scan_id)
            for event in events:
                data = json.dumps(
                    {
                        "scan_id": str(scan_id),
                        "status": event.status,
                        "stage_checkpoint": event.stage_checkpoint,
                        "message": event.message,
                        "created_at": event.created_at.isoformat(),
                    },
                    separators=(",", ":"),
                )
                after = event.sequence
                yield f"id: {event.sequence}\nevent: progress\ndata: {data}\n\n"
            if scan is None or scan.status in {"DONE", "FAILED", "CANCELLED"}:
                break
            await asyncio.sleep(0.25)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
