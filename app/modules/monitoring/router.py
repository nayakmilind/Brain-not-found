from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.models.auth import User
from app.db.session import get_db_session
from app.modules.auth.dependencies import get_current_user
from app.modules.consent.service import ConsentNotAccepted
from app.modules.monitoring.schemas import (
    MonitoringCreateRequest,
    MonitoringResponse,
    MonitoringTimelineResponse,
)
from app.modules.monitoring.service import (
    MonitoringAlreadyExists,
    MonitoringNotFound,
    MonitoringNotReady,
    MonitoringService,
)
from app.modules.scans.service import ScanNotFound
from app.modules.sources.service import SourceNotScannable

router = APIRouter(prefix="/v1/monitoring", tags=["monitoring"])


@router.post("", response_model=MonitoringResponse, status_code=status.HTTP_201_CREATED)
async def create_monitoring(
    payload: MonitoringCreateRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> MonitoringResponse:
    settings: Settings = request.app.state.settings
    try:
        return await MonitoringService(settings).create(
            session,
            user.id,
            payload.scan_id,
            payload.cadence,
        )
    except ScanNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        ) from error
    except MonitoringNotReady as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Monitoring requires a completed scan with generated results",
        ) from error
    except ConsentNotAccepted as error:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Current consent is required to enable monitoring",
        ) from error
    except SourceNotScannable as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Every monitored source must remain eligible for scanning",
        ) from error
    except MonitoringAlreadyExists as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An active monitor already exists for this scan",
        ) from error


@router.get("/{monitor_id}/timeline", response_model=MonitoringTimelineResponse)
async def monitoring_timeline(
    monitor_id: UUID,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> MonitoringTimelineResponse:
    settings: Settings = request.app.state.settings
    try:
        return await MonitoringService(settings).timeline(session, user.id, monitor_id)
    except MonitoringNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Monitoring job not found",
        ) from error
