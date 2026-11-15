from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.models.auth import User
from app.db.session import get_db_session
from app.modules.auth.dependencies import get_current_user
from app.modules.reports.schemas import ReportCreatedResponse, ReportCreateRequest
from app.modules.reports.service import (
    ReportNotFound,
    ReportNotReady,
    ReportService,
    ReportTooLarge,
)
from app.modules.scans.service import ScanNotFound

router = APIRouter(tags=["reports"])


@router.post(
    "/v1/scans/{scan_id}/report",
    response_model=ReportCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_scan_report(
    scan_id: UUID,
    payload: ReportCreateRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> ReportCreatedResponse:
    settings: Settings = request.app.state.settings
    try:
        report = await ReportService().create(
            session,
            settings,
            user,
            scan_id,
            payload.format,
            request.client.host if request.client else None,
        )
    except ScanNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        ) from error
    except ReportNotReady as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Reports are not available until scan processing is complete",
        ) from error
    except ReportTooLarge as error:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="The report exceeds the supported size limit",
        ) from error
    return ReportCreatedResponse.model_validate(report)


@router.get("/v1/reports/{report_id}/download")
async def download_report(
    report_id: UUID,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> Response:
    settings: Settings = request.app.state.settings
    try:
        report = await ReportService().get_for_user(
            session,
            settings,
            user.id,
            report_id,
            request.client.host if request.client else None,
        )
    except ReportNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        ) from error
    content_types = {
        "json": "application/json",
        "html": "text/html; charset=utf-8",
        "pdf": "application/pdf",
    }
    return Response(
        content=report.content,
        media_type=content_types[report.format],
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'attachment; filename="privacy-shield-report.{report.format}"',
            "X-Content-Type-Options": "nosniff",
        },
    )
