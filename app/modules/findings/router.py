import json
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.models.auth import User
from app.db.session import get_db_session
from app.modules.auth.dependencies import get_current_user
from app.modules.findings.schemas import (
    EvidenceClass,
    FindingCategory,
    FindingResponse,
    FindingsPage,
)
from app.modules.findings.service import (
    FindingNotRevealable,
    FindingRevealDataInvalid,
    FindingsNotReady,
    FindingsService,
)
from app.modules.scans.service import ScanNotFound

router = APIRouter(prefix="/v1/scans", tags=["findings"])
reveal_router = APIRouter(prefix="/v1/findings", tags=["findings"])


@reveal_router.post("/{finding_id}/reveal")
async def reveal_finding(
    finding_id: UUID,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> Response:
    settings: Settings = request.app.state.settings
    try:
        value = await FindingsService().reveal_for_user(
            session,
            settings,
            user,
            finding_id,
            request.client.host if request.client else None,
        )
    except ScanNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        ) from error
    except FindingNotRevealable as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This finding has no revealable value",
        ) from error
    except FindingRevealDataInvalid as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The encrypted finding could not be safely revealed",
        ) from error
    return Response(
        content=json.dumps({"finding_id": str(finding_id), "value": value}),
        media_type="application/json",
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


@router.get("/{scan_id}/findings", response_model=FindingsPage)
async def list_scan_findings(
    scan_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: UUID | None = None,
    category: FindingCategory | None = None,
    evidence_class: EvidenceClass | None = None,
) -> FindingsPage:
    try:
        findings, next_cursor = await FindingsService().list_for_user(
            session,
            user.id,
            scan_id,
            limit=limit,
            cursor=cursor,
            category=category,
            evidence_class=evidence_class,
        )
    except ScanNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        ) from error
    except FindingsNotReady as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Findings are not available until scan detection is complete",
        ) from error
    return FindingsPage(
        items=[FindingResponse.model_validate(item) for item in findings],
        next_cursor=next_cursor,
    )
