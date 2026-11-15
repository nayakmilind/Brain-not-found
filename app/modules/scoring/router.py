from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.auth import User
from app.db.session import get_db_session
from app.modules.auth.dependencies import get_current_user
from app.modules.scans.service import ScanNotFound
from app.modules.scoring.schemas import (
    AttackerViewResponse,
    ScoreResponse,
    SimulationRequest,
    SimulationResponse,
    UniquenessResponse,
)
from app.modules.scoring.service import (
    InvalidSimulation,
    ScoringNotReady,
    ScoringService,
)

router = APIRouter(prefix="/v1/scans", tags=["scoring"])


@router.get("/{scan_id}/score", response_model=ScoreResponse)
async def get_scan_score(
    scan_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> ScoreResponse:
    try:
        return await ScoringService().get_score(session, user.id, scan_id)
    except ScanNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        ) from error
    except ScoringNotReady as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Risk score is not available until scan processing is complete",
        ) from error


@router.get("/{scan_id}/uniqueness", response_model=UniquenessResponse)
async def get_scan_uniqueness(
    scan_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> UniquenessResponse:
    try:
        return await ScoringService().get_uniqueness(session, user.id, scan_id)
    except ScanNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        ) from error
    except ScoringNotReady as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Uniqueness estimate is not available until scan processing is complete",
        ) from error


@router.get("/{scan_id}/attacker-view", response_model=AttackerViewResponse)
async def get_scan_attacker_view(
    scan_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> AttackerViewResponse:
    try:
        return await ScoringService().get_attacker_view(session, user.id, scan_id)
    except ScanNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        ) from error
    except ScoringNotReady as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Attacker view is not available until scan processing is complete",
        ) from error


@router.post("/{scan_id}/simulate", response_model=SimulationResponse)
async def simulate_scan(
    scan_id: UUID,
    payload: SimulationRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> SimulationResponse:
    try:
        return await ScoringService().simulate(
            session,
            user.id,
            scan_id,
            payload.remove_findings,
        )
    except ScanNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        ) from error
    except ScoringNotReady as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Simulation is not available until scan processing is complete",
        ) from error
    except InvalidSimulation as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="One or more finding IDs are not part of this scan",
        ) from error
