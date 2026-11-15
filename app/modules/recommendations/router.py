from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.auth import User
from app.db.session import get_db_session
from app.modules.auth.dependencies import get_current_user
from app.modules.recommendations.schemas import (
    RecommendationResponse,
    RecommendationStatusRequest,
    RecommendationStatusResponse,
)
from app.modules.recommendations.service import (
    RecommendationNotFound,
    RecommendationService,
    RecommendationsNotReady,
)
from app.modules.scans.service import ScanNotFound

router = APIRouter(tags=["recommendations"])


@router.get(
    "/v1/scans/{scan_id}/recommendations",
    response_model=list[RecommendationResponse],
)
async def list_recommendations(
    scan_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> list[RecommendationResponse]:
    try:
        return await RecommendationService().list_for_scan(session, user.id, scan_id)
    except ScanNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        ) from error
    except RecommendationsNotReady as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Recommendations are not available until scan processing is complete",
        ) from error


@router.patch(
    "/v1/recommendations/{recommendation_id}",
    response_model=RecommendationStatusResponse,
)
async def update_recommendation(
    recommendation_id: UUID,
    payload: RecommendationStatusRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> RecommendationStatusResponse:
    try:
        record = await RecommendationService().update_status(
            session,
            user.id,
            recommendation_id,
            payload.status,
        )
    except RecommendationNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recommendation not found",
        ) from error
    return RecommendationStatusResponse.model_validate(record)
