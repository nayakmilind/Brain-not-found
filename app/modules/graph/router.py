from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.auth import User
from app.db.session import get_db_session
from app.modules.auth.dependencies import get_current_user
from app.modules.graph.schemas import GraphResponse
from app.modules.graph.service import GraphNotReady, GraphService
from app.modules.scans.service import ScanNotFound

router = APIRouter(prefix="/v1/scans", tags=["graph"])


@router.get("/{scan_id}/graph", response_model=GraphResponse)
async def get_scan_graph(
    scan_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> GraphResponse:
    try:
        return await GraphService().get_for_user(session, user.id, scan_id)
    except ScanNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        ) from error
    except GraphNotReady as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Exposure graph is not available until scan processing is complete",
        ) from error
