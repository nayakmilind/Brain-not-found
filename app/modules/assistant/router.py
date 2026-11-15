from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.models.auth import User
from app.db.session import get_db_session
from app.modules.assistant.schemas import AssistantRequest, AssistantResponse
from app.modules.assistant.service import AssistantNotReady, AssistantService
from app.modules.auth.dependencies import get_current_user
from app.modules.scans.service import ScanNotFound

router = APIRouter(prefix="/v1/assistant", tags=["assistant"])


@router.post("/ask", response_model=AssistantResponse)
async def ask_assistant(
    payload: AssistantRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> AssistantResponse:
    settings: Settings = request.app.state.settings
    try:
        return await AssistantService(settings).ask(session, user.id, payload)
    except ScanNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        ) from error
    except AssistantNotReady as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Assistant context is not available until scan processing is complete",
        ) from error
