from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.models.auth import User
from app.db.session import get_db_session
from app.modules.auth.dependencies import get_current_user
from app.modules.consent.service import ConsentNotAccepted
from app.modules.demo.schemas import PersonaCreateRequest, PersonaScanResponse
from app.modules.demo.service import SyntheticPersonaService, SyntheticScanConflict
from app.modules.scans.queue import ScanJobQueue
from app.modules.scans.service import ScanIdempotencyConflict, ScanQueueUnavailable

router = APIRouter(prefix="/v1/demo", tags=["demo"])


@router.post("/persona", response_model=PersonaScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_synthetic_persona(
    payload: PersonaCreateRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> PersonaScanResponse:
    settings: Settings = request.app.state.settings
    queue: ScanJobQueue = request.app.state.scan_queue
    try:
        return await SyntheticPersonaService(settings, queue).create_scan(
            session,
            user,
            seed=payload.seed,
            pattern=payload.pattern,
        )
    except ConsentNotAccepted as error:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Current consent is required to create a demo scan",
        ) from error
    except ScanIdempotencyConflict as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The seed was already used with a different demo request",
        ) from error
    except ScanQueueUnavailable as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The scan queue is unavailable; retry the same demo seed",
            headers={"Retry-After": "2"},
        ) from error
    except SyntheticScanConflict as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The previous demo scan no longer has its synthetic source",
        ) from error
