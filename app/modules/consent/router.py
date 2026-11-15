from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.models.auth import User
from app.db.models.consent import Consent
from app.db.session import get_db_session
from app.modules.auth.dependencies import get_current_user
from app.modules.consent.schemas import (
    ConsentAcceptRequest,
    ConsentCurrentVersionResponse,
    ConsentRevocationResponse,
    ConsentStateResponse,
)
from app.modules.consent.service import (
    CONSENT_SCOPE,
    CONSENT_STATEMENTS,
    CONSENT_VERSION,
    ConsentNotAccepted,
    ConsentService,
    UnsupportedConsentVersion,
)

router = APIRouter(prefix="/v1/consent", tags=["consent"])


def get_consent_service(request: Request) -> ConsentService:
    settings: Settings = request.app.state.settings
    return ConsentService(settings)


def _consent_state(consent: Consent | None) -> ConsentStateResponse:
    if consent is None:
        return ConsentStateResponse(
            accepted=False,
            version=CONSENT_VERSION,
            scope=CONSENT_SCOPE.copy(),
            accepted_at=None,
        )
    return ConsentStateResponse(
        accepted=True,
        version=consent.version,
        scope=consent.scope_json,
        accepted_at=consent.accepted_at,
    )


@router.get("/current-version", response_model=ConsentCurrentVersionResponse)
async def current_version() -> ConsentCurrentVersionResponse:
    return ConsentCurrentVersionResponse(
        scope=CONSENT_SCOPE.copy(),
        statements=CONSENT_STATEMENTS,
    )


@router.get("/current", response_model=ConsentStateResponse)
async def current_consent(
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    service: Annotated[ConsentService, Depends(get_consent_service)],
) -> ConsentStateResponse:
    return _consent_state(await service.status(session, user.id))


@router.post("/accept", response_model=ConsentStateResponse)
async def accept_consent(
    payload: ConsentAcceptRequest,
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    service: Annotated[ConsentService, Depends(get_consent_service)],
) -> ConsentStateResponse:
    try:
        consent = await service.accept(
            session,
            user_id=user.id,
            version=payload.version,
            accepted=payload.accepted,
            client_ip=request.client.host if request.client else "unknown",
        )
    except UnsupportedConsentVersion as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The consent version is no longer current",
        ) from error
    except ConsentNotAccepted as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Consent must be explicitly accepted",
        ) from error
    return _consent_state(consent)


@router.post("/revoke", response_model=ConsentRevocationResponse)
async def revoke_consent(
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    service: Annotated[ConsentService, Depends(get_consent_service)],
) -> ConsentRevocationResponse:
    revoked, revoked_at = await service.revoke(session, user.id)
    return ConsentRevocationResponse(revoked=revoked, revoked_at=revoked_at)
