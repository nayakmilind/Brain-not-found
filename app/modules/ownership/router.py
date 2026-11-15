from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.ssrf_guard import SafeFetcher
from app.db.models.auth import User
from app.db.models.source import OwnershipChallenge
from app.db.session import get_db_session
from app.modules.auth.dependencies import get_current_user
from app.modules.consent.service import ConsentNotAccepted
from app.modules.ownership.email import SMTPDeliveryError, SMTPNotConfigured
from app.modules.ownership.schemas import (
    OwnershipChallengeRequest,
    OwnershipChallengeResponse,
    OwnershipMethod,
    OwnershipVerifyRequest,
    OwnershipVerifyResponse,
)
from app.modules.ownership.service import (
    ChallengeAlreadyActive,
    ChallengeAttemptsExceeded,
    ChallengeExpired,
    EmailDomainMismatch,
    InvalidOwnershipMethod,
    InvalidOwnershipProof,
    OwnershipNotFound,
    OwnershipService,
    VerificationUnavailable,
)

router = APIRouter(prefix="/v1/sources/{source_id}/ownership", tags=["ownership"])


def get_ownership_service(request: Request) -> OwnershipService:
    settings: Settings = request.app.state.settings
    fetcher: SafeFetcher = request.app.state.safe_fetcher
    return OwnershipService(settings, fetcher)


def _challenge_response(
    method: OwnershipMethod,
    challenge: OwnershipChallenge | None,
    token: str | None,
    already_verified: bool,
) -> OwnershipChallengeResponse:
    if method == "BIO_TOKEN":
        instructions = (
            f"Place the visible text `{token}` in the public profile bio, then verify it here. "
            "Remove the token after verification."
        )
    elif method == "META_TAG":
        instructions = (
            "Add a meta tag to the public page: "
            f'<meta name="privacy-shield-verification" content="{token}">.'
        )
    elif method == "DNS_TXT":
        instructions = (
            f"Add a DNS TXT record named `_privacy-shield-verification` with value `{token}`."
        )
    elif method == "EMAIL_OTP":
        instructions = "Enter the one-time code sent to the matching-domain email address."
    else:
        instructions = "Confirm that this pasted or uploaded source is your own."

    if already_verified:
        ownership_status: Literal["PENDING", "VERIFIED", "SELF_DECLARED"] = (
            "SELF_DECLARED" if method == "SELF_DECLARE" else "VERIFIED"
        )
    else:
        ownership_status = "PENDING"
    return OwnershipChallengeResponse(
        challenge_id=challenge.id if challenge is not None else None,
        method=method,
        ownership_status=ownership_status,
        token=token,
        instructions=instructions,
        expires_at=challenge.expires_at if challenge is not None else None,
    )


@router.post("/challenge", response_model=OwnershipChallengeResponse)
async def create_ownership_challenge(
    source_id: UUID,
    payload: OwnershipChallengeRequest,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    service: Annotated[OwnershipService, Depends(get_ownership_service)],
) -> OwnershipChallengeResponse:
    try:
        challenge, token, already_verified = await service.create_challenge(
            session,
            user,
            source_id=source_id,
            method=payload.method,
            email=str(payload.email) if payload.email is not None else None,
        )
    except OwnershipNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Source not found",
        ) from error
    except ConsentNotAccepted as error:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Current consent is required before verifying a source",
        ) from error
    except InvalidOwnershipMethod as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="The selected ownership method is not valid for this source",
        ) from error
    except EmailDomainMismatch as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="The email domain must match the source domain or a parent domain",
        ) from error
    except ChallengeAlreadyActive as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An active ownership challenge already exists",
        ) from error
    except SMTPNotConfigured as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email ownership verification is not configured",
        ) from error
    except SMTPDeliveryError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The verification email could not be delivered",
        ) from error
    return _challenge_response(payload.method, challenge, token, already_verified)


@router.post("/verify", response_model=OwnershipVerifyResponse)
async def verify_ownership(
    source_id: UUID,
    payload: OwnershipVerifyRequest,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    service: Annotated[OwnershipService, Depends(get_ownership_service)],
) -> OwnershipVerifyResponse:
    try:
        await service.verify(
            session,
            user,
            source_id=source_id,
            challenge_id=payload.challenge_id,
            proof=payload.proof,
        )
    except OwnershipNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Ownership challenge not found",
        ) from error
    except ChallengeExpired as error:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Ownership challenge has expired",
        ) from error
    except ChallengeAttemptsExceeded as error:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Ownership challenge attempt limit exceeded",
        ) from error
    except InvalidOwnershipProof as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ownership proof did not match",
        ) from error
    except VerificationUnavailable as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ownership proof could not be checked safely; try again later",
        ) from error
    return OwnershipVerifyResponse(verified=True, ownership_status="VERIFIED")
