import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.models.auth import User
from app.db.session import get_db_session
from app.modules.audit import service as audit_service
from app.modules.auth.dependencies import get_current_user
from app.modules.auth.router import CSRF_COOKIE, REFRESH_COOKIE
from app.modules.privacy.schemas import (
    AuditEntryResponse,
    AuditIntegrityResponse,
    AuditPageResponse,
)
from app.modules.privacy.service import MAX_EXPORT_BYTES, erase_user_data, export_user_data

router = APIRouter(tags=["privacy"])


@router.get("/v1/me/export")
async def export_account_data(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> Response:
    settings: Settings = request.app.state.settings
    data = await export_user_data(
        session,
        settings,
        user,
        request.client.host if request.client else None,
    )
    body = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    if len(body.encode("utf-8")) > MAX_EXPORT_BYTES:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="The account export exceeds the supported size limit",
        )
    await session.commit()
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": 'attachment; filename="privacy-shield-export.json"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.delete("/v1/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> Response:
    settings: Settings = request.app.state.settings
    await erase_user_data(
        session,
        settings,
        user,
        request.client.host if request.client else None,
    )
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(
        key=REFRESH_COOKIE,
        path="/v1/auth",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )
    response.delete_cookie(
        key=CSRF_COOKIE,
        path="/v1/auth",
        secure=settings.cookie_secure,
        httponly=False,
        samesite="strict",
    )
    return response


@router.get("/v1/privacy/audit", response_model=AuditPageResponse)
async def list_audit_entries(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    user: Annotated[User, Depends(get_current_user)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    after: Annotated[int, Query(ge=0)] = 0,
) -> AuditPageResponse:
    settings: Settings = request.app.state.settings
    entries, next_cursor = await audit_service.list_actor_entries(
        session,
        settings,
        user.id,
        after_sequence=after,
        limit=limit,
    )
    return AuditPageResponse(
        items=[AuditEntryResponse.model_validate(entry) for entry in entries],
        next_cursor=next_cursor,
    )


@router.get("/v1/privacy/audit/verify", response_model=AuditIntegrityResponse)
async def verify_audit_chain(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[User, Depends(get_current_user)],
) -> AuditIntegrityResponse:
    result = await audit_service.verify_chain(session)
    return AuditIntegrityResponse(
        valid=result.valid,
        checked_entries=result.checked_entries,
        first_invalid_sequence=result.first_invalid_sequence,
    )
