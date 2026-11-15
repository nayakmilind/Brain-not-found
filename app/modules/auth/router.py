import secrets
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.session import get_db_session
from app.modules.auth.schemas import CredentialsRequest, TokenResponse
from app.modules.auth.service import (
    AuthService,
    AuthTokens,
    DuplicateEmail,
    InvalidCredentials,
    RefreshTokenReuse,
)

router = APIRouter(prefix="/v1/auth", tags=["auth"])
REFRESH_COOKIE = "psai_refresh"
CSRF_COOKIE = "psai_csrf"
REFRESH_COOKIE_PATH = "/v1/auth"
CSRF_COOKIE_PATH = "/"


def get_auth_service(request: Request) -> AuthService:
    service = request.app.state.auth_service
    if not isinstance(service, AuthService):
        raise RuntimeError("Authentication service is unavailable")
    return service


def _validate_csrf(request: Request, csrf_header: str | None) -> None:
    csrf_cookie = request.cookies.get(CSRF_COOKIE)
    if (
        csrf_cookie is None
        or csrf_header is None
        or not secrets.compare_digest(csrf_cookie, csrf_header)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed",
        )


def _token_response(tokens: AuthTokens, settings: Settings) -> TokenResponse:
    return TokenResponse(
        user_id=tokens.user_id,
        access_token=tokens.access_token,
        expires_in=settings.access_token_minutes * 60,
    )


def _set_auth_cookies(response: Response, tokens: AuthTokens, settings: Settings) -> None:
    csrf_token = secrets.token_urlsafe(32)
    max_age = settings.refresh_token_days * 24 * 60 * 60
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=tokens.refresh_token,
        max_age=max_age,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path=REFRESH_COOKIE_PATH,
    )
    response.set_cookie(
        key=CSRF_COOKIE,
        value=csrf_token,
        max_age=max_age,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="strict",
        path=CSRF_COOKIE_PATH,
    )


def _clear_auth_cookies(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=REFRESH_COOKIE,
        path=REFRESH_COOKIE_PATH,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )
    response.delete_cookie(
        key=CSRF_COOKIE,
        path=CSRF_COOKIE_PATH,
        secure=settings.cookie_secure,
        httponly=False,
        samesite="strict",
    )


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    payload: CredentialsRequest,
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> TokenResponse:
    settings: Settings = request.app.state.settings
    try:
        tokens = await service.register(session, str(payload.email), payload.password)
    except DuplicateEmail as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        ) from exc

    _set_auth_cookies(response, tokens, settings)
    return _token_response(tokens, settings)


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: CredentialsRequest,
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> TokenResponse:
    settings: Settings = request.app.state.settings
    try:
        tokens = await service.login(session, str(payload.email), payload.password)
    except InvalidCredentials as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    _set_auth_cookies(response, tokens, settings)
    return _token_response(tokens, settings)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    service: Annotated[AuthService, Depends(get_auth_service)],
    refresh_cookie: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
    csrf_header: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> TokenResponse:
    _validate_csrf(request, csrf_header)
    if refresh_cookie is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    settings: Settings = request.app.state.settings
    try:
        tokens = await service.refresh(session, refresh_cookie)
    except (InvalidCredentials, RefreshTokenReuse) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    _set_auth_cookies(response, tokens, settings)
    return _token_response(tokens, settings)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    service: Annotated[AuthService, Depends(get_auth_service)],
    refresh_cookie: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
    csrf_header: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    _validate_csrf(request, csrf_header)
    await service.logout(session, refresh_cookie)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_auth_cookies(response, request.app.state.settings)
    return response
