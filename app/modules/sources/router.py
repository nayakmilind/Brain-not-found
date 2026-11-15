from typing import Annotated, Literal
from urllib.parse import unquote
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.models.auth import User
from app.db.models.source import Source
from app.db.session import get_db_session
from app.modules.auth.dependencies import get_current_user
from app.modules.consent.service import ConsentNotAccepted
from app.modules.sources.schemas import (
    SourceCreate,
    SourceListResponse,
    SourceResponse,
    TextSourceCreate,
    URLSourceCreate,
)
from app.modules.sources.service import (
    InvalidSourceContent,
    SourceNotFound,
    SourceService,
    SourceTooLarge,
)

router = APIRouter(prefix="/v1/sources", tags=["sources"])


def get_source_service(request: Request) -> SourceService:
    settings: Settings = request.app.state.settings
    return SourceService(settings)


def _source_response(source: Source) -> SourceResponse:
    return SourceResponse(
        id=source.id,
        kind=source.kind,
        label_preview=source.label_preview,
        status=source.status,
        ownership_status=source.ownership_status,
        created_at=source.created_at,
    )


def _map_source_error(error: Exception) -> HTTPException:
    if isinstance(error, ConsentNotAccepted):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Current consent is required before adding or verifying a source",
        )
    if isinstance(error, SourceTooLarge):
        return HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="The source exceeds the configured size limit",
        )
    if isinstance(error, InvalidSourceContent):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(error),
        )
    raise error


@router.post("", response_model=SourceResponse, status_code=status.HTTP_201_CREATED)
async def create_source(
    payload: SourceCreate,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    service: Annotated[SourceService, Depends(get_source_service)],
) -> SourceResponse:
    try:
        if isinstance(payload, URLSourceCreate):
            source = await service.create_url(
                session,
                user,
                label=payload.label,
                uri=str(payload.uri),
            )
        elif isinstance(payload, TextSourceCreate):
            source = await service.create_text(
                session,
                user,
                kind=payload.kind,
                label=payload.label,
                content=payload.content,
            )
        else:
            raise RuntimeError("Unsupported source request type")
    except (ConsentNotAccepted, InvalidSourceContent, SourceTooLarge) as error:
        raise _map_source_error(error) from error
    return _source_response(source)


@router.post(
    "/file",
    response_model=SourceResponse,
    status_code=status.HTTP_201_CREATED,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/octet-stream": {
                    "schema": {"type": "string", "format": "binary"},
                },
                "text/plain": {"schema": {"type": "string", "format": "binary"}},
                "application/pdf": {"schema": {"type": "string", "format": "binary"}},
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {
                    "schema": {"type": "string", "format": "binary"},
                },
            },
        },
    },
)
async def upload_source_file(
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    request: Request,
    service: Annotated[SourceService, Depends(get_source_service)],
    encoded_label: Annotated[
        str,
        Header(alias="X-Source-Label", min_length=1, max_length=360),
    ],
    extension: Annotated[
        Literal["txt", "pdf", "docx"],
        Header(alias="X-Source-Extension"),
    ],
    kind: Annotated[
        Literal["FILE", "PLATFORM_EXPORT"],
        Header(alias="X-Source-Kind"),
    ] = "FILE",
) -> SourceResponse:
    settings: Settings = request.app.state.settings
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_size = int(content_length)
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid content length",
            ) from error
        if declared_size < 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid content length",
            )
        if declared_size > settings.source_max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="The source exceeds the configured size limit",
            )
    try:
        encoded_label.encode("ascii")
        label = unquote(encoded_label, encoding="utf-8", errors="strict")
    except (UnicodeEncodeError, UnicodeDecodeError) as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Source labels must be percent-encoded UTF-8",
        ) from error
    if not label.strip() or len(label) > 120:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="The source label must contain 1 to 120 characters",
        )

    try:
        await service.require_consent(session, user.id)
    except ConsentNotAccepted as error:
        raise _map_source_error(error) from error

    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > settings.source_max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="The source exceeds the configured size limit",
            )
        content.extend(chunk)
    try:
        source = await service.create_file(
            session,
            user,
            kind=kind,
            label=label,
            filename=f"source.{extension}",
            content=bytes(content),
        )
    except (ConsentNotAccepted, InvalidSourceContent, SourceTooLarge) as error:
        raise _map_source_error(error) from error
    return _source_response(source)


@router.get("", response_model=SourceListResponse)
async def list_sources(
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    service: Annotated[SourceService, Depends(get_source_service)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> SourceListResponse:
    sources = await service.list(session, user.id, limit=limit, offset=offset)
    return SourceListResponse(
        items=[_source_response(source) for source in sources],
        limit=limit,
        offset=offset,
    )


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_source(
    source_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    service: Annotated[SourceService, Depends(get_source_service)],
) -> None:
    try:
        await service.delete(session, user.id, source_id)
    except SourceNotFound as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Source not found",
        ) from error
