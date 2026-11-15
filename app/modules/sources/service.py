from __future__ import annotations

from io import BytesIO
from pathlib import PurePath
from uuid import UUID, uuid4
from zipfile import BadZipFile, ZipFile

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.crypto import decode_key, encrypt_bytes, encrypt_value, unwrap_data_key
from app.core.ssrf_guard import SSRFRejected, parse_http_url
from app.db.models.auth import User
from app.db.models.monitoring import MonitorJob, MonitorSource
from app.db.models.source import Source
from app.modules.consent.service import require_current_consent
from app.modules.sources import repository


class SourceNotFound(Exception):
    pass


class InvalidSourceContent(ValueError):
    pass


class SourceTooLarge(ValueError):
    pass


class SourceNotScannable(ValueError):
    pass


class SourceService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._kek = decode_key(settings.master_kek_b64.get_secret_value())

    def _data_key(self, user: User) -> bytes:
        return unwrap_data_key(
            user.dek_wrapped,
            self._kek,
            b"user-dek:" + user.id.bytes,
        )

    async def require_consent(self, session: AsyncSession, user_id: UUID) -> None:
        await require_current_consent(session, user_id)

    async def create_url(
        self,
        session: AsyncSession,
        user: User,
        *,
        label: str,
        uri: str,
    ) -> Source:
        await self.require_consent(session, user.id)
        try:
            parse_http_url(uri)
        except SSRFRejected as error:
            raise InvalidSourceContent("The URL is not allowed") from error
        return await self._create_source(
            session,
            user,
            kind="URL",
            label=label,
            label_preview="Website URL",
            uri=uri,
            ownership_status="UNVERIFIED",
        )

    async def create_text(
        self,
        session: AsyncSession,
        user: User,
        *,
        kind: str,
        label: str,
        content: str,
    ) -> Source:
        await self.require_consent(session, user.id)
        if kind not in {"TEXT", "PLATFORM_EXPORT"}:
            raise InvalidSourceContent("Unsupported text source type")
        encoded = content.encode("utf-8")
        if not encoded.strip():
            raise InvalidSourceContent("Source content must not be blank")
        if len(encoded) > self._settings.source_max_bytes:
            raise SourceTooLarge
        return await self._create_source(
            session,
            user,
            kind=kind,
            label=label,
            label_preview="Pasted text",
            content=encoded,
            media_type="text/plain; charset=utf-8",
            ownership_status="SELF_DECLARED",
        )

    async def create_file(
        self,
        session: AsyncSession,
        user: User,
        *,
        kind: str = "FILE",
        label: str,
        filename: str,
        content: bytes,
    ) -> Source:
        await self.require_consent(session, user.id)
        if kind not in {"FILE", "PLATFORM_EXPORT"}:
            raise InvalidSourceContent("Unsupported uploaded source type")
        if not content:
            raise InvalidSourceContent("Uploaded file must not be empty")
        if len(content) > self._settings.source_max_bytes:
            raise SourceTooLarge
        media_type = self._sniff_file(filename, content)
        return await self._create_source(
            session,
            user,
            kind=kind,
            label=label,
            label_preview="Uploaded file",
            content=content,
            media_type=media_type,
            ownership_status="SELF_DECLARED",
        )

    async def _create_source(
        self,
        session: AsyncSession,
        user: User,
        *,
        kind: str,
        label: str,
        label_preview: str,
        ownership_status: str,
        uri: str | None = None,
        content: bytes | None = None,
        media_type: str | None = None,
    ) -> Source:
        normalized_label = label.strip()
        if not normalized_label:
            raise InvalidSourceContent("Source label must not be blank")
        source_id = uuid4()
        data_key = self._data_key(user)
        source = Source(
            id=source_id,
            user_id=user.id,
            kind=kind,
            label_preview=label_preview,
            label_enc=encrypt_value(
                normalized_label,
                data_key,
                b"source-label:" + source_id.bytes,
            ),
            uri_enc=(
                encrypt_value(uri, data_key, b"source-uri:" + source_id.bytes)
                if uri is not None
                else None
            ),
            content_enc=(
                encrypt_bytes(content, data_key, b"source-content:" + source_id.bytes)
                if content is not None
                else None
            ),
            content_media_type=media_type,
            content_size=len(content) if content is not None else 0,
            ownership_status=ownership_status,
        )
        return await repository.add_source(session, source)

    def _sniff_file(self, filename: str, content: bytes) -> str:
        suffix = PurePath(filename).suffix.lower()
        if suffix == ".txt":
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError as error:
                raise InvalidSourceContent("Text uploads must use UTF-8 encoding") from error
            if "\x00" in text:
                raise InvalidSourceContent("Text uploads must not contain NUL bytes")
            return "text/plain; charset=utf-8"
        if suffix == ".pdf" and content.startswith(b"%PDF-"):
            return "application/pdf"
        if suffix == ".docx" and content.startswith(b"PK\x03\x04"):
            try:
                with ZipFile(BytesIO(content)) as archive:
                    names = set(archive.namelist())
            except (BadZipFile, OSError) as error:
                raise InvalidSourceContent("The DOCX upload is malformed") from error
            if {"[Content_Types].xml", "word/document.xml"}.issubset(names):
                return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        raise InvalidSourceContent("Only UTF-8 text, PDF, and DOCX uploads are supported")

    async def list(
        self,
        session: AsyncSession,
        user_id: UUID,
        *,
        limit: int,
        offset: int,
    ) -> list[Source]:
        return await repository.list_sources(session, user_id, limit=limit, offset=offset)

    async def delete(
        self,
        session: AsyncSession,
        user_id: UUID,
        source_id: UUID,
    ) -> None:
        source = await repository.get_source(session, source_id, user_id)
        if source is None:
            raise SourceNotFound
        monitors = list(
            (
                await session.execute(
                    select(MonitorJob)
                    .join(MonitorSource, MonitorSource.monitor_job_id == MonitorJob.id)
                    .where(MonitorSource.source_id == source_id)
                    .with_for_update()
                )
            ).scalars()
        )
        for monitor in monitors:
            await session.delete(monitor)
        await session.flush()
        await repository.delete_source(session, source)

    async def get(
        self,
        session: AsyncSession,
        user_id: UUID,
        source_id: UUID,
    ) -> Source:
        source = await repository.get_source(session, source_id, user_id)
        if source is None:
            raise SourceNotFound
        return source

    async def require_scannable(
        self,
        session: AsyncSession,
        user_id: UUID,
        source_id: UUID,
    ) -> Source:
        source = await self.get(session, user_id, source_id)
        if source.status != "ACTIVE" or source.ownership_status not in {
            "VERIFIED",
            "SELF_DECLARED",
        }:
            raise SourceNotScannable
        return source
