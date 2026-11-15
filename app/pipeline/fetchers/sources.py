from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from app.core.crypto import decrypt_bytes, decrypt_value
from app.core.ssrf_guard import SafeFetcher
from app.db.models.source import Source


class SourceContentError(ValueError):
    pass


@dataclass(frozen=True)
class SourcePayload:
    source_id: UUID
    content: bytes
    media_type: str
    content_hash: str
    fetched_at: datetime | None
    fetch_status: str


class SourceFetcher:
    def __init__(self, safe_fetcher: SafeFetcher, content_hash_key: bytes) -> None:
        self._safe_fetcher = safe_fetcher
        self._content_hash_key = content_hash_key

    async def load(self, source: Source, data_key: bytes) -> SourcePayload:
        if source.status != "ACTIVE":
            raise SourceContentError("The source is inactive")
        if source.kind == "URL":
            return await self._load_url(source, data_key)
        if source.kind in {"TEXT", "FILE", "PLATFORM_EXPORT"}:
            return self._load_declared_content(source, data_key)
        raise SourceContentError("The source type is unsupported")

    async def _load_url(self, source: Source, data_key: bytes) -> SourcePayload:
        if source.ownership_status != "VERIFIED" or source.uri_enc is None:
            raise SourceContentError("The URL source is not verified")
        url = decrypt_value(
            source.uri_enc,
            data_key,
            b"source-uri:" + source.id.bytes,
        )
        result = await self._safe_fetcher.fetch(url)
        media_type = result.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        return SourcePayload(
            source_id=source.id,
            content=result.body,
            media_type=media_type,
            content_hash=self._content_hash(result.body),
            fetched_at=datetime.now(UTC),
            fetch_status="FETCHED",
        )

    def _load_declared_content(self, source: Source, data_key: bytes) -> SourcePayload:
        if source.ownership_status != "SELF_DECLARED":
            raise SourceContentError("The source is not self-declared")
        if source.content_enc is None or source.content_media_type is None:
            raise SourceContentError("The source content is unavailable")
        content = decrypt_bytes(
            source.content_enc,
            data_key,
            b"source-content:" + source.id.bytes,
        )
        return SourcePayload(
            source_id=source.id,
            content=content,
            media_type=source.content_media_type,
            content_hash=self._content_hash(content),
            fetched_at=None,
            fetch_status="SELF_DECLARED",
        )

    def _content_hash(self, content: bytes) -> str:
        return hmac.new(self._content_hash_key, content, hashlib.sha256).hexdigest()
