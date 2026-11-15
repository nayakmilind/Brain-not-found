from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

import phonenumbers
from cryptography.exceptions import InvalidTag
from email_validator import EmailNotValidError, validate_email
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.crypto import decode_key, encrypt_value, hmac_value, unwrap_data_key
from app.core.ssrf_guard import FetchRejected, SafeFetcher
from app.db.models.auth import User
from app.db.models.finding import Finding
from app.db.models.scan import ScanSource
from app.db.models.source import Source
from app.modules.consent.repository import get_active_consent
from app.modules.consent.service import CONSENT_VERSION
from app.modules.findings import repository as findings_repository
from app.modules.graph import repository as graph_repository
from app.modules.graph.builder import MAX_GRAPH_FINDINGS, build_graph
from app.modules.graph.presentation import present_graph
from app.modules.recommendations.service import RecommendationService
from app.modules.scans import repository
from app.modules.scans.service import ScanNotFound
from app.modules.scoring import repository as scoring_repository
from app.modules.scoring.service import ScoringService
from app.pipeline.detectors.masking import mask_value, normalize_value
from app.pipeline.detectors.presidio_engine import DetectedSpan, detect
from app.pipeline.extractors import ExtractedDocument, ExtractionError, extract_document
from app.pipeline.fetchers import SourceContentError, SourceFetcher, SourcePayload

_CATEGORY_BY_TYPE = {
    "CREDIT_CARD": "FINANCIAL",
    "DATE_TIME": "IDENTITY",
    "DOB_DATE": "IDENTITY",
    "EMAIL_ADDRESS": "CONTACT",
    "IBAN_CODE": "FINANCIAL",
    "LOCATION": "LOCATION",
    "ORGANIZATION": "EMPLOYMENT",
    "PERSON": "IDENTITY",
    "PHONE_NUMBER": "CONTACT",
    "SOCIAL_HANDLE": "HANDLE",
    "US_SSN": "IDENTITY",
    "US_ZIP_CODE": "LOCATION",
}
_SENSITIVITY_BY_TYPE = {
    "CREDIT_CARD": 5,
    "DATE_TIME": 3,
    "DOB_DATE": 5,
    "EMAIL_ADDRESS": 4,
    "IBAN_CODE": 5,
    "LOCATION": 3,
    "ORGANIZATION": 2,
    "PERSON": 3,
    "PHONE_NUMBER": 4,
    "SOCIAL_HANDLE": 2,
    "US_SSN": 5,
    "US_ZIP_CODE": 3,
}


class ScanContentPipeline:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        scan_id: UUID,
        settings: Settings,
        safe_fetcher: SafeFetcher,
    ) -> None:
        self._session_factory = session_factory
        self._scan_id = scan_id
        self._settings = settings
        self._kek = decode_key(settings.master_kek_b64.get_secret_value())
        self._source_fetcher = SourceFetcher(
            safe_fetcher,
            decode_key(settings.hmac_pepper_b64.get_secret_value()),
        )
        self._payloads: dict[UUID, SourcePayload] = {}
        self.documents: dict[UUID, ExtractedDocument] = {}
        self._fetched = False
        self._ephemeral = False

    async def run_stage(self, stage: str) -> None:
        if stage == "FETCHING":
            await self._fetch_sources()
        elif stage == "ANALYZING":
            await self._extract_sources()
            await self._detect_findings()
        elif stage == "SCORING":
            await self._build_graph()
        elif stage == "RECOMMENDING":
            await self._build_recommendations()
        else:
            raise ValueError("Unsupported scan pipeline stage")

    async def _fetch_sources(self) -> None:
        user, mode, source_records = await self._load_source_records()
        self._ephemeral = mode == "EPHEMERAL"
        data_key = unwrap_data_key(
            user.dek_wrapped,
            self._kek,
            b"user-dek:" + user.id.bytes,
        )
        self._payloads.clear()
        for source, _scan_source in source_records:
            try:
                payload = await self._source_fetcher.load(source, data_key)
            except (FetchRejected, InvalidTag, SourceContentError, ValueError):
                await self._set_source_status(
                    source.id,
                    fetch_status="FAILED",
                    content_hash=None,
                    fetched_at=None,
                )
                continue
            self._payloads[source.id] = payload
            await self._set_source_status(
                source.id,
                fetch_status=payload.fetch_status,
                content_hash=None if self._ephemeral else payload.content_hash,
                fetched_at=None if self._ephemeral else payload.fetched_at,
            )
        self._fetched = True

    async def _extract_sources(self) -> None:
        if not self._fetched:
            await self._fetch_sources()
        for source_id, payload in list(self._payloads.items()):
            try:
                document = await asyncio.to_thread(
                    extract_document,
                    payload.content,
                    payload.media_type,
                    max_characters=self._settings.extraction_max_characters,
                    max_pdf_pages=self._settings.extraction_max_pdf_pages,
                    max_docx_uncompressed_bytes=(
                        self._settings.extraction_max_docx_uncompressed_bytes
                    ),
                )
            except ExtractionError:
                self._payloads.pop(source_id, None)
                await self._set_source_status(
                    source_id,
                    fetch_status="FAILED",
                    content_hash=None if self._ephemeral else payload.content_hash,
                    fetched_at=None if self._ephemeral else payload.fetched_at,
                )
                continue
            self.documents[source_id] = document
            self._payloads.pop(source_id, None)

    async def _detect_findings(self) -> None:
        user, mode, source_records = await self._load_source_records()
        data_key = unwrap_data_key(
            user.dek_wrapped,
            self._kek,
            b"user-dek:" + user.id.bytes,
        )
        pepper = decode_key(self._settings.hmac_pepper_b64.get_secret_value())
        findings: list[Finding] = []
        for source, _scan_source in source_records:
            document = self.documents.get(source.id)
            if document is None:
                continue
            offset = 0
            for segment, segment_flag in _document_segments(document):
                if segment:
                    spans = await asyncio.to_thread(detect, segment)
                    for span in spans:
                        finding = _make_finding(
                            span,
                            segment,
                            source.id,
                            self._scan_id,
                            data_key,
                            pepper,
                            ephemeral=mode == "EPHEMERAL",
                            offset=offset,
                            segment_flag=segment_flag,
                        )
                        if finding is not None:
                            findings.append(finding)
                offset += len(segment) + 1

        async with self._session_factory() as session:
            scan = await repository.get_scan(session, self._scan_id, for_update=True)
            if scan is None or scan.status in {"DONE", "FAILED", "CANCELLED"}:
                return
            consent = await get_active_consent(session, scan.user_id, CONSENT_VERSION)
            if consent is None:
                scan.status = "CANCELLED"
                scan.error_code = "CONSENT_REVOKED"
                scan.finished_at = datetime.now(UTC)
                repository.append_event(
                    session,
                    scan,
                    message="Consent is no longer active; scan cancelled.",
                )
                await session.commit()
                return
            await findings_repository.replace_for_scan(session, self._scan_id, findings)
            scan.result_state = "GENERATED"
            await session.commit()

    async def _build_graph(self) -> None:
        async with self._session_factory() as session:
            scan = await repository.get_scan(session, self._scan_id, for_update=True)
            if scan is None or scan.status in {"DONE", "FAILED", "CANCELLED"}:
                return
            consent = await get_active_consent(session, scan.user_id, CONSENT_VERSION)
            if consent is None:
                scan.status = "CANCELLED"
                scan.error_code = "CONSENT_REVOKED"
                scan.finished_at = datetime.now(UTC)
                repository.append_event(
                    session,
                    scan,
                    message="Consent is no longer active; scan cancelled.",
                )
                await session.commit()
                return
            findings = list(
                (
                    await session.execute(
                        select(Finding)
                        .where(Finding.scan_id == self._scan_id)
                        .order_by(
                            Finding.sensitivity.desc(),
                            Finding.confidence.desc(),
                            Finding.source_id,
                            Finding.span_start,
                            Finding.id,
                        )
                        .limit(MAX_GRAPH_FINDINGS + 1)
                    )
                ).scalars()
            )
            graph = build_graph(self._scan_id, findings)
            await graph_repository.replace_for_scan(
                session,
                scan,
                entities=graph.entities,
                mentions=graph.mentions,
                edges=graph.edges,
                truncated=graph.truncated,
            )
            exposures = await scoring_repository.findings_with_sources(
                session,
                self._scan_id,
            )
            graph_response = present_graph(
                graph.entities,
                graph.edges,
                graph.source_ids,
                truncated=graph.truncated,
            )
            await ScoringService().calculate_and_save(
                session,
                self._scan_id,
                exposures,
                graph_response,
            )
            await session.commit()

    async def _build_recommendations(self) -> None:
        async with self._session_factory() as session:
            scan = await repository.get_scan(session, self._scan_id, for_update=True)
            if scan is None or scan.status in {"DONE", "FAILED", "CANCELLED"}:
                return
            consent = await get_active_consent(session, scan.user_id, CONSENT_VERSION)
            if consent is None:
                scan.status = "CANCELLED"
                scan.error_code = "CONSENT_REVOKED"
                scan.finished_at = datetime.now(UTC)
                repository.append_event(
                    session,
                    scan,
                    message="Consent is no longer active; scan cancelled.",
                )
                await session.commit()
                return
            await RecommendationService(self._settings).generate_for_scan(session, self._scan_id)
            await session.commit()

    async def _load_source_records(
        self,
    ) -> tuple[User, str, list[tuple[Source, ScanSource]]]:
        async with self._session_factory() as session:
            scan = await repository.get_scan(session, self._scan_id)
            if scan is None:
                raise ScanNotFound
            user = await session.get(User, scan.user_id)
            if user is None or user.deleted_at is not None:
                raise SourceContentError("The scan owner is unavailable")
            records = await repository.source_records_for_scan(session, scan)
            return user, scan.mode, records

    async def _set_source_status(
        self,
        source_id: UUID,
        *,
        fetch_status: str,
        content_hash: str | None,
        fetched_at: datetime | None,
    ) -> None:
        async with self._session_factory() as session:
            await repository.update_scan_source(
                session,
                self._scan_id,
                source_id,
                fetch_status=fetch_status,
                content_hash=content_hash,
                fetched_at=fetched_at,
            )


def _document_segments(document: ExtractedDocument) -> list[tuple[str, str]]:
    segments = [
        (document.text, "VISIBLE_TEXT"),
        (document.hidden_text, "HIDDEN_TEXT"),
        (document.title or "", "TITLE"),
    ]
    segments.extend((value, "METADATA") for value in document.metadata.values())
    return segments


def _make_finding(
    span: DetectedSpan,
    text: str,
    source_id: UUID,
    scan_id: UUID,
    data_key: bytes,
    pepper: bytes,
    *,
    ephemeral: bool,
    offset: int,
    segment_flag: str,
) -> Finding | None:
    value = text[span.start : span.end]
    category = _CATEGORY_BY_TYPE.get(span.entity_type)
    if category is None or not value.strip() or not _is_valid_value(span.entity_type, value):
        return None
    finding_id = uuid4()
    value_enc = None
    if not ephemeral:
        associated_data = f"finding:{finding_id}:{scan_id}:{source_id}:{span.entity_type}".encode()
        value_enc = encrypt_value(value, data_key, associated_data)
    context_flags = sorted({*span.context_flags, segment_flag})
    return Finding(
        id=finding_id,
        scan_id=scan_id,
        source_id=source_id,
        type=span.entity_type,
        category=category,
        masked_preview=mask_value(value, span.entity_type),
        value_hmac=hmac_value(
            f"finding:{span.entity_type}:{normalize_value(value, span.entity_type)}",
            pepper,
        ),
        value_enc=value_enc,
        span_start=offset + span.start,
        span_end=offset + span.end,
        detector=span.detector,
        confidence=_finding_confidence(span),
        evidence_class=span.evidence_class,
        visibility="MASKED" if ephemeral else "REVEALABLE",
        sensitivity=_SENSITIVITY_BY_TYPE[span.entity_type],
        context_flags_json=context_flags,
    )


def _finding_confidence(span: DetectedSpan) -> float:
    if span.entity_type in {
        "DOB_DATE",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "SOCIAL_HANDLE",
        "US_ZIP_CODE",
    }:
        return max(span.confidence, 0.85)
    return span.confidence


def _is_valid_value(entity_type: str, value: str) -> bool:
    if entity_type == "EMAIL_ADDRESS":
        try:
            validate_email(
                value.strip(),
                check_deliverability=False,
                test_environment=True,
            )
        except EmailNotValidError:
            return False
    elif entity_type == "PHONE_NUMBER":
        try:
            phone = phonenumbers.parse(value, "US")
        except phonenumbers.NumberParseException:
            return False
        if not phonenumbers.is_valid_number(phone):
            return False
    return True
