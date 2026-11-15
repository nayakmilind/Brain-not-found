from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.crypto import decode_key, decrypt_bytes, decrypt_value, unwrap_data_key
from app.db.models.audit import AuditEntry
from app.db.models.auth import RefreshToken, User
from app.db.models.consent import Consent
from app.db.models.finding import Finding
from app.db.models.graph import Entity, EntityMention, GraphEdge
from app.db.models.recommendation import Recommendation
from app.db.models.report import Report
from app.db.models.scan import Scan, ScanDeadLetter, ScanEvent, ScanSource
from app.db.models.scoring import RiskScore
from app.db.models.source import OwnershipChallenge, Source
from app.modules.audit import service as audit_service

MAX_EXPORT_BYTES = 50 * 1024 * 1024


async def export_user_data(
    session: AsyncSession,
    settings: Settings,
    user: User,
    ip_address: str | None,
) -> dict[str, object]:
    await audit_service.append_entry(
        session,
        settings,
        user_id=user.id,
        action="data_exported",
        object_type="user",
        object_id=user.id,
        ip_address=ip_address,
    )
    kek = decode_key(settings.master_kek_b64.get_secret_value())
    data_key = unwrap_data_key(user.dek_wrapped, kek, b"user-dek:" + user.id.bytes)
    scans = _all(
        await session.execute(select(Scan).where(Scan.user_id == user.id).order_by(Scan.id))
    )
    scan_ids = [scan.id for scan in scans]
    sources = _all(
        await session.execute(select(Source).where(Source.user_id == user.id).order_by(Source.id))
    )
    source_ids = [source.id for source in sources]
    findings = (
        _all(
            await session.execute(
                select(Finding)
                .where(Finding.scan_id.in_(scan_ids))
                .order_by(Finding.scan_id, Finding.id)
            )
        )
        if scan_ids
        else []
    )
    entities = (
        _all(
            await session.execute(
                select(Entity)
                .where(Entity.scan_id.in_(scan_ids))
                .order_by(Entity.scan_id, Entity.id)
            )
        )
        if scan_ids
        else []
    )
    recommendations = (
        _all(
            await session.execute(
                select(Recommendation)
                .where(Recommendation.scan_id.in_(scan_ids))
                .order_by(Recommendation.scan_id, Recommendation.id)
            )
        )
        if scan_ids
        else []
    )
    reports = (
        _all(
            await session.execute(
                select(Report)
                .where(Report.scan_id.in_(scan_ids))
                .order_by(Report.scan_id, Report.id)
            )
        )
        if scan_ids
        else []
    )

    audit_rows = _all(
        await session.execute(
            select(AuditEntry)
            .where(AuditEntry.actor_hash == audit_service.actor_hash(user.id, settings))
            .order_by(AuditEntry.sequence)
        )
    )
    consents = _all(
        await session.execute(
            select(Consent).where(Consent.user_id == user.id).order_by(Consent.accepted_at)
        )
    )
    refresh_tokens = _all(
        await session.execute(
            select(RefreshToken).where(RefreshToken.user_id == user.id).order_by(RefreshToken.id)
        )
    )
    challenges = (
        _all(
            await session.execute(
                select(OwnershipChallenge)
                .where(OwnershipChallenge.source_id.in_(source_ids))
                .order_by(OwnershipChallenge.id)
            )
        )
        if source_ids
        else []
    )

    sections: dict[str, list[dict[str, object]]] = {
        "consents": [
            _fields(row, ("id", "version", "scope_json", "ip_hash", "accepted_at", "revoked_at"))
            for row in consents
        ],
        "sources": [_source_export(source, data_key) for source in sources],
        "ownership_challenges": [
            _fields(
                row,
                (
                    "id",
                    "source_id",
                    "method",
                    "attempts",
                    "expires_at",
                    "created_at",
                    "verified_at",
                ),
            )
            for row in challenges
        ],
        "scans": [
            _fields(
                row,
                (
                    "id",
                    "status",
                    "stage_checkpoint",
                    "mode",
                    "result_state",
                    "event_sequence",
                    "attempts",
                    "created_at",
                    "started_at",
                    "finished_at",
                    "error_code",
                    "graph_truncated",
                ),
            )
            for row in scans
        ],
        "scan_sources": (
            _fields_many(
                await session.execute(
                    select(ScanSource)
                    .where(ScanSource.scan_id.in_(scan_ids))
                    .order_by(ScanSource.scan_id, ScanSource.source_id)
                ),
                ("scan_id", "source_id", "content_hash", "fetched_at", "fetch_status"),
            )
            if scan_ids
            else []
        ),
        "scan_events": (
            _fields_many(
                await session.execute(
                    select(ScanEvent)
                    .where(ScanEvent.scan_id.in_(scan_ids))
                    .order_by(ScanEvent.scan_id, ScanEvent.sequence)
                ),
                (
                    "id",
                    "scan_id",
                    "sequence",
                    "status",
                    "stage_checkpoint",
                    "message",
                    "created_at",
                ),
            )
            if scan_ids
            else []
        ),
        "scan_dead_letters": (
            _fields_many(
                await session.execute(
                    select(ScanDeadLetter)
                    .where(ScanDeadLetter.scan_id.in_(scan_ids))
                    .order_by(ScanDeadLetter.scan_id)
                ),
                ("scan_id", "attempts", "error_code", "created_at"),
            )
            if scan_ids
            else []
        ),
        "findings": [_finding_export(finding, data_key) for finding in findings],
        "entities": [
            _fields(row, ("id", "scan_id", "kind", "canonical_hmac", "label_masked"))
            for row in entities
        ],
        "entity_mentions": (
            _fields_many(
                await session.execute(
                    select(EntityMention)
                    .where(EntityMention.entity_id.in_([entity.id for entity in entities]))
                    .order_by(EntityMention.entity_id, EntityMention.finding_id)
                ),
                ("entity_id", "finding_id"),
            )
            if entities
            else []
        ),
        "graph_edges": (
            _fields_many(
                await session.execute(
                    select(GraphEdge)
                    .where(GraphEdge.scan_id.in_(scan_ids))
                    .order_by(GraphEdge.scan_id, GraphEdge.id)
                ),
                (
                    "id",
                    "scan_id",
                    "source_id",
                    "src_entity_id",
                    "dst_entity_id",
                    "relation",
                    "weight",
                    "evidence_finding_ids",
                ),
            )
            if scan_ids
            else []
        ),
        "risk_scores": (
            _fields_many(
                await session.execute(
                    select(RiskScore)
                    .where(RiskScore.scan_id.in_(scan_ids))
                    .order_by(RiskScore.scan_id)
                ),
                (
                    "id",
                    "scan_id",
                    "total",
                    "band",
                    "confidence",
                    "factors_json",
                    "combination_json",
                    "method_version",
                ),
            )
            if scan_ids
            else []
        ),
        "recommendations": [
            _fields(
                row,
                (
                    "id",
                    "scan_id",
                    "playbook_id",
                    "priority",
                    "effort_minutes",
                    "expected_score_gain",
                    "finding_count",
                    "evidence_previews_json",
                    "status",
                ),
            )
            for row in recommendations
        ],
        "reports": [
            {
                **_fields(row, ("id", "scan_id", "format", "created_at")),
                "content_base64": base64.b64encode(row.content).decode("ascii"),
            }
            for row in reports
        ],
        "refresh_sessions": [
            _fields(row, ("id", "family_id", "expires_at", "created_at", "revoked_at"))
            for row in refresh_tokens
        ],
        "audit_entries": [
            _fields(
                row,
                (
                    "sequence",
                    "action",
                    "object_type",
                    "object_hash",
                    "ip_hash",
                    "created_at",
                    "prev_hash",
                    "entry_hash",
                ),
            )
            for row in audit_rows
        ],
    }

    email = decrypt_value(user.email_enc, data_key, b"user-email:" + user.id.bytes)
    export: dict[str, object] = {
        "schema_version": "1",
        "exported_at": datetime.now(UTC).isoformat(),
        "user_id": str(user.id),
        "account": {
            "email": email,
            "retention_mode": user.retention_mode,
            "created_at": user.created_at.isoformat(),
            "deleted_at": user.deleted_at.isoformat() if user.deleted_at else None,
        },
        "data": sections,
        "security_note": (
            "This export intentionally contains plaintext copies of your encrypted source "
            "content and any encrypted finding values. Store it securely. Passwords, "
            "refresh-token secrets, and encryption keys are never included."
        ),
    }
    return export


async def erase_user_data(
    session: AsyncSession,
    settings: Settings,
    user: User,
    ip_address: str | None,
) -> None:
    await audit_service.append_entry(
        session,
        settings,
        user_id=user.id,
        action="account_deleted",
        object_type="user",
        object_id=user.id,
        ip_address=ip_address,
    )
    await session.delete(user)
    await session.commit()


def _source_export(source: Source, data_key: bytes) -> dict[str, object]:
    result = _fields(
        source,
        (
            "id",
            "kind",
            "label_preview",
            "content_media_type",
            "content_size",
            "status",
            "ownership_status",
            "created_at",
        ),
    )
    result["label"] = decrypt_value(
        source.label_enc,
        data_key,
        b"source-label:" + source.id.bytes,
    )
    if source.uri_enc is not None:
        result["uri"] = decrypt_value(
            source.uri_enc,
            data_key,
            b"source-uri:" + source.id.bytes,
        )
    if source.content_enc is not None:
        content = decrypt_bytes(
            source.content_enc,
            data_key,
            b"source-content:" + source.id.bytes,
        )
        if (source.content_media_type or "").startswith("text/"):
            result["content_text"] = content.decode("utf-8")
        else:
            result["content_base64"] = base64.b64encode(content).decode("ascii")
    return result


def _finding_export(finding: Finding, data_key: bytes) -> dict[str, object]:
    result = _fields(
        finding,
        (
            "id",
            "scan_id",
            "source_id",
            "type",
            "category",
            "masked_preview",
            "value_hmac",
            "span_start",
            "span_end",
            "detector",
            "confidence",
            "evidence_class",
            "visibility",
            "sensitivity",
            "context_flags_json",
        ),
    )
    if finding.value_enc is not None:
        associated_data = (
            f"finding:{finding.id}:{finding.scan_id}:{finding.source_id}:{finding.type}".encode()
        )
        result["value"] = decrypt_value(finding.value_enc, data_key, associated_data)
    return result


def _fields_many(result: Any, fields: tuple[str, ...]) -> list[dict[str, object]]:
    return [_fields(row, fields) for row in result.scalars()]


def _fields(record: Any, fields: tuple[str, ...]) -> dict[str, object]:
    return {name: _json_value(getattr(record, name)) for name in fields}


def _json_value(value: Any) -> Any:
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def _all(result: Any) -> list[Any]:
    return list(result.scalars())
