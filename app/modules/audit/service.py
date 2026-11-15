from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.crypto import decode_key, hmac_value
from app.db.models.audit import AuditChainHead, AuditEntry

GENESIS_HASH = "0" * 64


class AuditIntegrityResult:
    def __init__(
        self,
        *,
        valid: bool,
        checked_entries: int,
        first_invalid_sequence: int | None,
    ) -> None:
        self.valid = valid
        self.checked_entries = checked_entries
        self.first_invalid_sequence = first_invalid_sequence


def actor_hash(user_id: UUID, settings: Settings) -> str:
    pepper = decode_key(settings.hmac_pepper_b64.get_secret_value())
    return hmac_value(f"audit-actor:{user_id}", pepper)


async def append_entry(
    session: AsyncSession,
    settings: Settings,
    *,
    user_id: UUID,
    action: str,
    object_type: str,
    object_id: UUID,
    ip_address: str | None,
) -> AuditEntry:
    head = (
        await session.execute(
            select(AuditChainHead).where(AuditChainHead.id == 1).with_for_update()
        )
    ).scalar_one_or_none()
    if head is None:
        head = AuditChainHead(id=1, last_sequence=0, last_hash=GENESIS_HASH)
        session.add(head)
        await session.flush()

    pepper = decode_key(settings.hmac_pepper_b64.get_secret_value())
    entry_time = datetime.now(UTC)
    entry = AuditEntry(
        id=uuid4(),
        sequence=head.last_sequence + 1,
        actor_hash=hmac_value(f"audit-actor:{user_id}", pepper),
        action=action,
        object_type=object_type,
        object_hash=hmac_value(f"audit-object:{object_type}:{object_id}", pepper),
        ip_hash=hmac_value(f"audit-ip:{ip_address or 'unknown'}", pepper),
        created_at=entry_time,
        prev_hash=head.last_hash,
        entry_hash="",
    )
    entry.entry_hash = _entry_hash(entry)
    head.last_sequence = entry.sequence
    head.last_hash = entry.entry_hash
    session.add(entry)
    await session.flush()
    return entry


async def list_actor_entries(
    session: AsyncSession,
    settings: Settings,
    user_id: UUID,
    *,
    after_sequence: int,
    limit: int,
) -> tuple[list[AuditEntry], int | None]:
    result = await session.execute(
        select(AuditEntry)
        .where(
            AuditEntry.actor_hash == actor_hash(user_id, settings),
            AuditEntry.sequence > after_sequence,
        )
        .order_by(AuditEntry.sequence)
        .limit(limit + 1)
    )
    entries = list(result.scalars())
    next_cursor = None
    if len(entries) > limit:
        entries = entries[:limit]
        next_cursor = entries[-1].sequence
    return entries, next_cursor


async def verify_chain(session: AsyncSession) -> AuditIntegrityResult:
    entries = list(
        (await session.execute(select(AuditEntry).order_by(AuditEntry.sequence))).scalars()
    )
    previous_hash = GENESIS_HASH
    expected_sequence = 1
    for entry in entries:
        try:
            calculated_hash = _entry_hash(entry)
        except ValueError:
            calculated_hash = ""
        if (
            entry.sequence != expected_sequence
            or entry.prev_hash != previous_hash
            or entry.entry_hash != calculated_hash
        ):
            return AuditIntegrityResult(
                valid=False,
                checked_entries=expected_sequence - 1,
                first_invalid_sequence=entry.sequence,
            )
        previous_hash = entry.entry_hash
        expected_sequence += 1

    head = (
        await session.execute(select(AuditChainHead).where(AuditChainHead.id == 1))
    ).scalar_one_or_none()
    if head is None:
        if entries:
            return AuditIntegrityResult(
                valid=False,
                checked_entries=len(entries),
                first_invalid_sequence=entries[-1].sequence,
            )
    elif head.last_sequence != len(entries) or head.last_hash != previous_hash:
        return AuditIntegrityResult(
            valid=False,
            checked_entries=len(entries),
            first_invalid_sequence=len(entries) + 1,
        )
    return AuditIntegrityResult(
        valid=True,
        checked_entries=len(entries),
        first_invalid_sequence=None,
    )


def _entry_hash(entry: AuditEntry) -> str:
    payload = json.dumps(
        {
            "id": str(entry.id),
            "sequence": entry.sequence,
            "actor_hash": entry.actor_hash,
            "action": entry.action,
            "object_type": entry.object_type,
            "object_hash": entry.object_hash,
            "ip_hash": entry.ip_hash,
            "created_at": _timestamp(entry.created_at),
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(bytes.fromhex(entry.prev_hash) + payload).hexdigest()


def _timestamp(value: datetime) -> str:
    normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return normalized.isoformat(timespec="microseconds")
