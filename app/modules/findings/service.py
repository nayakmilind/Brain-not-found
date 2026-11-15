from uuid import UUID

from cryptography.exceptions import InvalidTag
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.crypto import decode_key, decrypt_value, unwrap_data_key
from app.db.models.auth import User
from app.db.models.finding import Finding
from app.db.models.scan import Scan
from app.modules.audit import service as audit_service
from app.modules.findings import repository
from app.modules.scans.repository import get_scan
from app.modules.scans.service import ScanNotFound


class FindingsNotReady(Exception):
    pass


class FindingNotRevealable(Exception):
    pass


class FindingRevealDataInvalid(Exception):
    pass


class FindingsService:
    async def reveal_for_user(
        self,
        session: AsyncSession,
        settings: Settings,
        user: User,
        finding_id: UUID,
        ip_address: str | None,
    ) -> str:
        finding = (
            await session.execute(
                select(Finding)
                .join(Scan, Scan.id == Finding.scan_id)
                .where(Finding.id == finding_id, Scan.user_id == user.id)
            )
        ).scalar_one_or_none()
        if finding is None:
            raise ScanNotFound
        if finding.value_enc is None or finding.visibility != "REVEALABLE":
            raise FindingNotRevealable

        kek = decode_key(settings.master_kek_b64.get_secret_value())
        data_key = unwrap_data_key(
            user.dek_wrapped,
            kek,
            b"user-dek:" + user.id.bytes,
        )
        associated_data = (
            f"finding:{finding.id}:{finding.scan_id}:{finding.source_id}:{finding.type}".encode()
        )
        try:
            value = decrypt_value(finding.value_enc, data_key, associated_data)
        except (InvalidTag, UnicodeDecodeError, ValueError) as error:
            raise FindingRevealDataInvalid from error

        await audit_service.append_entry(
            session,
            settings,
            user_id=user.id,
            action="finding_revealed",
            object_type="finding",
            object_id=finding.id,
            ip_address=ip_address,
        )
        await session.commit()
        return value

    async def list_for_user(
        self,
        session: AsyncSession,
        user_id: UUID,
        scan_id: UUID,
        *,
        limit: int,
        cursor: UUID | None,
        category: str | None,
        evidence_class: str | None,
    ) -> tuple[list[Finding], UUID | None]:
        scan = await get_scan(session, scan_id, user_id=user_id)
        if scan is None:
            raise ScanNotFound
        if scan.status != "DONE" or scan.result_state != "GENERATED":
            raise FindingsNotReady
        records = await repository.list_for_scan(
            session,
            scan_id,
            limit=limit,
            cursor=cursor,
            category=category,
            evidence_class=evidence_class,
        )
        next_cursor = None
        if len(records) > limit:
            records = records[:limit]
            next_cursor = records[-1].id
        return records, next_cursor
