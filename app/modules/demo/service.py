from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.crypto import decode_key, hmac_value
from app.db.models.auth import User
from app.modules.demo.persona import PersonaPattern, generate_persona
from app.modules.demo.schemas import PersonaScanResponse
from app.modules.scans import repository
from app.modules.scans.queue import ScanJobQueue
from app.modules.scans.schemas import ScanCreateRequest
from app.modules.scans.service import ScanService
from app.modules.sources.service import SourceService


class SyntheticScanConflict(Exception):
    pass


class SyntheticPersonaService:
    def __init__(self, settings: Settings, queue: ScanJobQueue) -> None:
        self._settings = settings
        self._queue = queue

    async def create_scan(
        self,
        session: AsyncSession,
        user: User,
        *,
        seed: int,
        pattern: PersonaPattern,
    ) -> PersonaScanResponse:
        persona = generate_persona(seed, pattern)
        idempotency_key = f"demo-persona:{user.id}:{seed}:{pattern}"
        key_hash = hmac_value(
            f"scan-idempotency:{user.id}:{idempotency_key}",
            decode_key(self._settings.hmac_pepper_b64.get_secret_value()),
        )
        existing_scan = await repository.get_scan_by_idempotency_key(
            session,
            user.id,
            key_hash,
        )
        if existing_scan is None:
            source = await SourceService(self._settings).create_text(
                session,
                user,
                kind="TEXT",
                label=f"Synthetic demo persona {seed}",
                content=persona.content,
            )
            source_ids = [source.id]
        else:
            sources = await repository.get_sources_for_scan(session, existing_scan)
            if len(sources) != 1:
                raise SyntheticScanConflict
            source_ids = [sources[0].id]

        scan = await ScanService(self._settings, self._queue).create(
            session,
            user,
            ScanCreateRequest(source_ids=source_ids, mode="STANDARD"),
            idempotency_key,
        )
        return PersonaScanResponse(
            source_id=source_ids[0],
            scan_id=scan.id,
            status=scan.status,
            pattern=pattern,
        )
