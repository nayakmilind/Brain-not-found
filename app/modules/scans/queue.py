from typing import Protocol
from uuid import UUID

from arq.connections import ArqRedis
from redis.exceptions import RedisError


class QueueUnavailable(Exception):
    pass


class ScanJobQueue(Protocol):
    async def enqueue_scan(self, scan_id: UUID, generation: int) -> None: ...


class ArqScanQueue:
    def __init__(self, pool: ArqRedis) -> None:
        self._pool = pool

    async def enqueue_scan(self, scan_id: UUID, generation: int) -> None:
        try:
            await self._pool.enqueue_job(
                "run_scan",
                str(scan_id),
                _job_id=f"scan:{scan_id}:{generation}",
            )
        except (RedisError, OSError, TimeoutError) as error:
            raise QueueUnavailable from error
