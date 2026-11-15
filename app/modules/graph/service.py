from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.graph import repository
from app.modules.graph.presentation import present_graph
from app.modules.graph.schemas import GraphResponse
from app.modules.scans.repository import get_scan
from app.modules.scans.service import ScanNotFound


class GraphNotReady(Exception):
    pass


class GraphService:
    async def get_for_user(
        self,
        session: AsyncSession,
        user_id: UUID,
        scan_id: UUID,
    ) -> GraphResponse:
        scan = await get_scan(session, scan_id, user_id=user_id)
        if scan is None:
            raise ScanNotFound
        if scan.status != "DONE" or scan.result_state != "GENERATED":
            raise GraphNotReady

        entities, edges, source_ids = await repository.graph_records(session, scan_id)
        return present_graph(
            entities,
            edges,
            source_ids,
            truncated=scan.graph_truncated,
        )
