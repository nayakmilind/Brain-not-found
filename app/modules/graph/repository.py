from collections import defaultdict
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.finding import Finding
from app.db.models.graph import Entity, EntityMention, GraphEdge
from app.db.models.scan import Scan


async def replace_for_scan(
    session: AsyncSession,
    scan: Scan,
    *,
    entities: list[Entity],
    mentions: list[EntityMention],
    edges: list[GraphEdge],
    truncated: bool,
) -> None:
    await session.execute(delete(GraphEdge).where(GraphEdge.scan_id == scan.id))
    entity_ids = select(Entity.id).where(Entity.scan_id == scan.id)
    await session.execute(delete(EntityMention).where(EntityMention.entity_id.in_(entity_ids)))
    await session.execute(delete(Entity).where(Entity.scan_id == scan.id))
    session.add_all([*entities, *mentions, *edges])
    scan.graph_truncated = truncated


async def graph_records(
    session: AsyncSession,
    scan_id: UUID,
) -> tuple[list[Entity], list[GraphEdge], dict[UUID, list[UUID]]]:
    entities = list(
        (
            await session.execute(
                select(Entity).where(Entity.scan_id == scan_id).order_by(Entity.id)
            )
        ).scalars()
    )
    edges = list(
        (
            await session.execute(
                select(GraphEdge).where(GraphEdge.scan_id == scan_id).order_by(GraphEdge.id)
            )
        ).scalars()
    )
    rows = (
        await session.execute(
            select(EntityMention.entity_id, Finding.source_id)
            .join(Finding, Finding.id == EntityMention.finding_id)
            .join(Entity, Entity.id == EntityMention.entity_id)
            .where(Entity.scan_id == scan_id)
        )
    ).all()
    sources_by_entity: dict[UUID, set[UUID]] = defaultdict(set)
    for entity_id, source_id in rows:
        sources_by_entity[entity_id].add(source_id)
    return (
        entities,
        edges,
        {
            entity_id: sorted(source_ids, key=lambda value: value.hex)
            for entity_id, source_ids in sources_by_entity.items()
        },
    )
