from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.finding import Finding
from app.db.models.graph import Entity, EntityMention, GraphEdge
from app.db.models.scoring import RiskScore
from app.db.models.source import Source
from app.modules.scoring.calculation import FindingExposure, ScoreCalculation


async def findings_with_sources(
    session: AsyncSession,
    scan_id: UUID,
) -> list[FindingExposure]:
    rows = (
        await session.execute(
            select(Finding, Source.kind)
            .join(Source, Source.id == Finding.source_id)
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.id)
        )
    ).all()
    return [
        FindingExposure(finding=finding, source_kind=source_kind) for finding, source_kind in rows
    ]


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
    sources_by_entity: dict[UUID, set[UUID]] = {}
    for entity_id, source_id in rows:
        sources_by_entity.setdefault(entity_id, set()).add(source_id)
    return (
        entities,
        edges,
        {
            entity_id: sorted(source_ids, key=lambda value: value.hex)
            for entity_id, source_ids in sources_by_entity.items()
        },
    )


async def get_score(session: AsyncSession, scan_id: UUID) -> RiskScore | None:
    result = await session.execute(select(RiskScore).where(RiskScore.scan_id == scan_id))
    return result.scalar_one_or_none()


async def save_score(
    session: AsyncSession,
    scan_id: UUID,
    calculation: ScoreCalculation,
) -> RiskScore:
    score = await get_score(session, scan_id)
    if score is None:
        score = RiskScore(scan_id=scan_id, total=calculation.total, band=calculation.band)
        session.add(score)
    score.total = calculation.total
    score.band = calculation.band
    score.confidence = calculation.confidence
    score.factors_json = calculation.factors_json
    score.combination_json = calculation.combination_json
    score.method_version = calculation.method_version
    return score
