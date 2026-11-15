from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.scan import Scan
from app.db.models.scoring import RiskScore
from app.modules.graph import builder as graph_builder
from app.modules.graph.presentation import present_graph
from app.modules.graph.schemas import GraphResponse
from app.modules.scans.repository import get_scan
from app.modules.scans.service import ScanNotFound
from app.modules.scoring import repository
from app.modules.scoring.attacker_view import build_attacker_view
from app.modules.scoring.calculation import (
    FindingExposure,
    calculate_score,
    score_response,
    score_response_from_record,
)
from app.modules.scoring.schemas import (
    AttackerViewResponse,
    ScoreResponse,
    SimulationResponse,
    UniquenessResponse,
)
from app.modules.scoring.uniqueness import estimate_uniqueness


class ScoringNotReady(Exception):
    pass


class InvalidSimulation(Exception):
    pass


class ScoringService:
    async def get_score(
        self,
        session: AsyncSession,
        user_id: UUID,
        scan_id: UUID,
    ) -> ScoreResponse:
        _scan, score = await self._load_ready_score(
            session,
            user_id,
            scan_id,
        )
        return _score_record_response(score)

    async def get_uniqueness(
        self,
        session: AsyncSession,
        user_id: UUID,
        scan_id: UUID,
    ) -> UniquenessResponse:
        _scan, exposures, _score = await self._load_ready_scan(
            session,
            user_id,
            scan_id,
        )
        return estimate_uniqueness({exposure.finding.type for exposure in exposures})

    async def get_attacker_view(
        self,
        session: AsyncSession,
        user_id: UUID,
        scan_id: UUID,
    ) -> AttackerViewResponse:
        _scan, exposures, _score = await self._load_ready_scan(
            session,
            user_id,
            scan_id,
        )
        return build_attacker_view(exposures)

    async def simulate(
        self,
        session: AsyncSession,
        user_id: UUID,
        scan_id: UUID,
        remove_findings: list[UUID],
    ) -> SimulationResponse:
        scan, exposures, _score = await self._load_ready_scan(
            session,
            user_id,
            scan_id,
        )
        known_ids = {exposure.finding.id for exposure in exposures}
        if not set(remove_findings).issubset(known_ids):
            raise InvalidSimulation

        removed = set(remove_findings)
        remaining = [exposure for exposure in exposures if exposure.finding.id not in removed]
        graph = graph_builder.build_graph(
            scan_id,
            [exposure.finding for exposure in remaining],
        )
        graph_response = present_graph(
            graph.entities,
            graph.edges,
            graph.source_ids,
            truncated=graph.truncated,
        )
        calculation = calculate_score(remaining, graph_response)
        return SimulationResponse(
            score=score_response(calculation),
            graph=graph_response,
        )

    async def calculate_and_save(
        self,
        session: AsyncSession,
        scan_id: UUID,
        exposures: list[FindingExposure],
        graph_response: GraphResponse,
    ) -> RiskScore:
        calculation = calculate_score(exposures, graph_response)
        return await repository.save_score(session, scan_id, calculation)

    async def _load_ready_scan(
        self,
        session: AsyncSession,
        user_id: UUID,
        scan_id: UUID,
    ) -> tuple[Scan, list[FindingExposure], RiskScore]:
        scan, score = await self._load_ready_score(session, user_id, scan_id)
        exposures = await repository.findings_with_sources(session, scan_id)
        return scan, exposures, score

    async def _load_ready_score(
        self,
        session: AsyncSession,
        user_id: UUID,
        scan_id: UUID,
    ) -> tuple[Scan, RiskScore]:
        scan = await get_scan(session, scan_id, user_id=user_id)
        if scan is None:
            raise ScanNotFound
        if scan.status != "DONE" or scan.result_state != "GENERATED":
            raise ScoringNotReady
        score = await repository.get_score(session, scan_id)
        if score is None:
            raise ScoringNotReady
        return scan, score


def _score_record_response(score: RiskScore) -> ScoreResponse:
    return score_response_from_record(
        total=score.total,
        band=score.band,
        confidence=score.confidence,
        factors_json=score.factors_json,
        combination_json=score.combination_json,
        method_version=score.method_version,
    )
