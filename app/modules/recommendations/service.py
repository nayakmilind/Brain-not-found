from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.crypto import decode_key, decrypt_value, unwrap_data_key
from app.db.models.auth import User
from app.db.models.recommendation import Recommendation
from app.db.models.scan import Scan, ScanSource
from app.db.models.source import Source
from app.modules.graph import builder as graph_builder
from app.modules.graph.presentation import present_graph
from app.modules.recommendations.catalog import Playbook, load_playbooks, playbooks_by_id
from app.modules.recommendations.schemas import (
    RecommendationResponse,
    RecommendationStatus,
)
from app.modules.scans.repository import get_scan
from app.modules.scans.service import ScanNotFound
from app.modules.scoring import repository as scoring_repository
from app.modules.scoring.calculation import calculate_score

_HOST_PLATFORMS = {
    "linkedin.com": "linkedin",
    "instagram.com": "instagram",
    "github.com": "github",
    "x.com": "x",
    "twitter.com": "x",
    "myaccount.google.com": "google",
    "aboutme.google.com": "google",
    "profiles.google.com": "google",
}


class RecommendationsNotReady(Exception):
    pass


class RecommendationNotFound(Exception):
    pass


class RecommendationScoreUnavailable(Exception):
    pass


class RecommendationService:
    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings

    async def generate_for_scan(self, session: AsyncSession, scan_id: UUID) -> None:
        if self._settings is None:
            raise ValueError("Settings are required to generate scan recommendations")
        scan = await session.get(Scan, scan_id)
        if scan is None:
            raise ScanNotFound
        user = await session.get(User, scan.user_id)
        if user is None or user.deleted_at is not None:
            raise RecommendationScoreUnavailable
        kek = decode_key(self._settings.master_kek_b64.get_secret_value())
        data_key = unwrap_data_key(user.dek_wrapped, kek, b"user-dek:" + user.id.bytes)
        platforms_by_source = await _source_platforms(session, scan_id, data_key)
        exposures = await scoring_repository.findings_with_sources(session, scan_id)
        current_score = await scoring_repository.get_score(session, scan_id)
        if current_score is None:
            raise RecommendationScoreUnavailable

        recommendations: list[Recommendation] = []
        for playbook in load_playbooks():
            matching = [
                exposure
                for exposure in exposures
                if exposure.finding.type in playbook.finding_types
                and platforms_by_source.get(exposure.finding.source_id, "generic")
                == playbook.platform
            ]
            if not matching:
                continue
            removed_ids = {exposure.finding.id for exposure in matching}
            remaining = [
                exposure for exposure in exposures if exposure.finding.id not in removed_ids
            ]
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
            simulated = calculate_score(remaining, graph_response)
            score_gain = max(0, current_score.total - simulated.total)
            sensitivity = max(exposure.finding.sensitivity for exposure in matching)
            priority = _priority(sensitivity, score_gain)
            recommendations.append(
                Recommendation(
                    id=uuid5(
                        NAMESPACE_URL,
                        f"privacy-shield-recommendation:{scan_id}:{playbook.id}",
                    ),
                    scan_id=scan_id,
                    playbook_id=playbook.id,
                    priority=priority,
                    effort_minutes=playbook.effort_minutes,
                    expected_score_gain=score_gain,
                    finding_count=len(matching),
                    evidence_previews_json=[
                        exposure.finding.masked_preview for exposure in matching[:3]
                    ],
                    status="OPEN",
                )
            )

        await session.execute(delete(Recommendation).where(Recommendation.scan_id == scan_id))
        session.add_all(recommendations)

    async def list_for_scan(
        self,
        session: AsyncSession,
        user_id: UUID,
        scan_id: UUID,
    ) -> list[RecommendationResponse]:
        scan = await get_scan(session, scan_id, user_id=user_id)
        if scan is None:
            raise ScanNotFound
        if scan.status != "DONE" or scan.result_state != "GENERATED":
            raise RecommendationsNotReady

        records = list(
            (
                await session.execute(
                    select(Recommendation)
                    .where(Recommendation.scan_id == scan_id)
                    .order_by(
                        Recommendation.expected_score_gain.desc(),
                        Recommendation.priority.desc(),
                        Recommendation.id,
                    )
                )
            ).scalars()
        )
        if not records:
            return []

        catalog = playbooks_by_id()
        return [_response(record, catalog[record.playbook_id]) for record in records]

    async def update_status(
        self,
        session: AsyncSession,
        user_id: UUID,
        recommendation_id: UUID,
        new_status: RecommendationStatus,
    ) -> Recommendation:
        record = (
            await session.execute(
                select(Recommendation)
                .join(Scan, Scan.id == Recommendation.scan_id)
                .where(
                    Recommendation.id == recommendation_id,
                    Scan.user_id == user_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if record is None:
            raise RecommendationNotFound
        record.status = new_status
        await session.commit()
        await session.refresh(record)
        return record


def _priority(sensitivity: int, score_gain: int) -> str:
    if sensitivity >= 5 or score_gain >= 10:
        return "HIGH"
    if sensitivity >= 3 or score_gain >= 4:
        return "MEDIUM"
    return "LOW"


async def _source_platforms(
    session: AsyncSession,
    scan_id: UUID,
    data_key: bytes,
) -> dict[UUID, str]:
    sources = list(
        (
            await session.execute(
                select(Source)
                .join(ScanSource, ScanSource.source_id == Source.id)
                .where(ScanSource.scan_id == scan_id)
            )
        ).scalars()
    )
    platforms: dict[UUID, str] = {}
    for source in sources:
        platform = "generic"
        if source.kind == "URL":
            if source.uri_enc is None:
                raise ValueError("URL source is missing its encrypted URI")
            uri = decrypt_value(source.uri_enc, data_key, b"source-uri:" + source.id.bytes)
            host = urlsplit(uri).hostname
            if host is None:
                raise ValueError("URL source has no hostname")
            normalized_host = host.casefold().rstrip(".")
            platform = next(
                (
                    value
                    for domain, value in _HOST_PLATFORMS.items()
                    if normalized_host == domain or normalized_host.endswith(f".{domain}")
                ),
                "website",
            )
        platforms[source.id] = platform
    return platforms


def _response(record: Recommendation, playbook: Playbook) -> RecommendationResponse:
    return RecommendationResponse(
        id=record.id,
        playbook_id=record.playbook_id,
        platform=playbook.platform,
        title=playbook.title,
        description=playbook.description,
        finding_types=list(playbook.finding_types),
        evidence_previews=record.evidence_previews_json,
        finding_count=record.finding_count,
        steps=list(playbook.steps),
        priority=record.priority,
        effort_minutes=record.effort_minutes,
        expected_score_gain=record.expected_score_gain,
        status=record.status,
    )
