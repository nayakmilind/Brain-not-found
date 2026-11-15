from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
from arq import Retry
from arq.connections import ArqRedis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.crypto import decode_key, decrypt_value, unwrap_data_key
from app.core.ssrf_guard import FetchRejected, FetchResult, SafeFetcher
from app.db.models.audit import AuditEntry
from app.db.models.auth import User
from app.db.models.finding import Finding
from app.db.models.monitoring import MonitorJob, ScanDiff
from app.db.models.recommendation import Recommendation
from app.db.models.report import Report
from app.db.models.scan import Scan, ScanDeadLetter, ScanSource
from app.db.models.scoring import RiskScore
from app.db.models.source import Source
from app.modules.assistant.schemas import AssistantRequest
from app.modules.assistant.service import AssistantService
from app.modules.audit.service import actor_hash, verify_chain
from app.modules.demo.cli import main as demo_cli_main
from app.modules.demo.persona import generate_persona
from app.modules.graph.service import GraphService
from app.modules.monitoring.service import MonitoringService
from app.modules.scans.queue import ArqScanQueue, QueueUnavailable
from app.modules.scans.service import run_scan_pipeline
from app.pipeline.runner import ScanContentPipeline

TEST_PASSWORD = "synthetic-personal-password"


class FixtureFetcher(SafeFetcher):
    def __init__(self, *, body: bytes, content_type: str = "text/html") -> None:
        super().__init__()
        self.body = body
        self.content_type = content_type
        self.urls: list[str] = []
        self.error: Exception | None = None
        self.failed_urls: set[str] = set()

    async def fetch(self, url: str) -> FetchResult:
        self.urls.append(url)
        if url in self.failed_urls:
            raise FetchRejected("synthetic blocked source")
        if self.error is not None:
            raise self.error
        return FetchResult(
            url=url,
            status_code=200,
            headers={"content-type": self.content_type},
            body=self.body,
        )


class FixtureQueue:
    def __init__(self) -> None:
        self.scan_ids: list[UUID] = []
        self.attempts: list[tuple[UUID, int]] = []
        self.unavailable = False

    async def enqueue_scan(self, scan_id: UUID, generation: int) -> None:
        self.attempts.append((scan_id, generation))
        if self.unavailable:
            raise QueueUnavailable
        self.scan_ids.append(scan_id)


class FixtureArqPool:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []
        self.error = error

    async def enqueue_job(
        self,
        function: str,
        *args: object,
        **kwargs: object,
    ) -> None:
        self.calls.append((function, args, kwargs))
        if self.error is not None:
            raise self.error


class FixtureAssistant:
    def __init__(self, output: str) -> None:
        self.output = output
        self.prompt = ""

    async def complete(self, prompt: str) -> str:
        self.prompt = prompt
        return self.output


@pytest.fixture
async def scan_client(auth_app: FastAPI) -> AsyncIterator[AsyncClient]:
    queue = FixtureQueue()
    auth_app.state.scan_queue = queue
    auth_app.state.test_scan_queue = queue
    async with AsyncClient(
        transport=ASGITransport(app=auth_app),
        base_url="http://testserver",
    ) as client:
        yield client


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _register(client: AsyncClient, email: str) -> tuple[str, UUID]:
    response = await client.post(
        "/v1/auth/register",
        json={"email": email, "password": TEST_PASSWORD},
    )
    assert response.status_code == 201
    data = response.json()
    return data["access_token"], UUID(data["user_id"])


async def _accept_consent(client: AsyncClient, token: str) -> None:
    response = await client.post(
        "/v1/consent/accept",
        headers=_headers(token),
        json={"version": "2026-03", "accepted": True},
    )
    assert response.status_code == 200


async def _create_text_source(
    client: AsyncClient,
    token: str,
    *,
    content: str = "Synthetic persona Morgan Example, morgan@example.test",
) -> UUID:
    response = await client.post(
        "/v1/sources",
        headers=_headers(token),
        json={
            "kind": "TEXT",
            "label": "Synthetic profile",
            "content": content,
        },
    )
    assert response.status_code == 201
    return UUID(response.json()["id"])


async def _start_scan(
    client: AsyncClient,
    token: str,
    source_id: UUID,
    key: str = "scan-request-0001",
) -> Response:
    response = await client.post(
        "/v1/scans",
        headers={**_headers(token), "Idempotency-Key": key},
        json={"source_ids": [str(source_id)], "mode": "STANDARD"},
    )
    assert response.status_code == 202
    return response


async def _noop_stage(_stage: str) -> None:
    return None


async def test_scan_creation_is_consent_gated_idempotent_and_streamable(
    scan_client: AsyncClient,
    auth_app: FastAPI,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    token, _ = await _register(scan_client, "scan-owner@example.com")
    await _accept_consent(scan_client, token)
    source_id = await _create_text_source(scan_client, token)

    created = await _start_scan(scan_client, token, source_id)
    repeated = await _start_scan(scan_client, token, source_id)
    assert created.json()["id"] == repeated.json()["id"]
    assert created.json()["status"] == "QUEUED"
    assert created.json()["result_state"] == "NOT_GENERATED"
    findings_not_ready = await scan_client.get(
        f"/v1/scans/{created.json()['id']}/findings",
        headers=_headers(token),
    )
    graph_not_ready = await scan_client.get(
        f"/v1/scans/{created.json()['id']}/graph",
        headers=_headers(token),
    )
    score_not_ready = await scan_client.get(
        f"/v1/scans/{created.json()['id']}/score",
        headers=_headers(token),
    )
    assert findings_not_ready.status_code == 409
    assert graph_not_ready.status_code == 409
    assert score_not_ready.status_code == 409
    queue: FixtureQueue = auth_app.state.test_scan_queue
    assert queue.scan_ids == [UUID(created.json()["id"])]
    assert queue.attempts == [(UUID(created.json()["id"]), 1)]

    conflict = await scan_client.post(
        "/v1/scans",
        headers={**_headers(token), "Idempotency-Key": "scan-request-0001"},
        json={"source_ids": [str(source_id)], "mode": "EPHEMERAL"},
    )
    assert conflict.status_code == 409

    await run_scan_pipeline(
        auth_session_factory,
        UUID(created.json()["id"]),
        stage_runner=_noop_stage,
    )
    status_response = await scan_client.get(
        f"/v1/scans/{created.json()['id']}",
        headers=_headers(token),
    )
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "DONE"
    assert status_response.json()["stage_checkpoint"] == "DONE"
    assert status_response.json()["result_state"] == "NOT_GENERATED"
    score_unavailable = await scan_client.get(
        f"/v1/scans/{created.json()['id']}/score",
        headers=_headers(token),
    )
    assert score_unavailable.status_code == 409

    events = await scan_client.get(
        f"/v1/scans/{created.json()['id']}/events",
        headers=_headers(token),
    )
    assert events.status_code == 200
    assert events.headers["content-type"].startswith("text/event-stream")
    assert "event: progress" in events.text
    assert "Extraction complete; no findings or score were generated." in events.text
    assert "Morgan Example" not in events.text
    assert "morgan@example.test" not in events.text


async def test_scan_requires_active_consent_and_verified_url_ownership(
    scan_client: AsyncClient,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    token, _ = await _register(scan_client, "scan-consent@example.com")
    await _accept_consent(scan_client, token)
    text_id = await _create_text_source(scan_client, token)
    url_response = await scan_client.post(
        "/v1/sources",
        headers=_headers(token),
        json={
            "kind": "URL",
            "label": "My profile",
            "uri": "https://example.com/profile",
        },
    )
    assert url_response.status_code == 201

    rejected_url = await scan_client.post(
        "/v1/scans",
        headers={**_headers(token), "Idempotency-Key": "scan-url-request-0001"},
        json={"source_ids": [url_response.json()["id"]], "mode": "STANDARD"},
    )
    assert rejected_url.status_code == 409

    queued_before_revocation = await _start_scan(
        scan_client,
        token,
        text_id,
        "scan-revoke-worker-0001",
    )
    revoked = await scan_client.post("/v1/consent/revoke", headers=_headers(token))
    assert revoked.status_code == 200
    rejected_consent = await scan_client.post(
        "/v1/scans",
        headers={**_headers(token), "Idempotency-Key": "scan-no-consent-0001"},
        json={"source_ids": [str(text_id)], "mode": "STANDARD"},
    )
    assert rejected_consent.status_code == 403

    await run_scan_pipeline(
        auth_session_factory,
        UUID(queued_before_revocation.json()["id"]),
        stage_runner=_noop_stage,
    )
    revoked_scan = await scan_client.get(
        f"/v1/scans/{queued_before_revocation.json()['id']}",
        headers=_headers(token),
    )
    assert revoked_scan.json()["status"] == "CANCELLED"
    assert revoked_scan.json()["error_code"] == "CONSENT_REVOKED"


async def test_worker_fetches_only_verified_urls_and_extracts_sources_in_memory(
    scan_client: AsyncClient,
    auth_app: FastAPI,
    auth_settings: Settings,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    token, user_id = await _register(scan_client, "scan-content@example.com")
    await _accept_consent(scan_client, token)
    declared_id = await _create_text_source(scan_client, token)
    owned_url_ids: list[UUID] = []
    owned_urls = [
        "https://example.com/owned-profile",
        "https://example.com/unavailable-profile",
    ]
    for index, url in enumerate(owned_urls):
        response = await scan_client.post(
            "/v1/sources",
            headers=_headers(token),
            json={"kind": "URL", "label": f"Owned site {index}", "uri": url},
        )
        assert response.status_code == 201
        owned_url_ids.append(UUID(response.json()["id"]))
    async with auth_session_factory() as session:
        await session.execute(
            update(Source).where(Source.id.in_(owned_url_ids)).values(ownership_status="VERIFIED")
        )
        await session.commit()

    scan_response = await scan_client.post(
        "/v1/scans",
        headers={**_headers(token), "Idempotency-Key": "scan-content-pipeline-01"},
        json={
            "source_ids": [str(declared_id), *(str(source_id) for source_id in owned_url_ids)],
            "mode": "STANDARD",
        },
    )
    assert scan_response.status_code == 202
    scan_id = UUID(scan_response.json()["id"])
    fetcher = FixtureFetcher(
        body=(
            b"<html><head><title>Synthetic page</title></head><body>"
            b"<p>Synthetic web content</p></body></html>"
        )
    )
    fetcher.failed_urls.add(owned_urls[1])
    pipeline = ScanContentPipeline(auth_session_factory, scan_id, auth_settings, fetcher)

    await run_scan_pipeline(
        auth_session_factory,
        scan_id,
        stage_runner=pipeline.run_stage,
    )

    assert set(fetcher.urls) == set(owned_urls)
    assert "Synthetic web content" in pipeline.documents[owned_url_ids[0]].text
    assert "Morgan Example" in pipeline.documents[declared_id].text
    assert owned_url_ids[1] not in pipeline.documents
    async with auth_session_factory() as session:
        scan = await session.get(Scan, scan_id)
        sources = list(
            (
                await session.execute(select(ScanSource).where(ScanSource.scan_id == scan_id))
            ).scalars()
        )
        assert scan is not None
        assert scan.status == "DONE"
        assert scan.result_state == "GENERATED"
        assert scan.error_code == "PARTIAL_SOURCE_FAILURE"
        source_states = {source.source_id: source.fetch_status for source in sources}
        assert source_states == {
            declared_id: "SELF_DECLARED",
            owned_url_ids[0]: "FETCHED",
            owned_url_ids[1]: "FAILED",
        }
        source_data = {source.source_id: source for source in sources}
        assert len(source_data[declared_id].content_hash or "") == 64
        assert source_data[declared_id].fetched_at is None
        assert len(source_data[owned_url_ids[0]].content_hash or "") == 64
        assert source_data[owned_url_ids[0]].fetched_at is not None
        assert source_data[owned_url_ids[1]].content_hash is None
        email_finding = (
            await session.execute(
                select(Finding).where(
                    Finding.scan_id == scan_id,
                    Finding.type == "EMAIL_ADDRESS",
                )
            )
        ).scalar_one()
        user = await session.get(User, user_id)
        assert user is not None
        assert email_finding.value_enc is not None
        assert email_finding.value_hmac != "morgan@example.test"
        assert email_finding.masked_preview != "morgan@example.test"
        data_key = unwrap_data_key(
            user.dek_wrapped,
            decode_key(auth_settings.master_kek_b64.get_secret_value()),
            b"user-dek:" + user.id.bytes,
        )
        associated_data = (
            f"finding:{email_finding.id}:{scan_id}:{email_finding.source_id}:{email_finding.type}"
        ).encode()
        assert decrypt_value(email_finding.value_enc, data_key, associated_data) == (
            "morgan@example.test"
        )

    response = await scan_client.get(
        f"/v1/scans/{scan_id}/findings?category=CONTACT",
        headers=_headers(token),
    )
    assert response.status_code == 200
    response_json = response.json()
    assert any(item["type"] == "EMAIL_ADDRESS" for item in response_json["items"])
    assert "value_enc" not in response_json["items"][0]
    assert "value_hmac" not in response_json["items"][0]


async def test_ephemeral_scan_does_not_persist_content_fingerprints_or_timestamps(
    scan_client: AsyncClient,
    auth_settings: Settings,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    token, _ = await _register(scan_client, "scan-ephemeral@example.com")
    await _accept_consent(scan_client, token)
    source_id = await _create_text_source(scan_client, token)
    response = await scan_client.post(
        "/v1/scans",
        headers={**_headers(token), "Idempotency-Key": "scan-ephemeral-request-001"},
        json={"source_ids": [str(source_id)], "mode": "EPHEMERAL"},
    )
    assert response.status_code == 202
    scan_id = UUID(response.json()["id"])
    fetcher = FixtureFetcher(body=b"unused")
    pipeline = ScanContentPipeline(auth_session_factory, scan_id, auth_settings, fetcher)

    await run_scan_pipeline(
        auth_session_factory,
        scan_id,
        stage_runner=pipeline.run_stage,
    )

    assert fetcher.urls == []
    async with auth_session_factory() as session:
        scan = await session.get(Scan, scan_id)
        scan_source = await session.get(ScanSource, (scan_id, source_id))
        findings = list(
            (await session.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars()
        )
        assert scan is not None
        assert scan.result_state == "GENERATED"
        assert scan_source is not None
        assert scan_source.fetch_status == "SELF_DECLARED"
        assert scan_source.content_hash is None
        assert scan_source.fetched_at is None
        email_finding = next(item for item in findings if item.type == "EMAIL_ADDRESS")
        assert email_finding.value_enc is None
        assert email_finding.visibility == "MASKED"
        finding_id = email_finding.id

    reveal = await scan_client.post(
        f"/v1/findings/{finding_id}/reveal",
        headers=_headers(token),
    )
    assert reveal.status_code == 409


async def test_scan_queue_failure_can_be_retried_with_same_key(
    scan_client: AsyncClient,
    auth_app: FastAPI,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    token, _ = await _register(scan_client, "scan-queue@example.com")
    await _accept_consent(scan_client, token)
    source_id = await _create_text_source(scan_client, token)
    queue: FixtureQueue = auth_app.state.test_scan_queue
    queue.unavailable = True
    headers = {**_headers(token), "Idempotency-Key": "scan-queue-request-0001"}
    body = {"source_ids": [str(source_id)], "mode": "STANDARD"}

    unavailable = await scan_client.post("/v1/scans", headers=headers, json=body)
    assert unavailable.status_code == 503

    async with auth_session_factory() as session:
        scan = (await session.execute(select(Scan))).scalar_one()
        scan_id = scan.id
        assert scan.status == "FAILED"
        assert scan.error_code == "QUEUE_UNAVAILABLE"

    queue.unavailable = False
    retried = await scan_client.post("/v1/scans", headers=headers, json=body)
    assert retried.status_code == 202
    assert UUID(retried.json()["id"]) == scan_id
    assert retried.json()["status"] == "QUEUED"
    assert queue.scan_ids == [scan_id]
    assert queue.attempts == [(scan_id, 1), (scan_id, 2)]
    async with auth_session_factory() as session:
        scan = await session.get(Scan, scan_id)
        assert scan is not None
        assert scan.status == "QUEUED"
        assert scan.queue_generation == 2


async def test_scan_access_and_cancel_are_user_scoped(
    scan_client: AsyncClient,
    auth_app: FastAPI,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    token_a, _ = await _register(scan_client, "scan-a@example.com")
    token_b, _ = await _register(scan_client, "scan-b@example.com")
    await _accept_consent(scan_client, token_a)
    await _accept_consent(scan_client, token_b)
    source_id = await _create_text_source(scan_client, token_a)
    created = await _start_scan(scan_client, token_a, source_id, "scan-owner-a-0001")
    scan_id = created.json()["id"]

    foreign_read = await scan_client.get(
        f"/v1/scans/{scan_id}",
        headers=_headers(token_b),
    )
    foreign_findings = await scan_client.get(
        f"/v1/scans/{scan_id}/findings",
        headers=_headers(token_b),
    )
    foreign_cancel = await scan_client.post(
        f"/v1/scans/{scan_id}/cancel",
        headers=_headers(token_b),
    )
    assert foreign_read.status_code == 404
    assert foreign_findings.status_code == 404
    assert foreign_cancel.status_code == 404

    cancelled = await scan_client.post(
        f"/v1/scans/{scan_id}/cancel",
        headers=_headers(token_a),
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "CANCELLED"
    await run_scan_pipeline(
        auth_session_factory,
        UUID(scan_id),
        stage_runner=_noop_stage,
    )
    final = await scan_client.get(f"/v1/scans/{scan_id}", headers=_headers(token_a))
    assert final.json()["status"] == "CANCELLED"
    assert auth_app.state.test_scan_queue.scan_ids == [UUID(scan_id)]


async def test_graph_resolves_repeated_values_and_is_user_scoped(
    scan_client: AsyncClient,
    auth_settings: Settings,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    token_a, user_id = await _register(scan_client, "graph-owner@example.com")
    token_b, _ = await _register(scan_client, "graph-other@example.com")
    await _accept_consent(scan_client, token_a)
    await _accept_consent(scan_client, token_b)
    first_source_id = await _create_text_source(
        scan_client,
        token_a,
        content="Name: Morgan Example\nEmail: morgan@example.test",
    )
    second_source_id = await _create_text_source(
        scan_client,
        token_a,
        content="Contact email: morgan@example.test",
    )
    created = await scan_client.post(
        "/v1/scans",
        headers={**_headers(token_a), "Idempotency-Key": "graph-integration-0001"},
        json={
            "source_ids": [str(first_source_id), str(second_source_id)],
            "mode": "STANDARD",
        },
    )
    assert created.status_code == 202
    scan_id = UUID(created.json()["id"])
    pipeline = ScanContentPipeline(
        auth_session_factory,
        scan_id,
        auth_settings,
        FixtureFetcher(body=b"unused"),
    )
    await run_scan_pipeline(
        auth_session_factory,
        scan_id,
        stage_runner=pipeline.run_stage,
    )

    response = await scan_client.get(
        f"/v1/scans/{scan_id}/graph",
        headers=_headers(token_a),
    )
    assert response.status_code == 200
    graph = response.json()
    email = next(node for node in graph["nodes"] if node["kind"] == "EMAIL")
    assert email["source_count"] == 2
    assert set(email["source_ids"]) == {str(first_source_id), str(second_source_id)}
    assert graph["edges"]
    assert any("appeared together" in edge["reason"] for edge in graph["edges"])
    assert any(
        "appears in 2 authorized sources" in reason for reason in graph["combination_reasons"]
    )
    assert graph["combination_multiplier"] > 1.0
    assert graph["truncated"] is False
    assert "Morgan Example" not in response.text
    assert "morgan@example.test" not in response.text
    async with auth_session_factory() as session:
        service_graph = await GraphService().get_for_user(session, user_id, scan_id)
    assert service_graph.combination_multiplier == graph["combination_multiplier"]
    assert len(service_graph.edges) == len(graph["edges"])

    foreign_response = await scan_client.get(
        f"/v1/scans/{scan_id}/graph",
        headers=_headers(token_b),
    )
    assert foreign_response.status_code == 404


async def test_scoring_endpoints_and_what_if_are_masked_and_user_scoped(
    scan_client: AsyncClient,
    auth_settings: Settings,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    token, user_id = await _register(scan_client, "scoring-owner@example.com")
    other_token, _ = await _register(scan_client, "scoring-other@example.com")
    await _accept_consent(scan_client, token)
    await _accept_consent(scan_client, other_token)
    source_id = await _create_text_source(
        scan_client,
        token,
        content="Name: Morgan Example\nEmail: morgan@example.test",
    )
    created = await _start_scan(scan_client, token, source_id, "scoring-integration-001")
    scan_id = UUID(created.json()["id"])
    pipeline = ScanContentPipeline(
        auth_session_factory,
        scan_id,
        auth_settings,
        FixtureFetcher(body=b"unused"),
    )
    await run_scan_pipeline(
        auth_session_factory,
        scan_id,
        stage_runner=pipeline.run_stage,
    )

    score_response = await scan_client.get(
        f"/v1/scans/{scan_id}/score",
        headers=_headers(token),
    )
    assert score_response.status_code == 200
    score = score_response.json()
    assert score["method_version"] == "score-v1"
    assert score["privacy_score"] == 100 - score["risk_score"]
    assert score["factors"]
    assert all(
        {"finding_id", "type", "S", "V", "C", "K", "risk"} <= factor.keys()
        for factor in score["factors"]
    )
    assert "morgan@example.test" not in score_response.text
    email_finding_id = next(
        factor["finding_id"] for factor in score["factors"] if factor["type"] == "EMAIL_ADDRESS"
    )

    recommendations_response = await scan_client.get(
        f"/v1/scans/{scan_id}/recommendations",
        headers=_headers(token),
    )
    assert recommendations_response.status_code == 200
    recommendations = recommendations_response.json()
    email_recommendation = next(
        item for item in recommendations if item["playbook_id"] == "public-email"
    )
    assert email_recommendation["finding_count"] == 1
    assert email_recommendation["evidence_previews"]
    assert "morgan@example.test" not in recommendations_response.text

    uniqueness_response = await scan_client.get(
        f"/v1/scans/{scan_id}/uniqueness",
        headers=_headers(token),
    )
    attacker_response = await scan_client.get(
        f"/v1/scans/{scan_id}/attacker-view",
        headers=_headers(token),
    )
    assert uniqueness_response.status_code == 200
    assert uniqueness_response.json()["confidence"] == "VERY_LOW"
    assert attacker_response.status_code == 200
    assert (
        next(
            scenario
            for scenario in attacker_response.json()["scenarios"]
            if scenario["scenario"] == "phishing_personalisation"
        )["rating"]
        == "HIGH"
    )
    assert "morgan@example.test" not in attacker_response.text

    simulated = await scan_client.post(
        f"/v1/scans/{scan_id}/simulate",
        headers=_headers(token),
        json={"remove_findings": [email_finding_id]},
    )
    assert simulated.status_code == 200
    assert simulated.json()["score"]["risk_score"] <= score["risk_score"]
    assert all(node["kind"] != "EMAIL" for node in simulated.json()["graph"]["nodes"])
    assert "morgan@example.test" not in simulated.text
    assert (
        email_recommendation["expected_score_gain"]
        == score["risk_score"] - simulated.json()["score"]["risk_score"]
    )

    fallback_assistant = await scan_client.post(
        "/v1/assistant/ask",
        headers=_headers(token),
        json={"scan_id": str(scan_id), "question": "What should I fix?"},
    )
    assert fallback_assistant.status_code == 200
    assert fallback_assistant.json()["used_fallback"] is True
    assert fallback_assistant.json()["fallback_reason"] == "disabled"
    assert "morgan@example.test" not in fallback_assistant.text

    opted_out_provider = FixtureAssistant(
        '{"answer_focus":"score","playbook_ids":["public-email"]}'
    )
    async with auth_session_factory() as session:
        opted_out = await AssistantService(auth_settings, opted_out_provider).ask(
            session,
            user_id,
            AssistantRequest(scan_id=scan_id, question="What should I fix?"),
        )
    assert opted_out.used_fallback is True
    assert opted_out.fallback_reason == "external_processing_not_approved"
    assert opted_out_provider.prompt == ""

    safe_provider = FixtureAssistant('{"answer_focus":"score","playbook_ids":["public-email"]}')
    async with auth_session_factory() as session:
        safe_answer = await AssistantService(auth_settings, safe_provider).ask(
            session,
            user_id,
            AssistantRequest(
                scan_id=scan_id,
                question="Please explain morgan@example.test",
                allow_external_processing=True,
            ),
        )
    assert safe_answer.used_fallback is False
    assert "morgan@example.test" not in safe_provider.prompt
    assert "[REDACTED " in safe_provider.prompt

    leaking_provider = FixtureAssistant(
        '{"answer_focus":"score","playbook_ids":["morgan@example.test"]}'
    )
    async with auth_session_factory() as session:
        safe_fallback = await AssistantService(auth_settings, leaking_provider).ask(
            session,
            user_id,
            AssistantRequest(
                scan_id=scan_id,
                question="Summarize this report",
                allow_external_processing=True,
            ),
        )
    assert safe_fallback.used_fallback is True
    assert safe_fallback.fallback_reason == "pii_detected"
    assert "morgan@example.test" not in safe_fallback.answer

    updated_recommendation = await scan_client.patch(
        f"/v1/recommendations/{email_recommendation['id']}",
        headers=_headers(token),
        json={"status": "DONE"},
    )
    assert updated_recommendation.status_code == 200
    assert updated_recommendation.json()["status"] == "DONE"
    foreign_recommendation = await scan_client.patch(
        f"/v1/recommendations/{email_recommendation['id']}",
        headers=_headers(other_token),
        json={"status": "DISMISSED"},
    )
    assert foreign_recommendation.status_code == 404
    foreign_recommendations = await scan_client.get(
        f"/v1/scans/{scan_id}/recommendations",
        headers=_headers(other_token),
    )
    assert foreign_recommendations.status_code == 404
    async with auth_session_factory() as session:
        persisted_recommendation = await session.get(
            Recommendation,
            UUID(email_recommendation["id"]),
        )
        assert persisted_recommendation is not None
        assert persisted_recommendation.status == "DONE"

    invalid_simulation = await scan_client.post(
        f"/v1/scans/{scan_id}/simulate",
        headers=_headers(token),
        json={"remove_findings": [str(uuid4())]},
    )
    assert invalid_simulation.status_code == 422
    foreign_score = await scan_client.get(
        f"/v1/scans/{scan_id}/score",
        headers=_headers(other_token),
    )
    assert foreign_score.status_code == 404

    persisted_score = await scan_client.get(
        f"/v1/scans/{scan_id}/score",
        headers=_headers(token),
    )
    assert persisted_score.json()["risk_score"] == score["risk_score"]
    async with auth_session_factory() as session:
        stored_score = (
            await session.execute(select(RiskScore).where(RiskScore.scan_id == scan_id))
        ).scalar_one()
        assert stored_score.method_version == "score-v1"
        assert all("morgan@example.test" not in str(factor) for factor in stored_score.factors_json)


async def test_url_host_selects_a_platform_playbook_without_exposing_the_url(
    scan_client: AsyncClient,
    auth_settings: Settings,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    token, _ = await _register(scan_client, "playbook-owner@example.com")
    await _accept_consent(scan_client, token)
    source_response = await scan_client.post(
        "/v1/sources",
        headers=_headers(token),
        json={
            "kind": "URL",
            "label": "Synthetic GitHub profile",
            "uri": "https://www.github.com/synthetic-person",
        },
    )
    assert source_response.status_code == 201
    source_id = UUID(source_response.json()["id"])
    async with auth_session_factory() as session:
        source = await session.get(Source, source_id)
        assert source is not None
        source.ownership_status = "VERIFIED"
        await session.commit()

    created = await _start_scan(scan_client, token, source_id, "platform-playbook-0001")
    scan_id = UUID(created.json()["id"])
    pipeline = ScanContentPipeline(
        auth_session_factory,
        scan_id,
        auth_settings,
        FixtureFetcher(body=b"Email: morgan@example.test"),
    )
    await run_scan_pipeline(
        auth_session_factory,
        scan_id,
        stage_runner=pipeline.run_stage,
    )

    response = await scan_client.get(
        f"/v1/scans/{scan_id}/recommendations",
        headers=_headers(token),
    )
    assert response.status_code == 200
    recommendations = response.json()
    assert [item["playbook_id"] for item in recommendations] == ["github-profile-review"]
    assert recommendations[0]["platform"] == "github"
    assert "www.github.com" not in response.text
    assert "morgan@example.test" not in response.text


async def test_m9_reveal_reports_export_and_audit_integrity(
    scan_client: AsyncClient,
    auth_settings: Settings,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    token, user_id = await _register(scan_client, "m9-owner@example.com")
    other_token, _ = await _register(scan_client, "m9-other@example.com")
    await _accept_consent(scan_client, token)
    await _accept_consent(scan_client, other_token)
    source_id = await _create_text_source(
        scan_client,
        token,
        content="Name: Morgan Example\nEmail: morgan@example.test",
    )
    created = await _start_scan(scan_client, token, source_id, "m9-report-scan-0001")
    scan_id = UUID(created.json()["id"])
    pipeline = ScanContentPipeline(
        auth_session_factory,
        scan_id,
        auth_settings,
        FixtureFetcher(body=b"unused"),
    )
    await run_scan_pipeline(
        auth_session_factory,
        scan_id,
        stage_runner=pipeline.run_stage,
    )

    async with auth_session_factory() as session:
        finding = (
            await session.execute(
                select(Finding)
                .where(Finding.scan_id == scan_id, Finding.type == "EMAIL_ADDRESS")
                .limit(1)
            )
        ).scalar_one()
        finding_id = finding.id
    reveal = await scan_client.post(
        f"/v1/findings/{finding_id}/reveal",
        headers=_headers(token),
    )
    assert reveal.status_code == 200
    assert reveal.json()["value"] == "morgan@example.test"
    assert reveal.headers["cache-control"] == "no-store"
    assert "morgan@example.test" not in reveal.headers.get("x-request-id", "")
    foreign_reveal = await scan_client.post(
        f"/v1/findings/{finding_id}/reveal",
        headers=_headers(other_token),
    )
    assert foreign_reveal.status_code == 404

    reports: dict[str, UUID] = {}
    for report_format in ("json", "html", "pdf"):
        response = await scan_client.post(
            f"/v1/scans/{scan_id}/report",
            headers=_headers(token),
            json={"format": report_format},
        )
        assert response.status_code == 201
        report_id = UUID(response.json()["id"])
        reports[report_format] = report_id
        download = await scan_client.get(
            f"/v1/reports/{report_id}/download",
            headers=_headers(token),
        )
        assert download.status_code == 200
        assert download.headers["cache-control"] == "no-store"
        assert "morgan@example.test" not in download.content.decode(
            "utf-8",
            errors="ignore",
        )
        if report_format == "json":
            report_data = download.json()
            assert report_data["score"]["method_version"] == "score-v1"
            assert report_data["findings"]
        elif report_format == "html":
            assert b"Privacy Shield report" in download.content
            assert b"m*****@e******.test" in download.content
        else:
            assert download.content.startswith(b"%PDF-")
    foreign_report = await scan_client.get(
        f"/v1/reports/{reports['json']}/download",
        headers=_headers(other_token),
    )
    assert foreign_report.status_code == 404

    audit_page = await scan_client.get("/v1/privacy/audit", headers=_headers(token))
    assert audit_page.status_code == 200
    actions = [item["action"] for item in audit_page.json()["items"]]
    assert "finding_revealed" in actions
    assert actions.count("report_created") == 3
    assert actions.count("report_downloaded") == 3
    assert "morgan@example.test" not in audit_page.text
    assert (await scan_client.get("/v1/privacy/audit/verify", headers=_headers(token))).json()[
        "valid"
    ]

    export_response = await scan_client.get("/v1/me/export", headers=_headers(token))
    assert export_response.status_code == 200
    assert export_response.headers["cache-control"] == "no-store"
    exported = export_response.json()
    assert exported["account"]["email"] == "m9-owner@example.com"
    assert exported["data"]["sources"][0]["content_text"] == (
        "Name: Morgan Example\nEmail: morgan@example.test"
    )
    assert any(item.get("value") == "morgan@example.test" for item in exported["data"]["findings"])
    assert "morgan@example.test" not in exported["data"]["reports"][0]["content_base64"]

    async with auth_session_factory() as session:
        first_entry = (
            await session.execute(select(AuditEntry).order_by(AuditEntry.sequence).limit(1))
        ).scalar_one()
        original_hash = first_entry.entry_hash
        first_entry.entry_hash = "f" * 64
        await session.commit()
        tampered = await verify_chain(session)
        assert tampered.valid is False
        first_entry.entry_hash = original_hash
        await session.commit()
        assert (await verify_chain(session)).valid is True
        original_previous_hash = first_entry.prev_hash
        first_entry.prev_hash = "not-a-hex-hash"
        await session.commit()
        assert (await verify_chain(session)).valid is False
        first_entry.prev_hash = original_previous_hash
        await session.commit()
        assert (await verify_chain(session)).valid is True


async def test_account_erasure_cascades_and_keeps_only_pseudonymous_audit(
    scan_client: AsyncClient,
    auth_session_factory: async_sessionmaker[AsyncSession],
    auth_settings: Settings,
) -> None:
    token, user_id = await _register(scan_client, "m9-delete@example.com")
    other_token, other_id = await _register(scan_client, "m9-retain@example.com")
    await _accept_consent(scan_client, token)
    await _accept_consent(scan_client, other_token)
    source_id = await _create_text_source(scan_client, token)
    other_source_id = await _create_text_source(
        scan_client,
        other_token,
        content="Synthetic public profile, no identifiers",
    )
    scan_response = await _start_scan(scan_client, token, source_id, "m9-delete-scan-0001")
    scan_id = UUID(scan_response.json()["id"])
    pipeline = ScanContentPipeline(
        auth_session_factory,
        scan_id,
        auth_settings,
        FixtureFetcher(body=b"unused"),
    )
    await run_scan_pipeline(
        auth_session_factory,
        scan_id,
        stage_runner=pipeline.run_stage,
    )
    report_response = await scan_client.post(
        f"/v1/scans/{scan_id}/report",
        headers=_headers(token),
        json={"format": "json"},
    )
    assert report_response.status_code == 201

    deleted = await scan_client.delete("/v1/me", headers=_headers(token))
    assert deleted.status_code == 204
    unauthenticated_after_delete = await scan_client.get(
        "/v1/me/export",
        headers=_headers(token),
    )
    assert unauthenticated_after_delete.status_code == 401

    async with auth_session_factory() as session:
        assert await session.get(User, user_id) is None
        assert await session.get(Scan, scan_id) is None
        assert await session.get(Source, source_id) is None
        assert await session.get(Report, UUID(report_response.json()["id"])) is None
        assert await session.get(User, other_id) is not None
        assert await session.get(Source, other_source_id) is not None
        deleted_actor_hash = actor_hash(user_id, auth_settings)
        retained_audit = list(
            (
                await session.execute(
                    select(AuditEntry).where(AuditEntry.actor_hash == deleted_actor_hash)
                )
            ).scalars()
        )
        assert [entry.action for entry in retained_audit] == [
            "report_created",
            "account_deleted",
        ]
        assert all(str(user_id) not in entry.actor_hash for entry in retained_audit)
        assert (await verify_chain(session)).valid is True


async def test_arq_queue_uses_stable_job_id_and_surfaces_redis_errors() -> None:
    pool = FixtureArqPool()
    scan_id = UUID("218f90c4-2915-4270-a1ce-bf435a55aaf9")
    await ArqScanQueue(cast(ArqRedis, pool)).enqueue_scan(scan_id, 2)
    assert pool.calls == [("run_scan", (str(scan_id),), {"_job_id": f"scan:{scan_id}:2"})]

    failing_pool = FixtureArqPool(error=OSError("synthetic connection failure"))
    with pytest.raises(QueueUnavailable):
        await ArqScanQueue(cast(ArqRedis, failing_pool)).enqueue_scan(scan_id, 1)


async def test_worker_recovers_queued_scans_after_dispatch_interruption(
    scan_client: AsyncClient,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from app.modules.scans.worker import dispatch_pending_scans

    token, _ = await _register(scan_client, "scan-recovery@example.com")
    await _accept_consent(scan_client, token)
    source_id = await _create_text_source(scan_client, token)
    created = await _start_scan(scan_client, token, source_id, "scan-recovery-request-1")
    scan_id = UUID(created.json()["id"])
    pool = FixtureArqPool()

    await dispatch_pending_scans(
        {
            "session_factory": auth_session_factory,
            "redis": cast(ArqRedis, pool),
        }
    )
    assert pool.calls == [("run_scan", (str(scan_id),), {"_job_id": f"scan:{scan_id}:1"})]


async def test_worker_retries_then_dead_letters_unexpected_failure(
    scan_client: AsyncClient,
    auth_app: FastAPI,
    auth_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.modules.scans import worker

    token, _ = await _register(scan_client, "scan-worker@example.com")
    await _accept_consent(scan_client, token)
    source_id = await _create_text_source(scan_client, token)
    created = await _start_scan(scan_client, token, source_id, "scan-worker-request-001")
    scan_id = UUID(created.json()["id"])

    async def fail_pipeline(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("synthetic worker failure")

    monkeypatch.setattr(worker, "run_scan_pipeline", fail_pipeline)
    context = {
        "session_factory": auth_session_factory,
        "job_try": 1,
        "settings": auth_app.state.settings,
        "safe_fetcher": auth_app.state.safe_fetcher,
    }
    with pytest.raises(Retry) as retry:
        await worker.run_scan(context, str(scan_id))
    assert retry.value.defer_score == 1000

    context["job_try"] = 3
    await worker.run_scan(context, str(scan_id))
    async with auth_session_factory() as session:
        scan = await session.get(Scan, scan_id)
        dead_letter = await session.get(ScanDeadLetter, scan_id)
        assert scan is not None
        assert scan.status == "FAILED"
        assert scan.error_code == "WORKER_RETRIES_EXHAUSTED"
        assert dead_letter is not None
        assert dead_letter.attempts == 3


async def test_monitoring_rescans_mask_new_exposures_and_enforces_user_scope(
    scan_client: AsyncClient,
    auth_app: FastAPI,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    token, _ = await _register(scan_client, "monitor-owner@example.com")
    await _accept_consent(scan_client, token)
    source_id = await _create_text_source(scan_client, token)
    baseline_response = await _start_scan(
        scan_client,
        token,
        source_id,
        "monitor-baseline-scan-01",
    )
    baseline_id = UUID(baseline_response.json()["id"])
    async with auth_session_factory() as session:
        baseline = await session.get(Scan, baseline_id)
        assert baseline is not None
        baseline.status = "DONE"
        baseline.stage_checkpoint = "DONE"
        baseline.result_state = "GENERATED"
        session.add(
            Finding(
                scan_id=baseline_id,
                source_id=source_id,
                type="EMAIL_ADDRESS",
                category="CONTACT",
                masked_preview="m***@example.test",
                value_hmac="a" * 64,
                value_enc=None,
                span_start=0,
                span_end=18,
                detector="synthetic_fixture",
                confidence=0.95,
                evidence_class="VERIFIED",
                visibility="MASKED",
                sensitivity=3,
                context_flags_json=[],
            )
        )
        await session.commit()

    created = await scan_client.post(
        "/v1/monitoring",
        headers=_headers(token),
        json={"scan_id": str(baseline_id), "cadence": "DAILY"},
    )
    assert created.status_code == 201
    monitor_id = UUID(created.json()["id"])
    other_token, _ = await _register(scan_client, "monitor-other@example.com")
    unauthorized_timeline = await scan_client.get(
        f"/v1/monitoring/{monitor_id}/timeline",
        headers=_headers(other_token),
    )
    assert unauthorized_timeline.status_code == 404

    now = datetime.now(UTC)
    async with auth_session_factory() as session:
        monitor = await session.get(MonitorJob, monitor_id)
        assert monitor is not None
        monitor.next_run_at = now - timedelta(seconds=1)
        await session.commit()

    queue: FixtureQueue = auth_app.state.test_scan_queue
    dispatched = await MonitoringService(auth_app.state.settings, queue).dispatch_due(
        auth_session_factory,
        now=now,
    )
    assert dispatched == 1
    async with auth_session_factory() as session:
        monitor = await session.get(MonitorJob, monitor_id)
        assert monitor is not None
        scheduled_id = monitor.pending_scan_id
        assert scheduled_id is not None
        scheduled_scan = await session.get(Scan, scheduled_id)
        assert scheduled_scan is not None
        session.add(
            Finding(
                scan_id=scheduled_id,
                source_id=source_id,
                type="PHONE_NUMBER",
                category="CONTACT",
                masked_preview="+1 (***) ***-01**",
                value_hmac="b" * 64,
                value_enc=None,
                span_start=20,
                span_end=32,
                detector="synthetic_fixture",
                confidence=0.9,
                evidence_class="UNCERTAIN",
                visibility="MASKED",
                sensitivity=3,
                context_flags_json=[],
            )
        )
        scheduled_scan.status = "DONE"
        scheduled_scan.stage_checkpoint = "DONE"
        scheduled_scan.result_state = "GENERATED"
        await session.commit()

    await MonitoringService(auth_app.state.settings).complete_scheduled_scan(
        auth_session_factory,
        scheduled_id,
    )
    timeline = await scan_client.get(
        f"/v1/monitoring/{monitor_id}/timeline",
        headers=_headers(token),
    )
    assert timeline.status_code == 200
    diff = timeline.json()["diffs"][0]
    assert diff["new_exposure_count"] == 1
    assert diff["added"][0]["masked_preview"] == "+1 (***) ***-01**"
    assert "value_hmac" not in diff["added"][0]
    assert "value_enc" not in diff["added"][0]
    async with auth_session_factory() as session:
        stored_diff = await session.get(ScanDiff, UUID(diff["id"]))
        assert stored_diff is not None
        assert "PHONE_NUMBER" == stored_diff.added_json[0]["type"]
        monitor = await session.get(MonitorJob, monitor_id)
        assert monitor is not None
        later = now + timedelta(days=1)
        monitor.next_run_at = later - timedelta(seconds=1)
        await session.commit()

    assert (
        await MonitoringService(auth_app.state.settings, queue).dispatch_due(
            auth_session_factory,
            now=later,
        )
        == 1
    )
    async with auth_session_factory() as session:
        monitor = await session.get(MonitorJob, monitor_id)
        assert monitor is not None
        partial_scan_id = monitor.pending_scan_id
        assert partial_scan_id is not None
        partial_scan = await session.get(Scan, partial_scan_id)
        assert partial_scan is not None
        partial_scan.status = "DONE"
        partial_scan.stage_checkpoint = "DONE"
        partial_scan.result_state = "GENERATED"
        partial_scan.error_code = "PARTIAL_SOURCE_FAILURE"
        await session.commit()
    await MonitoringService(auth_app.state.settings).complete_scheduled_scan(
        auth_session_factory,
        partial_scan_id,
    )
    timeline = await scan_client.get(
        f"/v1/monitoring/{monitor_id}/timeline",
        headers=_headers(token),
    )
    assert len(timeline.json()["diffs"]) == 1
    async with auth_session_factory() as session:
        monitor = await session.get(MonitorJob, monitor_id)
        assert monitor is not None
        assert monitor.last_scan_id == scheduled_id
        assert monitor.pending_scan_id is None
        monitor.next_run_at = later - timedelta(seconds=1)
        await session.commit()

    revoked = await scan_client.post("/v1/consent/revoke", headers=_headers(token))
    assert revoked.status_code == 200
    assert (
        await MonitoringService(auth_app.state.settings, queue).dispatch_due(
            auth_session_factory,
            now=later,
        )
        == 0
    )
    async with auth_session_factory() as session:
        monitor = await session.get(MonitorJob, monitor_id)
        assert monitor is not None
        assert monitor.active is False
        assert monitor.pause_reason == "CONSENT_REVOKED"

    deleted_source = await scan_client.delete(
        f"/v1/sources/{source_id}",
        headers=_headers(token),
    )
    assert deleted_source.status_code == 204
    async with auth_session_factory() as session:
        assert await session.get(MonitorJob, monitor_id) is None
        assert (
            await session.scalar(select(ScanDiff.id).where(ScanDiff.monitor_job_id == monitor_id))
            is None
        )


async def test_demo_persona_is_synthetic_consent_gated_and_idempotent(
    scan_client: AsyncClient,
    auth_session_factory: async_sessionmaker[AsyncSession],
    auth_app: FastAPI,
) -> None:
    persona = generate_persona(42)
    assert persona == generate_persona(42)
    assert persona.email == "persona-42@example.test"
    assert "555-0142" in persona.content
    assert "@demo_persona_42" in persona.content

    token, user_id = await _register(scan_client, "demo-persona@example.com")
    request = {"seed": 42, "pattern": "all"}
    rejected = await scan_client.post(
        "/v1/demo/persona",
        headers=_headers(token),
        json=request,
    )
    assert rejected.status_code == 403
    await _accept_consent(scan_client, token)
    first = await scan_client.post(
        "/v1/demo/persona",
        headers=_headers(token),
        json=request,
    )
    repeated = await scan_client.post(
        "/v1/demo/persona",
        headers=_headers(token),
        json=request,
    )
    assert first.status_code == 202
    assert first.json()["synthetic"] is True
    assert first.json()["scan_id"] == repeated.json()["scan_id"]
    assert first.json()["source_id"] == repeated.json()["source_id"]

    async with auth_session_factory() as session:
        source = await session.get(Source, UUID(first.json()["source_id"]))
        assert source is not None
        assert source.user_id == user_id
        assert source.kind == "TEXT"
        assert source.ownership_status == "SELF_DECLARED"
        assert source.content_enc is not None
        assert b"persona-42@example.test" not in source.content_enc
        assert await session.scalar(
            select(Scan.id).where(Scan.id == UUID(first.json()["scan_id"]))
        ) == UUID(first.json()["scan_id"])
    queue: FixtureQueue = auth_app.state.test_scan_queue
    assert queue.scan_ids.count(UUID(first.json()["scan_id"])) == 1


async def test_demo_persona_retries_queue_failure_without_duplicating_source(
    scan_client: AsyncClient,
    auth_app: FastAPI,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    token, user_id = await _register(scan_client, "demo-retry@example.com")
    await _accept_consent(scan_client, token)
    queue: FixtureQueue = auth_app.state.test_scan_queue
    queue.unavailable = True
    payload = {"seed": 43, "pattern": "profile"}
    failed = await scan_client.post(
        "/v1/demo/persona",
        headers=_headers(token),
        json=payload,
    )
    assert failed.status_code == 503

    queue.unavailable = False
    retried = await scan_client.post(
        "/v1/demo/persona",
        headers=_headers(token),
        json=payload,
    )
    assert retried.status_code == 202
    async with auth_session_factory() as session:
        sources = list(
            (await session.execute(select(Source).where(Source.user_id == user_id))).scalars()
        )
        assert len(sources) == 1
        assert str(sources[0].id) == retried.json()["source_id"]
    assert queue.scan_ids == [UUID(retried.json()["scan_id"])]


def test_demo_persona_cli_prints_seeded_synthetic_content(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.argv", ["privacy-shield-demo-persona", "--seed", "42"])
    demo_cli_main()
    result = json.loads(capsys.readouterr().out)
    assert result["synthetic"] is True
    assert result["seed"] == 42
    assert result["pattern"] == "all"
    assert "persona-42@example.test" in result["content"]


def test_demo_persona_generator_rejects_out_of_range_seed() -> None:
    with pytest.raises(ValueError, match="seed"):
        generate_persona(-1)
