from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import OperationalError

from app.core.config import Settings
from app.main import create_app


class FakeConnection:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    async def __aenter__(self) -> FakeConnection:
        if self.fail:
            raise OperationalError("SELECT 1", {}, OSError("database unavailable"))
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def execute(self, _statement: Any) -> None:
        return None


class FakeEngine:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def connect(self) -> FakeConnection:
        return FakeConnection(fail=self.fail)

    async def dispose(self) -> None:
        return None


class FakeRedis:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    async def ping(self) -> bool:
        if self.fail:
            raise RedisConnectionError("redis unavailable")
        return True

    async def aclose(self) -> None:
        return None


@pytest.fixture
async def health_client(
    auth_settings: Settings,
) -> AsyncIterator[tuple[AsyncClient, FastAPI]]:
    app = create_app(auth_settings)
    async with app.router.lifespan_context(app):
        app.state.db_engine = FakeEngine()
        app.state.redis = FakeRedis()
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            yield client, app


def install_fake_dependencies(
    app: FastAPI,
    *,
    postgres_fail: bool = False,
    redis_fail: bool = False,
) -> None:
    app.state.db_engine = FakeEngine(fail=postgres_fail)
    app.state.redis = FakeRedis(fail=redis_fail)


async def test_healthz_is_live_and_includes_request_id(
    health_client: tuple[AsyncClient, FastAPI],
) -> None:
    client, _app = health_client
    response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["X-Request-ID"]


async def test_readyz_reports_all_dependencies_available(
    health_client: tuple[AsyncClient, FastAPI],
) -> None:
    client, _app = health_client
    response = await client.get("/readyz")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "dependencies": {"postgres": "available", "redis": "available"},
    }


@pytest.mark.parametrize(
    ("postgres_fail", "redis_fail", "expected_dependencies"),
    [
        (True, False, {"postgres": "unavailable", "redis": "available"}),
        (False, True, {"postgres": "available", "redis": "unavailable"}),
        (True, True, {"postgres": "unavailable", "redis": "unavailable"}),
    ],
)
async def test_readyz_reports_unavailable_dependencies_without_details(
    health_client: tuple[AsyncClient, FastAPI],
    postgres_fail: bool,
    redis_fail: bool,
    expected_dependencies: dict[str, str],
) -> None:
    client, app = health_client
    install_fake_dependencies(
        app,
        postgres_fail=postgres_fail,
        redis_fail=redis_fail,
    )
    response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "dependencies": expected_dependencies,
    }
