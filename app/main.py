from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import uuid4

import structlog
from arq.connections import ArqRedis
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.middleware.base import RequestResponseEndpoint

from app.core.config import Settings
from app.core.logging import configure_logging
from app.core.ssrf_guard import SafeFetcher
from app.modules.assistant.router import router as assistant_router
from app.modules.auth.router import router as auth_router
from app.modules.auth.service import AuthService
from app.modules.consent.router import router as consent_router
from app.modules.demo.router import router as demo_router
from app.modules.findings.router import reveal_router
from app.modules.findings.router import router as findings_router
from app.modules.graph.router import router as graph_router
from app.modules.health.router import router as health_router
from app.modules.monitoring.router import router as monitoring_router
from app.modules.ownership.router import router as ownership_router
from app.modules.privacy.router import router as privacy_router
from app.modules.recommendations.router import router as recommendations_router
from app.modules.reports.router import router as reports_router
from app.modules.scans.queue import ArqScanQueue
from app.modules.scans.router import router as scans_router
from app.modules.scoring.router import router as scoring_router
from app.modules.sources.router import router as sources_router


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app_settings = settings or Settings()
        configure_logging(app_settings.log_level)
        engine = create_async_engine(
            app_settings.database_url.get_secret_value(),
            pool_pre_ping=True,
        )
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        redis = Redis.from_url(
            app_settings.redis_url.get_secret_value(),
            decode_responses=True,
        )
        arq_pool = ArqRedis.from_url(app_settings.redis_url.get_secret_value())
        app.state.settings = app_settings
        app.state.db_engine = engine
        app.state.session_factory = session_factory
        app.state.redis = redis
        app.state.arq_pool = arq_pool
        app.state.scan_queue = ArqScanQueue(arq_pool)
        app.state.auth_service = AuthService(app_settings)
        app.state.safe_fetcher = SafeFetcher(
            max_bytes=app_settings.source_max_bytes,
            timeout_seconds=app_settings.source_fetch_timeout_seconds,
            max_redirects=app_settings.source_max_redirects,
        )
        try:
            yield
        finally:
            await engine.dispose()
            await redis.aclose()
            await arq_pool.aclose()

    application = FastAPI(
        title="Privacy Shield AI",
        version="0.1.0",
        lifespan=lifespan,
    )
    application.include_router(health_router)
    application.include_router(auth_router)
    application.include_router(consent_router)
    application.include_router(sources_router)
    application.include_router(ownership_router)
    application.include_router(scans_router)
    application.include_router(findings_router)
    application.include_router(reveal_router)
    application.include_router(graph_router)
    application.include_router(scoring_router)
    application.include_router(recommendations_router)
    application.include_router(assistant_router)
    application.include_router(reports_router)
    application.include_router(privacy_router)
    application.include_router(monitoring_router)
    application.include_router(demo_router)

    @application.exception_handler(RequestValidationError)
    async def validation_error_response(
        _request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        errors = [{"location": list(error["loc"]), "code": error["type"]} for error in exc.errors()]
        return JSONResponse(
            status_code=422,
            content={
                "type": "about:blank",
                "title": "Request validation failed",
                "status": 422,
                "detail": "One or more fields are invalid.",
                "errors": errors,
            },
        )

    @application.middleware("http")
    async def add_request_id(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        request_id = str(uuid4())
        structlog.contextvars.bind_contextvars(request_id=request_id)
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            structlog.contextvars.unbind_contextvars("request_id")

    return application


app = create_app()
