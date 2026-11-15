import asyncio
from typing import Literal

import structlog
from fastapi import APIRouter, Request, status
from pydantic import BaseModel
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.responses import JSONResponse

router = APIRouter(tags=["health"])
logger = structlog.get_logger(__name__)


class LivenessResponse(BaseModel):
    status: Literal["ok"]


class ReadinessResponse(BaseModel):
    status: Literal["ready"]
    dependencies: dict[str, Literal["available"]]


class DependencyStatus(BaseModel):
    status: Literal["not_ready"]
    dependencies: dict[str, Literal["available", "unavailable"]]


@router.get("/healthz", response_model=LivenessResponse)
async def healthz() -> LivenessResponse:
    return LivenessResponse(status="ok")


async def _check_postgres(engine: AsyncEngine) -> bool:
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    except (SQLAlchemyError, OSError, TimeoutError) as exc:
        logger.warning(
            "dependency_check_failed",
            dependency="postgres",
            error_type=type(exc).__name__,
        )
        return False
    return True


async def _check_redis(client: Redis) -> bool:
    try:
        await client.ping()
    except (RedisError, OSError, TimeoutError) as exc:
        logger.warning(
            "dependency_check_failed",
            dependency="redis",
            error_type=type(exc).__name__,
        )
        return False
    return True


@router.get(
    "/readyz",
    response_model=ReadinessResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": DependencyStatus}},
)
async def readyz(request: Request) -> ReadinessResponse | JSONResponse:
    engine: AsyncEngine = request.app.state.db_engine
    redis: Redis = request.app.state.redis
    postgres_ready, redis_ready = await asyncio.gather(
        _check_postgres(engine),
        _check_redis(redis),
    )
    dependencies: dict[str, Literal["available", "unavailable"]] = {
        "postgres": "available" if postgres_ready else "unavailable",
        "redis": "available" if redis_ready else "unavailable",
    }

    if not postgres_ready or not redis_ready:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=DependencyStatus(
                status="not_ready",
                dependencies=dependencies,
            ).model_dump(),
        )

    return ReadinessResponse(
        status="ready",
        dependencies={"postgres": "available", "redis": "available"},
    )
