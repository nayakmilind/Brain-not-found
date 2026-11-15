import base64
from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings
from app.db.base import Base
from app.main import create_app


def _key_material(char: bytes) -> str:
    return base64.b64encode(char * 32).decode("ascii")


@pytest.fixture
def auth_settings() -> Settings:
    return Settings(
        _env_file=None,
        database_url="postgresql+asyncpg://user:pass@localhost/db",
        redis_url="redis://localhost:6379/0",
        master_kek_b64=_key_material(b"k"),
        hmac_pepper_b64=_key_material(b"h"),
        jwt_secret_b64=_key_material(b"j"),
        cookie_secure=False,
        login_failure_threshold=2,
        login_backoff_base_seconds=60,
    )


@pytest.fixture
async def auth_app(
    auth_settings: Settings,
    auth_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[FastAPI]:
    app = create_app(auth_settings)
    async with app.router.lifespan_context(app):
        app.state.session_factory = auth_session_factory
        yield app


@pytest.fixture
async def auth_session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine: AsyncEngine = create_async_engine("sqlite+aiosqlite:///:memory:")
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine.sync_engine, "connect")
        def enable_sqlite_foreign_keys(connection, _record) -> None:
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    yield session_factory
    await engine.dispose()
