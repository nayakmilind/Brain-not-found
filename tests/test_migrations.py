import importlib.util
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import inspect
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine


def _migration_module(filename: str, module_name: str) -> ModuleType:
    migration_path = Path(__file__).parents[1] / "alembic" / "versions" / filename
    spec = importlib.util.spec_from_file_location(module_name, migration_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load initial auth migration")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_migrations_create_and_drop_scans_and_existing_tables() -> None:
    initial = _migration_module("0001_auth_tables.py", "initial_auth_migration")
    sources = _migration_module("0002_consent_sources.py", "consent_sources_migration")
    scans = _migration_module("0003_scans.py", "scans_migration")
    findings = _migration_module("0004_findings.py", "findings_migration")
    graph = _migration_module("0005_exposure_graph.py", "exposure_graph_migration")
    scoring = _migration_module("0006_risk_scoring.py", "risk_scoring_migration")
    recommendations = _migration_module(
        "0007_recommendations.py",
        "recommendations_migration",
    )
    reports_audit = _migration_module("0008_reports_audit.py", "reports_audit_migration")
    monitoring = _migration_module("0010_monitoring.py", "monitoring_migration")
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, initial.upgrade)
            )
            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, sources.upgrade)
            )
            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, scans.upgrade)
            )
            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, findings.upgrade)
            )
            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, graph.upgrade)
            )
            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, scoring.upgrade)
            )
            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, recommendations.upgrade)
            )
            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, reports_audit.upgrade)
            )
            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, monitoring.upgrade)
            )
            table_names = await connection.run_sync(
                lambda sync_connection: inspect(sync_connection).get_table_names()
            )
            assert {
                "users",
                "refresh_tokens",
                "consents",
                "sources",
                "ownership_challenges",
                "scans",
                "scan_sources",
                "scan_events",
                "scan_dead_letters",
                "findings",
                "entities",
                "entity_mentions",
                "graph_edges",
                "risk_scores",
                "recommendations",
                "reports",
                "audit_entries",
                "audit_chain_heads",
                "monitor_jobs",
                "monitor_sources",
                "scan_diffs",
            }.issubset(table_names)

            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, monitoring.downgrade)
            )
            table_names = await connection.run_sync(
                lambda sync_connection: inspect(sync_connection).get_table_names()
            )
            assert "monitor_jobs" not in table_names
            assert "monitor_sources" not in table_names
            assert "scan_diffs" not in table_names
            assert "monitor_job_id" not in {
                column["name"]
                for column in await connection.run_sync(
                    lambda sync_connection: inspect(sync_connection).get_columns("scans")
                )
            }

            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, reports_audit.downgrade)
            )
            table_names = await connection.run_sync(
                lambda sync_connection: inspect(sync_connection).get_table_names()
            )
            assert "reports" not in table_names
            assert "audit_entries" not in table_names
            assert "audit_chain_heads" not in table_names

            await connection.run_sync(
                lambda sync_connection: _run_migration(
                    sync_connection,
                    recommendations.downgrade,
                )
            )
            table_names = await connection.run_sync(
                lambda sync_connection: inspect(sync_connection).get_table_names()
            )
            assert "recommendations" not in table_names

            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, scoring.downgrade)
            )
            table_names = await connection.run_sync(
                lambda sync_connection: inspect(sync_connection).get_table_names()
            )
            assert "risk_scores" not in table_names

            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, graph.downgrade)
            )
            table_names = await connection.run_sync(
                lambda sync_connection: inspect(sync_connection).get_table_names()
            )
            assert "entities" not in table_names
            assert "entity_mentions" not in table_names
            assert "graph_edges" not in table_names

            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, findings.downgrade)
            )
            table_names = await connection.run_sync(
                lambda sync_connection: inspect(sync_connection).get_table_names()
            )
            assert "findings" not in table_names

            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, scans.downgrade)
            )
            table_names = await connection.run_sync(
                lambda sync_connection: inspect(sync_connection).get_table_names()
            )
            assert "scans" not in table_names
            assert "scan_sources" not in table_names
            assert "scan_events" not in table_names
            assert "scan_dead_letters" not in table_names

            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, sources.downgrade)
            )
            table_names = await connection.run_sync(
                lambda sync_connection: inspect(sync_connection).get_table_names()
            )
            assert "consents" not in table_names
            assert "sources" not in table_names
            assert "ownership_challenges" not in table_names

            await connection.run_sync(
                lambda sync_connection: _run_migration(sync_connection, initial.downgrade)
            )
            table_names = await connection.run_sync(
                lambda sync_connection: inspect(sync_connection).get_table_names()
            )
            assert "users" not in table_names
            assert "refresh_tokens" not in table_names
    finally:
        await engine.dispose()


def _run_migration(connection: Connection, migration_function: Callable[[], None]) -> None:
    context = MigrationContext.configure(connection)
    with Operations.context(context):
        migration_function()
