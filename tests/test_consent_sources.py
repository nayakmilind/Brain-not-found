from collections.abc import AsyncIterator
from datetime import UTC, datetime
from io import BytesIO
from urllib.parse import quote
from uuid import UUID
from zipfile import ZipFile

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.crypto import decode_key, decrypt_bytes, decrypt_value, unwrap_data_key
from app.db.models.auth import User
from app.db.models.consent import Consent
from app.db.models.source import Source
from app.modules.sources.service import (
    InvalidSourceContent,
    SourceNotScannable,
    SourceService,
)

TEST_PASSWORD = "synthetic-personal-password"


@pytest.fixture
async def m2_client(auth_app: FastAPI) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=auth_app),
        base_url="http://testserver",
    ) as client:
        yield client


async def _register(client: AsyncClient, email: str) -> tuple[str, UUID]:
    response = await client.post(
        "/v1/auth/register",
        json={"email": email, "password": TEST_PASSWORD},
    )
    assert response.status_code == 201
    data = response.json()
    return data["access_token"], UUID(data["user_id"])


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _accept_consent(client: AsyncClient, token: str) -> None:
    current_version = await client.get(
        "/v1/consent/current-version",
        headers=_headers(token),
    )
    assert current_version.status_code == 200
    response = await client.post(
        "/v1/consent/accept",
        headers=_headers(token),
        json={"version": current_version.json()["version"], "accepted": True},
    )
    assert response.status_code == 200
    assert response.json()["accepted"] is True


async def test_consent_gates_sources_and_source_fields_are_encrypted(
    m2_client: AsyncClient,
    auth_session_factory: async_sessionmaker[AsyncSession],
    auth_settings: Settings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    token, user_id = await _register(m2_client, "avery.example@example.com")
    headers = _headers(token)

    before_consent = await m2_client.post(
        "/v1/sources",
        headers=headers,
        json={
            "kind": "TEXT",
            "label": "Personal notes",
            "content": "Synthetic persona Morgan Example, morgan@example.test",
        },
    )
    assert before_consent.status_code == 403
    assert (await m2_client.get("/v1/consent/current", headers=headers)).json()["accepted"] is False

    await _accept_consent(m2_client, token)
    url_response = await m2_client.post(
        "/v1/sources",
        headers=headers,
        json={
            "kind": "URL",
            "label": "Avery's profile",
            "uri": "https://example.com/avery?view=public",
        },
    )
    text_response = await m2_client.post(
        "/v1/sources",
        headers=headers,
        json={
            "kind": "TEXT",
            "label": "Personal notes",
            "content": "Synthetic persona Morgan Example, morgan@example.test",
        },
    )
    assert url_response.status_code == 201
    assert text_response.status_code == 201
    url_source = url_response.json()
    text_source = text_response.json()
    assert url_source["ownership_status"] == "UNVERIFIED"
    assert text_source["ownership_status"] == "SELF_DECLARED"
    assert url_source["label_preview"] == "Website URL"
    assert text_source["label_preview"] == "Pasted text"
    assert "Avery" not in str(url_source)
    assert "Morgan" not in str(text_source)

    async with auth_session_factory() as session:
        user = await session.get(User, user_id)
        assert user is not None
        data_key = unwrap_data_key(
            user.dek_wrapped,
            decode_key(auth_settings.master_kek_b64.get_secret_value()),
            b"user-dek:" + user_id.bytes,
        )
        sources = list((await session.execute(select(Source))).scalars().all())
        consent = (await session.execute(select(Consent))).scalar_one()
        assert len(sources) == 2
        assert len(consent.ip_hash) == 64
        assert b"testclient" not in consent.ip_hash.encode()
        by_id = {source.id: source for source in sources}
        stored_url = by_id[UUID(url_source["id"])]
        stored_text = by_id[UUID(text_source["id"])]
        assert b"example.com" not in (stored_url.uri_enc or b"")
        assert b"Avery's profile" not in stored_url.label_enc
        assert b"Morgan Example" not in (stored_text.content_enc or b"")
        assert (
            decrypt_value(
                stored_url.uri_enc or b"",
                data_key,
                b"source-uri:" + stored_url.id.bytes,
            )
            == "https://example.com/avery?view=public"
        )
        assert (
            decrypt_bytes(
                stored_text.content_enc or b"",
                data_key,
                b"source-content:" + stored_text.id.bytes,
            )
            == b"Synthetic persona Morgan Example, morgan@example.test"
        )
        assert consent.scope_json == {
            "assess_only_my_own_sources": True,
            "never_request_platform_credentials": True,
            "scores_are_estimates_not_safety_guarantees": True,
        }
        service = SourceService(auth_settings)
        with pytest.raises(SourceNotScannable):
            await service.require_scannable(session, user_id, stored_url.id)
        assert (
            await service.require_scannable(session, user_id, stored_text.id)
        ).ownership_status == "SELF_DECLARED"
    assert "Morgan Example" not in caplog.text
    assert "morgan@example.test" not in caplog.text


async def test_source_file_types_size_caps_and_self_declaration(
    m2_client: AsyncClient,
    auth_app: FastAPI,
) -> None:
    token, _ = await _register(m2_client, "file.owner@example.com")
    await _accept_consent(m2_client, token)
    headers = _headers(token)

    text_upload = await m2_client.post(
        "/v1/sources/file",
        headers={
            **headers,
            "X-Source-Label": quote("Synthetic export", safe=""),
            "X-Source-Extension": "txt",
            "Content-Type": "text/plain",
        },
        content=b"synthetic exported text",
    )
    assert text_upload.status_code == 201
    assert text_upload.json()["kind"] == "FILE"
    assert text_upload.json()["ownership_status"] == "SELF_DECLARED"

    pdf_upload = await m2_client.post(
        "/v1/sources/file",
        headers={
            **headers,
            "X-Source-Label": quote("Synthetic PDF", safe=""),
            "X-Source-Extension": "pdf",
            "Content-Type": "application/pdf",
        },
        content=b"%PDF-1.7\nsynthetic",
    )
    assert pdf_upload.status_code == 201

    docx = BytesIO()
    with ZipFile(docx, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document/>")
    docx_content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    docx_upload = await m2_client.post(
        "/v1/sources/file",
        headers={
            **headers,
            "X-Source-Label": quote("Synthetic DOCX", safe=""),
            "X-Source-Extension": "docx",
            "X-Source-Kind": "PLATFORM_EXPORT",
            "Content-Type": docx_content_type,
        },
        content=docx.getvalue(),
    )
    assert docx_upload.status_code == 201
    assert docx_upload.json()["kind"] == "PLATFORM_EXPORT"

    invalid_upload = await m2_client.post(
        "/v1/sources/file",
        headers={
            **headers,
            "X-Source-Label": "Invalid",
            "X-Source-Extension": "pdf",
            "Content-Type": "application/pdf",
        },
        content=b"not a PDF",
    )
    assert invalid_upload.status_code == 422

    auth_app.state.settings = auth_app.state.settings.model_copy(update={"source_max_bytes": 4})
    oversized_upload = await m2_client.post(
        "/v1/sources/file",
        headers={
            **headers,
            "X-Source-Label": "Large",
            "X-Source-Extension": "txt",
            "Content-Type": "text/plain",
        },
        content=b"12345",
    )
    assert oversized_upload.status_code == 413
    oversized_text = await m2_client.post(
        "/v1/sources",
        headers=headers,
        json={"kind": "TEXT", "label": "Large", "content": "12345"},
    )
    assert oversized_text.status_code == 413


async def test_sources_are_isolated_and_revocation_blocks_additions(
    m2_client: AsyncClient,
) -> None:
    owner_token, _ = await _register(m2_client, "owner@example.com")
    await _accept_consent(m2_client, owner_token)
    created = await m2_client.post(
        "/v1/sources",
        headers=_headers(owner_token),
        json={"kind": "TEXT", "label": "Private", "content": "Synthetic text"},
    )
    assert created.status_code == 201

    other_token, _ = await _register(m2_client, "other@example.org")
    other_list = await m2_client.get("/v1/sources", headers=_headers(other_token))
    assert other_list.status_code == 200
    assert other_list.json()["items"] == []
    cross_user_delete = await m2_client.delete(
        f"/v1/sources/{created.json()['id']}",
        headers=_headers(other_token),
    )
    assert cross_user_delete.status_code == 404

    revoked = await m2_client.post(
        "/v1/consent/revoke",
        headers=_headers(owner_token),
    )
    assert revoked.status_code == 200
    assert revoked.json()["revoked"] is True
    assert revoked.json()["revoked_at"] is not None
    current = await m2_client.get(
        "/v1/consent/current",
        headers=_headers(owner_token),
    )
    assert current.json()["accepted"] is False
    denied = await m2_client.post(
        "/v1/sources",
        headers=_headers(owner_token),
        json={"kind": "TEXT", "label": "New", "content": "More synthetic text"},
    )
    assert denied.status_code == 403

    deleted = await m2_client.delete(
        f"/v1/sources/{created.json()['id']}",
        headers=_headers(owner_token),
    )
    assert deleted.status_code == 204
    assert deleted.content == b""


async def test_authentication_and_source_validation_errors(
    m2_client: AsyncClient,
    auth_app: FastAPI,
) -> None:
    unauthenticated = await m2_client.get("/v1/sources")
    assert unauthenticated.status_code == 401
    invalid_token = await m2_client.get(
        "/v1/sources",
        headers=_headers("not-a-valid-token"),
    )
    assert invalid_token.status_code == 401

    token, user_id = await _register(m2_client, "validation@example.com")
    async with auth_app.state.session_factory() as session:
        user = await session.get(User, user_id)
        assert user is not None
        user.deleted_at = datetime.now(UTC)
        await session.commit()
    deleted_user = await m2_client.get("/v1/sources", headers=_headers(token))
    assert deleted_user.status_code == 401

    token, _ = await _register(m2_client, "validation-again@example.com")
    no_op_revoke = await m2_client.post(
        "/v1/consent/revoke",
        headers=_headers(token),
    )
    assert no_op_revoke.status_code == 200
    assert no_op_revoke.json() == {"revoked": False, "revoked_at": None}
    await _accept_consent(m2_client, token)
    invalid_url = await m2_client.post(
        "/v1/sources",
        headers=_headers(token),
        json={"kind": "URL", "label": "Loopback", "uri": "http://127.0.0.1/"},
    )
    assert invalid_url.status_code == 422
    blank_label = await m2_client.post(
        "/v1/sources",
        headers=_headers(token),
        json={"kind": "TEXT", "label": "   ", "content": "Synthetic"},
    )
    assert blank_label.status_code == 422
    bad_consent_version = await m2_client.post(
        "/v1/consent/accept",
        headers=_headers(token),
        json={"version": "outdated", "accepted": True},
    )
    assert bad_consent_version.status_code == 409


def test_source_service_reports_file_format_and_size_errors(
    auth_settings: Settings,
) -> None:
    service = SourceService(auth_settings.model_copy(update={"source_max_bytes": 3}))
    with pytest.raises(InvalidSourceContent):
        service._sniff_file("file.txt", b"\xff")
    with pytest.raises(InvalidSourceContent):
        service._sniff_file("file.txt", b"a\x00b")
    with pytest.raises(InvalidSourceContent):
        service._sniff_file("file.docx", b"PK\x03\x04invalid")
    with pytest.raises(InvalidSourceContent):
        service._sniff_file("file.exe", b"anything")
