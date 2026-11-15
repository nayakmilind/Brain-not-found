from __future__ import annotations

from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from docx import Document

from app.pipeline.extractors import ExtractionError, extract_document

DOCX_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _extract(content: bytes, media_type: str, *, max_characters: int = 100_000):
    return extract_document(
        content,
        media_type,
        max_characters=max_characters,
        max_pdf_pages=10,
        max_docx_uncompressed_bytes=1_000_000,
    )


def _minimal_pdf(text: str) -> bytes:
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        (f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream"),
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, content in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode())
        pdf.extend(content)
        pdf.extend(b"\nendobj\n")
    xref_offset = len(pdf)
    pdf.extend(b"xref\n0 6\n0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode())
    pdf.extend(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode())
    return bytes(pdf)


def test_extracts_visible_and_hidden_html_with_metadata() -> None:
    content = (
        b"<html><head><title>Synthetic profile</title>"
        b'<meta name="description" content="synthetic summary"></head><body>'
        b"<p>Visible text</p><div hidden>Hidden detail</div>"
        b"<script>script content</script></body></html>"
    )

    extracted = _extract(content, "text/html; charset=utf-8")

    assert extracted.title == "Synthetic profile"
    assert extracted.metadata["description"] == "synthetic summary"
    assert "Visible text" in extracted.text
    assert extracted.hidden_text == "Hidden detail"
    assert "script content" not in extracted.text


def test_extracts_plain_text_and_pdf() -> None:
    plain = _extract(b"Synthetic plain text", "text/plain")
    pdf = _extract(_minimal_pdf("Synthetic PDF text"), "application/pdf")

    assert plain.text == "Synthetic plain text"
    assert "Synthetic PDF text" in pdf.text
    assert pdf.media_type == "application/pdf"


def test_extracts_docx_paragraphs_tables_headers_and_hidden_runs() -> None:
    document = Document()
    document.core_properties.title = "Synthetic document"
    document.add_paragraph("Visible paragraph")
    hidden_run = document.add_paragraph().add_run("Hidden paragraph")
    hidden_run.font.hidden = True
    cell = document.add_table(rows=1, cols=1).cell(0, 0)
    cell.text = "Table content"
    output = BytesIO()
    document.save(output)

    extracted = _extract(output.getvalue(), DOCX_TYPE)

    assert extracted.title == "Synthetic document"
    assert "Visible paragraph" in extracted.text
    assert "Table content" in extracted.text
    assert "Hidden paragraph" in extracted.hidden_text


def test_extractor_rejects_unsupported_malformed_and_oversized_content() -> None:
    with pytest.raises(ExtractionError, match="media type"):
        _extract(b"<svg/>", "image/svg+xml")
    with pytest.raises(ExtractionError, match="UTF-8"):
        _extract(b"\xff\xfe", "text/plain")
    with pytest.raises(ExtractionError, match="character limit"):
        _extract(b"five chars", "text/plain", max_characters=4)
    with pytest.raises(ExtractionError, match="signature"):
        _extract(b"not a PDF", "application/pdf")


def test_docx_expansion_limit_is_checked_before_parsing() -> None:
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "x" * 200)
        archive.writestr("word/document.xml", "y" * 200)

    with pytest.raises(ExtractionError, match="expanded size"):
        extract_document(
            output.getvalue(),
            DOCX_TYPE,
            max_characters=1000,
            max_pdf_pages=10,
            max_docx_uncompressed_bytes=300,
        )
