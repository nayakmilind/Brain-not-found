from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from io import BytesIO
from zipfile import BadZipFile, LargeZipFile, ZipFile

from docx import Document
from docx.opc.exceptions import PackageNotFoundError
from docx.table import Table
from docx.text.paragraph import Paragraph
from pypdf import PdfReader
from pypdf.errors import PdfReadError
from selectolax.lexbor import LexborHTMLParser

HTML_TYPES = frozenset({"application/xhtml+xml", "text/html"})
DOCX_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


class ExtractionError(ValueError):
    pass


@dataclass(frozen=True)
class ExtractedDocument:
    text: str
    hidden_text: str
    title: str | None
    metadata: dict[str, str]
    media_type: str


def extract_document(
    content: bytes,
    media_type: str,
    *,
    max_characters: int,
    max_pdf_pages: int,
    max_docx_uncompressed_bytes: int,
) -> ExtractedDocument:
    normalized_type = media_type.split(";", 1)[0].strip().lower()
    if not content:
        raise ExtractionError("The source document is empty")
    if len(content) > max_docx_uncompressed_bytes:
        raise ExtractionError("The source exceeds the extraction size limit")
    if normalized_type in HTML_TYPES:
        document = _extract_html(content, max_characters)
    elif normalized_type == "text/plain":
        document = _extract_plain_text(content, max_characters)
    elif normalized_type == "application/pdf":
        document = _extract_pdf(content, max_characters, max_pdf_pages)
    elif normalized_type == DOCX_TYPE:
        document = _extract_docx(content, max_characters, max_docx_uncompressed_bytes)
    else:
        raise ExtractionError("The source media type is not supported")
    return ExtractedDocument(
        text=document[0],
        hidden_text=document[1],
        title=document[2],
        metadata=document[3],
        media_type=normalized_type,
    )


def _extract_html(
    content: bytes,
    max_characters: int,
) -> tuple[str, str, str | None, dict[str, str]]:
    try:
        tree = LexborHTMLParser(content)
    except (TypeError, ValueError) as error:
        raise ExtractionError("The HTML source is malformed") from error

    title_node = tree.css_first("title")
    title = title_node.text(strip=True) if title_node is not None else None
    metadata: dict[str, str] = {}
    for node in tree.css("meta"):
        attributes = node.attributes
        key = attributes.get("name") or attributes.get("property") or attributes.get("itemprop")
        value = attributes.get("content")
        if key and value and len(metadata) < 100:
            metadata[key.strip().lower()[:100]] = value.strip()[:1000]

    for node in tree.css("script,style,noscript,svg,iframe,canvas,template"):
        node.decompose()

    hidden_nodes = tree.css(
        '[hidden], [aria-hidden="true"], [style*="display:none"], '
        '[style*="display: none"], [style*="visibility:hidden"], '
        '[style*="visibility: hidden"]'
    )
    hidden_text = " ".join(
        text for node in hidden_nodes if (text := node.text(separator=" ", strip=True))
    )
    for node in hidden_nodes:
        node.decompose()

    body = tree.css_first("body")
    text = (
        body.text(separator=" ", strip=True)
        if body is not None
        else tree.root.text(
            separator=" ",
            strip=True,
        )
    )
    if title is not None and len(title) > max_characters:
        raise ExtractionError("The extracted document exceeds the character limit")
    _require_character_limit(text, hidden_text, metadata, max_characters)
    return text, hidden_text, title, metadata


def _extract_plain_text(
    content: bytes,
    max_characters: int,
) -> tuple[str, str, None, dict[str, str]]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ExtractionError("Plain text sources must use UTF-8 encoding") from error
    _require_character_limit(text, "", {}, max_characters)
    return text, "", None, {}


def _extract_pdf(
    content: bytes,
    max_characters: int,
    max_pages: int,
) -> tuple[str, str, str | None, dict[str, str]]:
    if not content.startswith(b"%PDF-"):
        raise ExtractionError("The PDF signature is invalid")
    try:
        reader = PdfReader(BytesIO(content), strict=True)
        if reader.is_encrypted:
            raise ExtractionError("Encrypted PDF files are not supported")
        if len(reader.pages) > max_pages:
            raise ExtractionError("The PDF exceeds the page limit")
        page_text: list[str] = []
        character_count = 0
        for page in reader.pages:
            text = page.extract_text() or ""
            character_count += len(text)
            if character_count > max_characters:
                raise ExtractionError("The extracted document exceeds the character limit")
            page_text.append(text)
        metadata_value = reader.metadata.title if reader.metadata is not None else None
        title = str(metadata_value).strip() if metadata_value else None
        metadata: dict[str, str] = {}
        if reader.metadata is not None:
            for key, value in reader.metadata.items():
                if value is not None and len(metadata) < 100:
                    metadata[str(key)[:100]] = str(value)[:1000]
    except ExtractionError:
        raise
    except (PdfReadError, OSError, ValueError, EOFError) as error:
        raise ExtractionError("The PDF source is malformed") from error
    text = "\n".join(page_text)
    _require_character_limit(text, "", metadata, max_characters)
    return text, "", title, metadata


def _extract_docx(
    content: bytes,
    max_characters: int,
    max_uncompressed_bytes: int,
) -> tuple[str, str, str | None, dict[str, str]]:
    try:
        with ZipFile(BytesIO(content)) as archive:
            entries = archive.infolist()
            if (
                len(entries) > 256
                or sum(entry.file_size for entry in entries) > max_uncompressed_bytes
            ):
                raise ExtractionError("The DOCX exceeds the expanded size limit")
            names = {entry.filename for entry in entries}
            if not {"[Content_Types].xml", "word/document.xml"}.issubset(names):
                raise ExtractionError("The DOCX package is incomplete")
        document = Document(BytesIO(content))
    except ExtractionError:
        raise
    except (BadZipFile, LargeZipFile, PackageNotFoundError, OSError, ValueError, KeyError) as error:
        raise ExtractionError("The DOCX source is malformed") from error

    visible: list[str] = []
    hidden: list[str] = []
    _append_docx_blocks(document.paragraphs, document.tables, visible, hidden)
    for section in document.sections:
        _append_docx_blocks(section.header.paragraphs, section.header.tables, visible, hidden)
        _append_docx_blocks(section.footer.paragraphs, section.footer.tables, visible, hidden)
    text = "\n".join(visible)
    hidden_text = "\n".join(hidden)
    title_value = document.core_properties.title
    title = title_value.strip() if title_value else None
    _require_character_limit(text, hidden_text, {}, max_characters)
    return text, hidden_text, title, {}


def _append_docx_blocks(
    paragraphs: Sequence[Paragraph],
    tables: Sequence[Table],
    visible: list[str],
    hidden: list[str],
) -> None:
    for paragraph in paragraphs:
        visible_runs: list[str] = []
        hidden_runs: list[str] = []
        for run in paragraph.runs:
            if not run.text:
                continue
            if run.font.hidden:
                hidden_runs.append(run.text)
            else:
                visible_runs.append(run.text)
        if visible_runs:
            visible.append("".join(visible_runs))
        if hidden_runs:
            hidden.append("".join(hidden_runs))
    for table in tables:
        for row in table.rows:
            for cell in row.cells:
                _append_docx_blocks(cell.paragraphs, cell.tables, visible, hidden)


def _require_character_limit(
    text: str,
    hidden_text: str,
    metadata: dict[str, str],
    max_characters: int,
) -> None:
    total = len(text) + len(hidden_text) + sum(len(value) for value in metadata.values())
    if total > max_characters:
        raise ExtractionError("The extracted document exceeds the character limit")
