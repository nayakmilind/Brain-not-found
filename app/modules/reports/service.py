from __future__ import annotations

import asyncio
import html
import json
from io import BytesIO
from uuid import UUID, uuid4

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.models.auth import User
from app.db.models.finding import Finding
from app.db.models.report import Report
from app.db.models.scan import Scan
from app.modules.audit import service as audit_service
from app.modules.findings.schemas import FindingResponse
from app.modules.graph.service import GraphNotReady, GraphService
from app.modules.recommendations.service import RecommendationService, RecommendationsNotReady
from app.modules.scans.repository import get_scan
from app.modules.scans.service import ScanNotFound
from app.modules.scoring.service import ScoringNotReady, ScoringService

REPORT_DISCLAIMER = (
    "This estimate covers only the sources you supplied. A clean report does not prove "
    "complete safety."
)
MAX_REPORT_FINDINGS = 10_000
MAX_REPORT_BYTES = 10 * 1024 * 1024


class ReportNotReady(Exception):
    pass


class ReportNotFound(Exception):
    pass


class ReportTooLarge(Exception):
    pass


class ReportService:
    async def create(
        self,
        session: AsyncSession,
        settings: Settings,
        user: User,
        scan_id: UUID,
        report_format: str,
        ip_address: str | None,
    ) -> Report:
        scan = await get_scan(session, scan_id, user_id=user.id)
        if scan is None:
            raise ScanNotFound
        if scan.status != "DONE" or scan.result_state != "GENERATED":
            raise ReportNotReady
        try:
            score = await ScoringService().get_score(session, user.id, scan_id)
            graph = await GraphService().get_for_user(session, user.id, scan_id)
            uniqueness = await ScoringService().get_uniqueness(session, user.id, scan_id)
            attacker_view = await ScoringService().get_attacker_view(session, user.id, scan_id)
            recommendations = await RecommendationService().list_for_scan(
                session,
                user.id,
                scan_id,
            )
        except (ScanNotFound, GraphNotReady, ScoringNotReady, RecommendationsNotReady) as error:
            raise ReportNotReady from error

        finding_count = await session.scalar(
            select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
        )
        total_findings = int(finding_count or 0)
        if total_findings > MAX_REPORT_FINDINGS:
            raise ReportTooLarge
        findings = list(
            (
                await session.execute(
                    select(Finding)
                    .where(Finding.scan_id == scan_id)
                    .order_by(Finding.sensitivity.desc(), Finding.confidence.desc(), Finding.id)
                )
            ).scalars()
        )
        report_data: dict[str, object] = {
            "scan": {
                "id": str(scan.id),
                "status": scan.status,
                "mode": scan.mode,
                "created_at": scan.created_at.isoformat(),
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            },
            "score": score.model_dump(mode="json"),
            "graph": graph.model_dump(mode="json"),
            "uniqueness": uniqueness.model_dump(mode="json"),
            "attacker_view": attacker_view.model_dump(mode="json"),
            "recommendations": [
                recommendation.model_dump(mode="json") for recommendation in recommendations
            ],
            "findings": [
                FindingResponse.model_validate(finding).model_dump(mode="json")
                for finding in findings
            ],
            "disclaimer": REPORT_DISCLAIMER,
        }
        content = await asyncio.to_thread(_render_report, report_format, report_data)
        if len(content) > MAX_REPORT_BYTES:
            raise ReportTooLarge

        report = Report(
            id=uuid4(),
            scan_id=scan_id,
            format=report_format,
            content=content,
        )
        session.add(report)
        await session.flush()
        await audit_service.append_entry(
            session,
            settings,
            user_id=user.id,
            action="report_created",
            object_type="report",
            object_id=report.id,
            ip_address=ip_address,
        )
        await session.commit()
        await session.refresh(report)
        return report

    async def get_for_user(
        self,
        session: AsyncSession,
        settings: Settings,
        user_id: UUID,
        report_id: UUID,
        ip_address: str | None,
    ) -> Report:
        report = (
            await session.execute(
                select(Report)
                .join(Scan, Scan.id == Report.scan_id)
                .where(Report.id == report_id, Scan.user_id == user_id)
            )
        ).scalar_one_or_none()
        if report is None:
            raise ReportNotFound
        await audit_service.append_entry(
            session,
            settings,
            user_id=user_id,
            action="report_downloaded",
            object_type="report",
            object_id=report.id,
            ip_address=ip_address,
        )
        await session.commit()
        return report


def _render_report(report_format: str, data: dict[str, object]) -> bytes:
    if report_format == "json":
        return json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    if report_format == "html":
        return _render_html(data)
    if report_format == "pdf":
        return _render_pdf(data)
    raise ValueError(f"Unsupported report format: {report_format}")


def _render_html(data: dict[str, object]) -> bytes:
    scan = data["scan"]
    score = data["score"]
    findings = data["findings"]
    recommendations = data["recommendations"]
    if not isinstance(scan, dict) or not isinstance(score, dict):
        raise ValueError("Report context is malformed")
    if not isinstance(findings, list) or not isinstance(recommendations, list):
        raise ValueError("Report lists are malformed")

    finding_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(item['type']))}</td>"
        f"<td>{html.escape(str(item['masked_preview']))}</td>"
        f"<td>{html.escape(str(item['evidence_class']))}</td>"
        f"<td>{float(item['confidence']):.0%}</td>"
        "</tr>"
        for item in findings
        if isinstance(item, dict)
    )
    recommendation_items = "".join(
        "<li>"
        f"<strong>{html.escape(str(item['title']))}</strong> — "
        f"{html.escape(str(item['description']))}"
        f"<ol>{''.join(f'<li>{html.escape(str(step))}</li>' for step in item['steps'])}</ol>"
        "</li>"
        for item in recommendations
        if isinstance(item, dict)
    )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Privacy Shield report</title>
<style>body{{font:16px sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#18212b}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ccd3da;padding:.5rem;text-align:left}}
.notice{{padding:1rem;background:#eef5f8}}.muted{{color:#465563}}</style></head>
<body><h1>Privacy Shield report</h1>
<p>Scan {html.escape(str(scan["id"]))} · {html.escape(str(scan["mode"]))}</p>
<h2>Estimated score</h2><p>Privacy score: {int(score["privacy_score"])}/100 ·
Risk: {int(score["risk_score"])}/100 · {html.escape(str(score["band"]))}</p>
<p class="muted">{html.escape(str(score["disclaimer"]))}</p>
<h2>Findings</h2><table><thead><tr><th>Type</th><th>Masked preview</th>
<th>Evidence</th><th>Confidence</th></tr></thead><tbody>{finding_rows}</tbody></table>
<h2>Recommendations</h2><ol>{recommendation_items}</ol>
<p class="notice">{html.escape(str(data["disclaimer"]))}</p></body></html>"""
    return document.encode("utf-8")


def _render_pdf(data: dict[str, object]) -> bytes:
    scan = data["scan"]
    score = data["score"]
    findings = data["findings"]
    recommendations = data["recommendations"]
    if not isinstance(scan, dict) or not isinstance(score, dict):
        raise ValueError("Report context is malformed")
    if not isinstance(findings, list) or not isinstance(recommendations, list):
        raise ValueError("Report lists are malformed")

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title="Privacy Shield report",
    )
    styles = getSampleStyleSheet()
    body = ParagraphStyle("ReportBody", parent=styles["BodyText"], alignment=TA_LEFT)
    story = [
        Paragraph("Privacy Shield report", styles["Title"]),
        Paragraph(f"Scan {html.escape(str(scan['id']))} · {html.escape(str(scan['mode']))}", body),
        Spacer(1, 10),
        Paragraph("Estimated score", styles["Heading2"]),
        Paragraph(
            f"Privacy score: {int(score['privacy_score'])}/100 · "
            f"Risk: {int(score['risk_score'])}/100 · {html.escape(str(score['band']))}",
            body,
        ),
        Paragraph(html.escape(str(score["disclaimer"])), body),
        Spacer(1, 10),
        Paragraph("Findings", styles["Heading2"]),
    ]
    rows: list[list[object]] = [["Type", "Masked preview", "Evidence", "Confidence"]]
    for item in findings[:1000]:
        if isinstance(item, dict):
            rows.append(
                [
                    Paragraph(html.escape(str(item["type"])), body),
                    Paragraph(html.escape(str(item["masked_preview"])), body),
                    Paragraph(html.escape(str(item["evidence_class"])), body),
                    Paragraph(f"{float(item['confidence']):.0%}", body),
                ]
            )
    table = Table(rows, colWidths=[1.35 * inch, 2.45 * inch, 1.2 * inch, 0.9 * inch], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf0f4")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#9aa7b2")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(table)
    if len(findings) > 1000:
        story.append(
            Paragraph(
                f"PDF table shows 1,000 of {len(findings)} findings; use the JSON report for all.",
                body,
            )
        )
    story.extend([Spacer(1, 10), Paragraph("Recommendations", styles["Heading2"])])
    for recommendation in recommendations:
        if not isinstance(recommendation, dict):
            continue
        story.append(Paragraph(html.escape(str(recommendation["title"])), styles["Heading3"]))
        for step in recommendation["steps"]:
            story.append(Paragraph(f"• {html.escape(str(step))}", body))
    story.extend(
        [
            Spacer(1, 10),
            Paragraph(html.escape(str(data["disclaimer"])), body),
        ]
    )
    document.build(story)
    return buffer.getvalue()
