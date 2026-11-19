"""CSV and PDF report generation. Callers must pass only the current user's scans."""
from __future__ import annotations

import csv
import io
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models import Scan, User

_FORMULA_PREFIX = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection."""
    s = "" if value is None else str(value)
    return "'" + s if s.startswith(_FORMULA_PREFIX) else s


def scans_to_csv(scans: list[Scan]) -> bytes:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["scan_id", "scanned_at_utc", "ml_classification", "ml_risk_score", "ml_probability", "model_version",
                "rule_max_severity", "rule_findings", "preview"])
    for s in scans:
        findings = "; ".join(f"[{f['severity']}] {f['rule_id']}" for f in (s.rule_findings or []))
        w.writerow([s.id, s.created_at.strftime("%Y-%m-%d %H:%M:%S"), s.classification, s.risk_score, s.ml_probability,
                    csv_safe(s.model_version), s.rule_max_severity, csv_safe(findings), csv_safe(s.preview)])
    return out.getvalue().encode("utf-8-sig")


def _p(text, style) -> Paragraph:
    return Paragraph(escape(str(text)), style)


def scans_to_pdf(user: User, scans: list[Scan], detail: bool = True) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title="PhishNet AI Scan Report", author="PhishNet AI")
    st = getSampleStyleSheet()
    small = st["BodyText"].clone("small", fontSize=8.5, leading=11)
    story = [
        Paragraph("PhishNet AI — Scan Report", st["Title"]),
        _p(f"Generated {datetime.utcnow():%Y-%m-%d %H:%M} UTC for {user.name} ({user.email})", st["Normal"]),
        Spacer(1, 6),
        _p("Machine-learning risk scores are model-derived indicators, not calibrated probabilities. "
           "Rule findings are independent heuristics and have not been verified against any external reputation source.", small),
        Spacer(1, 10),
    ]
    head = colors.HexColor("#0f3d5e")
    sev_col = {"high": "#b42318", "medium": "#b54708", "low": "#475467", "none": "#067647"}
    cls_col = {"PHISHING": "#b42318", "SUSPICIOUS": "#b54708", "SAFE": "#067647"}
    if len(scans) != 1 or not detail:
        rows = [["ID", "Date (UTC)", "ML class", "Risk", "Rules", "Model"]]
        for s in scans:
            rows.append([str(s.id), f"{s.created_at:%Y-%m-%d %H:%M}", s.classification, f"{s.risk_score:.1f}",
                         f"{len(s.rule_findings or [])} ({s.rule_max_severity})", s.model_version])
        t = Table(rows, repeatRows=1, colWidths=[16 * mm, 36 * mm, 30 * mm, 18 * mm, 32 * mm, 40 * mm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), head), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                               ("FONTSIZE", (0, 0), (-1, -1), 8.5), ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                               ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f7fa")])]))
        story.append(t)
    else:
        for s in scans:
            story.append(_p(f"Scan #{s.id} — {s.created_at:%Y-%m-%d %H:%M} UTC", st["Heading2"]))
            story.append(Paragraph("<b>Machine Learning Analysis</b>", st["Heading3"]))
            story.append(Paragraph(
                f"Classification: <font color='{cls_col.get(s.classification, '#000')}'><b>{escape(s.classification)}</b></font><br/>"
                f"Risk score: {s.risk_score:.1f}/100 &nbsp; Model probability (phishing class): {s.ml_probability:.4f}<br/>"
                f"Model version: {escape(s.model_version)}", st["BodyText"]))
            story.append(Paragraph("<b>Security Rule Analysis</b> (independent of the ML score)", st["Heading3"]))
            if not s.rule_findings:
                story.append(_p("No rule-based indicators detected.", st["BodyText"]))
            for f in s.rule_findings or []:
                story.append(Paragraph(
                    f"<font color='{sev_col.get(f['severity'], '#000')}'><b>[{escape(f['severity'].upper())}]</b></font> "
                    f"<b>{escape(f['title'])}</b><br/>{escape(f['reason'])}<br/><i>Evidence:</i> {escape('; '.join(f['evidence']))}", small))
                story.append(Spacer(1, 4))
            story.append(Paragraph("<b>Submitted text (excerpt)</b>", st["Heading3"]))
            story.append(_p((s.preview or "(not stored)")[:200], small))
    doc.build(story)
    return buf.getvalue()
