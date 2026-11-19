"""Shared, user-scoped query helpers for the web UI, REST API and reports."""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import or_

from app.models import Scan, User

SORTS = {
    "date_desc": Scan.created_at.desc(), "date_asc": Scan.created_at.asc(),
    "risk_desc": Scan.risk_score.desc(), "risk_asc": Scan.risk_score.asc(),
}
CLASSES = {"SAFE", "SUSPICIOUS", "PHISHING"}


def parse_date(raw: str | None, end_of_day: bool = False) -> datetime | None:
    if not raw:
        return None
    try:
        d = datetime.strptime(raw, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError("Dates must be YYYY-MM-DD.") from exc
    return d + timedelta(days=1) if end_of_day else d


def like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")


def scan_query(user: User, q: str | None = None, classification: str | None = None, sort: str = "date_desc",
               date_from: str | None = None, date_to: str | None = None):
    query = Scan.query.filter(Scan.user_id == user.id)  # every query is scoped to the owner
    if classification:
        classification = classification.upper()
        if classification not in CLASSES:
            raise ValueError("classification must be SAFE, SUSPICIOUS or PHISHING.")
        query = query.filter(Scan.classification == classification)
    if q:
        term = f"%{like_escape(q[:100])}%"
        query = query.filter(or_(Scan.preview.like(term, escape="\\"), Scan.model_version.like(term, escape="\\")))
    df, dt = parse_date(date_from), parse_date(date_to, True)
    if df:
        query = query.filter(Scan.created_at >= df)
    if dt:
        query = query.filter(Scan.created_at < dt)
    return query.order_by(SORTS.get(sort, SORTS["date_desc"]), Scan.id.desc())


def clamp_page(page, per_page, max_per_page: int = 100) -> tuple[int, int]:
    try:
        page = max(1, int(page or 1))
        per_page = min(max_per_page, max(1, int(per_page or 20)))
    except (TypeError, ValueError):
        raise ValueError("page and per_page must be integers.") from None
    return page, per_page
