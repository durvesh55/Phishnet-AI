"""Orchestrates a scan: ML and rules run independently; results are stored side by side."""
from __future__ import annotations

import hashlib
import re
from datetime import timedelta

from flask import current_app
from sqlalchemy import func

from app.extensions import db
from app.models import Scan, User, utcnow
from app.services import rule_engine

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def validate_email_text(raw) -> str:
    if not isinstance(raw, str):
        raise ValueError("email_text must be a string.")
    text = _CTRL.sub("", raw).strip()
    if not text:
        raise ValueError("email_text must not be empty.")
    limit = current_app.config["MAX_EMAIL_CHARS"]
    if len(text) > limit:
        raise ValueError(f"email_text exceeds the {limit} character limit.")
    return text


def run_scan(user: User, raw_text, source: str = "web") -> Scan:
    text = validate_email_text(raw_text)
    ml = current_app.extensions["ml_service"].predict(text)  # ML only sees the text
    findings = rule_engine.analyze(text)  # rules only see the text; never ML output

    scan = Scan(
        user_id=user.id,
        email_text=text if user.store_email_text else None,
        text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        text_length=len(text),
        preview=re.sub(r"\s+", " ", text)[:200] if user.store_email_text else "",
        classification=ml.classification, risk_score=ml.risk_score, ml_probability=ml.probability,
        model_version=ml.model_version,
        rule_findings=[f.to_dict() for f in findings],
        rule_max_severity=rule_engine.max_severity(findings),
        source=source,
    )
    db.session.add(scan)
    db.session.commit()
    return scan


def scan_to_dict(scan: Scan, include_text: bool = False) -> dict:
    d = {
        "id": scan.id,
        "created_at": scan.created_at.isoformat() + "Z",
        "machine_learning": {
            "classification": scan.classification,
            "risk_score": scan.risk_score,
            "model_probability": scan.ml_probability,
            "model_version": scan.model_version,
            "note": "Model-derived risk indicator (phishing probability x 100); not a calibrated guarantee.",
        },
        "rule_analysis": {"max_severity": scan.rule_max_severity, "findings": scan.rule_findings or []},
        "source": scan.source,
        "preview": scan.preview,
        "text_length": scan.text_length,
        "feedback": [{"is_correct": f.is_correct, "comment": f.comment} for f in scan.feedback],
    }
    if include_text:
        d["email_text"] = scan.email_text
    return d


def purge_expired(user: User) -> int:
    if not user.retention_days:
        return 0
    cutoff = utcnow() - timedelta(days=user.retention_days)
    n = Scan.query.filter(Scan.user_id == user.id, Scan.created_at < cutoff).delete(synchronize_session=False)
    db.session.commit()
    return n


def purge_all_expired() -> int:
    total = 0
    for uid, days in db.session.query(User.id, User.retention_days).filter(User.retention_days > 0).all():
        cutoff = utcnow() - timedelta(days=days)
        total += Scan.query.filter(Scan.user_id == uid, Scan.created_at < cutoff).delete(synchronize_session=False)
    db.session.commit()
    return total


def dashboard_stats(user: User) -> dict:
    rows = dict(
        db.session.query(Scan.classification, func.count(Scan.id)).filter(Scan.user_id == user.id).group_by(Scan.classification).all()
    )
    since = utcnow() - timedelta(days=6)
    since = since.replace(hour=0, minute=0, second=0, microsecond=0)
    daily = dict(
        db.session.query(func.date(Scan.created_at), func.count(Scan.id))
        .filter(Scan.user_id == user.id, Scan.created_at >= since).group_by(func.date(Scan.created_at)).all()
    )
    daily = {str(k): v for k, v in daily.items()}
    trend = []
    for i in range(7):
        day = (since + timedelta(days=i)).date()
        trend.append({"date": day.isoformat(), "count": int(daily.get(str(day), 0))})
    avg = db.session.query(func.avg(Scan.risk_score)).filter(Scan.user_id == user.id).scalar()
    return {
        "total": int(sum(rows.values())),
        "safe": int(rows.get("SAFE", 0)), "suspicious": int(rows.get("SUSPICIOUS", 0)), "phishing": int(rows.get("PHISHING", 0)),
        "average_risk_score": round(float(avg), 1) if avg is not None else None,
        "trend_7d": trend,
    }
