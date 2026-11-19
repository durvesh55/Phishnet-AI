"""Public landing page and anonymous quick check (nothing is stored; links are never visited)."""
from types import SimpleNamespace

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from app.extensions import limiter
from app.services import rule_engine
from app.services.ml_service import ModelUnavailable
from app.utils.security import current_user

bp = Blueprint("public", __name__)
PUBLIC_MAX_CHARS = 5000
MIN_WORDS_FOR_ML = 6  # the model is trained on email text, not bare URLs


@bp.route("/")
def landing():
    user = current_user()
    if user and user.email_verified:
        return redirect(url_for("dashboard.index"))
    return render_template("public/landing.html", max_chars=PUBLIC_MAX_CHARS)


@bp.route("/check", methods=["POST"])
@limiter.limit("10 per minute;60 per hour")
def check():
    text = (request.form.get("content") or "").strip()
    if not text:
        flash("Paste a link or the text of an email to check.", "danger")
        return redirect(url_for("public.landing"))
    if len(text) > PUBLIC_MAX_CHARS:
        flash(f"Quick check is limited to {PUBLIC_MAX_CHARS} characters. Sign in to scan longer emails.", "danger")
        return redirect(url_for("public.landing"))

    links = rule_engine.analyze_links(text)
    findings = rule_engine.analyze(text)
    words = len([w for w in rule_engine.URL_RE.sub(" ", text).split() if w.strip()])
    ml = None
    if words >= MIN_WORDS_FOR_ML:
        try:
            ml = current_app.extensions["ml_service"].predict(text)
        except ModelUnavailable:
            ml = None
    scan = SimpleNamespace(
        classification=ml.classification if ml else None, risk_score=ml.risk_score if ml else 0.0,
        ml_probability=ml.probability if ml else 0.0, model_version=ml.model_version if ml else "",
        rule_findings=[f.to_dict() for f in findings], rule_max_severity=rule_engine.max_severity(findings),
    )
    return render_template("public/result.html", scan=scan, links=links, ml_ran=ml is not None, snippet=text[:300], max_chars=PUBLIC_MAX_CHARS)
