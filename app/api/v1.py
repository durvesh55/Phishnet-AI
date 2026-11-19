"""Versioned REST API: /api/v1. Auth: X-API-Key header or browser session."""
from __future__ import annotations

from datetime import datetime

from flask import Blueprint, Response, current_app, g, jsonify, request
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import csrf, db, limiter
from app.models import ApiKey, Scan, utcnow
from app.services import report_service, scan_service
from app.services.audit import audit
from app.services.feedback_service import save_feedback
from app.services.ml_service import ModelUnavailable
from app.services.query_service import clamp_page, scan_query
from app.utils.security import SCOPES, api_auth, api_error, generate_api_key, sha256_hex

bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")
csrf.exempt(bp)  # API-key calls have no cookies; session calls are CSRF-checked inside api_auth


def _rate_key() -> str:
    raw = request.headers.get("X-API-Key")
    return "key:" + sha256_hex(raw)[:16] if raw else "ip:" + (request.remote_addr or "?")


def rate_limited(f):
    return limiter.limit(lambda: current_app.config["API_RATE_LIMIT"], key_func=_rate_key)(f)


def _json_body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object.")
    return data


def _session_only():
    if g.api_key is not None:
        return api_error(403, "session_required", "This endpoint cannot be called with an API key.")
    return None


# ---------------------------------------------------------------- identity
@bp.get("/auth/me")
@rate_limited
@api_auth()
def me():
    u = g.user
    return jsonify({"data": {"id": u.id, "name": u.name, "email": u.email, "auth_method": "api_key" if g.api_key else "session",
                             "scopes": g.api_key.scope_list if g.api_key else list(SCOPES)}})


# ---------------------------------------------------------------- scans
@bp.post("/scans")
@rate_limited
@api_auth("scan:write")
def create_scan():
    try:
        scan = scan_service.run_scan(g.user, _json_body().get("email_text"), source="api" if g.api_key else "web")
    except ValueError as exc:
        return api_error(400, "validation_error", str(exc))
    except ModelUnavailable:
        return api_error(503, "model_unavailable", "The detection model is not available.")
    audit("scan.created", g.user.id, f"scan_id={scan.id} via=api")
    return jsonify({"data": scan_service.scan_to_dict(scan)}), 201


@bp.get("/scans")
@rate_limited
@api_auth("history:read")
def list_scans():
    a = request.args
    try:
        page, per_page = clamp_page(a.get("page"), a.get("per_page"))
        q = scan_query(g.user, a.get("q"), a.get("classification"), a.get("sort", "date_desc"), a.get("date_from"), a.get("date_to"))
    except ValueError as exc:
        return api_error(400, "validation_error", str(exc))
    p = q.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({"data": [scan_service.scan_to_dict(s) for s in p.items],
                    "pagination": {"page": p.page, "per_page": p.per_page, "total": p.total, "pages": p.pages}})


def _own_scan(scan_id: int) -> Scan | None:
    s = db.session.get(Scan, scan_id)
    return s if s and s.user_id == g.user.id else None


@bp.get("/scans/<int:scan_id>")
@rate_limited
@api_auth("history:read")
def get_scan(scan_id: int):
    s = _own_scan(scan_id)
    if not s:
        return api_error(404, "not_found", "Scan not found.")
    return jsonify({"data": scan_service.scan_to_dict(s, include_text=request.args.get("include_text") == "1")})


@bp.delete("/scans/<int:scan_id>")
@rate_limited
@api_auth("history:read")
def delete_scan(scan_id: int):
    s = _own_scan(scan_id)
    if not s:
        return api_error(404, "not_found", "Scan not found.")
    db.session.delete(s)
    db.session.commit()
    audit("scan.deleted", g.user.id, f"scan_id={scan_id} via=api")
    return "", 204


@bp.post("/scans/<int:scan_id>/feedback")
@rate_limited
@api_auth("feedback:write")
def post_feedback(scan_id: int):
    s = _own_scan(scan_id)
    if not s:
        return api_error(404, "not_found", "Scan not found.")
    try:
        body = _json_body()
        fb = save_feedback(s, g.user, body.get("is_correct"), body.get("comment"))
    except ValueError as exc:
        return api_error(400, "validation_error", str(exc))
    return jsonify({"data": {"scan_id": s.id, "is_correct": fb.is_correct, "comment": fb.comment}}), 201


# ---------------------------------------------------------------- stats & reports
@bp.get("/stats")
@rate_limited
@api_auth("stats:read")
def stats():
    return jsonify({"data": scan_service.dashboard_stats(g.user)})


@bp.get("/reports/scans.csv")
@rate_limited
@api_auth("reports:read")
def report_csv():
    a = request.args
    try:
        scans = scan_query(g.user, a.get("q"), a.get("classification"), a.get("sort", "date_desc"), a.get("date_from"), a.get("date_to")).limit(5000).all()
    except ValueError as exc:
        return api_error(400, "validation_error", str(exc))
    return Response(report_service.scans_to_csv(scans), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="phishnet_{datetime.utcnow():%Y%m%d}.csv"'})


@bp.get("/reports/scans/<int:scan_id>.pdf")
@rate_limited
@api_auth("reports:read")
def report_pdf(scan_id: int):
    s = _own_scan(scan_id)
    if not s:
        return api_error(404, "not_found", "Scan not found.")
    return Response(report_service.scans_to_pdf(g.user, [s]), mimetype="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="phishnet_scan_{s.id}.pdf"'})


# ---------------------------------------------------------------- API-key management (session only)
def _key_dict(k: ApiKey) -> dict:
    return {"id": k.id, "name": k.name, "prefix": k.prefix, "scopes": k.scope_list, "status": k.status,
            "created_at": k.created_at.isoformat() + "Z", "expires_at": k.expires_at.isoformat() + "Z" if k.expires_at else None,
            "last_used_at": k.last_used_at.isoformat() + "Z" if k.last_used_at else None, "usage_count": k.usage_count}


@bp.get("/api-keys")
@rate_limited
@api_auth()
def list_keys():
    if (err := _session_only()):
        return err
    keys = ApiKey.query.filter_by(user_id=g.user.id).order_by(ApiKey.created_at.desc()).all()
    return jsonify({"data": [_key_dict(k) for k in keys]})


@bp.post("/api-keys")
@rate_limited
@api_auth()
def create_key():
    if (err := _session_only()):
        return err
    try:
        b = _json_body()
        name = b.get("name")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
            raise ValueError("name must be 1-80 characters.")
        days = b.get("expires_in_days")
        if days is not None and (not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 730):
            raise ValueError("expires_in_days must be an integer between 1 and 730.")
        scopes = b.get("scopes")
        if scopes is not None and (not isinstance(scopes, list) or any(s not in SCOPES for s in scopes)):
            raise ValueError(f"scopes must be a list drawn from {list(SCOPES)}.")
        key, raw = generate_api_key(g.user, name.strip(), scopes, days)
        db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        return api_error(400, "validation_error", str(exc))
    audit("apikey.created", g.user.id, f"key_id={key.id} via=api")
    return jsonify({"data": {**_key_dict(key), "api_key": raw, "warning": "Store this key now; it cannot be shown again."}}), 201


def _own_key(key_id: int) -> ApiKey | None:
    k = db.session.get(ApiKey, key_id)
    return k if k and k.user_id == g.user.id else None


@bp.delete("/api-keys/<int:key_id>")
@rate_limited
@api_auth()
def revoke_key(key_id: int):
    if (err := _session_only()):
        return err
    k = _own_key(key_id)
    if not k:
        return api_error(404, "not_found", "API key not found.")
    k.revoked_at = k.revoked_at or utcnow()
    db.session.commit()
    audit("apikey.revoked", g.user.id, f"key_id={k.id} via=api")
    return "", 204


@bp.post("/api-keys/<int:key_id>/rotate")
@rate_limited
@api_auth()
def rotate_key(key_id: int):
    if (err := _session_only()):
        return err
    old = _own_key(key_id)
    if not old or old.status != "active":
        return api_error(404, "not_found", "Active API key not found.")
    days = max(1, (old.expires_at - old.created_at).days) if old.expires_at else None
    new, raw = generate_api_key(g.user, old.name, old.scope_list, days)
    old.revoked_at = utcnow()
    db.session.commit()
    audit("apikey.rotated", g.user.id, f"old={old.id} new={new.id}")
    return jsonify({"data": {**_key_dict(new), "api_key": raw, "warning": "Store this key now; it cannot be shown again."}}), 201


@bp.errorhandler(SQLAlchemyError)
def _db_error(exc):
    db.session.rollback()
    current_app.logger.error("database error in API: %s", type(exc).__name__)
    return api_error(500, "internal_error", "An internal error occurred.")
