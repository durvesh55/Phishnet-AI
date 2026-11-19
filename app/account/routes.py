"""Account settings, API-key UI, recovery codes, data export, account deletion."""
from __future__ import annotations

import json
from datetime import datetime

from flask import Blueprint, Response, flash, redirect, render_template, request, session, url_for

from app.auth import service
from app.extensions import db
from app.models import ApiKey, AuditLog, Feedback, Scan, utcnow
from app.services import scan_service
from app.services.audit import audit
from app.utils.security import (SCOPES, check_password_strength, current_user, generate_api_key, hash_password,
                                login_required, owned_or_404, verify_password, clean_name)

bp = Blueprint("account", __name__, url_prefix="/account")


@bp.route("/", methods=["GET", "POST"])
@login_required
def settings():
    user = current_user()
    if request.method == "POST":
        try:
            user.name = clean_name(request.form.get("name", ""))
            days = int(request.form.get("retention_days", "0") or 0)
            if days not in (0, 7, 30, 90, 365):
                raise ValueError("Invalid retention period.")
            user.retention_days = days
            user.store_email_text = request.form.get("store_email_text") == "on"
            user.otp_enabled = request.form.get("otp_enabled") == "on"
            db.session.commit()
            if days:
                scan_service.purge_expired(user)
            audit("account.updated", user.id)
            flash("Settings saved.", "success")
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        return redirect(url_for("account.settings"))
    return render_template("account/settings.html", user=user)


@bp.route("/password", methods=["POST"])
@login_required
def change_password():
    user = current_user()
    try:
        if not verify_password(user.password_hash, request.form.get("current_password", "")):
            raise ValueError("Current password is incorrect.")
        new = request.form.get("new_password", "")
        if new != request.form.get("confirm_password", ""):
            raise ValueError("Passwords do not match.")
        check_password_strength(new, user.email)
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("account.settings"))
    user.password_hash = hash_password(new)
    user.session_version += 1
    db.session.commit()
    audit("password.changed", user.id)
    session.clear()
    flash("Password changed. Please sign in again.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/recovery-codes", methods=["POST"])
@login_required
def recovery_codes():
    user = current_user()
    codes = service.generate_recovery_codes(user)
    audit("recovery_codes.generated", user.id)
    return render_template("account/recovery_codes.html", codes=codes)


# ---------------- API keys ----------------
@bp.route("/api-keys", methods=["GET", "POST"])
@login_required
def api_keys():
    user = current_user()
    new_key = None
    if request.method == "POST":
        try:
            name = request.form.get("name", "").strip()
            if not 1 <= len(name) <= 80:
                raise ValueError("Key name must be 1-80 characters.")
            exp = request.form.get("expires_in_days", "")
            days = int(exp) if exp else None
            if days is not None and not 1 <= days <= 730:
                raise ValueError("Expiry must be between 1 and 730 days.")
            if ApiKey.query.filter_by(user_id=user.id, revoked_at=None).count() >= 20:
                raise ValueError("Maximum of 20 active keys reached. Revoke some first.")
            scopes = [s for s in request.form.getlist("scopes") if s in SCOPES]
            key, raw = generate_api_key(user, name, scopes, days)
            db.session.commit()
            audit("apikey.created", user.id, f"key_id={key.id}")
            new_key = raw
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
    keys = ApiKey.query.filter_by(user_id=user.id).order_by(ApiKey.created_at.desc()).all()
    return render_template("account/api_keys.html", keys=keys, new_key=new_key, scopes=SCOPES)


@bp.route("/api-keys/<int:key_id>/revoke", methods=["POST"])
@login_required
def revoke_key(key_id: int):
    user = current_user()
    key = owned_or_404(ApiKey, key_id, user)
    key.revoked_at = key.revoked_at or utcnow()
    db.session.commit()
    audit("apikey.revoked", user.id, f"key_id={key.id}")
    flash("API key revoked.", "success")
    return redirect(url_for("account.api_keys"))


@bp.route("/api-keys/<int:key_id>/rotate", methods=["POST"])
@login_required
def rotate_key(key_id: int):
    user = current_user()
    old = owned_or_404(ApiKey, key_id, user)
    if old.status != "active":
        flash("Only active keys can be rotated.", "danger")
        return redirect(url_for("account.api_keys"))
    days = None
    if old.expires_at:
        days = max(1, (old.expires_at - old.created_at).days)
    new, raw = generate_api_key(user, old.name, old.scope_list, days)
    old.revoked_at = utcnow()
    db.session.commit()
    audit("apikey.rotated", user.id, f"old={old.id} new={new.id}")
    keys = ApiKey.query.filter_by(user_id=user.id).order_by(ApiKey.created_at.desc()).all()
    return render_template("account/api_keys.html", keys=keys, new_key=raw, scopes=SCOPES)


# ---------------- privacy ----------------
@bp.route("/export")
@login_required
def export_data():
    user = current_user()
    data = {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "profile": {"name": user.name, "email": user.email, "created_at": user.created_at.isoformat(),
                    "retention_days": user.retention_days, "store_email_text": user.store_email_text},
        "scans": [scan_service.scan_to_dict(s, include_text=True) for s in Scan.query.filter_by(user_id=user.id).order_by(Scan.id)],
        "feedback": [{"scan_id": f.scan_id, "is_correct": f.is_correct, "comment": f.comment, "created_at": f.created_at.isoformat()}
                     for f in Feedback.query.filter_by(user_id=user.id)],
        "api_keys": [{"name": k.name, "prefix": k.prefix, "scopes": k.scope_list, "status": k.status, "created_at": k.created_at.isoformat(),
                      "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None, "usage_count": k.usage_count}
                     for k in ApiKey.query.filter_by(user_id=user.id)],
        "audit_log": [{"event": a.event, "ip": a.ip_address, "at": a.created_at.isoformat()}
                      for a in AuditLog.query.filter_by(user_id=user.id).order_by(AuditLog.id)],
    }
    audit("account.data_exported", user.id)
    return Response(json.dumps(data, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": 'attachment; filename="phishnet_my_data.json"', "Cache-Control": "no-store"})


@bp.route("/delete", methods=["POST"])
@login_required
def delete_account():
    user = current_user()
    if not verify_password(user.password_hash, request.form.get("password", "")) or request.form.get("confirm") != "DELETE":
        flash("Password or confirmation text is incorrect. Type DELETE to confirm.", "danger")
        return redirect(url_for("account.settings"))
    uid = user.id
    audit("account.deleted", None, f"user_id={uid}", commit=False)  # keep an anonymised record
    db.session.delete(user)  # cascades: scans, feedback, keys, OTPs, tokens, recovery codes
    db.session.commit()
    session.clear()
    flash("Your account and all associated data have been permanently deleted.", "info")
    return redirect(url_for("auth.login"))
