"""Web authentication routes: register, verify, login (+2FA), logout, password reset."""
from __future__ import annotations

from datetime import timedelta

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from sqlalchemy.exc import IntegrityError

from app.auth import service
from app.extensions import db, limiter
from app.models import User, utcnow
from app.services.audit import audit
from app.utils.security import (check_password_strength, clean_email, clean_name, current_user, hash_password,
                                start_session, verify_password)

bp = Blueprint("auth", __name__, url_prefix="/auth")


def _safe_next(target: str | None) -> str:
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("dashboard.index")


@bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    if request.method == "POST":
        f = request.form
        try:
            name, email = clean_name(f.get("name", "")), clean_email(f.get("email", ""))
            pw = f.get("password", "")
            if pw != f.get("confirm_password", ""):
                raise ValueError("Passwords do not match.")
            check_password_strength(pw, email)
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("auth/register.html", name=f.get("name", ""), email=f.get("email", "")), 400
        user = User(name=name, email=email, password_hash=hash_password(pw), role="user",
                    retention_days=current_app.config["DEFAULT_RETENTION_DAYS"])
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            # Do not reveal whether the email exists: same response as success.
            audit("register.duplicate_email")
            flash("If that address can be registered, a verification email has been sent.", "info")
            return redirect(url_for("auth.login"))
        service.send_verification(user)
        audit("register", user.id)
        flash("Account created. Check your email for the verification link.", "success")
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html")


@bp.route("/verify/<token>")
@limiter.limit("20 per hour")
def verify_email(token: str):
    user = service.consume_verification(token)
    if not user:
        flash("This verification link is invalid or has expired. Request a new one.", "danger")
        return redirect(url_for("auth.verify_pending"))
    audit("email.verified", user.id)
    flash("Email verified. You can now sign in.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/verify-pending", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def verify_pending():
    if request.method == "POST":
        try:
            email = clean_email(request.form.get("email", ""))
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("auth/verify_pending.html"), 400
        user = User.query.filter_by(email=email).first()
        if user and not user.email_verified:
            service.send_verification(user)
            audit("email.verification_resent", user.id)
        flash("If the account exists and is unverified, a new link has been sent.", "info")
        return redirect(url_for("auth.login"))
    return render_template("auth/verify_pending.html")


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["LOGIN_RATE_LIMIT"], methods=["POST"])
def login():
    if current_user() and current_user().email_verified:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        try:
            email = clean_email(request.form.get("email", ""))
        except ValueError:
            email = ""
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first() if email else None
        generic = "Invalid email or password."
        if user and service.is_locked(user):
            verify_password(user.password_hash, password)  # keep timing uniform
            audit("login.locked", user.id)
            flash("Too many failed attempts. Try again later.", "danger")
            return render_template("auth/login.html", email=email), 429
        if not user or not user.is_active or not verify_password(user.password_hash, password):
            if user:
                service.register_failed_login(user)
            audit("login.failed", user.id if user else None)
            flash(generic, "danger")
            return render_template("auth/login.html", email=email), 401
        if not user.email_verified:
            audit("login.unverified", user.id)
            flash("Please verify your email first. You can request a new link below.", "warning")
            return redirect(url_for("auth.verify_pending"))
        nxt = _safe_next(request.args.get("next"))
        if user.otp_enabled:
            session.clear()
            session["pending_uid"] = user.id
            session["pending_next"] = nxt
            session["pending_exp"] = (utcnow() + timedelta(minutes=10)).timestamp()
            service.issue_otp(user)
            audit("login.otp_sent", user.id)
            return redirect(url_for("auth.otp"))
        service.register_successful_login(user)
        start_session(user)
        audit("login.success", user.id)
        return redirect(nxt)
    return render_template("auth/login.html")


def _pending_user() -> User | None:
    uid, exp = session.get("pending_uid"), session.get("pending_exp", 0)
    if not uid or exp < utcnow().timestamp():
        session.pop("pending_uid", None)
        return None
    return db.session.get(User, uid)


@bp.route("/otp", methods=["GET", "POST"])
@limiter.limit("20 per hour", methods=["POST"])
def otp():
    user = _pending_user()
    if not user:
        flash("Your sign-in session expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        use_recovery = request.form.get("mode") == "recovery"
        ok = False
        if use_recovery:
            ok = service.use_recovery_code(user, code)
            result = "ok" if ok else "invalid"
        else:
            result = service.verify_otp(user, code)
        if result == "ok":
            nxt = session.get("pending_next") or url_for("dashboard.index")
            service.register_successful_login(user)
            start_session(user)
            audit("login.success", user.id, "recovery_code" if use_recovery else "otp")
            return redirect(_safe_next(nxt))
        audit("otp.failed", user.id, result)
        msg = {"expired": "Code expired. Request a new one.", "locked": "Too many attempts. Request a new code."}.get(result, "Incorrect code.")
        flash(msg, "danger")
        return render_template("auth/otp.html"), 401
    return render_template("auth/otp.html")


@bp.route("/otp/resend", methods=["POST"])
@limiter.limit("10 per hour")
def otp_resend():
    user = _pending_user()
    if not user:
        return redirect(url_for("auth.login"))
    if service.issue_otp(user):
        audit("otp.resent", user.id)
        flash("A new code has been sent.", "info")
    else:
        flash(f"Please wait {current_app.config['OTP_RESEND_SECONDS']} seconds before requesting another code.", "warning")
    return redirect(url_for("auth.otp"))


@bp.route("/logout", methods=["POST"])
def logout():
    user = current_user()
    if user:
        user.session_version += 1  # invalidates every copy of the session cookie
        db.session.commit()
        audit("logout", user.id)
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/forgot", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def forgot_password():
    if request.method == "POST":
        try:
            email = clean_email(request.form.get("email", ""))
            user = User.query.filter_by(email=email).first()
            if user and user.is_active:
                service.send_password_reset(user)
                audit("password.reset_requested", user.id)
        except ValueError:
            pass
        flash("If an account exists for that address, a reset link has been sent.", "info")
        return redirect(url_for("auth.login"))
    return render_template("auth/forgot.html")


@bp.route("/reset/<token>", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def reset_password(token: str):
    tok = service.get_valid_reset_token(token)
    if not tok:
        flash("This reset link is invalid, expired or already used.", "danger")
        return redirect(url_for("auth.forgot_password"))
    if request.method == "POST":
        user = db.session.get(User, tok.user_id)
        pw = request.form.get("password", "")
        try:
            if pw != request.form.get("confirm_password", ""):
                raise ValueError("Passwords do not match.")
            check_password_strength(pw, user.email)
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("auth/reset.html", token=token), 400
        user.password_hash = hash_password(pw)
        user.session_version += 1
        user.failed_logins, user.locked_until = 0, None
        tok.used_at = utcnow()  # single use
        db.session.commit()
        audit("password.reset", user.id)
        flash("Password updated. Please sign in.", "success")
        return redirect(url_for("auth.login"))
    return render_template("auth/reset.html", token=token)
