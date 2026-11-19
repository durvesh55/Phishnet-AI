"""Authentication business logic (tokens, OTP, lockout, recovery codes)."""
from __future__ import annotations

from datetime import timedelta

from flask import current_app, url_for

from app.extensions import db
from app.models import (EmailVerificationToken, OtpRecord, PasswordResetToken, RecoveryCode, User, utcnow)
from app.services.mail_service import send_mail
from app.utils.security import keyed_hash, new_otp, new_recovery_code, new_token, safe_equal, sha256_hex


# ---------- email verification ----------
def send_verification(user: User) -> None:
    EmailVerificationToken.query.filter_by(user_id=user.id, used_at=None).delete()
    raw = new_token()
    db.session.add(EmailVerificationToken(
        user_id=user.id, token_hash=sha256_hex(raw),
        expires_at=utcnow() + timedelta(hours=current_app.config["VERIFY_TOKEN_HOURS"]),
    ))
    db.session.commit()
    link = f"{current_app.config['BASE_URL']}{url_for('auth.verify_email', token=raw)}"
    send_mail(user.email, "Verify your PhishNet AI email",
              f"Hi {user.name},\n\nConfirm your email address by opening this link (valid {current_app.config['VERIFY_TOKEN_HOURS']}h):\n{link}\n\nIf you did not sign up, ignore this message.")


def consume_verification(raw: str) -> User | None:
    t = EmailVerificationToken.query.filter_by(token_hash=sha256_hex(raw)).first()
    if not t or t.used_at or t.expires_at < utcnow():
        return None
    t.used_at = utcnow()
    user = db.session.get(User, t.user_id)
    user.email_verified = True
    db.session.commit()
    return user


# ---------- password reset ----------
def send_password_reset(user: User) -> None:
    PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).delete()
    raw = new_token()
    db.session.add(PasswordResetToken(
        user_id=user.id, token_hash=sha256_hex(raw),
        expires_at=utcnow() + timedelta(minutes=current_app.config["RESET_TOKEN_MINUTES"]),
    ))
    db.session.commit()
    link = f"{current_app.config['BASE_URL']}{url_for('auth.reset_password', token=raw)}"
    send_mail(user.email, "Reset your PhishNet AI password",
              f"Use this single-use link within {current_app.config['RESET_TOKEN_MINUTES']} minutes:\n{link}\n\nIf you did not request this, ignore this message.")


def get_valid_reset_token(raw: str) -> PasswordResetToken | None:
    t = PasswordResetToken.query.filter_by(token_hash=sha256_hex(raw)).first()
    if not t or t.used_at or t.expires_at < utcnow():
        return None
    return t


# ---------- lockout ----------
def is_locked(user: User) -> bool:
    return bool(user.locked_until and user.locked_until > utcnow())


def register_failed_login(user: User) -> None:
    user.failed_logins += 1
    if user.failed_logins >= current_app.config["MAX_FAILED_LOGINS"]:
        user.locked_until = utcnow() + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])
        user.failed_logins = 0
    db.session.commit()


def register_successful_login(user: User) -> None:
    user.failed_logins, user.locked_until, user.last_login_at = 0, None, utcnow()
    db.session.commit()


# ---------- OTP ----------
def issue_otp(user: User) -> bool:
    """Create + email a fresh OTP. Returns False if throttled."""
    cfg = current_app.config
    last = OtpRecord.query.filter_by(user_id=user.id).order_by(OtpRecord.created_at.desc()).first()
    if last and (utcnow() - last.created_at).total_seconds() < cfg["OTP_RESEND_SECONDS"]:
        return False
    OtpRecord.query.filter_by(user_id=user.id, consumed_at=None).update({"consumed_at": utcnow()})  # invalidate older codes
    code = new_otp()
    db.session.add(OtpRecord(user_id=user.id, code_hash=keyed_hash(f"{user.id}:{code}"),
                             expires_at=utcnow() + timedelta(seconds=cfg["OTP_TTL_SECONDS"])))
    db.session.commit()
    send_mail(user.email, "Your PhishNet AI sign-in code",
              f"Your one-time code is {code}. It expires in {cfg['OTP_TTL_SECONDS'] // 60} minutes. Never share it.")
    return True


def verify_otp(user: User, code: str) -> str:
    """Return 'ok', 'invalid', 'expired' or 'locked'."""
    rec = OtpRecord.query.filter_by(user_id=user.id, consumed_at=None).order_by(OtpRecord.created_at.desc()).first()
    if not rec:
        return "expired"
    if rec.expires_at < utcnow():
        return "expired"
    if rec.attempts >= current_app.config["OTP_MAX_ATTEMPTS"]:
        return "locked"
    rec.attempts += 1
    if not (code.isdigit() and len(code) == 6 and safe_equal(rec.code_hash, keyed_hash(f"{user.id}:{code}"))):
        db.session.commit()
        return "locked" if rec.attempts >= current_app.config["OTP_MAX_ATTEMPTS"] else "invalid"
    rec.consumed_at = utcnow()
    db.session.commit()
    return "ok"


# ---------- recovery codes ----------
def generate_recovery_codes(user: User, n: int = 8) -> list[str]:
    RecoveryCode.query.filter_by(user_id=user.id).delete()
    codes = [new_recovery_code() for _ in range(n)]
    for c in codes:
        db.session.add(RecoveryCode(user_id=user.id, code_hash=keyed_hash(f"rc:{user.id}:{c}")))
    db.session.commit()
    return codes


def use_recovery_code(user: User, code: str) -> bool:
    h = keyed_hash(f"rc:{user.id}:{code.strip().lower()}")
    rc = RecoveryCode.query.filter_by(user_id=user.id, code_hash=h, used_at=None).first()
    if not rc:
        return False
    rc.used_at = utcnow()
    db.session.commit()
    return True
