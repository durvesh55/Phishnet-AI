"""Security helpers: hashing, token generation, validation, decorators."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import timedelta
from functools import wraps

from email_validator import EmailNotValidError, validate_email
from flask import abort, current_app, g, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import csrf, db
from app.models import ApiKey, User, utcnow

SCOPES = ("scan:write", "history:read", "feedback:write", "reports:read", "stats:read")
DEFAULT_SCOPES = ("scan:write", "history:read", "feedback:write", "reports:read", "stats:read")
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


# ---------------- hashing / tokens ----------------
def hash_password(pw: str) -> str:
    return generate_password_hash(pw, method="scrypt")


def verify_password(pw_hash: str | None, pw: str) -> bool:
    """Constant-ish time even for unknown users (pass pw_hash=None)."""
    return check_password_hash(pw_hash or _DUMMY_HASH, pw) and pw_hash is not None


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def keyed_hash(value: str) -> str:
    """HMAC-SHA256 with the app secret (for short low-entropy secrets such as OTPs)."""
    return hmac.new(current_app.config["SECRET_KEY"].encode(), value.encode(), hashlib.sha256).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def new_otp() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def new_recovery_code() -> str:
    return "-".join(secrets.token_hex(2) for _ in range(3))


def safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------- validation ----------------
def clean_email(raw: str) -> str:
    try:
        return validate_email((raw or "").strip(), check_deliverability=False).normalized.lower()
    except EmailNotValidError as exc:
        raise ValueError("Please enter a valid email address.") from exc


def clean_name(raw: str) -> str:
    name = re.sub(r"\s+", " ", (raw or "").strip())
    if not 1 <= len(name) <= 100 or re.search(r"[<>\x00-\x1f]", name):
        raise ValueError("Name must be 1-100 characters and contain no markup.")
    return name


def check_password_strength(pw: str, email: str = "") -> None:
    n = current_app.config["MIN_PASSWORD_LENGTH"]
    if len(pw) < n:
        raise ValueError(f"Password must be at least {n} characters.")
    if len(pw) > 128:
        raise ValueError("Password must be at most 128 characters.")
    if sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w\s]")) < 3:
        raise ValueError("Password must mix at least 3 of: lowercase, uppercase, digits, symbols.")
    if email and email.split("@")[0].lower() in pw.lower():
        raise ValueError("Password must not contain your email name.")


def client_ip() -> str:
    return request.remote_addr or "unknown"


# ---------------- API keys ----------------
def generate_api_key(user: User, name: str, scopes: list[str] | None, expires_in_days: int | None) -> tuple[ApiKey, str]:
    scopes = [s for s in (scopes or DEFAULT_SCOPES) if s in SCOPES]
    if not scopes:
        raise ValueError("At least one valid scope is required.")
    raw = "pnk_" + secrets.token_urlsafe(32)
    key = ApiKey(
        user_id=user.id, name=name[:80], prefix=raw[:10], key_hash=sha256_hex(raw), scopes=",".join(scopes),
        expires_at=utcnow() + timedelta(days=expires_in_days) if expires_in_days else None,
    )
    db.session.add(key)
    return key, raw


def lookup_api_key(raw: str) -> ApiKey | None:
    """Hash then look up (hash of a 256-bit random key; DB equality on hash is not a timing oracle for the key)."""
    if not raw or len(raw) > 100:
        return None
    key = ApiKey.query.filter_by(key_hash=sha256_hex(raw)).first()
    if not key or key.status != "active" or not safe_equal(key.key_hash, sha256_hex(raw)):
        return None
    return key


# ---------------- auth decorators ----------------
def current_user() -> User | None:
    if "user" in g:
        return g.user
    user = None
    uid = session.get("uid")
    if uid:
        u = db.session.get(User, uid)
        if u and u.is_active and u.session_version == session.get("sv"):
            user = u
        else:
            session.clear()
    g.user = user
    return user


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        u = current_user()
        if not u:
            return redirect(url_for("auth.login", next=request.path if request.method == "GET" else None))
        if not u.email_verified:
            return redirect(url_for("auth.verify_pending"))
        return f(*a, **kw)

    return wrapper


def start_session(user: User) -> None:
    session.clear()
    session.permanent = True
    session["uid"] = user.id
    session["sv"] = user.session_version


def api_error(status: int, code: str, message: str, **extra):
    resp = jsonify({"error": {"code": code, "message": message, **extra}})
    resp.status_code = status
    return resp


def api_auth(scope: str | None = None):
    """API auth: X-API-Key header, or browser session (with CSRF check on unsafe methods)."""

    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            raw = request.headers.get("X-API-Key") or ""
            if raw:
                key = lookup_api_key(raw)
                if not key or not key.user.is_active or not key.user.email_verified:
                    return api_error(401, "invalid_api_key", "API key is invalid, expired or revoked.")
                if scope and scope not in key.scope_list:
                    return api_error(403, "insufficient_scope", f"This key lacks the '{scope}' scope.")
                key.last_used_at = utcnow()
                key.usage_count = (key.usage_count or 0) + 1
                db.session.commit()
                g.user, g.api_key = key.user, key
            else:
                u = current_user()
                if not u or not u.email_verified:
                    return api_error(401, "unauthenticated", "Authentication required (X-API-Key header or login session).")
                if request.method not in ("GET", "HEAD", "OPTIONS"):
                    if current_app.config.get("WTF_CSRF_ENABLED", True):
                        csrf.protect()  # session-authenticated writes need a CSRF token
                g.api_key = None
            return f(*a, **kw)

        return wrapper

    return deco


def owned_or_404(model, obj_id: int, user: User):
    """Fetch a row only if it belongs to *user* (prevents IDOR); 404 otherwise."""
    obj = db.session.get(model, obj_id)
    if obj is None or obj.user_id != user.id:
        abort(404)
    return obj
