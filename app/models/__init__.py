"""SQLAlchemy models. Timestamps are stored as naive UTC."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import CheckConstraint, Index, UniqueConstraint
from sqlalchemy.dialects.mysql import LONGTEXT

from app.extensions import db


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="user")
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    otp_enabled = db.Column(db.Boolean, nullable=False, default=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    session_version = db.Column(db.Integer, nullable=False, default=1)
    retention_days = db.Column(db.Integer, nullable=False, default=0)  # 0 = keep until deleted
    store_email_text = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)

    scans = db.relationship("Scan", back_populates="user", cascade="all, delete-orphan", passive_deletes=True)
    api_keys = db.relationship("ApiKey", back_populates="user", cascade="all, delete-orphan", passive_deletes=True)

    __table_args__ = (CheckConstraint("role in ('user','admin')", name="ck_users_role"),)


class Scan(db.Model):
    __tablename__ = "scans"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    email_text = db.Column(LONGTEXT().with_variant(db.Text, "sqlite"), nullable=True)  # NULL if user opted out
    text_sha256 = db.Column(db.String(64), nullable=False)
    text_length = db.Column(db.Integer, nullable=False)
    preview = db.Column(db.String(200), nullable=False, default="")
    # --- Machine-learning result (independent of the rule engine) ---
    classification = db.Column(db.String(12), nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    ml_probability = db.Column(db.Float, nullable=False)
    model_version = db.Column(db.String(64), nullable=False)
    # --- Rule-engine result (independent of the ML model) ---
    rule_findings = db.Column(db.JSON, nullable=False, default=list)
    rule_max_severity = db.Column(db.String(10), nullable=False, default="none")
    source = db.Column(db.String(10), nullable=False, default="web")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    user = db.relationship("User", back_populates="scans")
    feedback = db.relationship("Feedback", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)

    __table_args__ = (
        CheckConstraint("classification in ('SAFE','SUSPICIOUS','PHISHING')", name="ck_scans_class"),
        CheckConstraint("risk_score >= 0 and risk_score <= 100", name="ck_scans_risk"),
        Index("ix_scans_user_created", "user_id", "created_at"),
        Index("ix_scans_user_class", "user_id", "classification"),
    )


class Feedback(db.Model):
    __tablename__ = "feedback"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)
    comment = db.Column(db.String(1000), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    scan = db.relationship("Scan", back_populates="feedback")
    __table_args__ = (UniqueConstraint("scan_id", "user_id", name="uq_feedback_scan_user"),)


class ApiKey(db.Model):
    __tablename__ = "api_keys"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    prefix = db.Column(db.String(12), nullable=False)
    key_hash = db.Column(db.String(64), nullable=False, unique=True)  # SHA-256 of the raw key
    scopes = db.Column(db.String(100), nullable=False, default="scan:write,history:read")
    expires_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    last_used_at = db.Column(db.DateTime, nullable=True)
    usage_count = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    user = db.relationship("User", back_populates="api_keys")

    @property
    def scope_list(self) -> list[str]:
        return [s for s in self.scopes.split(",") if s]

    @property
    def status(self) -> str:
        if self.revoked_at:
            return "revoked"
        if self.expires_at and self.expires_at <= utcnow():
            return "expired"
        return "active"


class OtpRecord(db.Model):
    __tablename__ = "otp_records"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    code_hash = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    consumed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class RecoveryCode(db.Model):
    __tablename__ = "recovery_codes"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    code_hash = db.Column(db.String(64), nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class _TokenMixin:
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), nullable=False, unique=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class EmailVerificationToken(_TokenMixin, db.Model):
    __tablename__ = "email_verification_tokens"
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)


class PasswordResetToken(_TokenMixin, db.Model):
    __tablename__ = "password_reset_tokens"
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.BigInteger().with_variant(db.Integer, "sqlite"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    event = db.Column(db.String(60), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    detail = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    __table_args__ = (Index("ix_audit_user_created", "user_id", "created_at"), Index("ix_audit_event", "event"))


class ModelVersion(db.Model):
    __tablename__ = "model_versions"
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(64), nullable=False, unique=True)
    artifact_sha256 = db.Column(db.String(64), nullable=False)
    metrics = db.Column(db.JSON, nullable=True)
    first_seen_at = db.Column(db.DateTime, nullable=False, default=utcnow)
