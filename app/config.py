"""Application configuration. All secrets come from environment variables."""
from __future__ import annotations

import os
from datetime import timedelta
from urllib.parse import quote_plus

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def mysql_uri(database: str | None = None) -> str:
    """Build a MySQL URI from MYSQL_* env vars (credentials are URL-quoted)."""
    user = quote_plus(os.environ.get("MYSQL_USER", "phishnet"))
    pwd = quote_plus(os.environ.get("MYSQL_PASSWORD", ""))
    host = os.environ.get("MYSQL_HOST", "127.0.0.1")
    port = os.environ.get("MYSQL_PORT", "3306")
    db = database or os.environ.get("MYSQL_DATABASE", "phishnet")
    return f"mysql+pymysql://{user}:{pwd}@{host}:{port}/{db}?charset=utf8mb4"


class BaseConfig:
    SECRET_KEY = os.environ.get("SECRET_KEY", "")
    SQLALCHEMY_DATABASE_URI = mysql_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_size": int(os.environ.get("DB_POOL_SIZE", 10)),
        "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", 10)),
        "pool_recycle": 280,  # below MySQL wait_timeout
        "pool_pre_ping": True,
    }

    # Sessions / cookies
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=int(os.environ.get("SESSION_HOURS", 8)))
    WTF_CSRF_TIME_LIMIT = 3600 * 8

    # Request limits
    MAX_CONTENT_LENGTH = 256 * 1024
    MAX_EMAIL_CHARS = int(os.environ.get("MAX_EMAIL_CHARS", 50000))

    # Redis / rate limits
    REDIS_URL = os.environ.get("REDIS_URL", "")
    RATELIMIT_STORAGE_URI = os.environ.get("REDIS_URL") or "memory://"
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_ENABLED = True
    API_RATE_LIMIT = os.environ.get("API_RATE_LIMIT", "60 per minute")
    LOGIN_RATE_LIMIT = os.environ.get("LOGIN_RATE_LIMIT", "10 per minute")

    # Risk thresholds (risk = phishing_probability * 100)
    RISK_THRESHOLD_SUSPICIOUS = float(os.environ.get("RISK_THRESHOLD_SUSPICIOUS", 30))
    RISK_THRESHOLD_PHISHING = float(os.environ.get("RISK_THRESHOLD_PHISHING", 60))

    # Account security
    MAX_FAILED_LOGINS = int(os.environ.get("MAX_FAILED_LOGINS", 5))
    LOCKOUT_MINUTES = int(os.environ.get("LOCKOUT_MINUTES", 15))
    OTP_TTL_SECONDS = 300
    OTP_MAX_ATTEMPTS = 5
    OTP_RESEND_SECONDS = 30
    VERIFY_TOKEN_HOURS = 24
    RESET_TOKEN_MINUTES = 30
    MIN_PASSWORD_LENGTH = 10

    # Retention
    DEFAULT_RETENTION_DAYS = int(os.environ.get("DEFAULT_RETENTION_DAYS", 0))

    # Mail
    MAIL_BACKEND = os.environ.get("MAIL_BACKEND", "console")
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = _bool("MAIL_USE_TLS", True)
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_FROM = os.environ.get("MAIL_FROM", "PhishNet AI <no-reply@localhost>")
    BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")

    # ML
    ML_MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ml", "models")

    ENV_NAME = "base"


class DevelopmentConfig(BaseConfig):
    ENV_NAME = "development"
    DEBUG = False  # never enable the interactive debugger by default
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-only-insecure-key"  # noqa: S105


class TestingConfig(BaseConfig):
    ENV_NAME = "testing"
    TESTING = True
    SECRET_KEY = "test-secret-key"  # noqa: S105
    SQLALCHEMY_DATABASE_URI = mysql_uri(os.environ.get("TEST_MYSQL_DATABASE", "phishnet_test"))
    WTF_CSRF_ENABLED = False
    RATELIMIT_STORAGE_URI = "memory://"
    MAIL_BACKEND = "memory"


class ProductionConfig(BaseConfig):
    ENV_NAME = "production"
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_NAME = "__Host-phishnet"
    PREFERRED_URL_SCHEME = "https"

    @classmethod
    def validate(cls) -> None:
        key = cls.SECRET_KEY
        if not key or len(key) < 32 or key.startswith("change-me"):
            raise RuntimeError("SECRET_KEY must be a random value of >= 32 chars in production")
        if cls.MAIL_BACKEND != "smtp":
            raise RuntimeError("MAIL_BACKEND must be 'smtp' in production")
        if not os.environ.get("MYSQL_PASSWORD"):
            raise RuntimeError("MYSQL_PASSWORD must be set in production")


CONFIGS = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
