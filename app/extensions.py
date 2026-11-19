"""Flask extension singletons (initialised in the app factory)."""
from flask import request
from flask_limiter import Limiter
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()


def _client_key() -> str:
    # ProxyFix (configured in the factory) makes remote_addr the real client IP.
    return request.remote_addr or "unknown"


limiter = Limiter(key_func=_client_key, default_limits=[])
