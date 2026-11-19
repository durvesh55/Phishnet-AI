"""PhishNet AI application factory."""
from __future__ import annotations

import logging
import os
import uuid

from flask import Flask, g, jsonify, render_template, request
from sqlalchemy import text
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import CONFIGS
from app.extensions import csrf, db, limiter, migrate

log = logging.getLogger("phishnet")


def create_app(config_name: str | None = None) -> Flask:
    name = config_name or os.environ.get("FLASK_ENV", "development")
    cfg = CONFIGS.get(name)
    if cfg is None:
        raise RuntimeError(f"Unknown config {name!r}")
    if hasattr(cfg, "validate"):
        cfg.validate()

    app = Flask(__name__)
    app.config.from_object(cfg)

    from app.services.audit import configure_logging
    configure_logging(debug=app.debug)

    # Trust one reverse proxy hop (Nginx) for X-Forwarded-* when configured.
    hops = int(os.environ.get("TRUSTED_PROXY_HOPS", 1 if name == "production" else 0))
    if hops:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops, x_host=hops)  # type: ignore[method-assign]

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)

    from app import models  # noqa: F401  (register tables with metadata)
    from app.services.ml_service import MLService

    ml = MLService(app.config["ML_MODEL_DIR"], app.config["RISK_THRESHOLD_SUSPICIOUS"], app.config["RISK_THRESHOLD_PHISHING"])
    ml.load()
    app.extensions["ml_service"] = ml

    _register_blueprints(app)
    _register_hooks(app)
    _register_errors(app)
    _register_cli(app)
    _register_health(app)
    return app


def _register_blueprints(app: Flask) -> None:
    from app.account.routes import bp as account_bp
    from app.api.docs import bp as docs_bp
    from app.api.v1 import bp as api_bp
    from app.auth.routes import bp as auth_bp
    from app.dashboard.routes import bp as dash_bp
    from app.feedback.routes import bp as fb_bp
    from app.history.routes import bp as hist_bp
    from app.public.routes import bp as public_bp
    from app.reports.routes import bp as rep_bp
    from app.scanner.routes import bp as scan_bp

    for bp in (public_bp, dash_bp, auth_bp, scan_bp, hist_bp, fb_bp, rep_bp, account_bp, api_bp, docs_bp):
        app.register_blueprint(bp)


def _register_hooks(app: Flask) -> None:
    @app.before_request
    def _request_id():
        g.pop("user", None)  # never reuse per-request identity (test contexts share `g`)
        g.pop("api_key", None)
        g.request_id = request.headers.get("X-Request-ID", "")[:64] or uuid.uuid4().hex[:16]

    @app.after_request
    def _security_headers(resp):
        csp = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
               "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
        if request.path.startswith("/api/docs"):
            csp = ("default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
                   "style-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
        resp.headers.setdefault("Content-Security-Policy", csp)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if app.config["ENV_NAME"] == "production":
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if request.path.startswith(("/auth", "/account", "/api")):
            resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Request-ID"] = getattr(g, "request_id", "")
        return resp

    @app.template_global("icon")
    def _icon(name: str):
        from flask import url_for
        from markupsafe import Markup
        href = url_for("static", filename="images/icons.svg")
        return Markup('<svg class="ic" aria-hidden="true"><use href="{}#i-{}"/></svg>').format(href, name)  # args auto-escaped

    @app.context_processor
    def _inject():
        from app.utils.security import current_user
        from flask_wtf.csrf import generate_csrf
        return {"current_user": current_user(), "csrf_token": generate_csrf}

    @app.teardown_request
    def _cleanup(exc):
        if exc:
            db.session.rollback()


def _wants_json() -> bool:
    return request.path.startswith("/api/")


def _register_errors(app: Flask) -> None:
    from app.utils.security import api_error

    def render(status: int, code: str, message: str):
        if _wants_json():
            return api_error(status, code, message)
        return render_template("errors/error.html", status=status, message=message), status

    @app.errorhandler(RequestEntityTooLarge)
    def _too_large(_):
        return render(413, "payload_too_large", "The request body is too large.")

    @app.errorhandler(HTTPException)
    def _http(exc: HTTPException):
        from flask_limiter.errors import RateLimitExceeded
        from flask_wtf.csrf import CSRFError
        if isinstance(exc, RateLimitExceeded):
            return render(429, "rate_limited", "Too many requests. Please slow down.")
        if isinstance(exc, CSRFError):
            return render(400, "csrf_failed", "Your session token is missing or expired. Reload the page and try again.")
        names = {400: "bad_request", 401: "unauthenticated", 403: "forbidden", 404: "not_found", 405: "method_not_allowed"}
        return render(exc.code or 500, names.get(exc.code or 500, "error"), exc.name if (exc.code or 500) < 500 else "Server error")

    @app.errorhandler(Exception)
    def _unhandled(exc: Exception):
        db.session.rollback()
        log.error("unhandled %s on %s %s id=%s", type(exc).__name__, request.method, request.path, getattr(g, "request_id", "-"), exc_info=True)
        return render(500, "internal_error", "An internal error occurred.")


def _register_health(app: Flask) -> None:
    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/ready")
    def ready():
        checks = {}
        try:
            db.session.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception:  # noqa: BLE001
            checks["database"] = "unavailable"
        ml = app.extensions["ml_service"]
        checks["model"] = f"ok ({ml.version})" if ml.ready else "unavailable"
        redis_url = app.config.get("REDIS_URL")
        if redis_url:
            try:
                import redis
                redis.Redis.from_url(redis_url, socket_connect_timeout=2).ping()
                checks["redis"] = "ok"
            except Exception:  # noqa: BLE001
                checks["redis"] = "unavailable"
        ok = all(v.startswith("ok") for v in checks.values())
        return jsonify({"status": "ready" if ok else "degraded", "checks": checks}), (200 if ok else 503)


def _register_cli(app: Flask) -> None:
    import click

    @app.cli.command("purge-expired")
    def purge_expired_cmd():
        """Delete scans older than each user's retention period."""
        from app.services.scan_service import purge_all_expired
        click.echo(f"Deleted {purge_all_expired()} expired scans")

    @app.cli.command("reload-model")
    def reload_model_cmd():
        """Reload the active ML model (and record it in model_versions)."""
        ml = app.extensions["ml_service"]
        click.echo("loaded " + str(ml.version) if ml.load() else f"FAILED: {ml.error}")

    @app.cli.command("record-model")
    def record_model_cmd():
        """Record the active model version/metrics in the model_versions table."""
        from app.models import ModelVersion
        ml = app.extensions["ml_service"]
        if not ml.ready:
            raise click.ClickException(f"no model loaded: {ml.error}")
        if not ModelVersion.query.filter_by(version=ml.version).first():
            db.session.add(ModelVersion(version=ml.version, artifact_sha256=ml.meta["sha256"], metrics=ml.meta.get("metrics")))
            db.session.commit()
        click.echo(f"recorded {ml.version}")
