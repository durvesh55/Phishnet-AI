"""Audit trail + structured logging helpers. Never pass secrets as `detail`."""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, UTC

from flask import has_request_context, request

from app.extensions import db
from app.models import AuditLog

log = logging.getLogger("phishnet.audit")


def audit(event: str, user_id: int | None = None, detail: str | None = None, commit: bool = True) -> None:
    ip = request.remote_addr if has_request_context() else None
    db.session.add(AuditLog(user_id=user_id, event=event, ip_address=ip, detail=(detail or "")[:500] or None))
    if commit:
        db.session.commit()
    log.info("audit event=%s user_id=%s ip=%s", event, user_id, ip)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(UTC).isoformat(), "level": record.levelname,
            "logger": record.name, "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(debug: bool = False) -> None:
    root = logging.getLogger()
    if any(getattr(h, "_phishnet", False) for h in root.handlers):
        return
    h = logging.StreamHandler(sys.stdout)
    h._phishnet = True  # type: ignore[attr-defined]
    h.setFormatter(JsonFormatter())
    root.addHandler(h)
    root.setLevel(logging.DEBUG if debug else logging.INFO)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
