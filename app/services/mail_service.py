"""Outgoing email. Backends: smtp (production), console (dev only), memory (tests)."""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage

from flask import current_app

log = logging.getLogger("phishnet.mail")
OUTBOX: list[dict] = []  # used only by the 'memory' backend (tests)


def send_mail(to: str, subject: str, body: str) -> bool:
    """Send an email. Returns True when handed to the backend. Never raises into request handling."""
    cfg = current_app.config
    backend = cfg["MAIL_BACKEND"]
    try:
        if backend == "memory":
            OUTBOX.append({"to": to, "subject": subject, "body": body})
            return True
        if backend == "console":
            if cfg["ENV_NAME"] == "production":
                raise RuntimeError("console mail backend is not allowed in production")
            # Dev only: the message (including links/codes) is printed so you can complete flows locally.
            log.warning("DEV MAIL to=%s subject=%s\n%s", to, subject, body)
            return True
        if backend == "smtp":
            if not cfg["MAIL_SERVER"]:
                raise RuntimeError("MAIL_SERVER is not configured")
            msg = EmailMessage()
            msg["From"], msg["To"], msg["Subject"] = cfg["MAIL_FROM"], to, subject
            msg.set_content(body)
            with smtplib.SMTP(cfg["MAIL_SERVER"], cfg["MAIL_PORT"], timeout=15) as s:
                if cfg["MAIL_USE_TLS"]:
                    s.starttls(context=ssl.create_default_context())
                if cfg["MAIL_USERNAME"]:
                    s.login(cfg["MAIL_USERNAME"], cfg["MAIL_PASSWORD"])
                s.send_message(msg)
            return True
        raise RuntimeError(f"unknown MAIL_BACKEND {backend!r}")
    except Exception as exc:  # noqa: BLE001
        log.error("mail delivery failed (%s): %s", type(exc).__name__, exc)  # no body/secret logged
        return False
