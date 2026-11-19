"""Test fixtures. DB tests run against a dedicated MySQL 8 database (TEST_MYSQL_DATABASE) that is wiped per test."""
from __future__ import annotations

import re

import pytest
import sqlalchemy as sa

from app import create_app
from app.extensions import db
from app.models import User
from app.services import mail_service
from app.utils.security import hash_password

PASSWORD = "Str0ng!Passw0rd"


def _mysql_available() -> str | None:
    try:
        app = create_app("testing")
        with app.app_context():
            db.session.execute(sa.text("SELECT 1"))
        return None
    except Exception as exc:  # noqa: BLE001
        return f"MySQL test database unavailable ({type(exc).__name__}); set MYSQL_* and TEST_MYSQL_DATABASE"


_DB_PROBLEM = _mysql_available()
needs_db = pytest.mark.skipif(_DB_PROBLEM is not None, reason=_DB_PROBLEM or "")


@pytest.fixture()
def app():
    if _DB_PROBLEM:
        pytest.skip(_DB_PROBLEM)
    app = create_app("testing")
    with app.app_context():
        db.drop_all()
        db.create_all()
        mail_service.OUTBOX.clear()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def make_user(email="alice@example.com", name="Alice", verified=True, otp=False, password=PASSWORD) -> User:
    u = User(name=name, email=email, password_hash=hash_password(password), email_verified=verified, otp_enabled=otp)
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture()
def user(app):
    return make_user()


@pytest.fixture()
def other_user(app):
    return make_user("bob@example.com", "Bob")


def login(client, email="alice@example.com", password=PASSWORD):
    return client.post("/auth/login", data={"email": email, "password": password})


@pytest.fixture()
def logged_in(client, user):
    r = login(client)
    assert r.status_code == 302
    return client


def last_mail_value(pattern: str) -> str:
    m = re.search(pattern, mail_service.OUTBOX[-1]["body"])
    assert m, mail_service.OUTBOX[-1]["body"]
    return m.group(1)


PHISH = "URGENT: Your PayPal account has been suspended. Verify your password immediately at http://paypa1-secure.com or it will be deleted."
SAFE = "Hi team, reminder that the weekly sync is on Thursday at 3 PM in Conference Room B. Please bring your updates."
