"""Scans, history, feedback, API keys, REST API, reports, dashboard, isolation."""
import json

import pytest

from app.extensions import db
from app.models import ApiKey, Feedback, Scan, utcnow
from tests.conftest import PHISH, SAFE, login, make_user


def scan_web(client, text=PHISH):
    r = client.post("/scan/", data={"email_text": text})
    assert r.status_code == 302, r.get_data(as_text=True)[:300]
    return int(r.headers["Location"].rstrip("/").split("/")[-1])


def make_key(client, **body):
    body.setdefault("name", "k1")
    r = client.post("/api/v1/api-keys", json=body)
    assert r.status_code == 201, r.get_data(as_text=True)
    return r.get_json()["data"]


# ---------------- scanning & persistence ----------------
def test_scan_persists_ml_and_rules_separately(logged_in, user):
    sid = scan_web(logged_in)
    s = db.session.get(Scan, sid)
    assert s.user_id == user.id and s.classification == "PHISHING" and s.model_version.startswith("v")
    assert s.rule_findings and any(f["rule_id"] == "LOOKALIKE_DOMAIN" for f in s.rule_findings)
    assert s.text_sha256 and s.risk_score >= 60
    page = logged_in.get(f"/history/{sid}").get_data(as_text=True)
    assert "Machine Learning Analysis" in page and "Security Rule Analysis" in page


def test_rules_do_not_change_ml_score(app, logged_in, monkeypatch):
    from app.services import rule_engine
    a = db.session.get(Scan, scan_web(logged_in)).risk_score
    monkeypatch.setattr(rule_engine, "analyze", lambda t: [])
    b = db.session.get(Scan, scan_web(logged_in)).risk_score
    assert a == b


def test_scan_validation_and_limits(app, logged_in):
    assert logged_in.post("/scan/", data={"email_text": "   "}).status_code == 400
    app.config["MAX_EMAIL_CHARS"] = 100
    assert logged_in.post("/scan/", data={"email_text": "x" * 101}).status_code == 400


def test_xss_escaped(logged_in):
    sid = scan_web(logged_in, "<script>alert(1)</script> URGENT verify your password http://evil.xyz")
    html = logged_in.get(f"/history/{sid}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_privacy_no_text_storage(logged_in, user):
    user.store_email_text = False
    db.session.commit()
    s = db.session.get(Scan, scan_web(logged_in))
    assert s.email_text is None and s.preview == "" and s.text_sha256


# ---------------- history / filters / isolation ----------------
def test_history_filter_search_sort_paginate(logged_in):
    for i in range(3):
        scan_web(logged_in, SAFE + f" number {i}")
    scan_web(logged_in, PHISH)
    def h(q):
        return logged_in.get("/history/?" + q).get_data(as_text=True)

    assert "PHISHING" in h("classification=PHISHING") and "weekly sync" not in h("classification=PHISHING")
    assert "weekly sync" in h("q=weekly")
    assert logged_in.get("/history/?per_page=2&page=2").status_code == 200
    assert logged_in.get("/history/?sort=risk_desc").status_code == 200
    assert logged_in.get("/history/?q=%25_%5C").status_code == 200  # wildcard chars are escaped


def test_cross_user_isolation_web(client, app):
    make_user("a@example.com", "A")
    make_user("b@example.com", "B")
    login(client, "a@example.com")
    sid = scan_web(client)
    client.post("/auth/logout")
    login(client, "b@example.com")
    assert client.get(f"/history/{sid}").status_code == 404
    assert client.post(f"/history/{sid}/delete").status_code == 404
    assert client.post(f"/feedback/{sid}", data={"verdict": "correct"}).status_code == 404
    assert client.get(f"/reports/scan/{sid}.pdf").status_code == 404
    listing = client.get("/history/").get_data(as_text=True)
    assert f"/history/{sid}" not in listing and "No scans match" in listing
    assert Scan.query.count() == 1


def test_delete_scan(logged_in):
    sid = scan_web(logged_in)
    logged_in.post(f"/history/{sid}/delete")
    assert db.session.get(Scan, sid) is None


# ---------------- feedback ----------------
def test_feedback_stored_separately_and_upserts(logged_in, user):
    sid = scan_web(logged_in)
    logged_in.post(f"/feedback/{sid}", data={"verdict": "incorrect", "comment": "was fine"})
    logged_in.post(f"/feedback/{sid}", data={"verdict": "correct"})
    fbs = Feedback.query.all()
    assert len(fbs) == 1 and fbs[0].is_correct and fbs[0].user_id == user.id
    assert logged_in.post(f"/feedback/{sid}", data={"verdict": "bogus"}).status_code == 302
    assert Feedback.query.count() == 1


# ---------------- dashboard ----------------
def test_dashboard_stats_from_db(logged_in, user):
    scan_web(logged_in, PHISH)
    scan_web(logged_in, SAFE)
    scan_web(logged_in, PHISH + " again")
    other = make_user("z@example.com", "Z")
    db.session.add(Scan(user_id=other.id, text_sha256="0" * 64, text_length=1, classification="SAFE", risk_score=1, ml_probability=.01,
                        model_version="v", rule_findings=[], rule_max_severity="none"))
    db.session.commit()
    s = logged_in.get("/api/v1/stats").get_json()["data"]
    assert s["total"] == 3 and s["phishing"] == 2 and s["safe"] == 1 and s["suspicious"] == 0
    assert sum(d["count"] for d in s["trend_7d"]) == 3
    assert logged_in.get("/dashboard").status_code == 200


# ---------------- API keys ----------------
def test_api_key_lifecycle(logged_in, app):
    k = make_key(logged_in, scopes=["scan:write", "history:read"])
    raw = k["api_key"]
    row = db.session.get(ApiKey, k["id"])
    assert raw not in (row.key_hash, row.prefix) and len(row.key_hash) == 64  # only hash stored
    assert ApiKey.query.filter(ApiKey.key_hash == raw).count() == 0
    c = app.test_client()  # no session
    r = c.post("/api/v1/scans", json={"email_text": PHISH}, headers={"X-API-Key": raw})
    assert r.status_code == 201
    body = r.get_json()["data"]
    assert body["machine_learning"]["classification"] == "PHISHING" and body["rule_analysis"]["findings"]
    row = db.session.get(ApiKey, k["id"])
    assert row.usage_count == 1 and row.last_used_at is not None
    assert c.get("/api/v1/stats", headers={"X-API-Key": raw}).status_code == 403  # scope not granted
    # listing the key never reveals the raw key
    assert raw not in logged_in.get("/api/v1/api-keys").get_data(as_text=True)
    # rotate
    r = logged_in.post(f"/api/v1/api-keys/{k['id']}/rotate")
    new_raw = r.get_json()["data"]["api_key"]
    assert c.get("/api/v1/scans", headers={"X-API-Key": raw}).status_code == 401
    assert c.get("/api/v1/scans", headers={"X-API-Key": new_raw}).status_code == 200
    # revoke
    nid = r.get_json()["data"]["id"]
    assert logged_in.delete(f"/api/v1/api-keys/{nid}").status_code == 204
    assert c.get("/api/v1/scans", headers={"X-API-Key": new_raw}).status_code == 401


def test_api_key_expiry(logged_in, app):
    k = make_key(logged_in, expires_in_days=1)
    row = db.session.get(ApiKey, k["id"])
    row.expires_at = utcnow().replace(year=2000)
    db.session.commit()
    assert app.test_client().get("/api/v1/scans", headers={"X-API-Key": k["api_key"]}).status_code == 401


def test_api_key_cannot_manage_keys(logged_in, app):
    raw = make_key(logged_in)["api_key"]
    assert app.test_client().post("/api/v1/api-keys", json={"name": "x"}, headers={"X-API-Key": raw}).status_code == 403


def test_api_key_belongs_to_user(client, app):
    make_user("a@example.com", "A")
    make_user("b@example.com", "B")
    login(client, "a@example.com")
    ka = make_key(client)
    sid = client.post("/api/v1/scans", json={"email_text": PHISH}).get_json()["data"]["id"]
    client.post("/auth/logout")
    login(client, "b@example.com")
    kb = make_key(client, name="b")
    c = app.test_client()
    assert c.get(f"/api/v1/scans/{sid}", headers={"X-API-Key": kb["api_key"]}).status_code == 404
    assert c.get(f"/api/v1/scans/{sid}", headers={"X-API-Key": ka["api_key"]}).status_code == 200
    assert c.get("/api/v1/scans", headers={"X-API-Key": kb["api_key"]}).get_json()["pagination"]["total"] == 0
    assert client.delete(f"/api/v1/api-keys/{ka['id']}").status_code == 404


# ---------------- REST API ----------------
def test_api_unauthorized_and_invalid(client, logged_in, app):
    c = app.test_client()
    assert c.get("/api/v1/scans").status_code == 401
    assert c.get("/api/v1/scans", headers={"X-API-Key": "pnk_bogus"}).status_code == 401
    assert c.post("/api/v1/scans", json={"email_text": PHISH}).get_json()["error"]["code"] == "unauthenticated"


def test_api_validation_errors(logged_in):
    for body in ({}, {"email_text": ""}, {"email_text": 5}, [1]):
        r = logged_in.post("/api/v1/scans", json=body)
        assert r.status_code == 400 and r.get_json()["error"]["code"] == "validation_error"
    assert logged_in.post("/api/v1/scans", data="not json", content_type="text/plain").status_code == 400
    assert logged_in.get("/api/v1/scans?page=abc").status_code == 400
    assert logged_in.get("/api/v1/scans?classification=NOPE").status_code == 400
    assert logged_in.get("/api/v1/scans?date_from=yesterday").status_code == 400
    assert logged_in.get("/api/v1/scans/999999").status_code == 404
    assert logged_in.post("/api/v1/scans/999999/feedback", json={"is_correct": True}).status_code == 404


def test_api_oversized_body(app, logged_in):
    r = logged_in.post("/api/v1/scans", data="x" * (300 * 1024), content_type="application/json")
    assert r.status_code == 413 and r.get_json()["error"]["code"] == "payload_too_large"


def test_api_error_responses_hide_internals(app, logged_in, monkeypatch):
    from app.services import scan_service
    monkeypatch.setattr(scan_service, "run_scan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("secret sql details")))
    app.config["PROPAGATE_EXCEPTIONS"] = False
    r = logged_in.post("/api/v1/scans", json={"email_text": PHISH})
    assert r.status_code == 500 and "secret" not in r.get_data(as_text=True)


def test_api_rate_limit(app, logged_in):
    app.config["API_RATE_LIMIT"] = "3 per minute"
    raw = make_key(logged_in)["api_key"]
    c = app.test_client()
    codes = [c.get("/api/v1/scans", headers={"X-API-Key": raw}).status_code for _ in range(6)]
    assert codes[:3] == [200, 200, 200] and codes[-1] == 429
    assert c.get("/api/v1/scans", headers={"X-API-Key": raw}).get_json()["error"]["code"] == "rate_limited"


def test_api_session_write_requires_csrf(app, user):
    app.config["WTF_CSRF_ENABLED"] = True
    c = app.test_client()
    with app.test_request_context():
        pass
    # log in via session cookie directly
    with c.session_transaction() as s:
        s["uid"], s["sv"] = user.id, user.session_version
    r = c.post("/api/v1/scans", json={"email_text": PHISH})
    assert r.status_code == 400 and r.get_json()["error"]["code"] == "csrf_failed"


def test_api_feedback_and_pagination(logged_in):
    for _ in range(3):
        logged_in.post("/api/v1/scans", json={"email_text": PHISH})
    r = logged_in.get("/api/v1/scans?per_page=2&page=2").get_json()
    assert len(r["data"]) == 1 and r["pagination"]["total"] == 3 and r["pagination"]["pages"] == 2
    sid = r["data"][0]["id"]
    assert logged_in.post(f"/api/v1/scans/{sid}/feedback", json={"is_correct": "yes"}).status_code == 400
    assert logged_in.post(f"/api/v1/scans/{sid}/feedback", json={"is_correct": False, "comment": "hm"}).status_code == 201


def test_openapi_and_health(client):
    assert client.get("/api/v1/openapi.json").get_json()["openapi"].startswith("3.")
    assert client.get("/api/docs").status_code == 200
    assert client.get("/health").status_code == 200
    r = client.get("/ready")
    assert r.status_code == 200 and r.get_json()["checks"]["database"] == "ok"


# ---------------- reports ----------------
def test_csv_report_and_formula_injection(logged_in):
    scan_web(logged_in, "=HYPERLINK(\"http://evil\") URGENT verify your password http://paypa1.com")
    scan_web(logged_in, SAFE)
    r = logged_in.get("/reports/history.csv?classification=PHISHING")
    assert r.status_code == 200 and r.mimetype == "text/csv"
    text = r.get_data(as_text=True)
    assert "PHISHING" in text and "weekly sync" not in text and "'=HYPERLINK" in text
    assert logged_in.get("/reports/history.csv?date_from=2999-01-01").get_data(as_text=True).count("\n") == 1  # header only
    assert logged_in.get("/reports/history.csv?date_from=bad").status_code == 302


def test_pdf_reports(logged_in):
    sid = scan_web(logged_in)
    for url in (f"/reports/scan/{sid}.pdf", "/reports/history.pdf", f"/api/v1/reports/scans/{sid}.pdf"):
        r = logged_in.get(url)
        assert r.status_code == 200 and r.data.startswith(b"%PDF"), url
    assert logged_in.get("/api/v1/reports/scans.csv").status_code == 200


def test_reports_only_own_data(client, app):
    make_user("a@example.com", "A")
    make_user("b@example.com", "B")
    login(client, "a@example.com")
    scan_web(client)
    client.post("/auth/logout")
    login(client, "b@example.com")
    assert client.get("/reports/history.csv").get_data(as_text=True).strip().count("\n") == 0
    assert client.get("/api/v1/reports/scans/1.pdf").status_code == 404


# ---------------- data export & retention ----------------
def test_data_export_and_retention(logged_in, user):
    scan_web(logged_in)
    data = json.loads(logged_in.get("/account/export").data)
    assert data["profile"]["email"] == user.email and len(data["scans"]) == 1
    assert "password" not in json.dumps(data).lower() or "password_hash" not in json.dumps(data)
    from datetime import timedelta
    s = Scan.query.one()
    s.created_at = utcnow() - timedelta(days=40)
    user.retention_days = 30
    db.session.commit()
    from app.services.scan_service import purge_all_expired
    assert purge_all_expired() == 1 and Scan.query.count() == 0


# ---------------- database ----------------
def test_db_constraints_and_relationships(app, user):
    import sqlalchemy.exc as sx
    from app.models import User
    db.session.add(User(name="dup", email=user.email, password_hash="x"))
    with pytest.raises(sx.IntegrityError):
        db.session.commit()
    db.session.rollback()
    db.session.add(Scan(user_id=user.id, text_sha256="a" * 64, text_length=1, classification="BOGUS", risk_score=1, ml_probability=.1,
                        model_version="v", rule_findings=[], rule_max_severity="none"))
    with pytest.raises(sx.DatabaseError):  # CHECK constraint (enforced by MySQL 8.0.16+)
        db.session.commit()
    db.session.rollback()
    db.session.add(Scan(user_id=999999, text_sha256="a" * 64, text_length=1, classification="SAFE", risk_score=1, ml_probability=.1,
                        model_version="v", rule_findings=[], rule_max_severity="none"))
    with pytest.raises(sx.IntegrityError):  # FK
        db.session.commit()


def test_migrations_match_models(app):
    """The Alembic migration must create exactly the tables defined by the models."""
    import os
    from flask_migrate import upgrade
    db.drop_all()
    db.session.execute(db.text("DROP TABLE IF EXISTS alembic_version"))
    db.session.commit()
    upgrade(directory=os.path.join(os.path.dirname(__file__), "..", "migrations"))
    import sqlalchemy as sa
    names = set(sa.inspect(db.engine).get_table_names())
    assert set(db.metadata.tables) <= names
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    with db.engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), db.metadata)
    assert diff == [], diff
