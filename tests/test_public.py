import socket

from app.services import rule_engine
from tests.conftest import PHISH, SAFE


def test_link_analysis_flags_and_never_fetches(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)
    r = {x.host: x for x in rule_engine.analyze_links("see http://micros0ft.com/a and https://www.microsoft.com and http://192.168.1.1/x and bit.ly")}
    assert r["micros0ft.com"].severity == "high"
    assert r["www.microsoft.com"].severity == "none"
    assert r["192.168.1.1"].severity == "high"


def test_landing_is_public(client):
    r = client.get("/")
    assert r.status_code == 200 and b"Check now" in r.data and b"Sign in" in r.data


def test_landing_redirects_signed_in_user(logged_in):
    assert logged_in.get("/").headers["Location"].endswith("/dashboard")


def test_anonymous_check_email_not_stored(client, app):
    from app.models import Scan
    r = client.post("/check", data={"content": PHISH})
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and "Machine Learning Analysis" in html and "Link analysis" in html
    assert "High-risk indicators" in html and Scan.query.count() == 0


def test_anonymous_check_bare_link_skips_ml(client):
    html = client.post("/check", data={"content": "http://micros0ft.com/login"}).get_data(as_text=True)
    assert "Not run" in html and "lookalike" in html.lower()


def test_safe_text_never_called_safe(client):
    html = client.post("/check", data={"content": SAFE}).get_data(as_text=True)
    assert "not proof that it is safe" in html.lower()


def test_check_validation_and_xss(client):
    assert client.post("/check", data={"content": "  "}).status_code == 302
    assert client.post("/check", data={"content": "x" * 5001}).status_code == 302
    html = client.post("/check", data={"content": "<script>alert(1)</script> urgent verify your password http://evil.xyz"}).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html


def test_check_rate_limited(client):
    codes = [client.post("/check", data={"content": SAFE}).status_code for _ in range(12)]
    assert 429 in codes


def test_verdict_uses_link_severity_when_text_has_no_findings(client):
    html = client.post("/check", data={"content": "http://192.168.1.1/x"}).get_data(as_text=True)
    assert "High-risk indicators" in html
