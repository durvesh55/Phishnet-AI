from datetime import timedelta

from app.extensions import db
from app.models import EmailVerificationToken, OtpRecord, PasswordResetToken, User, utcnow
from app.services import mail_service
from app.utils.security import verify_password
from tests.conftest import PASSWORD, last_mail_value, login, make_user


def test_register_verify_login_flow(client):
    r = client.post("/auth/register", data={"name": "Carol", "email": "carol@example.com", "password": PASSWORD, "confirm_password": PASSWORD})
    assert r.status_code == 302
    u = User.query.filter_by(email="carol@example.com").one()
    assert u.password_hash != PASSWORD and u.password_hash.startswith("scrypt:")
    assert not u.email_verified
    # unverified cannot sign in
    assert login(client, "carol@example.com").headers["Location"].endswith("/auth/verify-pending")
    assert client.get("/dashboard").status_code == 302
    token = last_mail_value(r"/auth/verify/(\S+)")
    assert client.get(f"/auth/verify/{token}").status_code == 302
    assert db.session.get(User, u.id).email_verified
    # token is single use
    client.get(f"/auth/verify/{token}")
    assert "invalid" in client.get(f"/auth/verify/{token}", follow_redirects=True).get_data(as_text=True).lower()


def test_register_validation(client):
    bad = [("Dan", "not-an-email", PASSWORD, PASSWORD), ("Dan", "d@example.com", "short", "short"),
           ("Dan", "d@example.com", PASSWORD, "different"), ("<b>x</b>", "d@example.com", PASSWORD, PASSWORD),
           ("Dan", "d@example.com", "alllowercaseletters", "alllowercaseletters")]
    for n, e, p, c in bad:
        r = client.post("/auth/register", data={"name": n, "email": e, "password": p, "confirm_password": c})
        assert r.status_code == 400, (n, e, p)
    assert User.query.count() == 0


def test_duplicate_email_does_not_leak(client, user):
    r = client.post("/auth/register", data={"name": "X", "email": user.email, "password": PASSWORD, "confirm_password": PASSWORD})
    assert r.status_code == 302 and User.query.count() == 1


def test_expired_verification_token(client):
    client.post("/auth/register", data={"name": "Eve", "email": "eve@example.com", "password": PASSWORD, "confirm_password": PASSWORD})
    token = last_mail_value(r"/auth/verify/(\S+)")
    t = EmailVerificationToken.query.one()
    t.expires_at = utcnow() - timedelta(minutes=1)
    db.session.commit()
    client.get(f"/auth/verify/{token}")
    assert not User.query.filter_by(email="eve@example.com").one().email_verified


def test_login_logout_and_session_invalidation(client, user):
    assert login(client).status_code == 302
    assert client.get("/dashboard").status_code == 200
    with client.session_transaction() as s:
        stolen = dict(s)
    assert client.post("/auth/logout").status_code == 302
    assert client.get("/dashboard").status_code == 302
    # replaying the old cookie must not work (session_version bumped)
    with client.session_transaction() as s:
        s.update(stolen)
    assert client.get("/dashboard").status_code == 302


def test_wrong_password_and_generic_message(client, user):
    r = login(client, password="Wrong!Passw0rd1")
    r2 = login(client, "nobody@example.com", "Wrong!Passw0rd1")
    assert r.status_code == r2.status_code == 401
    assert "Invalid email or password" in r.get_data(as_text=True)


def test_account_lockout(app, client, user):
    for _ in range(app.config["MAX_FAILED_LOGINS"]):
        login(client, password="Wrong!Passw0rd1")
    r = login(client)  # correct password but locked
    assert r.status_code == 429


def test_login_rate_limit(app, client):
    app.config["LOGIN_RATE_LIMIT"] = "3 per minute"
    codes = [login(client, "x@example.com", "Wrong!Passw0rd1").status_code for _ in range(5)]
    assert 429 in codes


def test_protected_pages_require_login(client):
    for path in ["/dashboard", "/scan/", "/history/", "/account/", "/account/api-keys", "/reports/history.csv"]:
        assert client.get(path).status_code == 302, path


def test_open_redirect_blocked(client, user):
    r = client.post("/auth/login?next=//evil.example.org", data={"email": user.email, "password": PASSWORD})
    assert r.headers["Location"].endswith("/dashboard")


# ---------- OTP ----------
def _otp_user():
    return make_user("otp@example.com", "Otp", otp=True)


def test_otp_flow(client, app):
    _otp_user()
    r = login(client, "otp@example.com")
    assert r.headers["Location"].endswith("/auth/otp")
    assert client.get("/dashboard").status_code == 302  # not logged in yet
    code = last_mail_value(r"code is (\d{6})")
    stored = OtpRecord.query.one()
    assert code not in stored.code_hash  # stored hashed, not plaintext
    assert client.post("/auth/otp", data={"code": "000000", "mode": "otp"}).status_code == 401
    assert client.post("/auth/otp", data={"code": code, "mode": "otp"}).status_code == 302
    assert client.get("/dashboard").status_code == 200


def test_otp_expired(client):
    _otp_user()
    login(client, "otp@example.com")
    code = last_mail_value(r"code is (\d{6})")
    o = OtpRecord.query.one()
    o.expires_at = utcnow() - timedelta(seconds=1)
    db.session.commit()
    assert client.post("/auth/otp", data={"code": code, "mode": "otp"}).status_code == 401
    assert client.get("/dashboard").status_code == 302


def test_otp_attempt_limit(client, app):
    _otp_user()
    login(client, "otp@example.com")
    code = last_mail_value(r"code is (\d{6})")
    wrong = "111111" if code != "111111" else "222222"
    for _ in range(app.config["OTP_MAX_ATTEMPTS"]):
        client.post("/auth/otp", data={"code": wrong, "mode": "otp"})
    assert client.post("/auth/otp", data={"code": code, "mode": "otp"}).status_code == 401  # even correct code refused


def test_otp_resend_throttled(client):
    _otp_user()
    login(client, "otp@example.com")
    n = len(mail_service.OUTBOX)
    client.post("/auth/otp/resend")
    assert len(mail_service.OUTBOX) == n  # throttled


def test_recovery_code_login_single_use(client, app):
    u = _otp_user()
    from app.auth.service import generate_recovery_codes
    codes = generate_recovery_codes(u)
    login(client, "otp@example.com")
    assert client.post("/auth/otp", data={"code": codes[0], "mode": "recovery"}).status_code == 302
    client.post("/auth/logout")
    login(client, "otp@example.com")
    assert client.post("/auth/otp", data={"code": codes[0], "mode": "recovery"}).status_code == 401


# ---------- password reset ----------
def test_password_reset_flow(client, user):
    client.post("/auth/forgot", data={"email": user.email})
    token = last_mail_value(r"/auth/reset/(\S+)")
    new = "N3w!Passw0rd-xyz"
    assert client.post(f"/auth/reset/{token}", data={"password": new, "confirm_password": new}).status_code == 302
    assert verify_password(db.session.get(User, user.id).password_hash, new)
    # single use
    assert client.post(f"/auth/reset/{token}", data={"password": "An0ther!Passw0rd", "confirm_password": "An0ther!Passw0rd"}).status_code == 302
    assert verify_password(db.session.get(User, user.id).password_hash, new)
    assert login(client, user.email, new).status_code == 302


def test_password_reset_expired_and_unknown_email(client, user):
    n = len(mail_service.OUTBOX)
    client.post("/auth/forgot", data={"email": "ghost@example.com"})
    assert len(mail_service.OUTBOX) == n  # no mail, but identical response
    client.post("/auth/forgot", data={"email": user.email})
    token = last_mail_value(r"/auth/reset/(\S+)")
    t = PasswordResetToken.query.one()
    t.expires_at = utcnow() - timedelta(minutes=1)
    db.session.commit()
    r = client.post(f"/auth/reset/{token}", data={"password": "N3w!Passw0rd-xyz", "confirm_password": "N3w!Passw0rd-xyz"})
    assert r.status_code == 302 and verify_password(db.session.get(User, user.id).password_hash, PASSWORD)


def test_csrf_enforced_when_enabled(app):
    app.config["WTF_CSRF_ENABLED"] = True
    c = app.test_client()
    r = c.post("/auth/login", data={"email": "a@example.com", "password": "x"})
    assert r.status_code == 400


def test_security_headers(client):
    r = client.get("/auth/login")
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY" and r.headers["X-Content-Type-Options"] == "nosniff"


def test_account_deletion_cascades(client, user):
    login(client)
    client.post("/scan/", data={"email_text": "Hello this is a normal message about lunch tomorrow."})
    from app.models import Scan
    assert Scan.query.count() == 1
    assert client.post("/account/delete", data={"password": "wrong", "confirm": "DELETE"}).status_code == 302
    assert User.query.count() == 1
    client.post("/account/delete", data={"password": PASSWORD, "confirm": "DELETE"})
    assert User.query.count() == 0 and Scan.query.count() == 0
