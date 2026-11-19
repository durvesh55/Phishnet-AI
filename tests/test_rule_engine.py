from app.services import rule_engine as re_


def ids(text):
    return {f.rule_id for f in re_.analyze(text)}


def test_urgency():
    assert "URGENCY" in ids("URGENT: your account will be suspended within 24 hours")


def test_sensitive_info():
    assert "SENSITIVE_INFO" in ids("Please send your password and credit card number to confirm.")


def test_lookalike_char_substitution():
    f = {x.rule_id: x for x in re_.analyze("Login at http://micros0ft.com/verify now")}
    assert "LOOKALIKE_DOMAIN" in f
    assert "micros0ft.com" in f["LOOKALIKE_DOMAIN"].evidence[0]


def test_lookalike_rn_and_embedded_brand():
    assert "LOOKALIKE_DOMAIN" in ids("visit http://rnicrosoft.com")
    assert "LOOKALIKE_DOMAIN" in ids("visit https://paypal-secure-login.com/x")


def test_genuine_domains_not_flagged():
    assert "LOOKALIKE_DOMAIN" not in ids("See https://www.microsoft.com and https://accounts.google.com and mail@paypal.com")


def test_shortener_ip_tld_punycode():
    got = ids("http://bit.ly/abc http://192.168.1.5/login http://evil.xyz/a http://xn--pple-43d.com")
    assert {"URL_SHORTENER", "IP_URL", "RISKY_TLD", "PUNYCODE"} <= got


def test_url_userinfo():
    assert "URL_USERINFO" in ids("go to http://paypal.com@evil.example.org/login")


def test_attachment():
    assert "RISKY_ATTACHMENT" in ids("Open the attached invoice.pdf.exe now")


def test_payment_request():
    assert "PAYMENT_REQUEST" in ids("Please buy gift cards and send the codes")


def test_multiple_indicators_and_severity_order():
    fs = re_.analyze("URGENT: verify your password at http://paypa1.com within 24 hours or account suspended")
    assert len(fs) >= 3
    assert fs[0].severity == "high"
    assert re_.max_severity(fs) == "high"
    assert all(f.evidence and f.reason for f in fs)


def test_safe_email_has_no_findings():
    assert re_.analyze("Hi Sam, lunch on Friday? The agenda for Tuesday's meeting is attached as agenda.pdf. Thanks!") == []


def test_urls_are_never_fetched(monkeypatch):
    import socket
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)
    re_.analyze("http://evil.example.xyz/login http://bit.ly/x")


def test_rules_independent_of_ml():
    import inspect
    assert "ml_service" not in inspect.getsource(re_)
