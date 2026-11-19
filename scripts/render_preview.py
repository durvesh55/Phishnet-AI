"""Render logged-in pages to static HTML files for screenshotting (uses the TEST database)."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import User  # noqa: E402
from app.utils.security import hash_password  # noqa: E402

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
static = (ROOT / "app" / "static").as_uri()
app = create_app("testing")
PHISH = "From: PayPal Security <service@paypa1-secure.com>\nSubject: URGENT\n\nURGENT: Your PayPal account has been suspended. Verify your password and credit card number immediately at http://paypa1-secure.com/verify or it will be deleted within 24 hours."
SAFE = "Hi team, reminder that the weekly sync is on Thursday at 3 PM in Conference Room B. Please bring your updates."
with app.app_context():
    db.drop_all()
    db.create_all()
    u = User(name="Alex Morgan", email="alex@example.com", password_hash=hash_password("Str0ng!Passw0rd"), email_verified=True, otp_enabled=False)
    db.session.add(u)
    db.session.commit()
    c = app.test_client()
    c.post("/auth/login", data={"email": "alex@example.com", "password": "Str0ng!Passw0rd"})
    ids = [int(c.post("/scan/", data={"email_text": t}).headers["Location"].rsplit("/", 1)[1]) for t in (PHISH, SAFE, PHISH + " again", SAFE + " v2")]
    pages = {"dashboard": c.get("/dashboard"), "detail": c.get(f"/history/{ids[0]}"), "history": c.get("/history/"), "scan": c.get("/scan/"), "keys": c.get("/account/api-keys")}
    anon = app.test_client()
    pages["public_result"] = anon.post("/check", data={"content": PHISH})
    for name, r in pages.items():
        (out / f"{name}.html").write_text(r.get_data(as_text=True).replace('href="/static/', f'href="{static}/').replace('src="/static/', f'src="{static}/'), encoding="utf-8")
    db.session.remove()  # release the open transaction, otherwise DROP TABLE waits on our own metadata lock
    db.drop_all()
print("ok")
