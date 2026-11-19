# Project learning guide

Read in this order: `run.py` → `app/__init__.py` → `app/config.py` → `app/models/__init__.py` → `app/utils/security.py` → `app/auth/` → `app/services/scan_service.py` → `rule_engine.py` / `ml_service.py` → `app/api/v1.py` → templates.

## 1. How Flask works
Flask maps a URL + HTTP method to a Python function (a *route*). A **Blueprint** groups related routes (e.g. `auth`). The **application factory** `create_app()` builds the app, loads config, attaches extensions (DB, CSRF, rate limiter), registers blueprints, error handlers and security headers. `run.py` calls it; Gunicorn imports `run:app` in production.

## 2. Life of a request
Browser → (Nginx) → Gunicorn → Flask → `before_request` hooks → the matching route (decorators run first: rate limit → `login_required`) → service code → template/JSON → `after_request` adds security headers → response. Errors go to handlers in `_register_errors` which return HTML pages or JSON depending on the path (`/api/`).

## 3. SQLAlchemy & MySQL
Each model class in `app/models` is a table; columns are attributes. `db.session` collects changes (`add`, `delete`) and `commit()` sends them to MySQL in one transaction; `rollback()` undoes them. `User.query.filter_by(email=...)` becomes a parameterised SQL `SELECT` (so SQL injection is prevented). The connection URL is built from `MYSQL_*` variables in `config.py`; PyMySQL is the driver; the engine keeps a pool of connections. **Migrations** (`migrations/`) are versioned scripts that change the real schema (`flask db upgrade`).

## 4. Authentication
*Register* → password hashed with scrypt → verification token (random, only its hash is stored) emailed → user clicks link → `email_verified=True`. *Login* → check password (lockout after repeated failures) → if 2FA on, create a 6-digit OTP (HMAC-hashed in DB), email it, remember a short-lived "pending" state in the session → `/auth/otp` verifies → `start_session` stores `uid` + `session_version` in the signed cookie. `current_user()` reloads the user from the DB on each request and rejects the cookie if `session_version` changed (logout / password change). Password reset works like verification with single-use tokens. API calls use `X-API-Key`: the key is hashed (SHA-256) and looked up; scopes and expiry are checked.

## 5. How the ML model predicts
Training (offline): text → `TfidfVectorizer` (words/bigrams weighted by how distinctive they are) → `LogisticRegression` learns weights per term. Saved with joblib in `ml/models/<version>/`. At app start `MLService.load()` verifies the checksum and loads it. For a scan: `predict_proba([text])[0][1]` = P(phishing); ×100 = risk score; thresholds 30/60 give SAFE/SUSPICIOUS/PHISHING.

## 6. How the rule engine works
`rule_engine.analyze(text)` runs regex rules (urgency, credential requests, payment, attachments) and string-parses URLs/e-mail domains (shorteners, IP hosts, odd TLDs, punycode, `@` tricks). For lookalikes it normalises character swaps (`0→o`, `1→l`, `rn→m`) and compares with a brand list. It returns `Finding(rule_id, title, severity, reason, evidence)`. It never fetches URLs and never talks to the ML code.

## 7. Saving a scan
`scan_service.run_scan`: validate → `ml.predict` → `rule_engine.analyze` → create a `Scan` row with both results in separate columns (+ SHA-256 of the text, model version) → commit. History, dashboard, reports and the API all read from this table, always filtered by `user_id`.

## 8. API structure
`app/api/v1.py` – one blueprint under `/api/v1`. `@api_auth(scope)` authenticates (key or session), `@rate_limited` applies limits, handlers return `{"data": ...}` or `{"error": {...}}`. The OpenAPI spec lives in `app/api/openapi.py`, rendered by Swagger UI at `/api/docs`.

## 9. Docker
A **Dockerfile** is a recipe for an image (Python + dependencies + your code). **docker-compose.yml** starts three containers: `db` (MySQL with a persistent volume), `redis`, and `web` (Gunicorn). They talk over a private network by service name (`MYSQL_HOST=db`). Health checks make `web` wait until MySQL/Redis are ready.

## 10. Deployment
Put the containers (or a venv + systemd) on a server, put Nginx in front for HTTPS, set production env vars, run migrations, back up MySQL, monitor `/ready`. Details: `DEPLOYMENT.md`.
