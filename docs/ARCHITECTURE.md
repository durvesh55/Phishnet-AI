# Architecture

```
Browser / API client
      │  HTTPS (Nginx in production, ProxyFix trusts 1 hop)
      ▼
Gunicorn ── Flask app (app/__init__.py: create_app)
      │   blueprints: dashboard, auth, scanner, history, feedback, reports, account, api_v1, api_docs
      │
      ├── services/scan_service  ──► ml_service   (loaded once, versioned artifact in ml/models/<version>/)
      │                         └─► rule_engine  (pure text analysis; no network)
      ├── services/{audit, mail, report, query, feedback}_service
      ├── utils/security  (hashing, tokens, decorators, API-key auth, IDOR helper)
      ▼
SQLAlchemy ──► MySQL 8 (users, scans, feedback, api_keys, otp_records, recovery_codes,
                        email_verification_tokens, password_reset_tokens, audit_logs, model_versions)
Flask-Limiter ──► Redis (or memory in dev/test)
```

## Key rules
* **ML and rules are independent.** `scan_service.run_scan` calls both with only the text; neither sees the other's output; both are stored in separate columns (`risk_score/classification/ml_probability` vs `rule_findings/rule_max_severity`).
* **Every query on private data is scoped by `user_id`**; row lookups go through `owned_or_404` / `_own_scan`, so another user's id gives 404.
* **Models are loaded at startup** (never per request) and verified by SHA-256 before `joblib.load`. A failing reload keeps the previous model.
* **Training is an offline CLI** (`python -m ml.training.train`), never triggered by scans or feedback.
* Configuration is environment-driven (`app/config.py`); production refuses to start with a weak `SECRET_KEY` or console mail.

## Layout
`app/` application · `ml/` dataset, training, saved models, evaluation reports · `migrations/` Alembic · `tests/` pytest · `scripts/` helper SQL/scripts · `legacy/` the original single-file app (reference only).
