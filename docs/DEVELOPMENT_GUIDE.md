# Development guide

## Setup
See README. Useful env: `FLASK_ENV=development|testing|production`, `MAIL_BACKEND=console` (prints mails/OTPs in the server log), `RATELIMIT` values in `.env.example`.

## Daily commands
```bash
python run.py                            # dev server (127.0.0.1:5000)
pytest -q                                # ~100 s (scrypt hashing makes login-heavy tests slow)
pytest tests/test_rule_engine.py tests/test_ml.py -q   # fast, no database
ruff check app ml tests scripts run.py   # lint
python -m compileall -q app ml scripts run.py
flask --app run db migrate -m "msg"      # after changing models; review, then `db upgrade`
```
## Conventions
* New feature = new blueprint folder `app/<feature>/routes.py`, logic in `app/services/`, register in `_register_blueprints`.
* Every private query filters by the current user; use `owned_or_404` for id lookups.
* Never log secrets; use `audit(event, user_id, detail)` for security events.
* Templates must not use inline `<script>`/`style=` (CSP); put JS in `static/js/app.js`.
* Adding a rule: add a block in `rule_engine.analyze` returning a `Finding` with reason + evidence, then a test in `tests/test_rule_engine.py`. Rules must stay independent of ML.
* Tests use the MySQL database `TEST_MYSQL_DATABASE` and recreate its tables for each test.
