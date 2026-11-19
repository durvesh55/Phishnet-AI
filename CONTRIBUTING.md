# Contributing

1. Fork and create a branch: `git checkout -b feature/my-change`
2. Set up: `pip install -r requirements-dev.txt` and see the Quick start in the README.
3. Run `ruff check app ml tests scripts run.py` and `pytest -q` (tests need the MySQL test DB; they wipe it).
4. Open a pull request describing what changed and why.

Never commit `.env`, real emails, or personal data. Report security issues privately (see `docs/SECURITY.md`).
