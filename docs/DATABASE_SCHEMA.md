# Database schema (MySQL 8, InnoDB, utf8mb4)

Defined in `app/models/__init__.py`; created by Alembic migration `migrations/versions/*_initial_schema.py`. Times are UTC.

| Table | Purpose | Notable constraints |
|---|---|---|
| `users` | account, security state, privacy prefs | `email` unique; `role` CHECK in (user, admin); `session_version` (cookie invalidation) |
| `scans` | one row per analysis | FK `user_id` → users **ON DELETE CASCADE**; CHECK classification ∈ SAFE/SUSPICIOUS/PHISHING; CHECK 0 ≤ risk ≤ 100; indexes `(user_id, created_at)`, `(user_id, classification)`; `rule_findings` JSON; `email_text` LONGTEXT NULL |
| `feedback` | user correctness feedback | FKs cascade; UNIQUE `(scan_id, user_id)` |
| `api_keys` | hashed API keys | `key_hash` (SHA-256) unique; scopes, expiry, revoke, last-used, usage count |
| `otp_records` | email OTPs | HMAC-hashed code, expiry, attempts, consumed_at |
| `recovery_codes` | 2FA recovery | HMAC-hashed, single use |
| `email_verification_tokens`, `password_reset_tokens` | single-use tokens | SHA-256 hash unique, expiry, used_at |
| `audit_logs` | security/audit trail | `user_id` ON DELETE SET NULL (keeps anonymised history) |
| `model_versions` | registry of models seen | `version` unique, artifact sha256, metrics JSON |

Raw passwords, OTPs, tokens and API keys are **never stored** – only hashes.

## Commands
```bash
flask --app run db upgrade                       # apply migrations
flask --app run db migrate -m "describe change"  # generate after editing models, then REVIEW the file
flask --app run db downgrade
```
## Backup & recovery
```bash
mysqldump --single-transaction --routines -u phishnet -p phishnet > backup_$(date +%F).sql
mysql -u phishnet -p phishnet < backup_2026-01-01.sql       # restore into an empty database
```
Schedule dumps (cron), encrypt them, store off-host, and test a restore regularly. Scans are personal data: apply your retention policy to backups too. Docker: `docker compose exec db mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" phishnet > backup.sql`.
