# Security

> **Not independently audited.** The controls below are implemented and covered by automated tests where noted; they are not a substitute for a professional review/penetration test.

| Area | Implementation |
|---|---|
| Passwords | scrypt (Werkzeug) salted hashes; min 10 chars, 3 character classes; uniform timing for unknown users |
| Brute force | Flask-Limiter on login/OTP/reset/register (Redis in prod); per-account lockout (5 failures → 15 min); OTP: 5 attempts, 5-min expiry, 30 s resend throttle, HMAC-hashed storage |
| Enumeration | generic login errors; register/forgot/resend respond identically for existing and unknown emails |
| Sessions | signed cookie with HttpOnly, SameSite=Lax, `Secure` + `__Host-` prefix in production, 8 h lifetime; `session_version` bump on logout / password change / reset invalidates stolen cookies |
| CSRF | Flask-WTF on all forms; session-authenticated API writes require `X-CSRFToken`; API-key calls carry no cookies |
| XSS | Jinja autoescape; strict CSP (`script-src 'self'`, no inline script/style); `X-Content-Type-Options`, `X-Frame-Options: DENY`, Referrer-Policy, Permissions-Policy, HSTS in production |
| SQLi | SQLAlchemy ORM / bound parameters only; LIKE wildcards escaped |
| Access control | every query filters `user_id`; object lookups return 404 for other users' ids (tests: web, API, reports, keys) |
| API keys | `secrets.token_urlsafe(32)`; only SHA-256 stored; shown once; scopes, expiry, revoke, rotate; key management is session-only |
| Tokens | verification/reset tokens 256-bit random, hashed at rest, expiring, single use |
| Input limits | 256 KB request cap (413), 50k-char email limit, validated pagination/dates/enums |
| Reports | CSV formula-injection neutralised; PDF text XML-escaped; exports scoped to the caller |
| URLs | parsed as strings only; the app never fetches, resolves or opens submitted URLs; findings are indicators, not verdicts |
| Errors/logging | JSON error bodies without internals; structured JSON logs; no passwords/OTPs/keys logged (dev `console` mail backend prints mail and is refused in production) |
| Secrets | environment variables only; `.env` git-ignored; production refuses weak `SECRET_KEY` |

## Known limitations / to-do for a real launch
* No admin UI and no admin role enforcement beyond the schema (`role` column).
* Email OTP is only as strong as the mailbox; TOTP apps are not implemented.
* Rate limits fall back to per-process memory without `REDIS_URL`.
* No external URL reputation, no malware scanning of attachments (only filename heuristics in text).
* Run `pip-audit`/Dependabot, configure Nginx TLS, restrict MySQL to the app host, rotate secrets, and obtain an independent audit before handling real users' mail.
