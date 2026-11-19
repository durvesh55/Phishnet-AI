# REST API v1

Interactive: `/api/docs` · OpenAPI JSON: `/api/v1/openapi.json`.

**Auth:** header `X-API-Key: pnk_...` (create under *API keys*; shown once) or a browser session (writes then need `X-CSRFToken`). API-key management endpoints are **session-only**.
**Scopes:** `scan:write`, `history:read`, `feedback:write`, `reports:read`, `stats:read`.
**Rate limit:** `API_RATE_LIMIT` (default 60/min) per key (per IP if unauthenticated) → `429`.
**Errors:** `{"error": {"code": "...", "message": "..."}}` with 400/401/403/404/413/429/500/503. No stack traces or SQL details are returned.
**Limits:** body ≤ 256 KB, `email_text` ≤ `MAX_EMAIL_CHARS` (50,000).

| Method & path | Scope | Notes |
|---|---|---|
| GET `/api/v1/auth/me` | – | who am I |
| POST `/api/v1/scans` | scan:write | body `{"email_text": "..."}` → 201 |
| GET `/api/v1/scans` | history:read | `page, per_page(≤100), q, classification, sort, date_from, date_to` |
| GET `/api/v1/scans/{id}` | history:read | `?include_text=1` |
| DELETE `/api/v1/scans/{id}` | history:read | 204 |
| POST `/api/v1/scans/{id}/feedback` | feedback:write | `{"is_correct": true, "comment": "..."}` |
| GET `/api/v1/stats` | stats:read | totals, distribution, 7-day trend |
| GET `/api/v1/reports/scans.csv` | reports:read | same filters as list |
| GET `/api/v1/reports/scans/{id}.pdf` | reports:read | |
| GET/POST `/api/v1/api-keys`, DELETE `/{id}`, POST `/{id}/rotate` | session | key value returned once |

## Example response (`POST /api/v1/scans`)
```json
{"data": {"id": 12, "created_at": "...Z",
  "machine_learning": {"classification": "PHISHING", "risk_score": 89.1, "model_probability": 0.8905, "model_version": "v2026...", "note": "..."},
  "rule_analysis": {"max_severity": "high", "findings": [{"rule_id": "LOOKALIKE_DOMAIN", "title": "...", "severity": "high", "reason": "...", "evidence": ["paypa1-secure.com — ..."]}]}}}
```
`machine_learning` and `rule_analysis` are independent by design.
