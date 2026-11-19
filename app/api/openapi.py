"""OpenAPI 3 specification for /api/v1 (served at /api/v1/openapi.json, UI at /api/docs)."""

_err = {"description": "Error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
_sec = [{"ApiKeyAuth": []}]


def _op(summary, scope=None, body=None, params=None, ok="200", extra=None):
    op = {"summary": summary, "security": _sec, "responses": {ok: {"description": "Success"}, "401": _err, "429": _err}}
    if scope:
        op["description"] = f"Required API-key scope: `{scope}`."
    if body:
        op["requestBody"] = {"required": True, "content": {"application/json": {"schema": body}}}
    if params:
        op["parameters"] = params
    if extra:
        op["responses"].update(extra)
    return op


def _q(name, desc, typ="string", enum=None):
    s = {"type": typ}
    if enum:
        s["enum"] = enum
    return {"name": name, "in": "query", "description": desc, "schema": s}


_list_params = [
    _q("page", "Page number (>=1)", "integer"), _q("per_page", "Items per page (1-100)", "integer"), _q("q", "Search preview text"),
    _q("classification", "Filter by ML classification", enum=["SAFE", "SUSPICIOUS", "PHISHING"]),
    _q("sort", "Sort order", enum=["date_desc", "date_asc", "risk_desc", "risk_asc"]),
    _q("date_from", "YYYY-MM-DD (inclusive)"), _q("date_to", "YYYY-MM-DD (inclusive)"),
]
_id = [{"name": "scan_id", "in": "path", "required": True, "schema": {"type": "integer"}}]
_kid = [{"name": "key_id", "in": "path", "required": True, "schema": {"type": "integer"}}]

SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "PhishNet AI API", "version": "1.0.0",
        "description": ("Analyse emails for phishing. Responses keep **machine_learning** (model-derived risk indicator) and "
                        "**rule_analysis** (independent heuristics) strictly separate. Submitted URLs are never visited."),
    },
    "servers": [{"url": "/"}],
    "components": {
        "securitySchemes": {"ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}},
        "schemas": {
            "Error": {"type": "object", "properties": {"error": {"type": "object", "properties": {"code": {"type": "string"}, "message": {"type": "string"}}}}},
            "ScanRequest": {"type": "object", "required": ["email_text"], "properties": {"email_text": {"type": "string", "maxLength": 50000}}},
            "FeedbackRequest": {"type": "object", "required": ["is_correct"], "properties": {"is_correct": {"type": "boolean"}, "comment": {"type": "string", "maxLength": 1000}}},
            "KeyRequest": {"type": "object", "required": ["name"], "properties": {
                "name": {"type": "string"}, "expires_in_days": {"type": "integer", "minimum": 1, "maximum": 730},
                "scopes": {"type": "array", "items": {"type": "string", "enum": ["scan:write", "history:read", "feedback:write", "reports:read", "stats:read"]}}}},
        },
    },
    "paths": {
        "/api/v1/auth/me": {"get": _op("Identify the caller")},
        "/api/v1/scans": {
            "post": _op("Analyse an email", "scan:write", {"$ref": "#/components/schemas/ScanRequest"}, ok="201", extra={"400": _err, "503": _err}),
            "get": _op("List your scans (paginated)", "history:read", params=_list_params),
        },
        "/api/v1/scans/{scan_id}": {
            "get": _op("Get one scan", "history:read", params=_id + [_q("include_text", "Set to 1 to include stored text")], extra={"404": _err}),
            "delete": _op("Delete a scan", "history:read", params=_id, ok="204", extra={"404": _err}),
        },
        "/api/v1/scans/{scan_id}/feedback": {"post": _op("Mark a result correct/incorrect", "feedback:write", {"$ref": "#/components/schemas/FeedbackRequest"}, _id, "201", {"404": _err})},
        "/api/v1/stats": {"get": _op("Dashboard statistics", "stats:read")},
        "/api/v1/reports/scans.csv": {"get": _op("CSV report", "reports:read", params=_list_params[2:])},
        "/api/v1/reports/scans/{scan_id}.pdf": {"get": _op("PDF report for one scan", "reports:read", params=_id, extra={"404": _err})},
        "/api/v1/api-keys": {
            "get": _op("List API keys (browser session only)"),
            "post": _op("Create an API key (browser session only; key shown once)", body={"$ref": "#/components/schemas/KeyRequest"}, ok="201", extra={"400": _err}),
        },
        "/api/v1/api-keys/{key_id}": {"delete": _op("Revoke a key (session only)", params=_kid, ok="204", extra={"404": _err})},
        "/api/v1/api-keys/{key_id}/rotate": {"post": _op("Rotate a key (session only)", params=_kid, ok="201", extra={"404": _err})},
    },
}
