"""OpenAPI JSON + Swagger UI."""
from flask import Blueprint, jsonify, render_template

from app.api.openapi import SPEC
from app.extensions import csrf

bp = Blueprint("api_docs", __name__)
csrf.exempt(bp)


@bp.get("/api/v1/openapi.json")
def openapi():
    return jsonify(SPEC)


@bp.get("/api/docs")
def docs():
    return render_template("api_docs.html")
