from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.extensions import db
from app.models import Scan
from app.services.audit import audit
from app.services.query_service import clamp_page, scan_query
from app.utils.security import current_user, login_required, owned_or_404

bp = Blueprint("history", __name__, url_prefix="/history")


@bp.route("/")
@login_required
def index():
    user = current_user()
    a = request.args
    try:
        page, per_page = clamp_page(a.get("page"), a.get("per_page"), 50)
        q = scan_query(user, a.get("q"), a.get("classification"), a.get("sort", "date_desc"), a.get("date_from"), a.get("date_to"))
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("history.index"))
    pagination = q.paginate(page=page, per_page=per_page, error_out=False)
    return render_template("history/index.html", pagination=pagination, args=a)


@bp.route("/<int:scan_id>")
@login_required
def detail(scan_id: int):
    scan = owned_or_404(Scan, scan_id, current_user())
    return render_template("history/detail.html", scan=scan)


@bp.route("/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete(scan_id: int):
    user = current_user()
    scan = owned_or_404(Scan, scan_id, user)
    db.session.delete(scan)
    db.session.commit()
    audit("scan.deleted", user.id, f"scan_id={scan_id}")
    flash("Scan deleted.", "success")
    return redirect(url_for("history.index"))
