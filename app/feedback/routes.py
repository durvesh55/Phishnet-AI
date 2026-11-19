from flask import Blueprint, flash, redirect, request, url_for

from app.models import Scan
from app.services.audit import audit
from app.services.feedback_service import save_feedback
from app.utils.security import current_user, login_required, owned_or_404

bp = Blueprint("feedback", __name__, url_prefix="/feedback")


@bp.route("/<int:scan_id>", methods=["POST"])
@login_required
def submit(scan_id: int):
    user = current_user()
    scan = owned_or_404(Scan, scan_id, user)
    verdict = request.form.get("verdict")
    if verdict not in ("correct", "incorrect"):
        flash("Invalid feedback value.", "danger")
        return redirect(url_for("history.detail", scan_id=scan.id))
    try:
        save_feedback(scan, user, verdict == "correct", request.form.get("comment"))
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("history.detail", scan_id=scan.id))
    audit("feedback.saved", user.id, f"scan_id={scan.id}")
    flash("Thanks! Feedback saved. It is stored separately and is never used to retrain the model automatically.", "success")
    return redirect(url_for("history.detail", scan_id=scan.id))
