from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from app.extensions import limiter
from app.services import scan_service
from app.services.audit import audit
from app.services.ml_service import ModelUnavailable
from app.utils.security import current_user, login_required

bp = Blueprint("scanner", __name__, url_prefix="/scan")


@bp.route("/", methods=["GET", "POST"])
@login_required
@limiter.limit("30 per minute", methods=["POST"])
def new_scan():
    if request.method == "POST":
        user = current_user()
        try:
            scan = scan_service.run_scan(user, request.form.get("email_text", ""), source="web")
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("scanner/new.html", max_chars=current_app.config["MAX_EMAIL_CHARS"]), 400
        except ModelUnavailable:
            flash("The detection model is not available right now. Please contact the administrator.", "danger")
            return render_template("scanner/new.html", max_chars=current_app.config["MAX_EMAIL_CHARS"]), 503
        audit("scan.created", user.id, f"scan_id={scan.id}")
        return redirect(url_for("history.detail", scan_id=scan.id))
    return render_template("scanner/new.html", max_chars=current_app.config["MAX_EMAIL_CHARS"])
