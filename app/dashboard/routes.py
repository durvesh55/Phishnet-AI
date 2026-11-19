from flask import Blueprint, render_template

from app.models import AuditLog, Scan
from app.services.scan_service import dashboard_stats
from app.utils.security import current_user, login_required

bp = Blueprint("dashboard", __name__)


@bp.route("/privacy")
def privacy():
    return render_template("privacy.html")


@bp.route("/dashboard")
@login_required
def index():
    user = current_user()
    stats = dashboard_stats(user)
    recent = Scan.query.filter_by(user_id=user.id).order_by(Scan.created_at.desc()).limit(8).all()
    activity = AuditLog.query.filter_by(user_id=user.id).order_by(AuditLog.created_at.desc()).limit(8).all()
    return render_template("dashboard.html", stats=stats, recent=recent, activity=activity)
