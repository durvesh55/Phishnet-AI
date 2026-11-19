from datetime import datetime

from flask import Blueprint, Response, flash, redirect, request, url_for

from app.models import Scan
from app.services import report_service
from app.services.audit import audit
from app.services.query_service import scan_query
from app.utils.security import current_user, login_required, owned_or_404

bp = Blueprint("reports", __name__, url_prefix="/reports")
MAX_ROWS = 5000


def _download(data: bytes, mime: str, name: str) -> Response:
    return Response(data, mimetype=mime, headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})


@bp.route("/history.csv")
@login_required
def history_csv():
    user, a = current_user(), request.args
    try:
        scans = scan_query(user, a.get("q"), a.get("classification"), a.get("sort", "date_desc"), a.get("date_from"), a.get("date_to")).limit(MAX_ROWS).all()
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("history.index"))
    audit("report.csv", user.id, f"rows={len(scans)}")
    return _download(report_service.scans_to_csv(scans), "text/csv", f"phishnet_{datetime.utcnow():%Y%m%d}.csv")


@bp.route("/history.pdf")
@login_required
def history_pdf():
    user, a = current_user(), request.args
    try:
        scans = scan_query(user, a.get("q"), a.get("classification"), a.get("sort", "date_desc"), a.get("date_from"), a.get("date_to")).limit(500).all()
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("history.index"))
    audit("report.pdf", user.id, f"rows={len(scans)}")
    return _download(report_service.scans_to_pdf(user, scans, detail=False), "application/pdf", f"phishnet_{datetime.utcnow():%Y%m%d}.pdf")


@bp.route("/scan/<int:scan_id>.pdf")
@login_required
def scan_pdf(scan_id: int):
    user = current_user()
    scan = owned_or_404(Scan, scan_id, user)
    audit("report.pdf", user.id, f"scan_id={scan_id}")
    return _download(report_service.scans_to_pdf(user, [scan]), "application/pdf", f"phishnet_scan_{scan.id}.pdf")
