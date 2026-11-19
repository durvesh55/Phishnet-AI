from app.extensions import db
from app.models import Feedback, Scan, User


def save_feedback(scan: Scan, user: User, is_correct, comment) -> Feedback:
    """Create or update the user's single feedback row for a scan they own."""
    if not isinstance(is_correct, bool):
        raise ValueError("is_correct must be a boolean.")
    if comment is not None and not isinstance(comment, str):
        raise ValueError("comment must be a string.")
    comment = (comment or "").strip()
    if len(comment) > 1000:
        raise ValueError("comment must be at most 1000 characters.")
    fb = Feedback.query.filter_by(scan_id=scan.id, user_id=user.id).first()
    if fb is None:
        fb = Feedback(scan_id=scan.id, user_id=user.id, is_correct=is_correct, comment=comment or None)
        db.session.add(fb)
    else:
        fb.is_correct, fb.comment = is_correct, comment or None
    db.session.commit()
    return fb
