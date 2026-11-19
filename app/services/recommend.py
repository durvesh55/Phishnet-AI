"""Turns the (independent) ML and rule results into a plain-language recommended action.

This is presentation guidance only: it reads both signals but never changes either of them.
"""
from __future__ import annotations

SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
ML = {"SAFE": 0, "SUSPICIOUS": 2, "PHISHING": 3}
_SEV_NAME = {1: "low", 2: "medium", 3: "high"}


def recommend(classification: str | None, rule_severity: str = "none", link_severity: str = "none") -> dict:
    ml_level = ML.get(classification or "", 0)
    rule_level = max(SEV.get(rule_severity, 0), SEV.get(link_severity, 0))
    level = max(ml_level, rule_level)
    reasons = []
    if ml_level >= 2:
        reasons.append(f"ML model classified it {classification}")
    if rule_level >= 1:
        reasons.append(f"Rule engine found {_SEV_NAME[rule_level]}-severity indicators")
    if level >= 3:
        return {"key": "block", "level": "high", "title": "Recommended action: Block and report",
                "text": "High-risk indicators found. Do not click links, open attachments or reply.", "reasons": reasons}
    if level == 2:
        return {"key": "review", "level": "medium", "title": "Recommended action: Review carefully",
                "text": "Suspicious indicators found. Verify the sender through an official channel before acting.", "reasons": reasons}
    if level == 1:
        return {"key": "caution", "level": "low", "title": "Recommended action: Proceed with caution",
                "text": "Minor indicators found. Weak signals only.", "reasons": reasons}
    return {"key": "ok", "level": "none", "title": "Recommended action: Looks OK, stay alert",
            "text": "No indicators found by our checks. This is not proof that it is safe.", "reasons": reasons}
