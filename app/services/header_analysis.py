"""Static email-header analysis (SPF/DKIM/DMARC results, From/Reply-To/Return-Path, display-name spoofing).

Works only on the pasted text: no DNS lookups, no network access. It reports what the *receiving* server
already recorded in the headers; it cannot verify those claims independently. Independent of the ML model.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from email.parser import HeaderParser
from email.utils import parseaddr

from app.services.rule_engine import BRANDS, EMAIL_ADDR_RE, Finding, registrable_domain

FREEMAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "ymail.com", "aol.com", "proton.me",
            "protonmail.com", "gmx.com", "mail.com", "icloud.com", "zoho.com", "yandex.com"}
_AUTH_RE = re.compile(r"(?i)\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy|hardfail)")
_SPF_HDR_RE = re.compile(r"(?i)\s*(pass|fail|softfail|neutral|none|temperror|permerror)")
_HEADER_HINTS = {"subject", "to", "date", "received", "return-path", "authentication-results", "reply-to", "message-id", "received-spf"}
_TRANSPORT = {"received", "return-path", "authentication-results", "received-spf"}


@dataclass
class HeaderInfo:
    display_name: str
    from_addr: str
    reply_to: str
    return_path: str
    auth: dict
    received_hops: int
    has_transport_headers: bool

    @property
    def from_domain(self) -> str:
        return _domain(self.from_addr)

    def to_view(self) -> dict:
        return {"display_name": self.display_name, "from": self.from_addr, "reply_to": self.reply_to,
                "return_path": self.return_path, "auth": self.auth, "received_hops": self.received_hops}


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip("> ") if "@" in addr else ""


def parse_headers(text: str) -> HeaderInfo | None:
    """Return parsed info if *text* starts with a header block that contains a From header, else None."""
    head = re.split(r"\r?\n[ \t]*\r?\n", text.lstrip(), maxsplit=1)[0][:20000]
    first = head.splitlines()[0] if head.splitlines() else ""
    if ":" not in first:
        return None
    try:
        msg = HeaderParser().parsestr(head)
    except Exception:  # noqa: BLE001 - malformed input must never crash scanning
        return None
    keys = {k.lower() for k in msg.keys()}
    if "from" not in keys or not keys & _HEADER_HINTS:
        return None
    name, addr = parseaddr(str(msg.get("From", "")))
    _, reply = parseaddr(str(msg.get("Reply-To", "")))
    _, rpath = parseaddr(str(msg.get("Return-Path", "")))
    auth_raw = " ".join(str(v) for v in (msg.get_all("Authentication-Results") or []))
    auth: dict = {"spf": None, "dkim": None, "dmarc": None}
    for mech, res in _AUTH_RE.findall(auth_raw):
        if auth[mech.lower()] is None:
            auth[mech.lower()] = res.lower()
    if auth["spf"] is None:
        m = _SPF_HDR_RE.match(str(msg.get("Received-SPF", "")))
        auth["spf"] = m.group(1).lower() if m else None
    return HeaderInfo(name.strip(), addr.strip().lower(), reply.strip().lower(), rpath.strip().lower(), auth,
                      len(msg.get_all("Received") or []), bool(keys & _TRANSPORT))


def analyze_headers(info: HeaderInfo | None) -> list[Finding]:
    if info is None:
        return []
    out: list[Finding] = []
    fd = info.from_domain
    fd_reg = registrable_domain(fd) if fd else ""

    for mech, label in (("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")):
        res = info.auth.get(mech)
        if res in {"fail", "hardfail", "permerror"}:
            out.append(Finding(f"{label}_FAIL", f"{label} check failed", "high",
                               f"The receiving server recorded {label} = {res}, so the message may not really come from the claimed sender domain.",
                               [f"{mech}={res}"]))
        elif res in {"softfail", "temperror"}:
            out.append(Finding(f"{label}_SOFTFAIL", f"{label} check did not pass cleanly", "medium",
                               f"The receiving server recorded {label} = {res}.", [f"{mech}={res}"]))
    if info.has_transport_headers and not any(info.auth.values()):
        out.append(Finding("AUTH_RESULTS_MISSING", "No SPF/DKIM/DMARC results in the headers", "low",
                           "The headers contain no authentication results, so the sender could not be checked from this text alone.", []))

    if info.display_name:
        shown = EMAIL_ADDR_RE.search(info.display_name)
        if shown and _domain(shown.group(0)) != fd:
            out.append(Finding("DISPLAY_NAME_ADDRESS", "Display name shows a different email address", "high",
                               "The name shown to the reader contains an address that differs from the real sending address.",
                               [f'"{info.display_name}" <{info.from_addr}>']))
        for brand, legit in BRANDS.items():
            if fd and re.search(rf"(?i)\b{re.escape(brand)}\b", info.display_name) and not any(fd == d or fd.endswith("." + d) for d in legit):
                free = " (a free mailbox provider)" if fd in FREEMAIL else ""
                out.append(Finding("DISPLAY_NAME_SPOOF", f"Sender name claims {brand} but the domain is {fd}", "high",
                                   f"The sender name mentions '{brand}' while the message comes from '{fd}'{free}, which is not an official {brand} domain.",
                                   [f'"{info.display_name}" <{info.from_addr}>']))
                break

    if info.reply_to and fd_reg and registrable_domain(_domain(info.reply_to)) != fd_reg:
        rd = _domain(info.reply_to)
        sev = "high" if rd in FREEMAIL and fd not in FREEMAIL else "medium"
        extra = " (here a free mailbox provider)." if sev == "high" else "."
        out.append(Finding("REPLY_TO_MISMATCH", "Replies are redirected to a different domain", sev,
                           "Replies would go to a domain unrelated to the sender, a common trick to capture answers" + extra,
                           [f"From: {info.from_addr}  Reply-To: {info.reply_to}"]))
    if info.return_path and fd_reg and registrable_domain(_domain(info.return_path)) != fd_reg:
        out.append(Finding("RETURN_PATH_MISMATCH", "Return-Path domain differs from the From domain", "low",
                           "Legitimate bulk senders sometimes do this, but it also appears when a sender address is forged.",
                           [f"From: {info.from_addr}  Return-Path: {info.return_path}"]))
    return out
