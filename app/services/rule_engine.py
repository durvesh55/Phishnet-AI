"""Independent rule-based phishing indicator engine.

This module never imports or influences the ML model. It performs *static text
analysis only*: submitted URLs are parsed as strings and are NEVER fetched,
resolved or opened. A finding is an indicator, not proof of maliciousness.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}

# Legitimate registrable domains for commonly impersonated brands.
BRANDS: dict[str, tuple[str, ...]] = {
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"),
    "paypal": ("paypal.com", "paypal.me"),
    "google": ("google.com", "gmail.com", "googlemail.com", "youtube.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazonaws.com", "amazon.in"),
    "apple": ("apple.com", "icloud.com"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com",),
    "linkedin": ("linkedin.com",),
    "dropbox": ("dropbox.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com",),
    "hsbc": ("hsbc.com",),
    "sbi": ("sbi.co.in", "onlinesbi.com"),
}

SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "tiny.cc"}
RISKY_TLDS = {"ru", "xyz", "tk", "pw", "cc", "top", "click", "zip", "gq", "ml", "cf", "ga", "icu", "work", "support"}
RISKY_ATTACHMENT_EXT = (
    "exe", "scr", "bat", "cmd", "js", "vbs", "jar", "msi", "lnk", "iso", "img", "docm", "xlsm", "pptm", "html", "htm", "hta", "ps1", "dll",
)
# Common homoglyph / character-substitution map used to "normalise" a label.
_SUBST = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "@": "a"})
_MULTI_SUBST = (("rn", "m"), ("vv", "w"), ("cl", "d"))

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"')\]]+")
EMAIL_ADDR_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})\b")
BARE_DOMAIN_RE = re.compile(r"(?i)\b((?:[a-z0-9-]+\.)+(?:[a-z]{2,}))\b")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str  # low | medium | high
    reason: str
    evidence: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _snippet(text: str, m: re.Match, width: int = 40) -> str:
    """Context around a match, trimmed to whole words."""
    s, e = max(0, m.start() - width), min(len(text), m.end() + width)
    if s > 0:
        sp = text.find(" ", s, m.start())
        s = sp + 1 if sp != -1 else s
    if e < len(text):
        sp = text.rfind(" ", m.end(), e)
        e = sp if sp != -1 else e
    out = re.sub(r"\s+", " ", text[s:e]).strip()
    return (("…" if s > 0 else "") + out + ("…" if e < len(text) else ""))[:170]


def _keyword_rule(text: str, rule_id: str, title: str, severity: str, reason: str, patterns: list[str]) -> Finding | None:
    ev: list[str] = []
    for p in patterns:
        for m in re.finditer(p, text, re.I):
            ev.append(_snippet(text, m))
            if len(ev) >= 3:
                break
        if len(ev) >= 3:
            break
    return Finding(rule_id, title, severity, reason, ev) if ev else None


def registrable_domain(host: str) -> str:
    """Approximate registrable domain (last two labels; three for common 2-level ccTLDs)."""
    labels = [p for p in host.lower().strip(".").split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    if labels[-2] in {"co", "com", "org", "net", "gov", "ac"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _normalise_label(label: str) -> str:
    out = label.lower()
    for a, b in _MULTI_SUBST:
        out = out.replace(a, b)
    return out.translate(_SUBST)


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_brand(domain: str) -> tuple[str, str] | None:
    """Return (brand, reason) if *domain* imitates a known brand without being it."""
    domain = domain.lower().strip(".")
    reg = registrable_domain(domain)
    # Genuine domain of any known brand -> not a lookalike
    if any(reg == d or domain.endswith("." + d) for legit in BRANDS.values() for d in legit):
        return None
    labels = domain.split(".")
    sld = labels[-2] if len(labels) >= 2 else labels[0]
    for brand in BRANDS:
        norm = _normalise_label(sld)
        if sld != brand and norm == brand:
            return brand, f"'{sld}' uses character substitutions to imitate '{brand}'"
        if sld != brand and len(brand) >= 5 and _levenshtein(sld, brand, 1) <= 1:
            return brand, f"'{sld}' is one character away from '{brand}'"
        # brand embedded in a different registrable domain (paypal-secure-login.com, paypal.verify.xyz)
        candidates = [_normalise_label(x) for x in re.split(r"[-.]", ".".join(labels[:-1]))]
        if brand in candidates or any(brand in c and len(c) <= len(brand) + 12 for c in candidates if c != brand and brand in c):
            return brand, f"'{reg}' contains the brand name '{brand}' but is not an official domain"
    return None


def extract_domains(text: str) -> tuple[list[str], list[str]]:
    """Return (url_hosts, email_domains); purely string parsing."""
    hosts: list[str] = []
    for m in URL_RE.finditer(text):
        raw = m.group(0).rstrip(".,;:!?")
        if raw.lower().startswith("www."):
            raw = "http://" + raw
        try:
            host = urlparse(raw).hostname
        except ValueError:
            continue
        if host:
            hosts.append(host.lower())
    email_domains = [m.group(1).lower() for m in EMAIL_ADDR_RE.finditer(text)]
    return list(dict.fromkeys(hosts)), list(dict.fromkeys(email_domains))


def analyze(text: str) -> list[Finding]:
    """Run every rule against *text* and return findings (possibly empty)."""
    findings: list[Finding] = []

    def add(f: Finding | None) -> None:
        if f:
            findings.append(f)

    add(_keyword_rule(
        text, "URGENCY", "Urgency or threatening language", "medium",
        "Phishing messages pressure recipients to act before they can think or verify.",
        [r"\b(?:urgent(?:ly)?|immediately|act now|final notice|last warning|within \d+\s*(?:hours?|hrs?|minutes?|days?))\b",
         r"\b(?:account|access)\b[^.\n]{0,40}\b(?:suspended|locked|closed|terminated|disabled|deleted|banned)\b",
         r"\b(?:will be|has been)\s+(?:suspended|deleted|terminated|closed|locked)\b", r"\blimited time\b"],
    ))
    add(_keyword_rule(
        text, "SENSITIVE_INFO", "Request for credentials or sensitive information", "high",
        "Legitimate organisations do not ask for passwords, PINs or full card/ID numbers by email.",
        [r"\b(?:enter|send|provide|reply with|confirm|submit|update)\b[^.\n]{0,50}\b(?:password|passcode|pin|ssn|social security|credit card|card number|cvv|bank details|account number|security questions?|otp|one[- ]time (?:code|password))\b",
         r"\b(?:your|the)\s+(?:password|ssn|social security number|credit card number|cvv|pin)\b[^.\n]{0,30}\b(?:required|needed|expired|expires)\b"],
    ))
    add(_keyword_rule(
        text, "ACCOUNT_VERIFICATION", "Account verification / login prompt", "medium",
        "Prompts to 'verify', 'confirm' or 'restore' an account are a common credential-harvesting lure.",
        [r"\b(?:verify|confirm|validate|restore|reactivate|unlock|re-?enter)\b[^.\n]{0,30}\b(?:account|identity|credentials|login|access|information|details)\b",
         r"\b(?:click|tap|follow)\s+(?:here|the link|below)\b", r"\bsign[- ]?in\s+(?:now|here|to (?:verify|confirm|restore))\b"],
    ))
    add(_keyword_rule(
        text, "PAYMENT_REQUEST", "Unusual payment or money-transfer request", "high",
        "Unexpected requests for fees, gift cards, wire/crypto transfers or prize claims are typical fraud patterns.",
        [r"\b(?:gift cards?|wire transfer|western union|bitcoin|crypto(?:currency)?|bank transfer|processing fee|customs fee|pay(?:ment)? (?:of|a)?\s*\$?\d)",
         r"\b(?:you (?:have )?won|lottery|inheritance|prize|claim your (?:reward|refund|prize)|tax refund)\b", r"\b(?:invoice|payment)\b[^.\n]{0,30}\b(?:overdue|outstanding|pending)\b"],
    ))
    add(_keyword_rule(
        text, "GENERIC_GREETING", "Generic greeting", "low",
        "Mass phishing often uses non-personalised greetings.",
        [r"\bdear\s+(?:customer|user|member|valued\s+\w+|account holder|client|sir/madam|friend)\b"],
    ))

    # ---- Attachments (text-based references only) ----
    ext_pat = "|".join(RISKY_ATTACHMENT_EXT)
    ev = [m.group(0) for m in re.finditer(rf"(?i)\b[\w\-. ]{{1,60}}\.(?:{ext_pat})\b(?!\w)", text) if "." in m.group(0)]
    ev += [m.group(0) for m in re.finditer(r"(?i)\b[\w\-]+\.(?:pdf|docx?|xlsx?|zip|rar|7z)\.(?:exe|scr|js|bat|lnk)\b", text)]
    ev = [e for e in dict.fromkeys(x.strip() for x in ev) if not re.match(r"(?i)^(?:www\.|https?:)", e)]
    # exclude things that are part of URL hosts like 'example.js.com' roughly
    if ev:
        findings.append(Finding("RISKY_ATTACHMENT", "Reference to a potentially dangerous file type", "high",
                                "Executable, script, macro-enabled or HTML attachments are frequently used to deliver malware.", ev[:3]))

    # ---- URLs and domains ----
    hosts, email_domains = extract_domains(text)

    short = [h for h in hosts if h in SHORTENERS]
    if short:
        findings.append(Finding("URL_SHORTENER", "Shortened URL hides the destination", "medium",
                                "URL shorteners obscure where a link really leads; the link was not visited.", short[:3]))
    ip_hosts = [h for h in hosts if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", h)]
    if ip_hosts:
        findings.append(Finding("IP_URL", "URL uses a raw IP address", "high",
                                "Legitimate services rarely ask users to log in at a bare IP address.", ip_hosts[:3]))
    risky = [h for h in hosts if h not in SHORTENERS and h.rsplit(".", 1)[-1] in RISKY_TLDS]
    if risky:
        findings.append(Finding("RISKY_TLD", "URL on a top-level domain often abused for phishing", "medium",
                                "These TLDs are over-represented in abuse reports; this is a weak signal on its own.", risky[:3]))
    puny = [h for h in hosts + email_domains if "xn--" in h]
    if puny:
        findings.append(Finding("PUNYCODE", "Internationalised (punycode) domain", "high",
                                "Punycode domains can render as visually identical lookalikes of real brands.", puny[:3]))
    at_urls = [m.group(0) for m in URL_RE.finditer(text) if re.match(r"(?i)https?://[^/\s]*@", m.group(0))]
    if at_urls:
        findings.append(Finding("URL_USERINFO", "URL contains '@' before the host", "high",
                                "Text before '@' in a URL is ignored by browsers and is used to disguise the real host.", at_urls[:2]))
    deep = [h for h in hosts if h.count(".") >= 4]
    if deep:
        findings.append(Finding("EXCESS_SUBDOMAINS", "URL with an unusually long chain of subdomains", "low",
                                "Attackers pad hostnames with subdomains to make them look legitimate.", deep[:3]))
    insecure = [m.group(0) for m in URL_RE.finditer(text) if m.group(0).lower().startswith("http://")]
    if insecure and any(f.rule_id in {"SENSITIVE_INFO", "ACCOUNT_VERIFICATION"} for f in findings):
        findings.append(Finding("INSECURE_HTTP", "Unencrypted link combined with a credential prompt", "medium",
                                "A plain-HTTP link in a message that asks you to sign in is a red flag.", insecure[:2]))

    seen_look: set[str] = set()
    look_ev: list[str] = []
    brand_hit: list[str] = []
    for d in hosts + email_domains:
        hit = lookalike_brand(d)
        if hit and d not in seen_look:
            seen_look.add(d)
            look_ev.append(f"{d} — {hit[1]}")
            brand_hit.append(hit[0])
    if look_ev:
        findings.append(Finding("LOOKALIKE_DOMAIN", "Possible lookalike domain", "high",
                                "The domain closely resembles a well-known brand but is not one of its official domains.", look_ev[:4]))
        findings.append(Finding("BRAND_IMPERSONATION", "Possible impersonation of " + ", ".join(sorted(set(brand_hit))[:3]), "high",
                                "A well-known brand name appears in a domain that is not operated by that brand (indicator only; not verified).",
                                sorted(set(brand_hit))[:3]))
    else:
        # brand mentioned in the body + sender domain unrelated
        m = re.search(r"(?im)^from:.*?@([a-z0-9.-]+)", text)
        if m:
            sender = m.group(1).lower()
            body_brands = [b for b in BRANDS if re.search(rf"(?i)\b{b}\b", text)]
            for b in body_brands:
                if not any(sender == d or sender.endswith("." + d) for d in BRANDS[b]) and re.search(
                    r"(?i)(?:support|security|team|service|billing|account)", text
                ) and any(f.rule_id in {"ACCOUNT_VERIFICATION", "SENSITIVE_INFO", "URGENCY"} for f in findings):
                    findings.append(Finding("BRAND_IMPERSONATION", f"Mentions {b} but sender domain is unrelated", "medium",
                                            f"The message refers to '{b}' while the From address uses '{sender}'.", [f"From domain: {sender}"]))
                    break

    findings.sort(key=lambda f: -SEVERITY_ORDER[f.severity])
    return findings


def max_severity(findings: list[Finding]) -> str:
    return max((f.severity for f in findings), key=lambda s: SEVERITY_ORDER[s], default="none")


# ---------------------------------------------------------------- per-link static analysis
@dataclass
class LinkReport:
    url: str
    host: str
    indicators: list[dict]  # [{severity, title, reason}]

    @property
    def severity(self) -> str:
        return max((i["severity"] for i in self.indicators), key=lambda s: SEVERITY_ORDER[s], default="none")

    def to_dict(self) -> dict:
        return {"url": self.url, "host": self.host, "severity": self.severity, "indicators": self.indicators}


def analyze_links(text: str, limit: int = 20) -> list[LinkReport]:
    """Static, per-URL indicators. Nothing is fetched, resolved or opened."""
    reports: list[LinkReport] = []
    seen: set[str] = set()
    for m in URL_RE.finditer(text):
        raw = m.group(0).rstrip(".,;:!?")
        full = "http://" + raw if raw.lower().startswith("www.") else raw
        if full in seen:
            continue
        seen.add(full)
        try:
            host = (urlparse(full).hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        ind: list[dict] = []

        def add(sev: str, title: str, reason: str, _ind=ind) -> None:
            _ind.append({"severity": sev, "title": title, "reason": reason})

        if full.lower().startswith("http://"):
            add("low", "Not encrypted (HTTP)", "The link does not use HTTPS, so anything entered on the page travels unencrypted.")
        if host in SHORTENERS:
            add("medium", "URL shortener", "The real destination is hidden behind a shortening service.")
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            add("high", "Raw IP address", "Legitimate services rarely ask for logins at a bare IP address.")
        if host.rsplit(".", 1)[-1] in RISKY_TLDS and host not in SHORTENERS:
            add("medium", "High-abuse top-level domain", "This TLD is over-represented in abuse reports (weak signal on its own).")
        if "xn--" in host:
            add("high", "Punycode / internationalised domain", "Can render like a real brand while being a different domain.")
        if re.match(r"(?i)https?://[^/\s]*@", full):
            add("high", "'@' inside the URL", "Text before '@' is ignored by browsers and is used to disguise the real host.")
        if host.count(".") >= 4:
            add("low", "Very long subdomain chain", "Attackers pad hostnames to make them look legitimate.")
        if len(full) > 120:
            add("low", "Unusually long URL", "Long URLs can hide the real destination or carry tracking/redirect data.")
        hit = lookalike_brand(host)
        if hit:
            add("high", f"Possible lookalike of {hit[0]}", hit[1] + ". It is not an official domain of that brand.")
        reports.append(LinkReport(full, host, ind))
        if len(reports) >= limit:
            break
    return reports
