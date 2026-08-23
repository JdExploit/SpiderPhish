"""Advanced threat detection heuristics (spec section 36).

Brand impersonation, display-name spoofing, MFA/OAuth/invoice/delivery/BEC
phishing themes, QR phishing and Unicode lookalike detection.
"""
from __future__ import annotations

import re
import unicodedata
from email.utils import parseaddr

from app.models.schemas import Indicator, Status
from app.utils.url_heuristics import detect_brand_impersonation

THEME_PATTERNS: list[tuple[str, list[str], Status]] = [
    ("MFA phishing", ["mfa", "multi-factor", "two-factor", "2fa",
                      "authenticator app", "verify your identity"], Status.HIGH),
    ("Credential harvesting / password reset",
     ["reset your password", "password expired", "unusual sign-in",
      "sign-in attempt", "validate your account", "confirm your password"], Status.CRITICAL),
    ("Invoice phishing", ["invoice", "payment overdue", "past due",
                          "wire transfer", "bank transfer details"], Status.SUSPICIOUS),
    ("Delivery phishing", ["package delivery", "shipment", "tracking number",
                           "delivery failed", "customs fee", "redeliver"], Status.SUSPICIOUS),
    ("OAuth phishing", ["grant access", "authorize application",
                        "consent to access", "oauth"], Status.HIGH),
    ("Business Email Compromise",
     ["urgent request", "confidential", "asap", "gift card", "i'm in a meeting",
      "don't call me", "change of bank account"], Status.SUSPICIOUS),
    ("Bank impersonation theme",
     ["your account has been locked", "suspicious transaction",
      "security alert from your bank", "verify your card"], Status.HIGH),
]

QR_RE = re.compile(r"<img[^>]+(?:qr|barcode)[^>]*>|src=[\"'][^\"']*(?:qr|qrcode)[^\"']*", re.I)


def _norm(s: str) -> str:
    return unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().lower()


def analyze_advanced(subject: str, body_text: str, body_html: str,
                     from_display: str, from_addr: str,
                     urls_domains: list[str]) -> list[Indicator]:
    indicators: list[Indicator] = []
    hay = _norm(f"{subject} {body_text} {body_html[:20000]}")

    # --- Theme detection -------------------------------------------------
    for label, keywords, sev in THEME_PATTERNS:
        hits = [k for k in keywords if k in hay]
        if hits:
            indicators.append(Indicator(
                label=label, status=sev,
                detail=f"Keywords: {', '.join(hits[:4])}",
                actual="DETECTED"))

    # --- Display name spoofing --------------------------------------------
    name, addr = parseaddr(from_addr)
    display = (from_display or "").strip()
    if display:
        dm = _norm(display)
        for token in re.findall(r"[a-z0-9\-]{4,}", dm):
            if "@" in addr and token not in addr.lower() and \
                    any(b in token for b in ("microsoft", "outlook", "office", "google",
                                             "gmail", "paypal", "apple", "dhl")):
                indicators.append(Indicator(
                    label="Display Name spoofing", status=Status.CRITICAL,
                    detail=f"Display name '{display}' impersonates a known service "
                           f"but sender domain differs ({addr.split('@')[-1]})",
                    actual="CRITICAL"))
                break
        if re.search(r"[\u0400-\u04FF\u0370-\u03FF\u0430-\u045F]", display):
            indicators.append(Indicator(
                label="Unicode lookalike characters in display name",
                status=Status.SUSPICIOUS,
                detail="Non-Latin characters detected (Cyrillic/Greek homoglyphs)",
                actual="SUSPICIOUS"))

    # --- Brand impersonation across domains ---------------------------------
    seen_brands = set()
    for d in urls_domains[:12]:
        brand, reason = detect_brand_impersonation(d)
        if brand and brand not in seen_brands:
            seen_brands.add(brand)
            indicators.append(Indicator(
                label="Lookalike domain attack", status=Status.HIGH,
                detail=f"{reason}", actual=d))
        if d.startswith("xn--") or ".xn--" in d:
            indicators.append(Indicator(
                label="Punycode/IDN domain", status=Status.SUSPICIOUS,
                detail=d, actual=d))

    # --- QR phishing ---------------------------------------------------------
    if QR_RE.search(body_html):
        indicators.append(Indicator(
            label="QR code image embedded (possible QR/quishing)",
            status=Status.SUSPICIOUS,
            detail="Image tag matching qr/barcode naming found in HTML body",
            actual="DETECTED"))

    return indicators


def identity_indicators(from_addr: str, sender: str, return_path: str,
                        reply_to: str) -> list[Indicator]:
    """From vs Return-Path/Sender/Reply-To discrepancy checks (spec 7)."""
    out: list[Indicator] = []
    fa_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
    rp = return_path.strip("<> ")
    rp_domain = rp.split("@")[-1].lower() if "@" in rp else ""

    if rp:
        if not rp_domain or rp_domain != fa_domain:
            status = Status.MISMATCH
            out.append(Indicator(
                label="From != Return-Path", status=status,
                expected=fa_domain or from_addr, actual=rp,
                detail=f"Return-Path domain '{rp_domain}' differs From domain '{fa_domain}'"))
        else:
            out.append(Indicator(label="From == Return-Path", status=Status.MATCH,
                                 detail=rp_domain))

    snd = sender.strip("<> ")
    snd_domain = snd.split("@")[-1].lower() if "@" in snd else ""
    if snd:
        if snd_domain and snd_domain != fa_domain:
            out.append(Indicator(
                label="From != Sender", status=Status.MISMATCH,
                expected=fa_domain or from_addr, actual=snd,
                detail=f"Sender header domain '{snd_domain}' differs From"))
        else:
            out.append(Indicator(label="From == Sender", status=Status.MATCH,
                                 detail=snd_domain))

    rt = reply_to.strip("<> ")
    rt_domain = rt.split("@")[-1].lower() if "@" in rt else ""
    if rt and rt_domain and rt_domain != fa_domain:
        out.append(Indicator(
            label="Reply-To != From", status=Status.CRITICAL,
            expected=fa_domain or from_addr, actual=rt,
            detail="Replies would go to an external/unrelated mailbox - "
                   "common in BEC/phishing"))
    elif rt:
        out.append(Indicator(label="Reply-To == From domain", status=Status.MATCH,
                             detail=rt_domain))
    return out
