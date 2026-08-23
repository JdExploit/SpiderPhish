"""Risk engine: weighted scoring -> 0..100 + band + WHY list."""
from __future__ import annotations

from app.models.schemas import (
    EmailAnalysis, RiskAssessment, RiskFactor, RiskBand, Status)


def compute_risk(a: EmailAnalysis) -> RiskAssessment:
    factors: list[RiskFactor] = []

    def add(name: str, points: int, detail: str = "",
            severity: Status = Status.SUSPICIOUS) -> None:
        if points > 0:
            factors.append(RiskFactor(name=name, points=points, detail=detail,
                                      severity=severity))

    # --- Origin IP reputation ------------------------------------------
    ipr = a.ip_reputation
    if ipr.score is not None:
        if ipr.score >= 80:
            add("Origin IP reputation (AbuseIPDB)", 30,
                f"AbuseIPDB score {ipr.score}/100", Status.CRITICAL)
        elif ipr.score >= 60:
            add("Origin IP reputation (AbuseIPDB)", 20,
                f"AbuseIPDB score {ipr.score}/100", Status.HIGH)
        elif ipr.score >= 40:
            add("Origin IP reputation (AbuseIPDB)", 10,
                f"AbuseIPDB score {ipr.score}/100", Status.SUSPICIOUS)
    if ipr.is_tor:
        add("Origin via Tor exit node", 15, "Anonymized origin", Status.SUSPICIOUS)

    # --- Authentication -------------------------------------------------
    auth = a.authentication
    if auth.spf.result in FAIL_RESULTS:
        add("SPF failure", 15, f"SPF result {auth.spf.result}", Status.CRITICAL)
    elif auth.spf.result in ("softfail", "neutral"):
        add("SPF softfail/neutral", 8, f"SPF result {auth.spf.result}", Status.SUSPICIOUS)
    if auth.dkim.result in FAIL_RESULTS or auth.dkim.result == "none":
        add("DKIM failure", 15, f"DKIM result {auth.dkim.result}", Status.CRITICAL)
    if auth.dmarc.result in FAIL_RESULTS:
        add("DMARC failure", 15, f"DMARC result {auth.dmarc.result} - spoofing likely",
            Status.CRITICAL)

    # --- Identity discrepancies -----------------------------------------
    for ind in a.identity_indicators:
        if ind.status == Status.CRITICAL:
            add(ind.label, 10, ind.detail, Status.CRITICAL)
        elif ind.status == Status.MISMATCH:
            add(ind.label, 10, ind.detail, Status.SUSPICIOUS)
        elif ind.status == Status.SUSPICIOUS:
            add(ind.label, 6, ind.detail, Status.SUSPICIOUS)

    # --- Advanced detections ---------------------------------------------
    for ind in a.advanced_detections:
        pts = {"CRITICAL": 25, "HIGH": 18, "SUSPICIOUS": 12}.get(ind.status.value, 0)
        if pts:
            add(ind.label, pts, ind.detail, ind.status)

    # --- URLs --------------------------------------------------------------
    shortener = False
    redirect_chain = False
    for u in a.urls:
        for f in u.flags:
            if "shortener" in f.lower():
                shortener = True
            if "redirect chain" in f.lower():
                redirect_chain = True
            if "Punycode" in f:
                add(f"Punycode URL ({u.domain})", 15, u.url, Status.HIGH)
            if "Credential harvesting" in f:
                add("Credential harvesting indicators", 30, u.url, Status.CRITICAL)
        if u.urlscan_malicious:
            add("Malicious URL verdict (URLScan)", 30, u.url, Status.CRITICAL)
        elif u.urlscan_suspicious:
            add("Suspicious URL verdict (URLScan)", 15, u.url, Status.SUSPICIOUS)
        if u.risk_score >= 70 and not u.urlscan_malicious:
            add("High-risk URL heuristics", 20, f"{u.url}: {', '.join(u.flags[:3])}",
                Status.HIGH)
    if shortener:
        add("URL shortener used", 5, "", Status.SUSPICIOUS)
    if redirect_chain:
        add("Redirect chain", 15, "Multiple hops before final destination",
            Status.SUSPICIOUS)

    # --- Domains ------------------------------------------------------------
    for dname, dinfo in a.domains.items():
        for f in dinfo.flags:
            if "recently registered" in f.lower():
                add("Domain recently registered", 10, f"{dname}: {f}", Status.SUSPICIOUS)
                break

    # --- Attachments ----------------------------------------------------------
    for att in a.attachments:
        if att.dangerous:
            add("Dangerous attachment type", 15,
                f"{att.filename} ({att.extension})", Status.HIGH)

    # --- Known phishing IOC match ------------------------------------------------
    # (reserved: cross-check against stored cases / feeds)
    known_hit = any(
        ioc.type.value == "IPv4" and a.ip_reputation.ip == ioc.value and
        a.ip_reputation.verdict in (Status.MALICIOUS, Status.HIGH)
        for ioc in a.iocs)
    if known_hit:
        add("Known phishing IOC (origin IP)", 40, a.ip_reputation.ip, Status.CRITICAL)

    score = min(sum(f.points for f in factors), 100)
    band = RiskBand.from_score(score)
    verdict = _verdict_text(score, band)
    return RiskAssessment(score=score, max_score=100, band=band,
                          factors=factors, verdict=verdict)


FAIL_RESULTS = {"fail", "hardfail"}


def _verdict_text(score: int, band: RiskBand) -> str:
    if band == RiskBand.CRITICAL:
        return "MALICIOUS PHISHING EMAIL"
    if band == RiskBand.HIGH:
        return "HIGH RISK - LIKELY PHISHING"
    if band == RiskBand.SUSPICIOUS:
        return "SUSPICIOUS - MANUAL REVIEW RECOMMENDED"
    if band == RiskBand.LOW:
        return "LOW RISK"
    return "NO MAJOR THREAT INDICATORS"
