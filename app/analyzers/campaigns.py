"""Campaign detection: links IOCs of the current analysis with every past
analysis stored in the local database (ioc_observations table).

Only reports what was actually observed before - never invents history.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from app.models.schemas import CampaignMatch, CampaignResult, EmailAnalysis


def _norm_domain(v: str) -> str:
    return (v or "").strip().lower()


def sender_domain(a: EmailAnalysis) -> str:
    addr = a.from_addr or a.return_path or ""
    if "@" in addr:
        return _norm_domain(addr.rsplit("@", 1)[-1])
    return ""


def candidate_values(a: EmailAnalysis) -> dict[str, list[tuple[str, str]]]:
    """Return {ioc_type: [(value, role), ...]} for campaign matching."""
    out: dict[str, list[tuple[str, str]]] = {"ip": [], "domain": [], "url": [],
                                             "asn": []}

    def push(t: str, v: str, role: str):
        v = _norm_domain(v)
        if v and (v, role) not in out[t]:
            out[t].append((v, role))

    sd = sender_domain(a)
    if sd:
        push("domain", sd, "sender_domain")
    if a.reply_to:
        rd = _norm_domain(str(a.reply_to).rsplit("@", 1)[-1]) if "@" in str(a.reply_to) else ""
        if rd and rd != sd:
            push("domain", rd, "reply_to_domain")
    if a.origin_ip.ip:
        push("ip", a.origin_ip.ip, "origin_ip")
    asn = (a.ip_classification.asn_number or "").strip().upper()
    if asn:
        asn_num = asn.lstrip("AS")
        push("asn", f"AS{asn_num}" if asn_num else "", "asn")

    seen_doms = set()
    for u in a.urls:
        push("url", u.url, "url")
        if u.final_url and u.final_url != u.url:
            push("url", u.final_url, "final_url")
        for dom, role in ((u.domain, "url_domain"),):
            if dom and dom not in seen_doms:
                seen_doms.add(dom)
                push("domain", dom, role)
        for h in u.redirect_chain:
            hd = h.domain or ""
            if hd and hd not in seen_doms:
                seen_doms.add(hd)
                push("domain", hd, "redirect_domain")
            if h.ip:
                push("ip", h.ip, "hop_ip")
    for dname in a.domains.keys():
        if dname not in seen_doms:
            seen_doms.add(dname)
            push("domain", dname, "analyzed_domain")
    return out


def flat_values(a: EmailAnalysis) -> list[str]:
    cv = candidate_values(a)
    return [v for t in ("ip", "domain", "asn", "url") for v, _ in cv.get(t, [])]


def extract_observations(a: EmailAnalysis) -> list[tuple[str, str, str, str, str, str]]:
    """Rows ready for Database.record_observations."""
    now = datetime.now().isoformat(timespec="seconds")
    recipient = a.delivered_to or (a.to_addrs.split(",")[0].strip()
                                   if a.to_addrs else "")
    rep_band = a.ip_reputation.band.value if a.ip_reputation.score is not None \
        else a.ip_reputation.verdict.value
    rows: list[tuple[str, str, str, str, str, str]] = []
    for ioc_type, pairs in candidate_values(a).items():
        for value, role in pairs:
            verdict = rep_band if ioc_type == "ip" and role == "origin_ip" \
                else "OBSERVED"
            rows.append((ioc_type, value, role, verdict, recipient or "", now))
    return rows[:300]


def detect_campaign(db: Any, a: EmailAnalysis,
                    exclude_id: str = "") -> Optional[CampaignResult]:
    """Compare current IOCs against all stored observations."""
    try:
        matches = db.campaign_lookup(flat_values(a),
                                     exclude_id=exclude_id or a.case_id)
    except Exception:
        return None
    if not matches:
        return None

    past_ids: set[str] = set()
    cluster: list[CampaignMatch] = []
    n_domains = n_ips = 0
    for m in matches[:60]:
        past_ids.update(m["analysis_ids"])
        cluster.append(CampaignMatch(
            ioc_type=m["ioc_type"], value=m["value"],
            past_analyses=m["past_analyses"],
            analysis_ids=m["analysis_ids"][:20],
            first_seen=m["first_seen"], last_seen=m["last_seen"]))
        if m["ioc_type"] == "domain":
            n_domains += 1
        elif m["ioc_type"] == "ip":
            n_ips += 1

    firsts = [m["first_seen"] for m in matches if m["first_seen"]]
    lasts = [m["last_seen"] for m in matches if m["last_seen"]]
    first_seen = min(firsts) if firsts else ""
    last_seen = max(lasts) if lasts else ""

    emails_past = len(past_ids)
    detected = emails_past >= 2

    recipients: set[str] = set()
    try:
        recipients = db.campaign_recipients(flat_values(a),
                                            exclude_id=exclude_id or a.case_id)
    except Exception:
        pass
    cur_rcpt = a.delivered_to or (a.to_addrs.split(",")[0].strip()
                                  if a.to_addrs else "")
    if cur_rcpt:
        recipients.add(cur_rcpt)

    total_emails = emails_past + 1
    note = (f"{total_emails} analyses share infrastructure"
            if detected else f"IOC reuse observed ({emails_past} prior case)")

    conf = min(100, total_emails * 18 + len(cluster) * 8)

    return CampaignResult(
        detected=detected, note=note, emails=total_emails,
        recipients=len(recipients), domains=n_domains, ips=n_ips,
        cluster=cluster, first_seen=first_seen, last_seen=last_seen,
        confidence=conf)
