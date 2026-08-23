"""IOC Correlation engine.

Connects every indicator of one analysis (sender domain, origin IP, ASN,
URLs, redirect chain, authentication results, domain age...) into a single
attack narrative with an Attack Graph (nodes + edges) and weighted evidence.
Pure logic: never invents data, only links what analyzers actually found.
"""
from __future__ import annotations

from urllib.parse import urlparse

from app.models.schemas import (
    CorrelationEvidence, CorrelationResult, EmailAnalysis, GraphEdge,
    GraphNode, RiskBand, Status)

BRAND_TOKENS = (
    "microsoft", "office365", "outlook", "onedrive", "sharepoint", "teams",
    "paypal", "apple", "icloud", "google", "gmail", "amazon", "aws",
    "netflix", "facebook", "instagram", "whatsapp", "dhl", "fedex", "ups",
    "usps", "chase", "wellsfargo", "bankofamerica", "bbva", "santander",
    "binance", "coinbase", "metamask", "steam", "discord", "adobe",
    "dropbox", "linkedin", "zoom", "docusign", "hsbc",
)

CRED_HARVEST_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "secure", "account", "update", "confirm", "password", "webscr",
    "oauth", "mfa", "2fa", "reset", "unlock", "suspend", "limited",
    "billing", "wallet", "recover",
)

# Evidence weights (sum -> confidence 0..100)
W_AUTH_FAIL = 15
W_IP_BAD = 20
W_URL_BAD = 20
W_INFRA_LINK = 15
W_DOMAIN_NEW = 10
W_CRED_HARVEST = 15
W_REDIRECT_DEEP = 10
W_BRAND_SPOOF = 10


def _domain_of(addr_or_url: str) -> str:
    v = (addr_or_url or "").strip()
    if "@" in v and "/" not in v:
        return v.rsplit("@", 1)[-1].lower().strip()
    try:
        host = urlparse(v if "//" in v else "//" + v).hostname or ""
        return host.lower()
    except ValueError:
        return ""


def _bad(status: Status) -> bool:
    return status in (Status.SUSPICIOUS, Status.HIGH, Status.MALICIOUS,
                      Status.CRITICAL)


def build_graph(a: EmailAnalysis):
    """Return (nodes, edges) of the attack graph for an analysis."""
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    band_status = {
        RiskBand.CRITICAL: Status.CRITICAL, RiskBand.HIGH: Status.HIGH,
        RiskBand.SUSPICIOUS: Status.SUSPICIOUS, RiskBand.LOW: Status.LOW,
        RiskBand.SAFE: Status.SAFE}[a.risk.band]

    nodes.append(GraphNode(
        node_id="email", kind="email",
        label=a.from_display or a.from_addr or "(unknown sender)",
        value=(a.subject or "")[:60], verdict=band_status,
        detail=f"{a.from_addr} | score {a.risk.score}/100"))

    # --- sender domain -----------------------------------------------------
    sender_dom = _domain_of(a.from_addr) or _domain_of(a.return_path)
    chain_last = "email"
    ip_node_id = ""
    if sender_dom:
        sid = f"domain:{sender_dom}"
        di = a.domains.get(sender_dom)
        bits = []
        verd = Status.UNKNOWN
        if di is not None:
            if di.age_days is not None:
                bits.append(f"age {di.age_days}d")
            if di.registrar:
                bits.append(f"registrar {di.registrar[:28]}")
        auth_bad = any(r.result in ("fail", "softfail")
                       for r in (a.authentication.spf, a.authentication.dkim,
                                 a.authentication.dmarc))
        if auth_bad:
            verd = Status.SUSPICIOUS
            bits.append("auth alignment issues")
        nodes.append(GraphNode(node_id=sid, kind="domain", label=sender_dom,
                               value=sender_dom, verdict=verd,
                               detail=" | ".join(bits)))
        edges.append(GraphEdge(src="email", dst=sid, relation="sender"))
        chain_last = sid

    # --- origin IP ----------------------------------------------------------
    ip_val = (a.origin_ip.ip or "").strip()
    if ip_val:
        iid = f"ip:{ip_val}"
        rep = a.ip_reputation
        verd = rep.band if rep.score is not None else rep.verdict
        bits = []
        if rep.score is not None:
            bits.append(f"abuse score {rep.score}/100")
        elif rep.verdict not in (Status.NOT_ANALYZED, Status.UNKNOWN):
            bits.append(rep.verdict.value)
        cls = a.ip_classification.classification
        if cls and cls != "Unknown":
            bits.append(cls.lower())
        nodes.append(GraphNode(node_id=iid, kind="ip", label=ip_val,
                               value=ip_val, verdict=verd,
                               detail=" | ".join(bits)))
        src = chain_last if chain_last != "email" else "email"
        edges.append(GraphEdge(src=src, dst=iid, relation="originates from"))
        chain_last = iid
        ip_node_id = iid

    # --- ASN ------------------------------------------------------------------
    asn = (a.ip_classification.asn_number or a.ip_reputation.asn or "").strip()
    if asn and ip_val:
        aid = f"asn:{asn.lower()}"
        org = (a.ip_classification.asn_org or a.ip_reputation.isp
               or a.ip_reputation.org or "")
        ip_verdict = next((n.verdict for n in nodes if n.node_id == iid),
                          Status.UNKNOWN)
        verd = Status.MALICIOUS if ip_verdict == Status.CRITICAL else (
            ip_verdict if _bad(ip_verdict) else Status.UNKNOWN)
        nodes.append(GraphNode(node_id=aid, kind="asn", label=asn.upper(),
                               value=org[:48], verdict=verd,
                               detail="hosting network"))
        edges.append(GraphEdge(src=iid, dst=aid, relation="announced by"))

    # --- URLs + redirect chains ----------------------------------------------
    for i, u in enumerate(a.urls):
        uid = f"url:{i}"
        nodes.append(GraphNode(
            node_id=uid, kind="url", label=u.domain or u.url[:40],
            value=u.url[:70], verdict=u.risk_level,
            detail=(f"risk {u.risk_score} | {u.redirect_count} redirects"
                    if u.redirect_count else f"risk {u.risk_score}")))
        edges.append(GraphEdge(src="email", dst=uid, relation="contains"))

        prev = uid
        seen = {u.domain}
        for h in u.redirect_chain:
            hd = h.domain or _domain_of(h.url)
            if not hd or hd in seen:
                continue
            seen.add(hd)
            hid = f"hop:{i}:{h.step}:{hd}"
            nodes.append(GraphNode(
                node_id=hid, kind="redirect", label=hd, value=h.url[:70],
                verdict=u.risk_level,
                detail=("hop %d%s" % (h.step,
                        f" | HTTP {h.status_code}" if h.status_code else ""))))
            edges.append(GraphEdge(src=prev, dst=hid, relation="redirect"))
            prev = hid

        final_dom = _domain_of(u.final_url)
        if u.final_url and final_dom and final_dom not in seen:
            fid = f"final:{i}:{final_dom}"
            cred = any(k in u.final_url.lower() for k in CRED_HARVEST_KEYWORDS)
            nodes.append(GraphNode(
                node_id=fid, kind="final", label=final_dom,
                value=u.final_url[:70],
                verdict=Status.CRITICAL if cred else u.risk_level,
                detail=("credential-harvest pattern"
                        if cred else "final destination")))
            edges.append(GraphEdge(src=prev, dst=fid, relation="lands on"))

    return nodes, edges


def correlate(a: EmailAnalysis, db=None) -> CorrelationResult:
    """Full cross-IOC correlation for one email analysis."""
    nodes, edges = build_graph(a)

    evidence: list[CorrelationEvidence] = []
    conf = 0

    def add(title, weight, sev, detail="", ids=None):
        nonlocal conf
        conf += weight
        evidence.append(CorrelationEvidence(
            title=title, severity=sev, detail=detail, nodes=ids or []))

    def node(kind_prefix):
        return [n.node_id for n in nodes if n.node_id.startswith(kind_prefix)]

    # 1. Authentication failure chain ---------------------------------------
    fails = [r.mechanism.upper() for r in
             (a.authentication.spf, a.authentication.dkim, a.authentication.dmarc)
             if r.result in ("fail", "softfail")]
    if fails:
        add(f"Sender authentication failure ({'+'.join(fails)})",
            W_AUTH_FAIL, Status.HIGH,
            "SPF/DKIM/DMARC do not align with the sending infrastructure.",
            ["email"] + node("domain:")[:1])

    # 2. Origin IP reputation -----------------------------------------------
    rep = a.ip_reputation
    if rep.score is not None and _bad(rep.band):
        add("Origin IP has malicious reputation", W_IP_BAD, Status.MALICIOUS,
            f"{rep.provider or 'AbuseIPDB'} abuse confidence "
            f"{rep.score}/100{', reports: ' + str(rep.total_reports) if rep.total_reports else ''}",
            node("ip:"))
    elif rep.score is None and _bad(rep.verdict):
        add("Origin IP flagged by reputation feed", W_IP_BAD // 2,
            rep.verdict, "", node("ip:"))

    # 3. URL risk -------------------------------------------------------------
    bad_urls = [u for u in a.urls if _bad(u.risk_level)]
    if bad_urls:
        worst = max(bad_urls, key=lambda x: x.risk_score)
        add(f"{len(bad_urls)} URL(s) classified {worst.risk_level.value}",
            W_URL_BAD, worst.risk_level,
            f"e.g. {worst.url[:80]} | heuristics: {', '.join(worst.flags[:4])}",
            node("url:"))

    # 4. Infrastructure link: origin IP serves a phishing domain --------------
    ip_val = a.origin_ip.ip
    if ip_val:
        for dname, di in a.domains.items():
            if ip_val in (di.a or []) and any(
                    u.domain == dname and _bad(u.risk_level) for u in a.urls):
                add("Origin IP serves the phishing domain",
                    W_INFRA_LINK, Status.CRITICAL,
                    f"DNS A record of {dname} resolves to the header origin IP "
                    f"{ip_val}: same infrastructure end-to-end.",
                    node("ip:") + [n.node_id for n in nodes
                                   if n.kind == "domain" and n.label == dname])
                break

    # 5. Newly registered domains ----------------------------------------------
    cand_doms = ({_domain_of(u.url) for u in a.urls}
                 | {_domain_of(a.from_addr), _domain_of(a.reply_to)})
    cand_doms.discard("")
    fresh = []
    for nd in sorted(cand_doms):
        di = a.domains.get(nd)
        if di is not None and di.age_days is not None and di.age_days <= 30:
            fresh.append((nd, di.age_days))
    if fresh:
        names = ", ".join(f"{d} ({age}d)" for d, age in fresh)
        add("Newly registered domain(s) in the attack path", W_DOMAIN_NEW,
            Status.SUSPICIOUS, names, node("domain:") + node("url:"))

    # 6. Credential harvesting final destination ------------------------------
    cred_urls = [u for u in a.urls
                 if any(k in (u.final_url or u.url).lower()
                        for k in CRED_HARVEST_KEYWORDS)]
    if cred_urls:
        u0 = cred_urls[0]
        add("Final destination matches credential-harvesting pattern",
            W_CRED_HARVEST, Status.CRITICAL,
            f"{(u0.final_url or u0.url)[:90]}",
            [n.node_id for n in nodes if n.kind == "final"] or node("url:"))

    # 7. Redirect depth ---------------------------------------------------------
    deep = [u for u in a.urls if u.redirect_count >= 2]
    if deep:
        u0 = max(deep, key=lambda x: x.redirect_count)
        hops = " -> ".join(h.domain or "?" for h in u0.redirect_chain[:5])
        add(f"Multi-hop redirect chain ({u0.redirect_count} hops)",
            W_REDIRECT_DEEP, Status.SUSPICIOUS, hops,
            [n.node_id for n in nodes if n.kind == "redirect"])

    # 8. Brand impersonation linked across email -> URL -------------------------
    display = (a.from_display or "").lower()
    url_text = " ".join((u.url + " " + (u.final_url or "")).lower()
                        for u in a.urls)
    sender_dom = _domain_of(a.from_addr)
    spoofed = None
    for b in BRAND_TOKENS:
        in_url = b in url_text.replace("-", "").replace(".", "")
        in_display = b in display.replace(" ", "")
        legit_sender = b in (sender_dom or "")
        if in_display and in_url and not legit_sender:
            spoofed = b
            break
    if spoofed:
        add(f"Brand impersonation: '{spoofed}' in sender name AND URLs",
            W_BRAND_SPOOF, Status.HIGH,
            f"display name claims {spoofed}; URLs use look-alike domains.",
            ["email"] + node("url:")[:2])

    indicators = len(evidence)
    conf = min(100, conf)
    if conf >= 75 and indicators >= 4:
        verdict = "HIGH CONFIDENCE PHISHING"
    elif conf >= 60:
        verdict = "PHISHING - CORRELATED INDICATORS"
    elif conf >= 40:
        verdict = "SUSPICIOUS - PARTIAL CORRELATION"
    elif conf > 0:
        verdict = "LOW CONFIDENCE CORRELATION"
    else:
        verdict = "NO STRONG CORRELATION"

    result = CorrelationResult(
        verdict=verdict, confidence=conf, band=RiskBand.from_score(conf),
        correlated_indicators=indicators, evidence=evidence,
        graph_nodes=nodes, graph_edges=edges)

    if db is not None:
        try:
            from app.analyzers.campaigns import detect_campaign
            result.campaign = detect_campaign(db, a)
        except Exception:
            pass
    return result
