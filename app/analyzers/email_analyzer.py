"""Email analysis orchestrator - the full pipeline (spec section 45).

Runs as asyncio task; emits progress via callback(percent, message).
External integrations never block the flow: failures are recorded and the
analysis continues (spec section 31).
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Awaitable, Callable, Optional

import httpx

from app.core.logging_setup import get_logger
from app.models.schemas import (
    AttachmentInfo, EmailAnalysis, IOC, IOCType, Status, UrlInfo)
from app.utils.email_parsing import (
    addr_domain, detect_origin_ip, extract_attachments, extract_header_fields,
    get_body_parts, header_map, parse_raw_email, parse_received_chain)
from app.utils.ioc_extraction import (
    domain_of, extract_iocs, extract_urls, registered_domain)

ProgressCb = Callable[[int, str], Awaitable[None]] | Callable[[int, str], None] | None

log = get_logger("email_analyzer")


class EmailAnalyzer:
    def __init__(self, settings, registry) -> None:  # noqa: ANN001
        self.settings = settings
        self.reg = registry
        from app.analyzers.redirect_analyzer import RedirectAnalyzer
        self.redirect_analyzer = RedirectAnalyzer(settings)
        self._sem = asyncio.Semaphore(settings.analysis.concurrent_requests)

    # ------------------------------------------------------------------
    async def analyze(self, raw: bytes, progress: ProgressCb = None,
                      case_id: str = "") -> EmailAnalysis:
        a = EmailAnalysis(case_id=case_id or _new_case_id(),
                          demo_mode=self.settings.demo_mode,
                          analyzed_at=datetime.now().isoformat(timespec="seconds"))
        sem = self._sem

        async def step(pct: int, msg: str):
            log.info(msg)
            if progress:
                r = progress(pct, msg)
                if hasattr(r, "__await__"):
                    await r

        try:
            await step(3, "Starting email analysis...")

            # [1][2] Parse + headers -------------------------------------
            msg = parse_raw_email(raw)
            fields, hmap = extract_header_fields(msg)
            a.headers = fields
            a.header_map = hmap
            a.size_bytes = len(raw)
            await step(8, f"Extracting headers ({len(fields)} found)...")
            _fill_basics(a, msg)

            text_body, html_body = get_body_parts(msg)
            a.format = "multipart/mixed" if msg.is_multipart() else \
                (msg.get_content_type() if hasattr(msg, "get_content_type") else "text/plain")
            a.attachments = extract_attachments(msg)
            if a.attachments:
                await step(12, f"{len(a.attachments)} attachment(s) found")

            # [5][6] Origin IP -------------------------------------------
            hops = parse_received_chain(hmap)
            a.origin_ip = detect_origin_ip(hmap, hops)
            if a.origin_ip.ip:
                await step(16, f"Origin IP detected: {a.origin_ip.ip} "
                               f"(source: {a.origin_ip.source_header})")
            else:
                await step(16, "No origin IP could be determined")

            # [7] Authentication ------------------------------------------
            from app.analyzers.authentication_analyzer import analyze_authentication
            a.authentication = analyze_authentication(hmap)
            await step(22, "Analyzing SPF/DKIM/DMARC authentication results...")

            # Identity checks ----------------------------------------------
            from app.analyzers.advanced_detection import identity_indicators
            a.identity_indicators = identity_indicators(
                a.from_addr, a.sender, a.return_path, a.reply_to)
            mism = [i for i in a.identity_indicators
                    if i.status in (Status.MISMATCH, Status.CRITICAL)]
            if mism:
                log.warning("[WARN] %d identity mismatch(es): %s", len(mism),
                            ", ".join(i.label for i in mism))

            async with httpx.AsyncClient(
                    timeout=self.settings.analysis.timeout_seconds,
                    verify=self.settings.analysis.verify_tls,
                    proxy=self.settings.analysis.proxy or None,
                    follow_redirects=False) as client:
                # [8][9] IP reputation (AbuseIPDB) --------------------------
                if a.origin_ip.ip:
                    await step(26, f"Querying AbuseIPDB for {a.origin_ip.ip}...")
                    rep = await self._ip_reputation(a, client)
                    a.ip_reputation = rep
                    if rep.score is not None:
                        msg = f"AbuseIPDB score: {rep.score}/100"
                        log.warning("[WARN] %s", msg) if rep.score >= 60 \
                            else log.info(msg)
                        if rep.score >= 80:
                            log.critical("[CRITICAL] Origin IP is MALICIOUS "
                                         "(score %d)", rep.score)
                    elif rep.verdict == Status.NOT_CONFIGURED:
                        log.warning(rep.error)
                    elif rep.error:
                        log.warning("AbuseIPDB unavailable - continuing local analysis")

                # IP classification (RDAP/PTR)
                if a.origin_ip.ip:
                    from app.analyzers.ip_analyzer import analyze_ip
                    a.ip_classification = await analyze_ip(a.origin_ip.ip, client)
                    await step(34, f"IP classification: {a.ip_classification.classification}")

                # [10] URLs --------------------------------------------------
                await step(38, "Extracting URLs...")
                urls = self._extract_urls(a, text_body, html_body, hmap)
                log.info("%d unique URL(s) extracted", len(urls))

                # [11] redirects + heuristics per URL -------------------------
                url_infos: list[UrlInfo] = []
                tasks = []
                for u in urls[:25]:   # bounded fan-out
                    tasks.append(self._analyze_url(u, client, a))
                done = 0
                for coro in asyncio.as_completed(tasks):
                    ui = await coro
                    url_infos.append(ui)
                    done += 1
                    await step(38 + int(done * 20 / max(len(tasks), 1)),
                               f"URL analyzed [{done}/{len(tasks)}]: {ui.domain or ui.url[:40]}")
                a.urls = sorted(url_infos, key=lambda u: -u.risk_score)

                # [12] URLScan (only top risky URLs, user-visible) --------------
                if any(self._should_urlscan(u) for u in a.urls):
                    log.info("Querying URLScan...")
                    scan_targets = [u for u in a.urls if self._should_urlscan(u)][:3]
                    for u in scan_targets:
                        res = await self._urlscan_lookup(u.url, client)
                        if res.get("status") == Status.NOT_CONFIGURED:
                            log.warning(res["error"])
                            break
                        if res.get("status") == Status.INFO:
                            u.urlscan_verdict = (
                                Status.MALICIOUS if res.get("malicious")
                                else Status.SUSPICIOUS if res.get("suspicious")
                                else Status.SAFE)
                            u.urlscan_malicious = bool(res.get("malicious"))
                            u.urlscan_suspicious = bool(res.get("suspicious"))
                            u.urlscan_score = res.get("score")
                            log.warning("[WARN] URLScan verdict %s: %s",
                                        u.urlscan_verdict.value, u.url)
                        else:
                            log.warning("URLScan unavailable: %s", res.get("error", ""))
                            a.errors.append(res.get("error", "URLScan error"))

                # Domains DNS/RDAP ------------------------------------------------
                dom_names = []
                for u in a.urls:
                    if u.domain and registered_domain(u.domain) not in dom_names:
                        dom_names.append(registered_domain(u.domain))
                if a.from_addr and "@" in a.from_addr:
                    fd = registered_domain(addr_domain(a.from_addr))
                    if fd and fd not in dom_names:
                        dom_names.insert(0, fd)
                dom_results = await asyncio.gather(*[
                    self._analyze_domain(d, client) for d in dom_names[:10]])
                for dinfo in dom_results:
                    a.domains[dinfo.domain] = dinfo

            # [13] IOCs -----------------------------------------------------
            body_all = "\n".join(filter(None, [
                text_body, html_body, "\n".join(f"{h.name}: {h.value}" for h in fields)]))
            a.iocs = extract_iocs(body_all)
            counts = {}
            for ioc in a.iocs:
                counts[ioc.type.value] = counts.get(ioc.type.value, 0) + 1
            summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
            log.info("IOCs FOUND: %s" % (summary or "none"))

            # Advanced detections ---------------------------------------------
            from app.analyzers.advanced_detection import analyze_advanced
            url_domains = [u.domain for u in a.urls if u.domain] + list(a.domains.keys())
            a.advanced_detections = analyze_advanced(
                a.subject, text_body, html_body, a.from_display, a.from_addr, url_domains)
            for ind in a.advanced_detections:
                log.warning("[WARN] Detection: %s (%s)", ind.label, ind.detail[:80])

            # Browser safety ------------------------------------------------------
            for u in a.urls:
                a.browser_safety[u.url] = browser_safety_status(u)

            # [14][15] Risk engine ---------------------------------------------------
            await step(88, "Calculating risk score...")
            from app.analyzers.risk_engine import compute_risk
            a.risk = compute_risk(a)
            log.critical("[CRITICAL] Final verdict: %s (%d/100)" %
                         (a.risk.band.value, a.risk.score)
                         ) if a.risk.score >= 60 else log.info(
                "Risk score: %d/100 (%s)", a.risk.score, a.risk.band.value)

            # [16] Recommendations ------------------------------------------------------
            from app.analyzers.recommendations import build_recommendations
            a.recommendations = build_recommendations(a)

            await step(100, "Analysis completed")
        except Exception as e:  # noqa: BLE001
            import traceback
            tb = traceback.format_exc()
            log.error("Analysis failed: %s: %s\n%s", type(e).__name__, e, tb)
            a.errors.append(f"Pipeline error: {type(e).__name__}: {e}")
        return a

    # ------------------------------------------------------------------
    async def _ip_reputation(self, a: EmailAnalysis, client: httpx.AsyncClient):
        prov = self.reg.abuseipdb
        if self.settings.demo_mode and not prov.is_configured():
            from app.models.schemas import IPReputation
            return IPReputation(provider="AbuseIPDB",
                                ip=a.origin_ip.ip,
                                verdict=Status.NOT_CONFIGURED,
                                error=prov.not_configured_error(
                                    "an API key (demo mode never invents scores)"))
        return await prov.lookup_ip(a.origin_ip.ip, client)

    # ------------------------------------------------------------------
    def _extract_urls(self, a: EmailAnalysis, text_body: str, html_body: str,
                      hmap: dict[str, list[str]]) -> list[str]:
        urls: list[str] = []

        def add_all(src: str, items: list[str]) -> None:
            for u in items:
                if u.startswith(("http://", "https://")) and u not in urls:
                    urls.append(u)

        add_all("html-href", _html_urls(html_body, ("href",)))
        add_all("html-src", _html_urls(html_body, ("src",)))
        add_all("text", extract_urls(text_body))
        for name in ("List-Unsubscribe", "X-Link"):
            for v in hmap.get(name.lower(), []):
                add_all(name, extract_urls(v))
        # also URLs inside HTML text content
        add_all("html-text", extract_urls(_strip_tags(html_body)))
        return urls[:50]

    async def _analyze_url(self, url: str, client: httpx.AsyncClient,
                           a: EmailAnalysis) -> UrlInfo:
        from app.utils.url_heuristics import score_url
        ui = UrlInfo(url=url)
        p = domain_of(url)
        ui.domain = p
        from urllib.parse import urlparse
        try:
            up = urlparse(url)
            ui.scheme = up.scheme
            ui.port = up.port
            ui.path = up.path
            ui.query = up.query
            ui.fragment = up.fragment
            host_parts = (up.hostname or "").split(".")
            ui.tld = host_parts[-1] if host_parts else ""
            ui.subdomain = ".".join(host_parts[:-2]) if len(host_parts) > 2 else ""
        except Exception:
            pass

        score, flags = score_url(url)
        ui.flags.extend(flags)

        # redirect trace (real HTTP HEAD/GET following)
        red = await self.redirect_analyzer.trace(url, client)
        if red["status"] == Status.INFO:
            chain = red.get("hops", [])
            ui.redirect_chain = chain
            ui.redirect_count = max(len(chain) - 1, 0)
            ui.final_url = red.get("final_url", url)
            if ui.redirect_count >= 2:
                ui.flags.append(f"Redirect chain detected ({ui.redirect_count} hops)")
            final_flags_score, extra = score_url(ui.final_url)
            if ui.final_url != url and final_flags_score >= 40:
                ui.flags.append("Final destination is high risk: " +
                                ", ".join(extra[:2]))
                score = min(score + 15, 100)
        else:
            ui.flags.append("Redirect analysis unavailable" if not red.get("error")
                            else f"Redirect error: {red['error'][:120]}")

        ui.risk_score, ui.flags = min(score, 100), list(dict.fromkeys(ui.flags))
        ui.risk_level = (_score_to_status(ui.risk_score))
        return ui

    def _should_urlscan(self, u: UrlInfo) -> bool:
        return (self.reg.urlscan.is_configured()
                and (u.risk_score >= 30 or u.redirect_count >= 2))

    async def _urlscan_lookup(self, url: str, client: httpx.AsyncClient) -> dict:
        return await self.reg.urlscan.lookup_url(url, client)

    async def _analyze_domain(self, d: str, client: httpx.AsyncClient):
        from app.analyzers.domain_analyzer import analyze_domain
        info = await analyze_domain(d, client)
        log.info("Domain %s: A=%d MX=%d age=%s", d, len(info.a), len(info.mx),
                 f"{info.age_days}d" if info.age_days is not None else "unknown")
        return info


class _ClientHolder:
    """Legacy placeholder kept for API compatibility; unused."""


_client_holder = _ClientHolder()


# ----------------------------------------------------------------------
def _fill_basics(a: EmailAnalysis, msg) -> None:
    from email.utils import parseaddr
    a.subject = str(msg.get("Subject", ""))
    a.from_display, a.from_addr = parseaddr(str(msg.get("From", "")))
    _, snd = parseaddr(str(msg.get("Sender", "")))
    a.sender = snd
    a.return_path = str(msg.get("Return-Path", "")).strip("<>")
    _, rt = parseaddr(str(msg.get("Reply-To", "")))
    a.reply_to = rt
    a.to_addrs = str(msg.get("To", ""))
    a.cc_addrs = str(msg.get("Cc", ""))
    a.delivered_to = str(msg.get("Delivered-To", ""))
    a.date = str(msg.get("Date", ""))
    a.message_id = str(msg.get("Message-ID", ""))
    a.mime_version = str(msg.get("MIME-Version", ""))
    a.content_type = msg.get_content_type() if hasattr(msg, "get_content_type") else ""
    a.x_mailer = str(msg.get("X-Mailer", ""))
    a.user_agent = str(msg.get("User-Agent", ""))
    a.x_originating_ip = str(msg.get("X-Originating-IP", ""))


def _html_urls(html: str, attrs: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    if not html:
        return out
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "lxml")
        for tag, attr in (("a", "href"), ("img", "src"), ("iframe", "src"),
                          ("form", "action")):
            if attr not in attrs and not (tag == "form" and "action" in attrs):
                continue
            for el in soup.find_all(tag):
                v = el.get(attr)
                if isinstance(v, str):
                    v = v.strip()
                    if v.startswith(("http://", "https://")):
                        out.append(v)
                    elif v.startswith("//"):
                        out.append("http:" + v)
    except Exception:
        pass
    return out


def _strip_tags(html: str) -> str:
    try:
        from bs4 import BeautifulSoup
        return BeautifulSoup(html or "", "lxml").get_text(separator=" ")
    except Exception:
        return html or ""


def _score_to_status(score: int) -> Status:
    if score >= 80:
        return Status.CRITICAL
    if score >= 60:
        return Status.HIGH
    if score >= 40:
        return Status.SUSPICIOUS
    if score >= 15:
        return Status.LOW
    return Status.SAFE


def browser_safety_status(u: UrlInfo) -> Status:
    """CAN I OPEN THIS URL? (spec 15)."""
    if u.urlscan_malicious or u.risk_level in (Status.MALICIOUS, Status.CRITICAL):
        return Status.MALICIOUS      # DO NOT OPEN
    if u.risk_level in (Status.HIGH, Status.SUSPICIOUS):
        return Status.SUSPICIOUS     # NOT RECOMMENDED
    if u.risk_level == Status.UNKNOWN or u.risk_level == Status.NOT_ANALYZED:
        return Status.UNKNOWN
    return Status.SAFE


def _new_case_id() -> str:
    return f"CASE-{datetime.now().year}-{uuid.uuid4().hex[:6].upper()}"
