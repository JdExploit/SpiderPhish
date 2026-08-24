"""Reputation pages: IP, Domain, Hash lookup and Threat Feeds overview."""
from __future__ import annotations

import re

import httpx

from PySide6.QtWidgets import (QHBoxLayout, QLabel, QLineEdit, QVBoxLayout,
                               QWidget)

from app.core.logging_setup import get_logger
from app.gui.theme import TEXT_DIM
from app.gui.widgets.common import Card, KVCard, add_table_row, make_table
from app.gui.pages.url_analyzer_page import _IntelBase
from app.gui.pages.ioc_lookup_page import classify

log = get_logger("gui.reputation")


class IPReputationPage(_IntelBase):
    def __init__(self, app_ctx):
        super().__init__(app_ctx)
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        t = QLabel("IP REPUTATION")
        t.setStyleSheet("font-size:14pt; font-weight:800;")
        d = QLabel("AbuseIPDB + VirusTotal + OTX + GreyNoise (proveedores configurados).")
        d.setStyleSheet(f"color:{TEXT_DIM};")
        root.addWidget(t); root.addWidget(d)
        row = QHBoxLayout()
        self.input = QLineEdit(); self.input.setPlaceholderText("185.xxx.xxx.xxx")
        from PySide6.QtWidgets import QPushButton
        btn = QPushButton("CHECK IP"); btn.setObjectName("Primary")
        row.addWidget(self.input, 1); row.addWidget(btn)
        root.addLayout(row)
        self.card = KVCard("RESULT", [])
        root.addWidget(self.card); root.addStretch()
        btn.clicked.connect(self.check)
        self.input.returnPressed.connect(self.check)

    def check(self):
        import ipaddress
        ip = self.input.text().strip()
        if not ip:
            return
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self.card.set_rows([("Error",
                                 f"'{ip}' no es una IPv4/IPv6 valida "
                                 f"(ejemplo: 8.8.8.8)")])
            return
        reg = self.app_ctx.registry
        timeout = self.app_ctx.settings.analysis.timeout_seconds

        async def job():
            rows = []
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await reg.abuseipdb.lookup_ip(ip, client)
                if r.score is not None:
                    rows += [("ABUSEIPDB SCORE", f"{r.score}/100 ({r.band.value})"),
                             ("Total reports", str(r.total_reports)),
                             ("Last report", r.last_report or "-"),
                             ("Country / ISP", f"{r.country} · {r.isp}"),
                             ("Domain", r.domain or "-"),
                             ("Usage type", r.usage_type or "-"),
                             ("Categories", ", ".join(r.categories) or "-"),
                             ("Tor/Proxy", f"{r.is_tor}/{r.is_proxy}")]
                else:
                    rows.append(("AbuseIPDB", r.error))
                vt = await reg.virustotal.lookup_ip(ip, client)
                st = getattr(vt.get("status"), "value", "?")
                if st == "INFO":
                    rows.append(("VirusTotal",
                                 f"malicious votes: {vt.get('malicious_votes')} · "
                                 f"rep: {vt.get('reputation')}"))
                else:
                    rows.append(("VirusTotal", vt.get("error") or st))
            return rows

        log.info("IP reputation check: %s", ip)
        self.run_async(job)

    def on_result(self, res):  # noqa: ANN001
        self.card.set_rows(res)


class DomainReputationPage(_IntelBase):
    def __init__(self, app_ctx):
        super().__init__(app_ctx)
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        t = QLabel("DOMAIN REPUTATION")
        t.setStyleSheet("font-size:14pt; font-weight:800;")
        d = QLabel("DNS local + RDAP + VirusTotal/OTX si están configurados.")
        d.setStyleSheet(f"color:{TEXT_DIM};")
        root.addWidget(t); root.addWidget(d)
        row = QHBoxLayout()
        self.input = QLineEdit(); self.input.setPlaceholderText("suspicious-domain.com")
        from PySide6.QtWidgets import QPushButton
        btn = QPushButton("CHECK DOMAIN"); btn.setObjectName("Primary")
        row.addWidget(self.input, 1); row.addWidget(btn)
        root.addLayout(row)
        self.card = KVCard("DOMAIN INFO", [])
        root.addWidget(self.card); root.addStretch()
        btn.clicked.connect(self.check)
        self.input.returnPressed.connect(self.check)

    def check(self):
        from urllib.parse import urlparse
        raw = self.input.text().strip().lower()
        domain = re.sub(r"^[a-z][a-z0-9+.-]*://", "", raw)
        domain = urlparse(f"https://{domain}").hostname or ""
        if not domain or "." not in domain:
            self.card.set_rows([("Error",
                                 f"'{raw}' no parece un dominio valido "
                                 f"(ejemplo: suspicious-domain.com)")])
            return
        reg = self.app_ctx.registry
        timeout = self.app_ctx.settings.analysis.timeout_seconds

        async def job():
            from app.analyzers.domain_analyzer import analyze_domain
            rows = []
            async with httpx.AsyncClient(timeout=timeout) as client:
                info = await analyze_domain(domain, client)
            rows += [
                ("A", ", ".join(info.a) or "-"), ("MX", "; ".join(info.mx[:3]) or "-"),
                ("NS", "; ".join(info.ns[:3]) or "-"),
                ("Registrar", info.registrar or "-"),
                ("Created", info.creation_date or "-"),
                ("Age", f"{info.age_days} days" if info.age_days is not None else "unknown"),
                ("Flags", ", ".join(info.flags) or "-")]
            vt = await reg.virustotal.lookup_domain(domain, client)
            st = getattr(vt.get("status"), "value", "?")
            rows.append(("VirusTotal",
                         f"malicious votes: {vt.get('malicious_votes')}" if st == "INFO"
                         else vt.get("error") or st))
            return rows

        log.info("Domain reputation check: %s", domain)
        self.run_async(job)

    def on_result(self, res):  # noqa: ANN001
        self.card.set_rows(res)


class HashLookupPage(_IntelBase):
    def __init__(self, app_ctx):
        super().__init__(app_ctx)
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        t = QLabel("HASH LOOKUP")
        t.setStyleSheet("font-size:14pt; font-weight:800;")
        d = QLabel("Consulta MD5/SHA1/SHA256 en VirusTotal (requiere API key gratuita).")
        d.setStyleSheet(f"color:{TEXT_DIM};")
        root.addWidget(t); root.addWidget(d)
        row = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setPlaceholderText("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        from PySide6.QtWidgets import QPushButton
        btn = QPushButton("LOOKUP HASH"); btn.setObjectName("Primary")
        row.addWidget(self.input, 1); row.addWidget(btn)
        root.addLayout(row)
        self.card = KVCard("RESULT", [])
        root.addWidget(self.card); root.addStretch()
        btn.clicked.connect(self.check)
        self.input.returnPressed.connect(self.check)

    def check(self):
        h = self.input.text().strip()
        kind = classify(h)
        timeout = self.app_ctx.settings.analysis.timeout_seconds

        async def job():
            if kind != "hash":
                return [("Error", "No parece un hash válido (MD5/SHA1/SHA256/SHA512)")]
            reg = self.app_ctx.registry
            async with httpx.AsyncClient(timeout=timeout) as client:
                vt = await reg.virustotal.lookup_hash(h.lower(), client)
            st = getattr(vt.get("status"), "value", "?")
            if st == "NOT_CONFIGURED":
                return [("VirusTotal", vt.get("error"))]
            if st != "INFO":
                return [("VirusTotal", vt.get("error") or st)]
            if not vt.get("found"):
                return [("VirusTotal", "Unknown hash - no existe en el dataset de VT")]
            return [("Detection ratio",
                     f"{vt.get('malicious_votes')} engines flagged malicious"),
                    ("Top signatures", ", ".join(vt.get("signatures", [])[:8]) or "-"),
                    ("Names", ", ".join(vt.get("names", [])) or "-"),
                    ("Type", vt.get("type_description") or "-")]

        log.info("Hash lookup: %s...", h[:16])
        self.run_async(job)

    def on_result(self, res):  # noqa: ANN001
        self.card.set_rows(res)


class ThreatFeedsPage(QWidget):
    """Provider status + locally stored IOC counts. Real feeds require keys."""

    def __init__(self, app_ctx):
        super().__init__()
        self.app_ctx = app_ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        t = QLabel("THREAT FEEDS")
        t.setStyleSheet("font-size:14pt; font-weight:800;")
        d = QLabel("Estado de proveedores e IOCs almacenados localmente.")
        d.setStyleSheet(f"color:{TEXT_DIM};")
        root.addWidget(t); root.addWidget(d)

        self.status_card = Card("PROVIDER STATUS")
        self.status_table = make_table(["Provider", "State"], stretch_cols=[0])
        self.status_card.add(self.status_table)
        root.addWidget(self.status_card)

        self.ioc_card = Card("LOCAL IOC DATABASE (from analyzed cases)")
        self.ioc_table = make_table(["Type", "Value", "Severity", "Case"],
                                    stretch_cols=[1])
        self.ioc_card.add(self.ioc_table)
        root.addWidget(self.ioc_card, 1)

    def refresh(self):
        self.status_table.setRowCount(0)
        summary = self.app_ctx.provider_summary
        for name, state in (summary or {}).items():
            color = "#3fb950" if state == "CONFIGURED" else "#8b949e"
            add_table_row(self.status_table, [name, state], colors_by_col={1: color})
        self.ioc_table.setRowCount(0)
        try:
            rows = self.app_ctx.db.query(
                "SELECT type, value, severity, case_id FROM iocs ORDER BY id DESC LIMIT 200")
            for r in rows:
                sev_color = {"SUSPICIOUS": "#d29922", "CRITICAL": "#e5484d"}.get(
                    r["severity"], "#58a6ff")
                add_table_row(self.ioc_table,
                              [r["type"], r["value"], r["severity"], r["case_id"] or "-"],
                              colors_by_col={2: sev_color})
        except Exception:
            pass
