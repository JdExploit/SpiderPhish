"""IOC Lookup page: query one indicator against configured providers."""
from __future__ import annotations

import ipaddress

import httpx

from PySide6.QtWidgets import (QHBoxLayout, QLabel, QLineEdit, QVBoxLayout,
                               QWidget)

from app.core.logging_setup import get_logger
from app.gui.theme import TEXT_DIM
from app.gui.widgets.common import KVCard
from app.gui.pages.url_analyzer_page import _IntelBase

log = get_logger("gui.ioc")


def classify(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if len(value) in (32, 40, 64, 128) and all(c in "0123456789abcdefABCDEF" for c in value):
        return "hash"
    if "@" in value and "." in value:
        return "email"
    if "." in value and " " not in value:
        return "domain"
    return "?"


class IOCLookupPage(_IntelBase):
    def __init__(self, app_ctx):
        super().__init__(app_ctx)
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        t = QLabel("IOC LOOKUP")
        t.setStyleSheet("font-size:14pt; font-weight:800;")
        d = QLabel("Consulta un IOC (IP / dominio / hash) contra los proveedores "
                   "configurados. Sin claves: NOT CONFIGURED.")
        d.setStyleSheet(f"color:{TEXT_DIM};")
        root.addWidget(t); root.addWidget(d)

        row = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setPlaceholderText("1.2.3.4  ·  evil-domain.com  ·  <sha256>")
        btn = QPushButton = None  # placeholder to keep linters quiet
        from PySide6.QtWidgets import QPushButton as _PB
        self.btn = _PB("LOOKUP"); self.btn.setObjectName("Primary")
        row.addWidget(self.input, 1); row.addWidget(self.btn)
        root.addLayout(row)

        self.results = KVCard(
            "PROVIDER RESULTS",
            [("Status", "Introduce un IOC y pulsa Lookup")])
        root.addWidget(self.results)
        root.addStretch()
        self.btn.clicked.connect(self.lookup)

    def lookup(self):
        value = self.input.text().strip()
        if not value:
            return
        kind = classify(value)
        reg = self.app_ctx.registry
        timeout = self.app_ctx.settings.analysis.timeout_seconds

        async def job():
            out = {"kind": kind, "rows": []}
            async with httpx.AsyncClient(timeout=timeout) as client:
                if kind == "ip":
                    out["rows"].append(("Type", "IPv4/IPv6"))
                    r = await reg.abuseipdb.lookup_ip(value, client)
                    if r.score is not None:
                        out["rows"] += [
                            ("AbuseIPDB", f"{r.score}/100 ({r.band.value})"),
                            ("Reports", str(r.total_reports)),
                            ("Country / ISP", f"{r.country} · {r.isp}"),
                            ("Usage", r.usage_type),
                        ]
                    else:
                        out["rows"].append(("AbuseIPDB", r.error or "NOT CONFIGURED"))
                    vt = await reg.virustotal.lookup_ip(value, client)
                    out["rows"].append(_fmt("VirusTotal", vt))
                    otx = await reg.otx.lookup_ip(value, client)
                    out["rows"].append(_fmt("OTX", otx,
                                            lambda x: f"{x.get('pulse_count',0)} pulses"))
                    gn = await reg.greynoise.lookup_ip(value, client)
                    out["rows"].append(_fmt("GreyNoise", gn))
                elif kind == "domain":
                    out["rows"].append(("Type", "Domain"))
                    vt = await reg.virustotal.lookup_domain(value, client)
                    out["rows"].append(_fmt("VirusTotal", vt))
                    otx = await reg.otx.lookup_domain(value, client)
                    out["rows"].append(_fmt("OTX", otx,
                                            lambda x: f"{x.get('pulse_count',0)} pulses"))
                elif kind == "hash":
                    out["rows"].append(("Type", "File hash"))
                    vt = await reg.virustotal.lookup_hash(value.lower(), client)
                    if vt.get("status").value == "INFO" and vt.get("found"):
                        out["rows"] += [
                            ("VirusTotal", f"MALICIOUS {vt.get('malicious_votes')}/"
                                           f"{vt.get('malicious_votes',0)+vt.get('undetected_votes',0)}"),
                            ("Signatures", ", ".join(vt.get("signatures", [])[:8]) or "-"),
                            ("Names", ", ".join(vt.get("names", [])) or "-"),
                        ]
                    elif vt.get("status").value == "INFO":
                        out["rows"].append(("VirusTotal", "Unknown hash (not in dataset)"))
                    else:
                        out["rows"].append(("VirusTotal", vt.get("error")))
                else:
                    out["rows"].append(("Error", "IOC no reconocido (usa IP, dominio o hash)"))
            return out

        log.info("IOC lookup [%s]: %s", kind, value)
        self.run_async(job)

    def on_result(self, res):  # noqa: ANN001
        rows = res.get("rows", [])
        self.results.set_rows(rows if rows else [("Sin resultados", "")])
        for k, v in rows:
            log.info("  %s: %s", k, str(v).replace("\n", " ")[:90])


def _fmt(name: str, result: dict, detail_fn=None) -> tuple[str, str]:
    status = getattr(result.get("status"), "value", "?")
    if status == "INFO":
        detail = detail_fn(result) if detail_fn else \
            f"malicious votes: {result.get('malicious_votes', '?')}"
        return (name, detail)
    return (name, result.get("error") or status)
