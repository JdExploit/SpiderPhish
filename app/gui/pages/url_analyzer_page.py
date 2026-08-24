"""URL Analyzer page: local heuristics + real redirect trace + URLScan."""
from __future__ import annotations

import httpx

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                               QPushButton, QSplitter, QVBoxLayout, QWidget)

from app.core.logging_setup import get_logger
from app.gui.theme import TEXT_DIM
from app.gui.widgets.common import Card, KVCard, SeverityBadge, add_table_row, make_table
from app.gui.workers import SimpleWorker
from app.utils.net import SafeClient
from app.utils.url_heuristics import score_url

log = get_logger("gui.url")


class _IntelBase(QWidget):
    def __init__(self, app_ctx):
        super().__init__()
        self.app_ctx = app_ctx
        self._worker = None

    def run_async(self, coro_fn, *args):
        if self._worker and self._worker.isRunning():
            return
        self._worker = SimpleWorker(coro_fn, *args, parent=self)
        self._worker.result_ready.connect(self.on_result)
        self._worker.failed.connect(self.on_failed)
        self._worker.start()

    def on_failed(self, err: str):
        QMessageBox.critical(self, "Error", err)


class UrlAnalyzerPage(_IntelBase):
    def __init__(self, app_ctx):
        super().__init__(app_ctx)
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        t = QLabel("URL ANALYZER")
        t.setStyleSheet("font-size:14pt; font-weight:800;")
        d = QLabel("Heurística local + cadena de redirecciones real + "
                   "reputación URLScan.io si está configurada.")
        d.setStyleSheet(f"color:{TEXT_DIM};")
        root.addWidget(t); root.addWidget(d)

        row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/path")
        self.btn = QPushButton("ANALYZE URL"); self.btn.setObjectName("Primary")
        row.addWidget(self.url_input, 1); row.addWidget(self.btn)
        root.addLayout(row)

        split = QSplitter(Qt.Horizontal)
        left = QWidget(); ll = QVBoxLayout(left); ll.setContentsMargins(0,0,0,0)
        self.info_card = KVCard("RESULT", [])
        ll.addWidget(self.info_card); ll.addStretch()
        safety_card = Card("BROWSER SAFETY CHECK — CAN I OPEN THIS URL?")
        self.safety_badge = SeverityBadge("UNKNOWN")
        self.safety_note = QLabel("Introduce una URL y analízala.")
        self.safety_note.setWordWrap(True)
        self.safety_note.setStyleSheet(f"color:{TEXT_DIM}; font-size:8.5pt;")
        sandbox_btn = QPushButton("Open in isolated environment")
        sandbox_btn.setEnabled(False)
        sandbox_btn.setToolTip("Requiere integración con sandbox en Settings")
        sl = QVBoxLayout(); sl.addWidget(self.safety_badge)
        sl.addWidget(self.safety_note); sl.addWidget(sandbox_btn)
        safety_card.add_layout(sl); ll.addWidget(safety_card)
        split.addWidget(left)

        right = QWidget(); rl = QVBoxLayout(right); rl.setContentsMargins(0,0,0,0)
        chain_card = Card("REDIRECT CHAIN (real HTTP trace)")
        from app.gui.widgets.redirect_flow import RedirectFlowView
        self.flow_view = RedirectFlowView()
        chain_card.add(self.flow_view)
        self.chain_view = make_table(
            ["#", "Status", "URL", "Server", "Location"], stretch_cols=[2])
        chain_card.add(self.chain_view); rl.addWidget(chain_card)
        scan_card = Card("URLSCAN.IO")
        self.scan_card = KVCard("", [])
        self.scan_card.body.parentWidget().hide() if False else None
        scan_card.add(self.scan_card)
        rl.addWidget(scan_card); rl.addStretch()
        split.addWidget(right)
        split.setSizes([430, 800])
        root.addWidget(split, 1)

        self.btn.clicked.connect(self.analyze)

    # ------------------------------------------------------------------
    def _set_busy(self, busy: bool) -> None:
        self.btn.setEnabled(not busy)
        self.btn.setText("ANALYZING…" if busy else "ANALYZE URL")

    def analyze(self):
        url = self.url_input.text().strip()
        if not url:
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.url_input.setText(url)

        settings_a = self.app_ctx.settings.analysis

        async def job(u: str):
            out = {}
            out["score"], out["flags"] = score_url(u)
            try:
                with SafeClient(settings_a) as safe:
                    red = await self.app_ctx.redirect_analyzer.trace(u, safe.client)
                out["redirect"] = {"status": red["status"].value,
                                   "error": red.get("error", ""),
                                   "hops": [h.model_dump() for h in red.get("hops", [])],
                                   "final": red.get("final_url", u)}
            except Exception as e:  # noqa: BLE001
                out["redirect"] = {"status": "ERROR",
                                   "error": f"{type(e).__name__}: {e}",
                                   "hops": [], "final": u}
            try:
                async with httpx.AsyncClient(timeout=max(settings_a.timeout_seconds, 30),
                                             verify=settings_a.verify_tls) as client:
                    prov = self.app_ctx.registry.urlscan
                    out["urlscan"] = await prov.lookup_url(u, client) \
                        if prov.is_configured() else None
            except Exception as e:  # noqa: BLE001
                out["urlscan"] = {"status": "ERROR", "error": str(e)}
            return out

        log.info("Analyzing URL: %s", url)
        self._set_busy(True)
        self.info_card.set_rows([("Status", "Tracing redirects + querying URLScan.io…")])
        self.scan_card.set_rows([("URLScan.io",
                                  "Esperando resultado (puede tardar ~1-2 min)…")])
        self.run_async(job, url)

    def on_failed(self, err: str):
        self._set_busy(False)
        QMessageBox.critical(self, "Error", err)

    def on_result(self, res):  # noqa: ANN001
        self._set_busy(False)
        score, flags = res.get("score", 0), res.get("flags", [])
        scan = res.get("urlscan")
        scan_ok = isinstance(scan, dict)
        scan_malicious = bool(scan_ok and scan.get("malicious"))
        scan_suspicious = bool(scan_ok and scan.get("suspicious"))
        if scan_malicious:
            level = "MALICIOUS"
            score = max(score, 85)
        elif scan_suspicious:
            level = "SUSPICIOUS"
            score = max(score, 40)
        else:
            level = ("MALICIOUS" if score >= 80 else "HIGH" if score >= 60 else
                     "SUSPICIOUS" if score >= 40 else "LOW" if score >= 15 else "SAFE")
        red = res.get("redirect") or {}
        self.info_card.set_rows([
            ("Heuristic risk", f"{score}/100 ({level})"),
            ("Flags", "\n".join(flags) or "-"),
            ("Redirect status", red.get("status", "?")),
            ("Final destination", red.get("final") or "-"),
        ])
        if score >= 60:
            self.safety_badge.set_severity("CRITICAL"); self.safety_badge.setText("DO NOT OPEN")
            note = ("The URL should not be opened in your normal browser.\n"
                    "Use an isolated sandbox or analysis environment.")
        elif score >= 40:
            self.safety_badge.set_severity("SUSPICIOUS"); self.safety_badge.setText("NOT RECOMMENDED")
            note = "Riesgo moderado: abrir solo en entorno aislado."
        else:
            self.safety_badge.set_severity("SAFE"); self.safety_badge.setText("SAFE TO OPEN")
            note = "Sin indicadores de riesgo conocidos."
        self.safety_note.setText(note)

        self.chain_view.setRowCount(0)
        self.flow_view.set_hops(red.get("hops", []))
        for h in red.get("hops", []):
            add_table_row(self.chain_view, [
                str(h.get("step")), str(h.get("status_code") or "META"),
                h.get("url"), h.get("server") or "-", h.get("location") or "-"])
        scan = res.get("urlscan")
        if scan is None:
            self.scan_card.set_rows([("URLScan.io",
                                      "NOT CONFIGURED — requiere API key (Settings → API Configuration)")])
        else:
            st = getattr(scan.get("status"), "value", scan.get("status"))
            if str(st).upper() == "INFO":
                rows = [
                    ("Verdict", "MALICIOUS" if scan.get("malicious")
                     else "SUSPICIOUS" if scan.get("suspicious") else "CLEAN"),
                    ("Score", str(scan.get("score"))),
                    ("IP / ASN", f"{scan.get('ip') or '-'} · {scan.get('asn') or '-'}"),
                    ("Country", scan.get("country") or "-"),
                    ("Server", scan.get("server") or "-"),
                    ("HTTP requests", str(scan.get("http_requests", 0))),
                    ("Screenshot", scan.get("screenshot_url", "")),
                ]
                if scan.get("uuid"):
                    rows.append(("Scan report",
                                 f"https://urlscan.io/result/{scan['uuid']}/"))
                self.scan_card.set_rows(rows)
            else:
                self.scan_card.set_rows([("URLScan.io",
                                          scan.get("error") or f"error ({st})")])
        if scan_ok and str(st).upper() == "INFO":
            self.flow_view.set_urlscan_redirects(scan.get("redirects") or [])
        log.info("URL analysis finished: %s (%d/100)", self.url_input.text(), score)
