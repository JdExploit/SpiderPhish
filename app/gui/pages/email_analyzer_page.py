"""EMAIL ANALYZER page - the core feature."""
from __future__ import annotations

import json
from datetime import datetime

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout,
    QHeaderView, QLabel, QMessageBox, QProgressBar, QPushButton, QSplitter,
    QStackedWidget, QTabWidget, QTextEdit, QVBoxLayout, QWidget, QFrame)

from app.core.logging_setup import get_logger
from app.gui.theme import (ACCENT, GREEN, PANEL2, RED, TEXT, TEXT_DIM, YELLOW)
from app.gui.widgets.common import (
    Card, EmptyState, KVCard, RiskBar, SeverityBadge, add_table_row,
    copy_button, make_table)
from app.gui.workers import AnalysisWorker

log = get_logger("gui.email")


class PasteDialog(QDialog):
    def __init__(self, title: str, hint: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 520)
        lay = QVBoxLayout(self)
        hint_l = QLabel(hint)
        hint_l.setWordWrap(True)
        hint_l.setStyleSheet(f"color:{TEXT_DIM};")
        lay.addWidget(hint_l)
        self.edit = QTextEdit()
        self.edit.setPlaceholderText("Paste here...")
        font = QFont("Consolas", 9)
        self.edit.setFont(font)
        lay.addWidget(self.edit)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)


class VerdictCard(QFrame):
    """Big final verdict card (spec 37)."""

    def __init__(self):
        super().__init__()
        self.setObjectName("Card")
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignCenter)
        lay.setSpacing(6)

        self.icon_label = QLabel("\u26a0")
        self.icon_label.setAlignment(Qt.AlignCenter)
        self.icon_label.setStyleSheet("font-size:30pt;")
        self.verdict_label = QLabel("NO ANALYSIS YET")
        f = QFont()
        f.setBold(True)
        f.setPointSize(16)
        self.verdict_label.setFont(f)
        self.verdict_label.setAlignment(Qt.AlignCenter)
        self.sub_label = QLabel("Import or paste an email and press Analyze")
        self.sub_label.setAlignment(Qt.AlignCenter)
        self.score_label = QLabel("-- / 100")
        sf = QFont()
        sf.setBold(True)
        sf.setPointSize(13)
        self.score_label.setFont(sf)
        self.score_label.setAlignment(Qt.AlignCenter)
        self.riskbar = RiskBar()
        self.badge = SeverityBadge("NOT ANALYZED")

        lay.addWidget(self.icon_label)
        lay.addWidget(self.verdict_label)
        lay.addWidget(self.sub_label)
        lay.addWidget(self.riskbar)
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(self.score_label)
        row.addSpacing(10)
        row.addWidget(self.badge)
        row.addStretch()
        lay.addLayout(row)

    def set_analysis(self, a) -> None:
        band = a.risk.band.value
        score = a.risk.score
        color = RED if score >= 60 else YELLOW if score >= 40 else GREEN if score < 20 else YELLOW
        icon = "\u2715" if score >= 80 else ("\u26a0" if score >= 40 else "\u2713")
        self.icon_label.setText(icon)
        self.icon_label.setStyleSheet(f"font-size:30pt; color:{color};")
        self.verdict_label.setText(a.risk.verdict or band)
        self.verdict_label.setStyleSheet(f"color:{color}; font-size:16pt; font-weight:800;")
        self.sub_label.setText(
            f"Risk band: {band}" + ("  ·  DEMO MODE" if a.demo_mode else ""))
        self.sub_label.setStyleSheet(f"color:{TEXT_DIM};")
        self.score_label.setText(f"{score} / 100")
        self.score_label.setStyleSheet(f"color:{color};")
        self.badge.set_severity(band.replace(" / MALICIOUS", ""))
        self.badge.setText(band.split(" /")[0])
        self.badge.setStyleSheet(
            f"background:{color}; color:#0a0c0e; font-weight:800;"
            f"font-size:9pt; letter-spacing:1px; border-radius:3px; padding:3px 12px;")


class EmailAnalyzerPage(QWidget):
    def __init__(self, app_ctx):
        super().__init__()
        self.app_ctx = app_ctx          # holds settings/registry/db/analyzer
        self._analysis = None
        self._raw_bytes = b""
        self._worker = None

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        root.setSpacing(8)

        # ---------------- Header -------------------------
        head = QHBoxLayout()
        title_box = QVBoxLayout()
        t = QLabel("EMAIL ANALYZER")
        t.setObjectName("CardTitle")
        t.setStyleSheet("font-size:14pt; font-weight:800; letter-spacing:1px;")
        d = QLabel("Analiza correos sospechosos, extrae cabeceras, IOCs, URLs,\n"
                   "reputación y genera un veredicto de riesgo.")
        d.setStyleSheet(f"color:{TEXT_DIM}; font-size:9pt;")
        title_box.addWidget(t)
        title_box.addWidget(d)
        head.addLayout(title_box)
        head.addStretch()

        self.btn_import = QPushButton("\u2192  Importar .eml")
        self.btn_headers = QPushButton("\u270e  Pegar cabeceras")
        self.btn_paste = QPushButton("\u29c9  Pegar correo")
        self.btn_analyze = QPushButton("ANALIZAR CORREO")
        self.btn_analyze.setObjectName("Primary")
        for i, b in enumerate((self.btn_import, self.btn_headers, self.btn_paste)):
            head.addWidget(b)
        head.addWidget(self.btn_analyze)

        self.btn_import.setToolTip("Importar archivo .eml o .msg exportado como texto (Ctrl+O)")
        self.btn_analyze.setToolTip("Ejecutar el análisis completo (Ctrl+Enter)")

        root.addLayout(head)

        # progress row
        prow = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setVisible(False)
        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet(f"color:{TEXT_DIM}; font-size:8.5pt;")
        prow.addWidget(self.progress, 1)
        prow.addWidget(self.status_lbl)
        root.addLayout(prow)

        # ---------------- Splitter: left info | right tabs --------------
        split = QSplitter(Qt.Horizontal)
        root.addWidget(split, 1)

        # LEFT column -----------------------------------------------------
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(8)

        self.verdict_card = VerdictCard()
        why_btn = QPushButton("WHY?")
        why_btn.setToolTip("Ver exactamente qué indicadores produjeron el score")
        why_btn.clicked.connect(self._show_why)
        vc_lay = QVBoxLayout()
        vc_lay.addWidget(self.verdict_card)
        wrow = QHBoxLayout()
        wrow.addStretch()
        wrow.addWidget(copy_button(lambda: json.dumps({
            "verdict": self._analysis.risk.verdict if self._analysis else "",
            "score": self._analysis.risk.score if self._analysis else 0}, indent=2),
            "Copy verdict"))
        wrow.addWidget(why_btn)
        vc_lay.addLayout(wrow)
        ll.addLayout(vc_lay)

        self.email_card = KVCard("EMAIL INFORMATION", [])
        self.auth_card = KVCard("AUTHENTICATION", [])
        self.ip_card = KVCard("ORIGIN IP & REPUTATION", [])
        for c in (self.email_card, self.auth_card, self.ip_card):
            ll.addWidget(c)

        self.reco_card = Card("RECOMMENDATIONS")
        ll.addWidget(self.reco_card)
        ll.addStretch()

        scroll_left = _ScrollArea(left)
        split.addWidget(scroll_left)

        # RIGHT column (tabs) ----------------------------------------------
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.tabs = QTabWidget()
        rl.addWidget(self.tabs)

        self.stack = QStackedWidget()
        empty = EmptyState("\u2709", "No email loaded",
                           "Use [Importar .eml] o pega las cabeceras/correo para comenzar.")
        self.stack.addWidget(empty)   # index 0
        content = QWidget()           # index 1 - real tabs
        cl = QVBoxLayout(content)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.addWidget(self.tabs)
        self.stack.addWidget(content)
        self.stack.setCurrentIndex(0)

        right_wrap = QWidget()
        rwl = QVBoxLayout(right_wrap)
        rwl.setContentsMargins(0, 0, 0, 0)
        rwl.addWidget(self.stack)
        split.addWidget(right_wrap)

        split.setSizes([430, 900])

        # Tabs content
        self.txt_raw = self._mono_view()
        self.txt_headers = self._mono_view()
        self.txt_results_original = self._mono_view()
        self.txt_routing = self._mono_view()
        self.tab_auth_table = make_table(
            ["Mechanism", "Result", "Domain", "Status"], stretch_cols=[1])
        self.tab_ioc_table = make_table(["Type", "Value", "Severity"], stretch_cols=[1])
        self.tab_url_table = make_table(
            ["URL", "Domain", "Redirects", "Final destination", "Score",
             "Risk"], stretch_cols=[0, 3])

        self.tabs.addTab(self._wrap_copy(self.txt_headers, "Headers"), "Headers")
        self.tabs.addTab(self._wrap_copy(self.txt_results_original, "Results-Original"),
                         "Results-Original")
        self.tabs.addTab(self._wrap_copy(self.txt_raw, "Raw Source"), "Raw Source")
        auth_w = QWidget()
        al = QVBoxLayout(auth_w)
        al.setContentsMargins(4, 4, 4, 4)
        al.addWidget(self.tab_auth_table)
        self.tabs.addTab(self._wrap_generic(auth_w), "Authentication")
        route_w = QWidget()
        rul = QVBoxLayout(route_w)
        rul.setContentsMargins(4, 4, 4, 4)
        rul.addWidget(self.txt_routing)
        self.tabs.addTab(self._wrap_generic(route_w), "Routing")
        ioc_w = QWidget()
        il = QVBoxLayout(ioc_w)
        il.setContentsMargins(4, 4, 4, 4)
        ioc_btns = QHBoxLayout()
        ioc_btns.addStretch()
        ioc_btns.addWidget(copy_button(self._copy_iocs_all, "Copy All IOCs"))
        il.addLayout(ioc_btns)
        il.addWidget(self.tab_ioc_table)
        self.tabs.addTab(self._wrap_generic(ioc_w), "IOCs")
        url_w = QWidget()
        ul = QVBoxLayout(url_w)
        ul.setContentsMargins(4, 4, 4, 4)
        self.url_detail = QLabel("")
        self.url_detail.setWordWrap(True)
        self.url_detail.setStyleSheet(f"color:{TEXT_DIM}; font-size:8.5pt;")
        self.url_detail.setVisible(False)
        ul.addWidget(self.tab_url_table, 1)
        ul.addWidget(self.url_detail)
        self.tabs.addTab(self._wrap_generic(url_w), "URLs")

        # wire buttons
        self.btn_import.clicked.connect(self.import_eml)
        self.btn_headers.clicked.connect(self.paste_headers)
        self.btn_paste.clicked.connect(self.paste_email)
        self.btn_analyze.clicked.connect(self.start_analysis)
        self.tab_url_table.itemSelectionChanged.connect(self._url_selected)

        self._update_buttons()

    # ------------------------------------------------------------------ helpers
    def _mono_view(self) -> QTextEdit:
        v = QTextEdit()
        v.setReadOnly(True)
        v.setFont(QFont("Consolas", 8))
        v.setStyleSheet(f"background:#07090b; border:1px solid {PANEL2};")
        return v

    def _wrap_copy(self, widget: QWidget, name: str) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(4, 4, 4, 4)
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(copy_button(lambda: widget.toPlainText(), f"Copy {name}"))
        l.addLayout(row)
        l.addWidget(widget, 1)
        return w

    def _wrap_generic(self, widget: QWidget) -> QWidget:
        return widget

    def _copy_iocs_all(self):
        if not self._analysis:
            return ""
        return "\n".join(f"{i.type.value}: {i.value}" for i in self._analysis.iocs)

    def _update_buttons(self):
        has = bool(self._raw_bytes)
        self.btn_analyze.setEnabled(has)
        self.btn_analyze.setToolTip("" if has else
                                    "Primero importa o pega un correo")

    # ------------------------------------------------------------------ input
    def import_eml(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Importar correo", "", "Email files (*.eml *.msg *.txt);;All files (*)")
        if not path:
            return
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            # crude .msg guard: OLE files are not RFC822; warn but try text decode
            if path.lower().endswith(".msg") and data[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                pass
            if data[:8] == bytes.fromhex("d0cf11e0a1b11ae1"):
                QMessageBox.warning(
                    self, ".MSG binary",
                    "El archivo .msg es un contenedor OLE binario.\n"
                    "Ábrelo en Outlook y usa 'Guardar como .eml' o copia las cabeceras.")
                return
            self._set_source(data, f"Loaded {path}")
        except OSError as e:
            QMessageBox.critical(self, "Error", f"No se pudo leer el archivo:\n{e}")

    def paste_headers(self):
        dlg = PasteDialog("Pegar cabeceras",
                          "Pega solo las cabeceras del correo (From, Received, "
                          "Authentication-Results...). Se analizarán sin el cuerpo.")
        if dlg.exec() == QDialog.Accepted and dlg.edit.toPlainText().strip():
            self._set_source(dlg.edit.toPlainText().encode("utf-8", "replace"),
                             "Headers pasted from clipboard")

    def paste_email(self):
        dlg = PasteDialog("Pegar correo completo",
                          "Pega el correo completo incluyendo cabeceras y cuerpo.")
        if dlg.exec() == QDialog.Accepted and dlg.edit.toPlainText().strip():
            self._set_source(dlg.edit.toPlainText().encode("utf-8", "replace"),
                             "Full email pasted from clipboard")

    def _set_source(self, raw: bytes, msg: str):
        self._raw_bytes = raw
        self._analysis = None
        self.txt_raw.setPlainText(raw.decode("utf-8", errors="replace"))
        self.stack.setCurrentIndex(0)
        log.info(msg + f" ({len(raw):,} bytes)")
        self._update_buttons()

    # ------------------------------------------------------------------ analysis
    def start_analysis(self):
        if not self._raw_bytes:
            return
        if self._worker and self._worker.isRunning():
            return
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.status_lbl.setText("Analyzing...")
        self.btn_analyze.setEnabled(False)
        case_id = self.app_ctx.db.next_case_id()
        self._worker = AnalysisWorker(self.app_ctx.analyzer, self._raw_bytes, case_id)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished_ok.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        log.info(f"Starting email analysis [{case_id}]...")
        self._worker.start()

    def _on_progress(self, pct: int, msg: str):
        self.progress.setValue(pct)
        self.status_lbl.setText(f"Analyzing... {pct}% — {msg}")
        if pct >= 100:
            self.status_lbl.setText("Analysis completed")

    def _on_failed(self, err: str):
        self.progress.setVisible(False)
        self.btn_analyze.setEnabled(True)
        QMessageBox.critical(self, "Analysis failed", err)

    def _on_finished(self, analysis):
        self._analysis = analysis
        self.progress.setVisible(False)
        self.btn_analyze.setEnabled(True)
        self.stack.setCurrentIndex(1)
        self._render(analysis)
        self.app_ctx.analysis_ready.emit(analysis)
        self.app_ctx.save_case_suggested.emit(analysis.case_id)

    # ------------------------------------------------------------------ render
    def _render(self, a):
        self.verdict_card.set_analysis(a)

        # email info card
        self.email_card.set_rows([
            ("Remitente", f"{a.from_display} <{a.from_addr}>" if a.from_display
             else a.from_addr),
            ("Sender", a.sender or "-"),
            ("Return-Path", a.return_path or "-"),
            ("Reply-To", a.reply_to or "-"),
            ("Destinatario", a.to_addrs or "-"),
            ("Asunto", a.subject or "-"),
            ("Fecha", a.date or "-"),
            ("Message-ID", a.message_id or "-"),
            ("Tamaño", f"{a.size_bytes:,} bytes"),
            ("Formato", a.format),
        ])

        # identity indicators appended to auth card
        rows = []
        for r, lbl in ((a.authentication.spf, "SPF"),
                       (a.authentication.dkim, "DKIM"),
                       (a.authentication.dmarc, "DMARC")):
            status = "PASS" if r.result == "pass" else \
                (r.result.upper() if r.result not in ("none", "") else "N/D")
            rows.append((lbl, status + (f" · {r.domain}" if r.domain else "")))
        for ind in a.identity_indicators:
            rows.append((ind.label, ind.status.value +
                         (f" — {ind.detail}" if ind.detail else "")))
        self.auth_card.set_rows(rows)

        # IP card
        ipr = a.ip_reputation
        ip_rows = [
            ("Origin IP", a.origin_ip.ip or "Not determined"),
            ("Source", a.origin_ip.source_header or "-"),
            ("Confidence", f"{int(a.origin_ip.confidence * 100)}%"),
            ("Tipo", a.ip_classification.classification),
            ("Reverse DNS/PTR", a.ip_classification.reverse_dns or "-"),
            ("ASN", a.ip_classification.asn_number or ipr.asn or "-"),
            ("Org/ISP", a.ip_classification.asn_org or ipr.isp or "-"),
            ("Country", ipr.country or a.ip_classification.country or "-"),
        ]
        if ipr.score is not None:
            band = ipr.band.value
            ip_rows.append(("ABUSEIPDB SCORE", f"{ipr.score} / 100  →  {band}"
                            + ("  [DEMO]" if ipr.demo else "")))
            if ipr.total_reports is not None:
                ip_rows.append(("Total Reports", str(ipr.total_reports)))
                ip_rows.append(("Last Report", ipr.last_report or "-"))
                ip_rows.append(("Usage Type", ipr.usage_type or "-"))
                if ipr.categories:
                    ip_rows.append(("Categories", ", ".join(ipr.categories)))
        elif ipr.error:
            ip_rows.append(("AbuseIPDB", ipr.error))
        self.ip_card.set_rows(ip_rows)
        self.ip_card.setTitle("ORIGIN IP & REPUTATION" +
                              ("" if ipr.score is None else
                               f"   [{ipr.provider}]"))

        # recommendations card
        while self.reco_card.body.count() > 1:
            item = self.reco_card.body.takeAt(1)
            if item.widget():
                item.widget().deleteLater()
        for rec in a.recommendations:
            lbl = QLabel(f"<b style='color:{RED if rec.priority.value in ('CRITICAL','HIGH') else YELLOW if rec.priority.value=='SUSPICIOUS' else '#58a6ff'}'>"
                         f"[{rec.priority.value}]</b> {rec.title}<br/>"
                         f"<span style='color:{TEXT_DIM};'>{rec.detail}</span>")
            lbl.setWordWrap(True)
            self.reco_card.add(lbl)

        # headers tab
        hdr_lines = []
        for h in a.headers:
            hdr_lines.append(f"{h.name}: {h.value}")
        self.txt_headers.setPlainText("\n".join(hdr_lines))

        # results-original tab (Microsoft / antispam specific)
        ms_prefixes = ("X-MS-", "X-Forefront", "X-Microsoft", "ARC-",
                       "Received-SPF", "Authentication-Results", "X-Originating-IP")
        ro_lines = [f"{h.name}: {h.value}" for h in a.headers
                    if h.name.startswith(ms_prefixes)]
        self.txt_results_original.setPlainText("\n\n".join(ro_lines) or
                                               "No Results-Original/Microsoft headers found.")

        # routing tab (SOURCE -> ... -> RECIPIENT visual)
        lines = []
        hops = a.origin_ip.hops
        if hops:
            lines.append("SOURCE IP")
            first_pub = next((h.from_ip for h in hops if h.from_ip and "." in h.from_ip),
                             a.origin_ip.ip or "?")
            lines.append(f"   {first_pub}")
            lines.append("      ↓")
            for h in hops:
                arrow = "->"
                tls = f" [{h.tls}]" if h.tls else ""
                lines.append(f"[{h.index:02d}] {h.from_host or '?'} {arrow} "
                             f"{h.by_host or '?'} via {h.with_proto or '?'}{tls}")
                lines.append(f"     connecting IP: {h.from_ip or '-'}   {h.date}")
                lines.append("      ↓")
            lines.append("RECIPIENT")
            lines.append(f"   {a.delivered_to or a.to_addrs or '?'}")
        else:
            lines.append("(no Received chain found)")
        self.txt_routing.setPlainText("\n".join(lines))

        # raw source already set on load

        # auth table
        self.tab_auth_table.setRowCount(0)
        for r, st_color in (
                (a.authentication.spf, GREEN if a.authentication.spf.result == "pass" else RED),
                (a.authentication.dkim, GREEN if a.authentication.dkim.result == "pass" else RED),
                (a.authentication.dmarc, GREEN if a.authentication.dmarc.result == "pass" else RED)):
            add_table_row(self.tab_auth_table,
                          [r.mechanism.upper(), (r.result or "none").upper(),
                           r.domain or "-", "MATCH" if r.result == "pass" else
                           (r.result.upper() if r.result else "UNKNOWN")],
                          colors_by_col={3: st_color})

        # IOCs
        self.tab_ioc_table.setRowCount(0)
        sev_colors = {"SUSPICIOUS": YELLOW, "INFO": "#58a6ff"}
        for ioc in a.iocs:
            add_table_row(self.tab_ioc_table,
                          [ioc.type.value, ioc.value, ioc.severity.value],
                          colors_by_col={2: sev_colors.get(ioc.severity.value, TEXT_DIM)})

        # URLs
        self.tab_url_table.setRowCount(0)
        for u in a.urls:
            risk_color = RED if u.risk_level.value in ("HIGH", "CRITICAL", "MALICIOUS") \
                else YELLOW if u.risk_level.value == "SUSPICIOUS" else GREEN
            add_table_row(
                self.tab_url_table,
                [u.url[:110], u.domain, str(u.redirect_count),
                 (u.final_url[:70] + "...") if len(u.final_url) > 73 else u.final_url,
                 str(u.risk_score), u.risk_level.value],
                colors_by_col={5: risk_color},
                data=u)

        self.app_ctx.log_console_append(
            datetime.now().strftime("%H:%M:%S"), "INFO",
            f"UI updated — verdict: {a.risk.band.value} ({a.risk.score}/100)")

    def _url_selected(self):
        sel = self.tab_url_table.selectedItems()
        if not sel or not self._analysis:
            return
        row = sel[0].row()
        item = self.tab_url_table.item(row, 0)
        u = item.data(Qt.UserRole)
        if not u:
            return
        safety = self._analysis.browser_safety.get(u.url, "UNKNOWN")
        verdict_txt = {"MALICIOUS": ("DO NOT OPEN", RED),
                       "CRITICAL": ("DO NOT OPEN", RED),
                       "SUSPICIOUS": ("NOT RECOMMENDED", YELLOW),
                       "SAFE": ("SAFE TO OPEN", GREEN),
                       "UNKNOWN": ("UNKNOWN RISK", TEXT_DIM)}.get(safety.value,
                                                                  ("UNKNOWN RISK", TEXT_DIM))
        flags = "; ".join(u.flags) or "-"
        chain = "\n".join(
            f"  {h.step}. [{h.status_code or 'META'}] {h.url}" +
            (f" -> {h.location}" if h.location else "")
            for h in u.redirect_chain) or "  (not traced)"
        sandbox_note = ("\n\nThe URL should not be opened in your normal browser. "
                        "Use an isolated sandbox or analysis environment."
                        if verdict_txt[0] == "DO NOT OPEN" else "")
        self.url_detail.setVisible(True)
        self.url_detail.setText(
            f"BROWSER SAFETY: {verdict_txt[0]}   [{safety.value}]{sandbox_note}\n"
            f"Flags: {flags}\nRedirect chain:\n{chain}")

    # ------------------------------------------------------------------ WHY dialog
    def _show_why(self):
        if not self._analysis:
            return
        a = self._analysis
        dlg = QDialog(self)
        dlg.setWindowTitle(f"WHY? — Risk factors ({a.risk.score}/100)")
        dlg.resize(620, 480)
        lay = QVBoxLayout(dlg)
        txt = QTextEdit()
        txt.setReadOnly(True)
        lines = []
        factors = a.risk.why
        if factors:
            for f in sorted(factors, key=lambda x: -x.points):
                lines.append(f"+{f.points:>3}  {f.name}")
                if f.detail:
                    lines.append(f"       {f.detail}")
        else:
            lines.append("No positive risk factors were triggered.")
        txt.setPlainText("\n".join(lines))
        f = QFont("Consolas", 9)
        txt.setFont(f)
        lay.addWidget(txt)
        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.rejected.connect(dlg.reject)
        bb.accepted.connect(dlg.accept)
        lay.addWidget(bb)
        dlg.exec()


class _ScrollArea(QFrame):
    """Simple scrollable container with transparent background."""

    def __init__(self, inner: QWidget):
        from PySide6.QtWidgets import QScrollArea
        super().__init__()
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        sa.setWidget(inner)
        sa.setFrameShape(QFrame.NoFrame)
        sa.setStyleSheet("QScrollArea { background: transparent; }")
        l = QVBoxLayout(self)
        l.setContentsMargins(0, 0, 0, 0)
        l.addWidget(sa)
