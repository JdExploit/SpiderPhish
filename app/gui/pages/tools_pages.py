"""Tools pages: Browser Safety, Phishing Templates knowledge base, Case Reports."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (QDialog, QFileDialog, QHBoxLayout, QLabel,
                               QMessageBox, QPushButton, QVBoxLayout, QWidget)

from app.core.logging_setup import get_logger
from app.gui.theme import RED, TEXT_DIM
from app.gui.widgets.common import (Card, KVCard, SeverityBadge,
                                    add_table_row, make_table)

log = get_logger("gui.tools")


class BrowserSafetyPage(QWidget):
    """CAN I OPEN THIS URL? — evaluates without ever auto-opening."""

    def __init__(self, app_ctx):
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        t = QLabel("BROWSER SAFETY CHECK")
        t.setStyleSheet("font-size:14pt; font-weight:800;")
        d = QLabel("CAN I OPEN THIS URL? — evalúa la URL y decide si es seguro "
                   "abrirla en tu navegador normal. Nunca abre URLs peligrosas.")
        d.setStyleSheet(f"color:{TEXT_DIM};"); root.addWidget(t); root.addWidget(d)
        self.info = KVCard("HOW IT WORKS", [
            ("SAFE TO OPEN", "Sin indicadores conocidos de riesgo."),
            ("NOT RECOMMENDED", "Indicadores sospechosos: abrir solo si es "
             "estrictamente necesario y en entorno controlado."),
            ("DO NOT OPEN", "URL maliciosa o de alto riesgo. No abrir en el "
             "navegador principal."),
            ("UNKNOWN / NOT ANALYZED", "Sin datos suficientes. No se asume seguro."),
            ("Nota", "'Open in isolated environment' requiere integración con "
             "sandbox (futura versión)."),
        ])
        root.addWidget(self.info)
        root.addStretch()


class PhishingTemplatesPage(QWidget):
    """Knowledge base of phishing patterns the engine detects."""

    PATTERNS = [
        ("Microsoft impersonation", "Lookalike domains (micros0ft, microsoft-login), "
         "display-name spoofing, OAuth consent phishing con branding M365."),
        ("Google impersonation", "Gmail security alerts falsos, lookalikes "
         "(g00gle, google-verify), Google Drive abuse."),
        ("Bank impersonation", "'Cuenta bloqueada', 'transacción sospechosa', "
         "formularios de verificación de tarjeta."),
        ("MFA phishing", "Solicitudes de códigos 2FA, fake authenticator login pages."),
        ("Credential harvesting", "Paths tipo /login, /verify, /password con "
         "campos de contraseña."),
        ("Password reset phishing", "'Su contraseña expira', reset links externos."),
        ("Invoice fraud", "Adjuntos PDF/DOC con facturas, cambio de cuenta bancaria."),
        ("Delivery phishing", "DHL/FedEx/UPS falsos, fees aduaneros, tracking falso."),
        ("QR phishing (quishing)", "Imágenes QR que ocultan URLs maliciosas."),
        ("OAuth phishing", "Páginas de consentimiento para robar tokens."),
        ("BEC / CEO fraud", "Urgencia + confidencialidad + transferencias/gift cards."),
        ("Typosquatting / homograph", "Distancia Levenshtein baja vs marcas, "
         "punycode/IDN, caracteres cirílicos."),
    ]

    def __init__(self, app_ctx):
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        t = QLabel("PHISHING TEMPLATES / DETECTION KNOWLEDGE BASE")
        t.setStyleSheet("font-size:14pt; font-weight:800;")
        d = QLabel("Patrones que el motor de detección heurística identifica "
                   "automáticamente durante el análisis.")
        d.setStyleSheet(f"color:{TEXT_DIM};")
        root.addWidget(t); root.addWidget(d)
        table = make_table(["Pattern", "Description"], stretch_cols=[0, 1])
        for name, desc in self.PATTERNS:
            add_table_row(table, [name, desc])
        card = Card("DETECTED PATTERNS")
        card.add(table)
        root.addWidget(card, 1)


class CaseReportsPage(QWidget):
    def __init__(self, app_ctx):
        super().__init__()
        self.app_ctx = app_ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        t = QLabel("CASE REPORTS")
        t.setStyleSheet("font-size:14pt; font-weight:800;")
        d = QLabel("Casos guardados (CASE-YYYY-NNNNN). Abre, exporta a PDF o elimina.")
        d.setStyleSheet(f"color:{TEXT_DIM};")
        root.addWidget(t); root.addWidget(d)

        row = QHBoxLayout()
        self.btn_refresh = QPushButton("Refresh")
        self.btn_open = QPushButton("Open case")
        self.btn_export = QPushButton("Export PDF report")
        self.btn_delete = QPushButton("Delete case"); self.btn_delete.setObjectName("Danger")
        for b in (self.btn_refresh, self.btn_open, self.btn_export, self.btn_delete):
            row.addWidget(b)
        row.addStretch()
        root.addLayout(row)

        card = Card("SAVED CASES")
        self.table = make_table(
            ["Case ID", "Date", "Severity", "Sender", "Origin IP", "Verdict",
             "Score"], stretch_cols=[3])
        card.add(self.table)
        root.addWidget(card, 1)

        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_open.clicked.connect(self.open_case)
        self.btn_export.clicked.connect(self.export_case)
        self.btn_delete.clicked.connect(self.delete_case)

    def _selected_case_id(self) -> str:
        rows = self.table.selectionModel().selectedRows() \
            if self.table.selectionModel() else []
        if not rows:
            return ""
        return self.table.item(rows[0].row(), 0).text()

    def refresh(self):
        self.table.setRowCount(0)
        try:
            for case in self.app_ctx.db.list_cases():
                color = RED if case["risk_score"] >= 60 else \
                    "#d29922" if case["risk_score"] >= 40 else "#3fb950"
                add_table_row(self.table, [
                    case["id"], case["created_at"], case["severity"],
                    case["sender"], case["origin_ip"], case["verdict"],
                    str(case["risk_score"])], colors_by_col={6: color})
        except Exception as e:  # noqa: BLE001
            log.warning("Case refresh failed: %s", e)

    def open_case(self):
        cid = self._selected_case_id()
        if not cid:
            return
        case = self.app_ctx.db.get_case(cid)
        if not case:
            return
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Case {cid}")
        dlg.resize(700, 500)
        lay = QVBoxLayout(dlg)
        info = QLabel(
            f"<b>{case['id']}</b><br/>Date: {case['created_at']}<br/>"
            f"Analyst: {case['analyst']}<br/>Severity: {case['severity']}<br/>"
            f"Sender: {case['sender']}<br/>Origin IP: {case['origin_ip']}<br/>"
            f"Verdict: {case['verdict']} ({case['risk_score']}/100)<br/>"
            f"Tags: {', '.join(case['tags']) or '-'}<br/><br/>"
            f"<b>Notes:</b><br/>{case['notes'] or '-'}")
        info.setWordWrap(True)
        lay.addWidget(info)
        bb_layout = QHBoxLayout()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        bb_layout.addStretch(); bb_layout.addWidget(close_btn)
        lay.addLayout(bb_layout)
        dlg.exec()

    def export_case(self):
        cid = self._selected_case_id()
        if not cid:
            return
        case = self.app_ctx.db.get_case(cid)
        analysis_json = (case or {}).get("analysis_json") or {}
        if not analysis_json:
            QMessageBox.information(self, "Sin análisis",
                                    "Este caso no incluye análisis embebido.")
            return
        out, _ = QFileDialog.getSaveFileName(self, "Guardar informe PDF",
                                             f"{cid}.pdf", "*.pdf")
        if not out:
            return
        from app.models.schemas import EmailAnalysis
        from app.reports.pdf_report import generate_report
        a = EmailAnalysis.model_validate(analysis_json["analysis"])
        path = generate_report(a, out, notes=case.get("notes", ""),
                               tags=case.get("tags"))
        log.info("PDF exportado: %s", Path(path).name)
        QMessageBox.information(self, "Informe generado",
                                f"Informe PDF generado:\n{path}")

    def delete_case(self):
        cid = self._selected_case_id()
        if not cid:
            return
        if QMessageBox.question(self, "Confirmar",
                                f"¿Eliminar el caso {cid}?") == QMessageBox.Yes:
            self.app_ctx.db.delete_case(cid)
            log.info("Case deleted: %s", cid)
            self.refresh()
