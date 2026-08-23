"""Settings pages: general settings, API configuration, logs viewer."""
from __future__ import annotations

from PySide6.QtWidgets import (QCheckBox, QDoubleSpinBox, QFileDialog,
                               QGridLayout, QGroupBox, QHBoxLayout, QLabel,
                               QLineEdit, QMessageBox, QPushButton,
                               QVBoxLayout, QWidget)

from app.config.settings import secure_store
from app.core.logging_setup import get_logger, set_log_level
from app.gui.theme import TEXT_DIM
from app.gui.widgets.common import Card

log = get_logger("gui.settings")

KEY_FIELDS = [
    ("ABUSEIPDB_API_KEY", "AbuseIPDB", "https://www.abuseipdb.com/account/api - free tier"),
    ("URLSCAN_API_KEY", "URLScan.io", "https://urlscan.io/user/profile - free tier"),
    ("VIRUSTOTAL_API_KEY", "VirusTotal", "https://www.virustotal.com/gui/my-apikey"),
    ("OTX_API_KEY", "AlienVault OTX", "https://otx.alienvault.com/settings"),
    ("GREYNOISE_API_KEY", "GreyNoise", "https://viz.greynoise.io/signup - community free"),
]


class SettingsPage(QWidget):
    def __init__(self, app_ctx):
        super().__init__()
        self.app_ctx = app_ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        t = QLabel("SETTINGS")
        t.setStyleSheet("font-size:14pt; font-weight:800;")
        root.addWidget(t)

        grid = QGridLayout()
        grid.addWidget(self._analysis_group(), 0, 0)
        grid.addWidget(self._security_group(), 0, 1)
        grid.addWidget(self._ui_group(), 1, 0)
        grid.addWidget(self._storage_group(), 1, 1)
        root.addLayout(grid)

        save_btn = QPushButton("SAVE SETTINGS")
        save_btn.setObjectName("Primary")
        save_btn.clicked.connect(self.save)
        row = QHBoxLayout(); row.addStretch(); row.addWidget(save_btn)
        root.addLayout(row); root.addStretch()
        self.load()

    def _analysis_group(self):
        g = QGroupBox("Analysis"); g.setObjectName("Card")
        a = self.app_ctx.settings.analysis
        lay = QGridLayout(g)
        self.spin_timeout = QDoubleSpinBox()
        self.spin_timeout.setRange(1.0, 120.0); self.spin_timeout.setValue(a.timeout_seconds)
        from PySide6.QtWidgets import QSpinBox
        self.spin_retries = QSpinBox(); self.spin_retries.setRange(0, 5)
        self.spin_retries.setValue(a.retries)
        self.spin_redirects = QSpinBox(); self.spin_redirects.setRange(1, 30)
        self.spin_redirects.setValue(a.max_redirects)
        self.spin_conc = QSpinBox(); self.spin_conc.setRange(1, 16)
        self.spin_conc.setValue(a.concurrent_requests)
        for r, (lbl, w) in enumerate([
                ("Timeout (s)", self.spin_timeout), ("Retries", self.spin_retries),
                ("Max redirects", self.spin_redirects),
                ("Concurrent requests", self.spin_conc)]):
            lay.addWidget(QLabel(lbl), r, 0); lay.addWidget(w, r, 1)
        return g

    def _security_group(self):
        g = QGroupBox("Security"); g.setObjectName("Card")
        lay = QGridLayout(g)
        self.edit_proxy = QLineEdit(self.app_ctx.settings.analysis.proxy)
        self.edit_proxy.setPlaceholderText("http://proxy:port (opcional)")
        self.chk_tls = QCheckBox("TLS verification (recommended)")
        self.chk_tls.setChecked(self.app_ctx.settings.analysis.verify_tls)
        self.chk_internal = QCheckBox(
            "Allow internal/private targets (SSRF guard OFF - only labs)")
        self.chk_internal.setChecked(self.app_ctx.settings.analysis.allow_internal_targets)
        self.chk_demo = QCheckBox("Development / Demo mode (sin API keys)")
        self.chk_demo.setChecked(self.app_ctx.settings.demo_mode)
        for r, w in enumerate([self.chk_tls, self.chk_internal, self.chk_demo]):
            lay.addWidget(w, r, 0, 1, 2)
        lay.addWidget(QLabel("Proxy"), 3, 0); lay.addWidget(self.edit_proxy, 3, 1)
        return g

    def _ui_group(self):
        g = QGroupBox("UI / Logging"); g.setObjectName("Card")
        lay = QGridLayout(g)
        from PySide6.QtWidgets import QComboBox
        self.combo_log = QComboBox()
        self.combo_log.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.combo_log.setCurrentText(self.app_ctx.settings.ui.log_level)
        lay.addWidget(QLabel("Log level"), 0, 0); lay.addWidget(self.combo_log, 0, 1)
        return g

    def _storage_group(self):
        g = QGroupBox("Storage"); g.setObjectName("Card")
        lay = QGridLayout(g)
        s = self.app_ctx.settings.storage
        self.edit_db = QLineEdit(s.db_path)
        self.edit_reports = QLineEdit(s.report_path)
        btn_db = QPushButton("...")
        btn_db.setFixedWidth(32)
        def pick_db():
            path, _ = QFileDialog.getSaveFileName(self, "Database", s.db_path, "*.db")
            if path:
                self.edit_db.setText(path)
        btn_db.clicked.connect(pick_db)
        lay.addWidget(QLabel("Database path"), 0, 0)
        lay.addWidget(self.edit_db, 0, 1); lay.addWidget(btn_db, 0, 2)
        lay.addWidget(QLabel("Report path"), 1, 0)
        lay.addWidget(self.edit_reports, 1, 1)
        return g

    def load(self):
        pass  # values already initialized in builders

    def save(self):
        s = self.app_ctx.settings
        s.analysis.timeout_seconds = float(self.spin_timeout.value())
        s.analysis.retries = int(self.spin_retries.value())
        s.analysis.max_redirects = int(self.spin_redirects.value())
        s.analysis.concurrent_requests = int(self.spin_conc.value())
        s.analysis.proxy = self.edit_proxy.text().strip()
        s.analysis.verify_tls = self.chk_tls.isChecked()
        s.analysis.allow_internal_targets = self.chk_internal.isChecked()
        s.demo_mode = self.chk_demo.isChecked()
        s.ui.log_level = self.combo_log.currentText()
        s.storage.db_path = self.edit_db.text().strip() or s.storage.db_path
        s.storage.report_path = self.edit_reports.text().strip() or s.storage.report_path
        s.save()
        set_log_level(s.ui.log_level)
        log.info("Settings saved")
        QMessageBox.information(self, "Settings",
                                "Configuración guardada.\n"
                                "(El cambio de base de datos se aplica al reiniciar)")


class ApiConfigPage(QWidget):
    """API key management - stored encrypted, never in source code."""

    def __init__(self, app_ctx):
        super().__init__()
        self.app_ctx = app_ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        t = QLabel("API CONFIGURATION")
        t.setStyleSheet("font-size:14pt; font-weight:800;")
        d = QLabel("Las claves se guardan CIFRADAS en config/secure.json "
                   "(nunca en el código fuente).")
        d.setStyleSheet(f"color:{TEXT_DIM};")
        root.addWidget(t); root.addWidget(d)

        card = Card("THREAT INTELLIGENCE API KEYS")
        grid = QGridLayout()
        self.edits = {}
        store = secure_store()
        for i, (key, label, help_url) in enumerate(KEY_FIELDS):
            lbl = QLabel(label)
            edit = QLineEdit()
            edit.setEchoMode(QLineEdit.Password)
            current = store.get(key)
            if current:
                edit.setPlaceholderText(f"configured: {store.mask(current)}")
            else:
                edit.setPlaceholderText("NOT CONFIGURED - paste key here")
            note = QLabel(help_url)
            note.setStyleSheet(f"color:{TEXT_DIM}; font-size:7.5pt;")
            grid.addWidget(lbl, i, 0)
            grid.addWidget(edit, i, 1)
            grid.addWidget(note, i, 2)
            self.edits[key] = edit
        card.add_layout(grid)
        root.addWidget(card)

        # MHA toggle
        mha_card = Card("MHA (Microsoft Header Analyzer)")
        self.chk_mha = QCheckBox(
            "Enable remote MHA analysis (mha.azurewebsites.net) — sends headers "
            "externally. Local analysis always runs regardless.")
        self.chk_mha.setChecked(store.get("MHA_ENABLED") == "1")
        mha_card.add(self.chk_mha)
        root.addWidget(mha_card)

        btn_row = QHBoxLayout()
        save = QPushButton("SAVE KEYS"); save.setObjectName("Primary")
        clear = QPushButton("Clear all keys"); clear.setObjectName("Danger")
        test = QPushButton("Test providers")
        btn_row.addStretch(); btn_row.addWidget(test)
        btn_row.addWidget(clear); btn_row.addWidget(save)
        root.addLayout(btn_row); root.addStretch()

        save.clicked.connect(self.save_keys)
        clear.clicked.connect(self.clear_keys)
        test.clicked.connect(self.test_providers)

    def save_keys(self):
        store = secure_store()
        for key, edit in self.edits.items():
            val = edit.text().strip()
            if val:
                store.set(key, val)
                edit.clear()
                edit.setPlaceholderText(f"configured: {store.mask(val)}")
        store.set("MHA_ENABLED", "1" if self.chk_mha.isChecked() else "")
        self.app_ctx.refresh_providers()
        log.info("API configuration updated (%d keys configured)",
                 sum(1 for k, _ in KEY_FIELDS if store.get(k)))
        QMessageBox.information(self, "Saved",
                                "Claves guardadas cifradas y proveedores actualizados.")

    def clear_keys(self):
        if QMessageBox.question(self, "Confirmar",
                                "¿Eliminar TODAS las claves almacenadas?") == QMessageBox.Yes:
            store = secure_store()
            for key, _label, _u in KEY_FIELDS:
                store.set(key, "")
            store.set("MHA_ENABLED", "")
            self.app_ctx.refresh_providers()
            log.warning("All API keys cleared")
            self.__init__(self.parentWidget())

    def test_providers(self):
        summary = self.app_ctx.refresh_providers()
        lines = "\n".join(f"{k}: {v}" for k, v in summary.items())
        QMessageBox.information(self, "Providers", lines)


class LogsPage(QWidget):
    """Full-height live log console + DB history."""

    def __init__(self, app_ctx):
        super().__init__()
        self.app_ctx = app_ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        t = QLabel("LOGS")
        t.setStyleSheet("font-size:14pt; font-weight:800;")
        d = QLabel("Registro estructurado en vivo + histórico persistente (SQLite).")
        d.setStyleSheet(f"color:{TEXT_DIM};")
        root.addWidget(t); root.addWidget(d)

        from app.gui.widgets.log_console import LogConsole
        self.console = LogConsole(height=400)
        self.console.setMinimumHeight(300)
        root.addWidget(self.console, 2)

        card = Card("PERSISTENT HISTORY (last 200 entries)")
        from app.gui.widgets.common import make_table
        self.table = make_table(["Time", "Level", "Logger", "Message"],
                                stretch_cols=[3])
        card.add(self.table)
        root.addWidget(card, 1)

    def refresh(self):
        self.table.setRowCount(0)
        try:
            rows = self.app_ctx.db.query(
                "SELECT ts, level, logger, message FROM logs ORDER BY id DESC LIMIT 200")
            from app.gui.theme import RED, YELLOW
            from app.gui.widgets.common import add_table_row
            for r in reversed(rows):
                color = {"CRITICAL": RED, "ERROR": "#db6d28",
                         "WARNING": YELLOW}.get(r["level"], "#8b949e")
                add_table_row(self.table,
                              [r["ts"], r["level"], r["logger"], r["message"][:160]],
                              colors_by_col={1: color})
        except Exception:
            pass
