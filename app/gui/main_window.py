"""Main window: sidebar + top bar + stacked pages + bottom log console."""
from __future__ import annotations

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QAction, QIcon, QKeySequence, QPixmap
from PySide6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QLabel, QMainWindow, QMessageBox,
    QPushButton, QSplitter, QStackedWidget, QVBoxLayout, QWidget)

from app import APP_NAME, APP_SUBTITLE, APP_TAGLINE, __version__
from app.config.settings import AppSettings
from app.core.logging_setup import get_logger
from app.gui.context import AppContext, build_context
from app.gui.icons import app_icon, brand_pixmap
from app.gui.theme import ACCENT, BG2, GREEN, TEXT_DIM, build_qss
from app.gui.widgets.log_console import LogConsole

log = get_logger("gui.main")

NAV = [
    ("ANTI-PHISHING", None),
    ("Email Analyzer", "email", "\u2709"),
    ("URL Analyzer", "url", "\u2315"),
    ("IOC Correlation", "corr", "\u2691"),
    ("IOC Lookup", "ioc", "\u25c9"),
    ("Bulk Analysis", "bulk", "\u25a6"),
    ("INTELLIGENCE", None),
    ("IP Reputation", "iprep", "\u25ce"),
    ("Domain Reputation", "domrep", "\u25ce"),
    ("Hash Lookup", "hash", "#"),
    ("Threat Feeds", "feeds", "\u2611"),
    ("TOOLS", None),
    ("Browser Safety Check", "safety", "\u25c9"),
    ("Phishing Templates", "templates", "\u25a3"),
    ("Case Reports", "cases", "\u25a4"),
    ("SYSTEM", None),
    ("Settings", "settings", "\u2699"),
    ("API Configuration", "api", "\u25a3"),
    ("Logs", "logs", "\u237f"),
]


class MainWindow(QMainWindow):
    def __init__(self, ctx: AppContext):
        super().__init__()
        self.ctx = ctx
        self.qsettings = QSettings("SpiderPhish", "AntiPhishingAnalyzer")
        self.setWindowTitle(f"{APP_NAME} — {APP_SUBTITLE}")
        self.setWindowIcon(app_icon())
        self.resize(1500, 900)
        self.setMinimumSize(1150, 700)

        central = QWidget()
        central.setObjectName("Root")
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.setCentralWidget(central)

        root.addWidget(self._build_sidebar())

        main_col = QVBoxLayout()
        main_col.setContentsMargins(0, 0, 0, 0)
        main_col.setSpacing(0)
        root.addLayout(main_col, 1)

        main_col.addWidget(self._build_topbar())

        # content splitter (pages | log console)
        split_v = QSplitter(Qt.Vertical)
        split_v.setChildrenCollapsible(False)
        main_col.addWidget(split_v, 1)

        self.stack = QStackedWidget()
        split_v.addWidget(self.stack)

        # bottom live console
        console_wrap = QWidget()
        cl = QVBoxLayout(console_wrap)
        cl.setContentsMargins(8, 4, 8, 4)
        header = QHBoxLayout()
        lbl = QLabel("LIVE LOGS")
        lbl.setStyleSheet(
            f"color:{TEXT_DIM}; font-weight:800; letter-spacing:2px; font-size:8pt;")
        header.addWidget(lbl); header.addStretch()
        self.sys_status = QLabel("\u25cf System Online")
        self.sys_status.setStyleSheet(f"color:{GREEN}; font-size:8.5pt; font-weight:700;")
        header.addWidget(self.sys_status)
        ver = QLabel(f"v{__version__} · {APP_SUBTITLE}")
        ver.setStyleSheet(f"color:{TEXT_DIM}; font-size:8.5pt;")
        header.addWidget(ver)
        cl.addLayout(header)
        self.console = LogConsole()
        self.console.setMinimumHeight(120)
        cl.addWidget(self.console)
        split_v.addWidget(console_wrap)
        split_v.setSizes([720, 170])

        self._build_pages()
        self._build_statusbar()
        self._wire_bus()
        self._restore_geometry()

    # ------------------------------------------------------------------
    def _build_sidebar(self) -> QWidget:
        side = QWidget()
        side.setObjectName("Sidebar")
        side.setFixedWidth(230)
        lay = QVBoxLayout(side)
        lay.setContentsMargins(0, 14, 0, 10)
        lay.setSpacing(2)

        logo_row = QHBoxLayout()
        logo_row.setContentsMargins(12, 0, 8, 0)
        icon_lbl = QLabel()
        pm = brand_pixmap(64, 64).scaled(40, 40, Qt.KeepAspectRatio,
                                         Qt.SmoothTransformation)
        icon_lbl.setPixmap(pm)
        brand_box = QVBoxLayout()
        b1 = QLabel("SPIDERPHISH")
        b1.setObjectName("Brand")
        b2 = QLabel(APP_SUBTITLE)
        b2.setObjectName("BrandSub")
        brand_box.addWidget(b1)
        brand_box.addWidget(b2)
        logo_row.addWidget(icon_lbl)
        logo_row.addLayout(brand_box)
        logo_row.addStretch()
        lay.addLayout(logo_row)
        lay.addSpacing(10)

        self.nav_buttons: dict[str, QPushButton] = {}
        for item in NAV:
            if item[1] is None:
                section = QLabel(item[0])
                section.setObjectName("NavSection")
                lay.addWidget(section)
                continue
            label, key, glyph = item
            btn = QPushButton(f"{glyph}  {label}")
            btn.setProperty("nav", True)
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _=False, k=key: self.navigate(k))
            self.nav_buttons[key] = btn
            lay.addWidget(btn)
        lay.addStretch()
        return side

    def _build_topbar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("TopBar")
        bar.setFixedHeight(58)
        h = QHBoxLayout(bar)
        h.setContentsMargins(16, 0, 16, 0)
        title = QLabel(f"SpiderPhish <span style='color:{ACCENT}'>|</span> {APP_TAGLINE}")
        title.setObjectName("TopTitle")
        h.addWidget(title)
        h.addSpacing(24)

        from PySide6.QtWidgets import QButtonGroup
        self.top_tabs_group = QButtonGroup(self)
        tabs_widget = QWidget()
        tabs_widget.setObjectName("TopTabs")
        th = QHBoxLayout(tabs_widget)
        th.setContentsMargins(0, 0, 0, 0)
        th.setSpacing(0)
        for label, key in (("Dashboard", "dashboard"), ("Analyzer", "email"),
                           ("URLs", "url"), ("Reputation", "iprep"),
                           ("Logs", "logs"), ("Settings", "settings")):
            b = QPushButton(label)
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda _=False, k=key: self.navigate(k))
            self.top_tabs_group.addButton(b)
            th.addWidget(b)
        h.addWidget(tabs_widget)
        h.addStretch()
        return bar

    def _build_pages(self):
        from app.gui.pages.bulk_page import BulkAnalysisPage
        from app.gui.pages.correlation_page import CorrelationPage
        from app.gui.pages.dashboard_page import DashboardPage
        from app.gui.pages.email_analyzer_page import EmailAnalyzerPage
        from app.gui.pages.ioc_lookup_page import IOCLookupPage
        from app.gui.pages.reputation_pages import (
            DomainReputationPage, HashLookupPage, IPReputationPage,
            ThreatFeedsPage)
        from app.gui.pages.settings_pages import (
            ApiConfigPage, LogsPage, SettingsPage)
        from app.gui.pages.tools_pages import (
            BrowserSafetyPage, CaseReportsPage, PhishingTemplatesPage)

        self.page_dashboard = DashboardPage(self.ctx)
        self.page_email = EmailAnalyzerPage(self.ctx)
        self.page_url = None  # lazy below to keep imports tidy
        from app.gui.pages.url_analyzer_page import UrlAnalyzerPage
        self.page_url = UrlAnalyzerPage(self.ctx)
        self.page_corr = CorrelationPage(self.ctx, main_window=self)
        self.page_ioc = IOCLookupPage(self.ctx)
        self.page_bulk = BulkAnalysisPage(self.ctx)
        self.page_iprep = IPReputationPage(self.ctx)
        self.page_domrep = DomainReputationPage(self.ctx)
        self.page_hash = HashLookupPage(self.ctx)
        self.page_feeds = ThreatFeedsPage(self.ctx)
        self.page_safety = BrowserSafetyPage(self.ctx)
        self.page_templates = PhishingTemplatesPage(self.ctx)
        self.page_cases = CaseReportsPage(self.ctx)
        self.page_settings = SettingsPage(self.ctx)
        self.page_api = ApiConfigPage(self.ctx)
        self.page_logs = LogsPage(self.ctx)

        self._pages = {
            "dashboard": self.page_dashboard,
            "email": self.page_email,
            "url": self.page_url,
            "corr": self.page_corr,
            "ioc": self.page_ioc,
            "bulk": self.page_bulk,
            "iprep": self.page_iprep,
            "domrep": self.page_domrep,
            "hash": self.page_hash,
            "feeds": self.page_feeds,
            "safety": self.page_safety,
            "templates": self.page_templates,
            "cases": self.page_cases,
            "settings": self.page_settings,
            "api": self.page_api,
            "logs": self.page_logs,
        }
        for w in self._pages.values():
            self.stack.addWidget(w)

        # default selection
        first = self.nav_buttons.get("email")
        if first:
            first.setChecked(True)
        self.navigate("email")

        # context signals
        self.ctx.analysis_ready.connect(self._on_analysis_ready)

        # shortcuts
        from PySide6.QtGui import QShortcut
        QShortcut(QKeySequence("Ctrl+O"), self, self.page_email.import_eml)
        QShortcut(QKeySequence("Ctrl+Return"), self, self.page_email.start_analysis)
        QShortcut(QKeySequence("Ctrl+S"), self, self.save_case)
        QShortcut(QKeySequence("Ctrl+E"), self, self.export_report)

    def _build_statusbar(self):
        sb = self.statusBar()
        left = QLabel("\u25cf Ready")
        left.setStyleSheet(f"color:{GREEN}; font-weight:700;")
        sb.addWidget(left)
        center = QLabel("SpiderPhish · ANTI-PHISHING ANALYZER · Built for a Safer Tomorrow")
        center.setStyleSheet(f"color:{TEXT_DIM};")
        sb.addPermanentWidget(center)
        right = QLabel(f"v{__version__}")
        right.setStyleSheet(f"color:{TEXT_DIM};")
        sb.addPermanentWidget(right)

    def _wire_bus(self):
        from app.core.logging_setup import log_bus
        self.console.connect_bus()
        log_bus().attach_db(self.ctx.db)

    # ------------------------------------------------------------------
    def navigate(self, key: str):
        page = self._pages.get(key)
        if not page:
            return
        self.stack.setCurrentWidget(page)
        for k, btn in self.nav_buttons.items():
            btn.setChecked(k == key)
        if hasattr(page, "refresh"):
            try:
                page.refresh()
            except Exception as e:  # noqa: BLE001
                log.warning("page refresh failed: %s", e)

    def _on_analysis_ready(self, analysis):
        """Auto-save the case, record IOC observations, refresh dashboards."""
        try:
            case_id = self.ctx.save_current_case(analysis)
            log.info("Case stored automatically: %s", case_id)
        except Exception as e:  # noqa: BLE001
            log.warning("Could not store case: %s", e)
            case_id = analysis.case_id
        try:
            from app.analyzers.campaigns import extract_observations
            self.ctx.db.record_observations(
                case_id, extract_observations(analysis))
        except Exception as e:  # noqa: BLE001
            log.warning("IOC observation recording failed: %s", e)
        self.ctx.last_analysis = analysis
        self.page_dashboard.refresh()
        self.page_feeds.refresh()
        self.page_corr.refresh()

    def save_case(self):
        """Ctrl+S — add notes/tags to the latest analysis."""
        page = self._pages.get("email")
        a = getattr(page, "_analysis", None) if page else None
        if not a:
            QMessageBox.information(self, "Guardar caso",
                                    "No hay ningún análisis en esta sesión.")
            return
        from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLineEdit, QTextEdit, QVBoxLayout
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Save case {a.case_id}")
        dlg.resize(520, 320)
        lay = QVBoxLayout(dlg)
        notes_edit = QTextEdit()
        notes_edit.setPlaceholderText("Notes del caso...")
        tags_edit = QLineEdit()
        tags_edit.setPlaceholderText("tags separados por coma: phishing,bec,microsoft")
        lay.addWidget(QLabel("Tags:")); lay.addWidget(tags_edit)
        lay.addWidget(QLabel("Notes:")); lay.addWidget(notes_edit)
        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.accepted.connect(dlg.accept); bb.rejected.connect(dlg.reject)
        lay.addWidget(bb)
        if dlg.exec() == QDialog.Accepted:
            tags = [t.strip() for t in tags_edit.text().split(",") if t.strip()]
            self.ctx.save_current_case(a, notes=notes_edit.toPlainText(), tags=tags)
            log.info("Case updated with notes/tags: %s", a.case_id)

    def export_report(self):
        page = self._pages.get("email")
        a = getattr(page, "_analysis", None) if page else None
        if not a:
            QMessageBox.information(self, "Exportar informe",
                                    "No hay ningún análisis para exportar.")
            return
        from pathlib import Path
        out, _ = __import__("PySide6.QtWidgets", fromlist=["QFileDialog"]) \
            .QFileDialog.getSaveFileName(self, "GENERATE PDF REPORT",
                                         f"{a.case_id}.pdf", "*.pdf")
        if not out:
            return
        from app.reports.pdf_report import generate_report
        path = generate_report(a, Path(out))
        log.info("PDF report generated: %s", path)
        QMessageBox.information(self, "Informe PDF", f"Informe generado:\n{path}")

    # ------------------------------------------------------------------
    def closeEvent(self, ev):  # noqa: N802
        self.qsettings.setValue("geometry", self.saveGeometry())
        self.qsettings.setValue("maximized", self.isMaximized())
        try:
            self.ctx.settings.save()
        except Exception:
            pass
        super().closeEvent(ev)

    def _restore_geometry(self):
        geo = self.qsettings.value("geometry")
        if geo is not None:
            try:
                self.restoreGeometry(geo)
            except Exception:
                pass
        if str(self.qsettings.value("maximized", "false")).lower() == "true":
            self.showMaximized()


def run_app():
    import sys

    from PySide6.QtWidgets import QSplashScreen

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")
    app.setStyleSheet(build_qss())

    splash_pm = brand_pixmap(560, 360)
    splash = QSplashScreen(splash_pm)
    splash.show()
    app.processEvents()

    ctx = build_context()

    win = MainWindow(ctx)
    win.setWindowIcon(app_icon())
    splash.finish(win)
    win.show()
    return app.exec()
