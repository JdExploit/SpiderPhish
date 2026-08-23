"""GUI smoke test - instantiates every page offscreen to catch runtime errors.

Run:  python scripts/smoke_gui.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncio


def main() -> int:
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    from app.gui.context import build_context
    from app.gui.main_window import MainWindow
    from app.gui.theme import build_qss

    app = QApplication(sys.argv)
    app.setStyleSheet(build_qss())
    ctx = build_context()
    win = MainWindow(ctx)
    win.show()

    # exercise the email analyzer pipeline through the GUI worker path
    raw = Path("tests/data/phishing.eml").read_bytes()

    def load_and_analyze():
        page = win.page_email
        page._set_source(raw, "smoke test")
        page.start_analysis()

    def check_result():
        a = win.page_email._analysis
        assert a is not None, "analysis did not finish"
        print(f"[SMOKE] verdict: {a.risk.band.value} ({a.risk.score}/100)")
        print(f"[SMOKE] urls={len(a.urls)} iocs={len(a.iocs)} "
              f"domains={len(a.domains)} recs={len(a.recommendations)}")
        for key in win._pages:
            win.navigate(key)
        print("[SMOKE] all pages navigated OK")
        # exercise PDF report generation end-to-end
        out = Path("data/smoke_report.pdf")
        from app.reports.pdf_report import generate_report
        p = generate_report(a, out)
        print(f"[SMOKE] PDF generated: {p} ({p.stat().st_size:,} bytes)")
        app.quit()

    QTimer.singleShot(200, load_and_analyze)

    def wait_finish():
        if win.page_email._worker and win.page_email._worker.isRunning():
            QTimer.singleShot(300, wait_finish)
        else:
            check_result()
    QTimer.singleShot(1500, wait_finish)
    QTimer.singleShot(120000, app.quit)   # hard timeout

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
