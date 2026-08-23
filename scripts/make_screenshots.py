"""Generates README screenshots by driving the real GUI offscreen."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

OUT = ROOT / "docs" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402


def main() -> int:
    from app.gui.context import build_context
    from app.gui.main_window import MainWindow
    from app.gui.theme import build_qss

    app = QApplication([])
    app.setStyle("Fusion")
    app.setStyleSheet(build_qss())

    ctx = build_context()
    win = MainWindow(ctx)
    win.resize(1500, 900)
    # render fully but never appear on the user's screen
    win.setAttribute(Qt.WA_DontShowOnScreen, True)
    win.show()
    app.processEvents()

    raw = (ROOT / "tests" / "data" / "phishing.eml").read_bytes()
    case_id = ctx.db.next_case_id()
    result = asyncio.run(ctx.analyzer.analyze(
        raw, case_id=case_id,
        progress=lambda p, m: None))

    # replicate what a real session does
    ctx.save_current_case(result)
    from app.analyzers.campaigns import extract_observations
    ctx.db.record_observations(case_id, extract_observations(result))
    ctx.last_analysis = result

    page_email = win.page_email
    page_email._analysis = result
    page_email.stack.setCurrentIndex(1)
    page_email._render(result)

    win.navigate("corr")
    app.processEvents()

    shots = [
        ("dashboard", "dashboard"),
        ("email-analyzer", "email"),
        ("ioc-correlation", "corr"),
        ("url-analyzer", "url"),
        ("threat-intel", "iprep"),
    ]
    for name, key in shots:
        win.navigate(key)
        for _ in range(6):
            app.processEvents()
        pm = win.grab()
        path = OUT / f"{name}.png"
        pm.save(str(path), "PNG")
        print(f"[SHOT] {path.name} ({pm.width()}x{pm.height()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
