"""Generates assets/spiderphish.ico + png icons using the programmatic spider glyph."""
from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> int:
    from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    from app.gui.icons import draw_spider

    out_dir = Path(__file__).resolve().parent.parent / "assets"
    out_dir.mkdir(exist_ok=True)

    icon = QIcon()
    for sz in (16, 24, 32, 48, 64, 128, 256):
        pm = draw_spider(sz)
        pm.save(str(out_dir / f"spiderphish_{sz}.png"), "PNG")
        icon.addPixmap(pm)

    # multi-resolution .ico
    ico_pm = draw_spider(256)
    painter = QPainter(ico_pm)  # ensure fully rendered before saving ico
    painter.end()
    ok = ico_pm.save(str(out_dir / "spiderphish.ico"), "ICO",
                     [QColor("#0a0c0e")]) if False else ico_pm.save(
        str(out_dir / "spiderphish.ico"))
    print(f"Icon written: {out_dir / 'spiderphish.ico'} (ok={ok})")
    for p in sorted(out_dir.glob("*.png")):
        print(" ", p.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

