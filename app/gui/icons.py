"""Programmatic icon assets (spider glyph) - no external files needed."""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (QBrush, QColor, QFont, QIcon, QPainter, QPen,
                           QPixmap, QPolygonF)

RED = "#e5484d"


def draw_spider(size: int = 256, bg: str = "#0a0c0e", fg: str = RED) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(QColor(bg))
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    cx, cy = size / 2.0, size * 0.52

    pen = QPen(QColor(fg), max(2.0, size / 34.0), Qt.SolidLine,
               Qt.RoundCap, Qt.RoundJoin)
    p.setPen(pen)

    legs = [
        (0.10, -0.02, 0.42, -0.34, 0.62, -0.05),
        (0.11,  0.06, 0.46, -0.12, 0.66,  0.16),
        (0.11,  0.13, 0.44,  0.16, 0.60,  0.42),
        (0.09,  0.18, 0.30,  0.40, 0.38,  0.62),
    ]
    for sx, sy, kx, ky, ex, ey in legs:
        for side in (-1.0, 1.0):
            pts = [
                QPointF(cx + side * sx * size, cy + sy * size),
                QPointF(cx + side * kx * size, cy + ky * size),
                QPointF(cx + side * ex * size, cy + ey * size),
            ]
            p.drawPolyline(QPolygonF(pts))

    p.setPen(Qt.NoPen)
    brush = QBrush(QColor(fg))
    p.setBrush(brush)
    hr = size * 0.085
    p.drawEllipse(QPointF(cx, cy - size * 0.14), hr, hr * 0.85)
    p.drawEllipse(QRectF(cx - size * 0.15, cy - size * 0.075,
                         size * 0.30, size * 0.30))
    p.setBrush(QBrush(QColor(bg)))
    er = size * 0.022
    p.drawEllipse(QPointF(cx - size * 0.045, cy - size * 0.165), er, er)
    p.drawEllipse(QPointF(cx + size * 0.045, cy - size * 0.165), er, er)
    p.end()
    return pm


def app_icon() -> QIcon:
    icon = QIcon()
    for sz in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(draw_spider(sz))
    return icon


def brand_pixmap(width: int = 460, height: int = 300) -> QPixmap:
    """Splash/branding pixmap."""
    pm = QPixmap(width, height)
    pm.fill(QColor("#0a0c0e"))
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    sp_size = int(height * 0.62)
    sp = draw_spider(sp_size)
    p.drawPixmap(10, int(height * 0.18), sp)

    f = QFont("Segoe UI", int(height * 0.082), QFont.Black)
    p.setFont(f)
    p.setPen(QColor("#d7dde3"))
    x_text = sp_size + 24
    p.drawText(x_text, int(height * 0.42), "SPIDERPHISH")
    f2 = QFont("Segoe UI", int(height * 0.045), QFont.Bold)
    p.setFont(f2)
    p.setPen(QColor(RED))
    p.drawText(x_text, int(height * 0.58), "ANTI-PHISHING ANALYZER")
    p.setPen(QColor("#8b949e"))
    f3 = QFont("Segoe UI", int(height * 0.038), QFont.Normal)
    p.setFont(f3)
    p.drawText(x_text, int(height * 0.70), "DEFEND TODAY, HACK TOMORROW")
    p.end()
    return pm
