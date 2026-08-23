"""Reusable widgets: severity badges, cards, KV tables, empty states."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QSizePolicy,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from app.gui.theme import (
    GREEN, PANEL, RED, SEVERITY_COLORS, TEXT, TEXT_DIM, YELLOW)


def severity_color(status: str) -> str:
    return SEVERITY_COLORS.get(status.upper(), TEXT_DIM)


class SeverityBadge(QLabel):
    def __init__(self, text: str = "UNKNOWN", parent=None):
        super().__init__(text.upper(), parent)
        self.set_severity(text)

    def set_severity(self, text: str) -> None:
        color = severity_color(text)
        self.setStyleSheet(
            f"background:{color}; color:#0a0c0e; font-weight:800;"
            f"font-size:8pt; letter-spacing:1px; border-radius:3px;"
            f"padding:2px 8px;")
        f = QFont()
        f.setBold(True)
        self.setFont(f)


class Card(QFrame):
    def __init__(self, title: str = "", subtitle: str = ""):
        super().__init__()
        self.setObjectName("Card")
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 12)
        lay.setSpacing(6)
        if title:
            t = QLabel(title)
            t.setObjectName("CardTitle")
            lay.addWidget(t)
        if subtitle:
            s = QLabel(subtitle)
            s.setStyleSheet(f"color:{TEXT_DIM}; font-size:8.5pt;")
            lay.addWidget(s)
        self.body = lay

    def add(self, w: QWidget) -> None:
        self.body.addWidget(w)

    def add_layout(self, lay) -> None:
        self.body.addLayout(lay)

    def setTitle(self, title: str) -> None:
        for i in range(self.body.count()):
            item = self.body.itemAt(i)
            w = item.widget() if item else None
            if isinstance(w, QLabel) and w.objectName() == "CardTitle":
                w.setText(title)
                return


def kv_rows(rows: list[tuple[str, str]]) -> QGridLayout:
    grid = QGridLayout()
    grid.setVerticalSpacing(3)
    grid.setHorizontalSpacing(14)
    for i, (k, v) in enumerate(rows):
        kl = QLabel(k)
        kl.setStyleSheet(f"color:{TEXT_DIM}; font-size:8.5pt; font-weight:700;")
        vl = QLabel(v or "-")
        vl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        vl.setWordWrap(True)
        vl.setStyleSheet(f"font-size:9pt;")
        grid.addWidget(kl, i, 0, Qt.AlignTop)
        grid.addWidget(vl, i, 1)
    grid.setColumnStretch(1, 1)
    return grid


class KVCard(Card):
    def __init__(self, title: str, rows: list[tuple[str, str]], subtitle: str = ""):
        super().__init__(title, subtitle)
        self.grid = kv_rows(rows)
        self.add_layout(self.grid)

    def set_rows(self, rows: list[tuple[str, str]]) -> None:
        while self.grid.count():
            item = self.grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for i, (k, v) in enumerate(rows):
            kl = QLabel(k)
            kl.setStyleSheet(f"color:{TEXT_DIM}; font-size:8.5pt; font-weight:700;")
            vl = QLabel(v or "-")
            vl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            vl.setWordWrap(True)
            self.grid.addWidget(kl, i, 0, Qt.AlignTop)
            self.grid.addWidget(vl, i, 1)


def make_table(headers: list[str], stretch_cols: list[int] | None = None) -> QTableWidget:
    from PySide6.QtWidgets import QHeaderView
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setAlternatingRowColors(True)
    t.setSelectionBehavior(QTableWidget.SelectRows)
    t.setEditTriggers(QTableWidget.NoEditTriggers)
    t.setSortingEnabled(True)
    t.setWordWrap(False)
    if stretch_cols:
        for c in stretch_cols:
            t.horizontalHeader().setSectionResizeMode(c, QHeaderView.Stretch)
        t.horizontalHeader().setStretchLastSection(True)
    else:
        t.horizontalHeader().setStretchLastSection(True)
    t.setStyleSheet("QTableWidget { font-size: 8.7pt; }")
    return t


def add_table_row(table: QTableWidget, values: list[str],
                  colors_by_col: dict[int, str] | None = None,
                  data: object = None) -> None:
    r = table.rowCount()
    table.insertRow(r)
    colors_by_col = colors_by_col or {}
    for c, val in enumerate(values):
        item = QTableWidgetItem(str(val))
        if c in colors_by_col:
            item.setForeground(QColor(colors_by_col[c]))
            f = item.font()
            f.setBold(True)
            item.setFont(f)
        table.setItem(r, c, item)
    if data is not None:
        table.item(r, 0).setData(Qt.UserRole, data)


def copy_button(get_text, label="Copy") -> QPushButton:
    btn = QPushButton(label)
    btn.setToolTip("Copy to clipboard")
    btn.setFixedHeight(24)

    def do_copy():
        from PySide6.QtWidgets import QApplication
        txt = get_text() if callable(get_text) else get_text
        if txt:
            QApplication.clipboard().setText(txt)

    btn.clicked.connect(do_copy)
    return btn


class EmptyState(QWidget):
    """Placeholder shown when no analysis has run yet."""

    def __init__(self, icon: str = "\u2715", title: str = "No data",
                 detail: str = ""):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignCenter)
        ic = QLabel(icon)
        ic.setAlignment(Qt.AlignCenter)
        ic.setStyleSheet(f"color:{TEXT_DIM}; font-size:34pt;")
        t = QLabel(title)
        t.setAlignment(Qt.AlignCenter)
        t.setStyleSheet(f"color:{TEXT}; font-weight:700; font-size:11pt;")
        d = QLabel(detail)
        d.setAlignment(Qt.AlignCenter)
        d.setWordWrap(True)
        d.setStyleSheet(f"color:{TEXT_DIM}; font-size:9pt;")
        lay.addStretch()
        lay.addWidget(ic)
        lay.addWidget(t)
        lay.addWidget(d)
        lay.addStretch()


class RiskBar(QWidget):
    """Horizontal risk meter 0..100."""

    def __init__(self):
        super().__init__()
        self.setFixedHeight(14)
        self._value = 0

    def set_value(self, v: int) -> None:
        self._value = max(0, min(100, int(v)))
        self.update()

    def paintEvent(self, ev):  # noqa: N802
        from PySide6.QtGui import QPainter
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = self.rect().adjusted(0, 4, 0, -4)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(PANEL))
        p.drawRoundedRect(r, 5, 5)
        v = self._value
        col = GREEN if v < 40 else YELLOW if v < 60 else RED
        if v > 0:
            filled = r.adjusted(0, 0, int((r.width()) * v / 100.0 - r.width()), 0)
            p.setBrush(QColor(col))
            p.drawRoundedRect(r.x(), r.y(), int(r.width() * v / 100.0), r.height(), 5, 5)
        p.end()
