"""Live log console widget fed by the logging LogBus."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QTextCursor
from PySide6.QtWidgets import (QHBoxLayout, QPlainTextEdit, QPushButton,
                               QVBoxLayout, QWidget)

LEVEL_COLORS = {
    "INFO": "#8b949e",
    "WARNING": "#d29922",
    "CRITICAL": "#e5484d",
    "ERROR": "#db6d28",
    "DEBUG": "#58a6ff",
}


class LogConsole(QWidget):
    clear_requested = Signal()

    def __init__(self, height: int = 170):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)
        self.view = QPlainTextEdit()
        self.view.setObjectName("LogConsole")
        self.view.setReadOnly(True)
        self.view.setMaximumBlockCount(5000)
        self.view.setPlaceholderText("[--:--:--] Waiting for activity...")
        lay.addWidget(self.view)
        row = QHBoxLayout()
        row.addStretch()
        btn_clear = QPushButton("Clear")
        btn_copy = QPushButton("Copy All")
        btn_clear.clicked.connect(self.view.clear)
        btn_copy.clicked.connect(lambda: self._copy_all())
        for b in (btn_copy, btn_clear):
            b.setFixedHeight(22)
            row.addWidget(b)
        lay.addLayout(row)

    def _copy_all(self):
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(self.view.toPlainText())

    def append(self, ts: str, level: str, message: str) -> None:
        color = LEVEL_COLORS.get(level.upper(), "#8b949e")
        html_msg = (message.replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;"))
        self.view.appendHtml(
            f'<span style="color:#3d444d">[{ts}]</span> '
            f'<span style="color:{color};font-weight:bold">[{level}]</span> '
            f'<span style="color:#c9d1d9">{html_msg}</span>')
        self.view.moveCursor(QTextCursor.End)

    def connect_bus(self) -> None:
        from app.core.logging_setup import log_bus
        log_bus().message.connect(self.append)
