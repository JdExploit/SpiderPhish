"""Visual redirect-chain flow view (any.run-style timeline, HTTP-only).

Renders each hop as a card connected by arrows: status badge, URL,
domain, server header and cross-domain / downgrade warnings. Purely a
viewer: nothing is executed, no browser involved.
"""
from __future__ import annotations

from urllib.parse import urlparse

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QScrollArea,
                               QSizePolicy, QVBoxLayout, QWidget)

from app.gui.theme import BLUE, BORDER, GREEN, ORANGE, PANEL2, RED, TEXT, \
    TEXT_DIM, YELLOW
from app.utils.ioc_extraction import registered_domain


def _status_color(code) -> str:
    """Return hex color for an HTTP status code (or None for META)."""
    if code is None:
        return BLUE
    try:
        c = int(code)
    except (TypeError, ValueError):
        return TEXT_DIM
    if 300 <= c < 400:
        return YELLOW
    if 200 <= c < 300:
        return GREEN
    if c >= 400:
        return ORANGE
    return TEXT_DIM


class HopCard(QFrame):
    def __init__(self, hop: dict, prev_domain: str | None):
        super().__init__()
        code = hop.get("status_code")
        color = _status_color(code)
        is_meta = code is None

        self.setStyleSheet(
            f"QFrame {{ background-color: {PANEL2}; border: 1px solid {BORDER};"
            f" border-left: 3px solid {color}; border-radius: 6px; }}")

        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 7, 10, 7)
        lay.setSpacing(3)

        top = QHBoxLayout()
        top.setSpacing(8)

        step_lbl = QLabel(f"HOP {hop.get('step', '?')}")
        step_lbl.setStyleSheet(
            f"color:{TEXT_DIM}; font-size:7.5pt; font-weight:700;"
            "letter-spacing:1px; border:none;")

        pill_txt = ("META-REFRESH" if is_meta
                    else f"HTTP {code}" if code else "HTTP ?")
        pill = QLabel(pill_txt)
        pill.setStyleSheet(
            f"background-color:{color}; color:#0a0c0e; font-size:8pt;"
            "font-weight:800; padding:1px 8px; border-radius:8px; border:none;")
        top.addWidget(step_lbl)
        top.addWidget(pill)
        top.addStretch()

        dom = hop.get("domain") or ""
        if dom:
            d_lbl = QLabel(dom)
            d_lbl.setStyleSheet(
                f"color:{BLUE}; font-size:8pt; font-weight:600; border:none;")
            top.addWidget(d_lbl)
        lay.addLayout(top)

        url_lbl = QLabel(str(hop.get("url", "")))
        url_lbl.setWordWrap(True)
        url_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        url_lbl.setStyleSheet(
            f"color:{TEXT}; font-family:Consolas,monospace; font-size:9pt;"
            "border:none;")
        lay.addWidget(url_lbl)

        extras = []
        server = hop.get("server")
        if server:
            extras.append(f"server: {server}")
        loc = hop.get("location")
        if loc:
            extras.append(f"location: {loc[:120]}")

        # cross-domain detection between consecutive hops
        cur_reg = registered_domain(dom) if dom else None
        if prev_domain and cur_reg and cur_reg != prev_domain:
            extras.append(f"!! CROSS-DOMAIN JUMP ({prev_domain} -> {cur_reg})")
        proto = (hop.get("protocol") or "").lower()
        if proto == "http":
            extras.append("no TLS on this hop")

        if extras:
            ex_lbl = QLabel("   ".join(extras))
            ex_lbl.setWordWrap(True)
            warn = any(e.startswith("!!") for e in extras)
            ex_lbl.setStyleSheet(
                f"color:{RED if warn else TEXT_DIM}; font-size:8pt;"
                "border:none;")
            lay.addWidget(ex_lbl)
        self._reg = cur_reg

    @property
    def reg_domain(self):
        return self._reg


class RedirectFlowView(QWidget):
    """Scrollable vertical timeline of hops with connecting arrows."""

    def __init__(self, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.NoFrame)
        self._container = QWidget()
        self._lay = QVBoxLayout(self._container)
        self._lay.setContentsMargins(2, 4, 2, 4)
        self._lay.setSpacing(0)
        self._lay.setAlignment(Qt.AlignTop)
        self._scroll.setWidget(self._container)
        outer.addWidget(self._scroll)

        note = QLabel("HTTP-level trace: no browser, no scripts executed. "
                      "Note: requests originate from this machine's IP "
                      "(use urlscan.io scan for remote execution).")
        note.setStyleSheet(f"color:{TEXT_DIM}; font-size:7.5pt;"
                           "border:none;")
        note.setWordWrap(True)
        outer.addWidget(note)

    def set_hops(self, hops: list[dict]) -> None:
        while self._lay.count():
            item = self._lay.takeAt(0)
            if w := item.widget():
                w.deleteLater()
        prev = None
        for h in hops:
            arrow = QLabel("| v")
            arrow.setAlignment(Qt.AlignHCenter)
            arrow.setStyleSheet(
                f"color:{TEXT_DIM}; font-size:9pt; border:none; padding:0;")
            card = HopCard(h, prev)
            self._lay.addWidget(card)
            self._lay.addWidget(arrow)
            prev = card.reg_domain or prev
        if not hops:
            empty = QLabel("(sin redirecciones registradas)")
            empty.setStyleSheet(f"color:{TEXT_DIM}; border:none;")
            self._lay.addWidget(empty)

    def sizeHint(self):  # sensible default inside splitters
        s = super().sizeHint()
        s.setHeight(min(max(s.height(), 180), 420))
        return s
