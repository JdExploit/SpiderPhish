"""Dashboard page - stats + charts (risk distribution, threats by day, tops)."""
from __future__ import annotations

from collections import Counter

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QVBoxLayout, QWidget)

from app.gui.theme import (ACCENT, BLUE, GREEN, PANEL2, RED, TEXT, TEXT_DIM,
                          YELLOW)
from app.gui.widgets.common import Card, EmptyState, make_table, add_table_row


class StatCard(QFrame):
    def __init__(self, title: str, color: str = TEXT):
        super().__init__()
        self.setObjectName("Card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        self.value_lbl = QLabel("0")
        self.value_lbl.setStyleSheet(f"color:{color}; font-size:22pt; font-weight:800;")
        self.title_lbl = QLabel(title.upper())
        self.title_lbl.setStyleSheet(f"color:{TEXT_DIM}; font-size:7.5pt; font-weight:800; letter-spacing:1.5px;")
        lay.addWidget(self.value_lbl)
        lay.addWidget(self.title_lbl)

    def set_value(self, v):
        self.value_lbl.setText(str(v))


class BarChart(QWidget):
    """Simple horizontal bar chart."""

    def __init__(self, color: str = ACCENT):
        super().__init__()
        self.setMinimumHeight(120)
        self._data: list[tuple[str, int]] = []
        self._color = color

    def set_data(self, data: list[tuple[str, int]]):
        self._data = data[:6]
        self.update()

    def paintEvent(self, ev):  # noqa: N802
        if not self._data:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        maxv = max((v for _, v in self._data), default=1) or 1
        w = self.width()
        h = self.height()
        row_h = h / max(len(self._data), 1)
        label_w = int(w * 0.42)
        for i, (label, v) in enumerate(self._data):
            y = i * row_h + row_h * 0.18
            bar_h = row_h * 0.5
            p.setPen(QColor(TEXT_DIM))
            f = p.font()
            f.setPointSize(7)
            p.setFont(f)
            p.drawText(0, int(y), label_w - 6, int(bar_h) + 4,
                       Qt.AlignRight | Qt.AlignVCenter,
                       label if len(label) <= 34 else label[:32] + "…")
            bx = label_w
            bw = int((w - label_w - 34) * (v / maxv))
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(self._color))
            p.drawRoundedRect(bx, int(y), max(bw, 2), int(bar_h), 3, 3)
            p.setPen(QColor(TEXT))
            p.drawText(bx + bw + 6, int(y), 30, int(bar_h) + 4,
                       Qt.AlignLeft | Qt.AlignVCenter, str(v))
        p.end()


class DashboardPage(QWidget):
    def __init__(self, app_ctx):
        super().__init__()
        self.app_ctx = app_ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        t = QLabel("DASHBOARD")
        t.setObjectName("CardTitle")
        t.setStyleSheet("font-size:14pt; font-weight:800; letter-spacing:1px;")
        d = QLabel("Resumen operativo de la herramienta de defensa.")
        d.setStyleSheet(f"color:{TEXT_DIM};")
        root.addWidget(t)
        root.addWidget(d)
        root.addSpacing(4)

        # stat cards
        grid = QGridLayout()
        grid.setSpacing(8)
        self.stats = {
            "emails": StatCard("Emails analyzed", TEXT),
            "malicious": StatCard("Malicious", RED),
            "suspicious": StatCard("Suspicious", YELLOW),
            "safe": StatCard("Safe", GREEN),
            "urls": StatCard("URLs analyzed", BLUE),
            "bad_ips": StatCard("Malicious IPs", RED),
            "bad_domains": StatCard("Malicious domains", YELLOW),
            "cases": StatCard("Cases", TEXT),
        }
        for i, card in enumerate(self.stats.values()):
            grid.addWidget(card, i // 4, i % 4)
        root.addLayout(grid)

        # charts row
        charts = QHBoxLayout()
        self.risk_chart = BarChart(ACCENT)
        c_risk = Card("RISK DISTRIBUTION")
        c_risk.add(self.risk_chart)
        self.day_chart = BarChart(BLUE)
        c_day = Card("THREATS BY DAY")
        c_day.add(self.day_chart)
        self.domain_chart = BarChart(YELLOW)
        c_dom = Card("TOP FLAGGED DOMAINS")
        c_dom.add(self.domain_chart)
        self.asn_chart = BarChart("#bc8cff")
        c_asn = Card("TOP ORIGIN NETWORKS")
        c_asn.add(self.asn_chart)
        charts.addWidget(c_risk)
        charts.addWidget(c_day)
        charts.addWidget(c_dom)
        charts.addWidget(c_asn)
        root.addLayout(charts)

        # recent cases table
        c_cases = Card("RECENT CASES")
        self.cases_table = make_table(
            ["Case ID", "Date", "Severity", "Sender", "Origin IP",
             "Verdict", "Score"], stretch_cols=[3])
        c_cases.add(self.cases_table)
        root.addWidget(c_cases, 1)
        self.refresh()

    def refresh(self):
        try:
            db = self.app_ctx.db
            s = db.dashboard_stats()
            self.stats["emails"].set_value(s["emails"] or s["cases"])
            self.stats["malicious"].set_value(s["malicious"])
            self.stats["suspicious"].set_value(s["suspicious"])
            self.stats["safe"].set_value(s["safe"])
            self.stats["urls"].set_value(s["malicious_urls"])
            self.stats["bad_ips"].set_value(s["malicious_ips"])
            self.stats["bad_domains"].set_value("-")
            self.stats["cases"].set_value(s["cases"])

            # risk distribution from stored analyses
            rows = db.query(
                "SELECT band, COUNT(*) c FROM analysis_results GROUP BY band ORDER BY c DESC")
            dist = [(r["band"] or "?", r["c"]) for r in rows]
            self.risk_chart.set_data(dist)

            day_rows = db.query(
                "SELECT substr(created_at,1,10) d, SUM(CASE WHEN band IN "
                "('HIGH','CRITICAL / MALICIOUS') THEN 1 ELSE 0 END) c "
                "FROM analysis_results GROUP BY d ORDER BY d DESC LIMIT 7")
            self.day_chart.set_data([(r["d"], r["c"]) for r in reversed(day_rows)])

            dom_rows = db.query(
                "SELECT domain, COUNT(*) c FROM urls WHERE risk_level IN "
                "('HIGH','CRITICAL','MALICIOUS','SUSPICIOUS') GROUP BY domain "
                "ORDER BY c DESC LIMIT 6")
            self.domain_chart.set_data([(r["domain"] or "?", r["c"]) for r in dom_rows])

            asn_rows = db.query(
                "SELECT isp, COUNT(*) c FROM ip_reputation WHERE isp != '' "
                "GROUP BY isp ORDER BY c DESC LIMIT 6")
            self.asn_chart.set_data([(r["isp"][:30], r["c"]) for r in asn_rows])

            # recent cases
            self.cases_table.setRowCount(0)
            for case in db.list_cases()[:20]:
                sev_color = RED if case["severity"] in ("CRITICAL / MALICIOUS", "HIGH") \
                    else YELLOW if case["severity"] == "SUSPICIOUS" else GREEN
                add_table_row(self.cases_table, [
                    case["id"], case["created_at"], case["severity"],
                    case["sender"], case["origin_ip"], case["verdict"],
                    str(case["risk_score"])],
                    colors_by_col={2: sev_color})
        except Exception as e:  # noqa: BLE001
            from app.core.logging_setup import get_logger
            get_logger("gui.dashboard").warning("Dashboard refresh failed: %s", e)

