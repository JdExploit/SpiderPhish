"""IOC CORRELATION page - attack graph with clickable nodes + inspector."""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QPushButton, QScrollArea, QSplitter, QTextEdit,
    QVBoxLayout, QWidget)

from app.core.logging_setup import get_logger
from app.gui.theme import ACCENT, BG, GREEN, ORANGE, PANEL2, RED, TEXT_DIM, YELLOW
from app.gui.widgets.common import Card, EmptyState, RiskBar, SeverityBadge

log = get_logger("gui.corr")

NODE_W = 190
NODE_H = 52
GAP_X = 46
GAP_Y = 34
KIND_GLYPH = {"email": "\u2709", "domain": "\u25c9", "ip": "\u25ce",
              "asn": "\u2261", "url": "\u2315", "redirect": "\u21c4",
              "final": "\u26a0"}

VERDICT_COLORS = {
    "CRITICAL": RED, "MALICIOUS": RED, "HIGH": RED,
    "SUSPICIOUS": YELLOW, "GUARDED": ORANGE,
    "SAFE": GREEN, "LOW": GREEN, "MATCH": GREEN,
    "UNKNOWN": TEXT_DIM, "NOT ANALYZED": TEXT_DIM,
    "ERROR": TEXT_DIM, "INFO": "#58a6ff",
}


def verdict_color(status_value: str) -> str:
    return VERDICT_COLORS.get((status_value or "").upper(), TEXT_DIM)


class GraphNodeRect:
    __slots__ = ("node", "x", "y", "w", "h")

    def __init__(self, node, x: float, y: float):
        self.node = node
        self.x, self.y, self.w, self.h = x, y, NODE_W, NODE_H


class AttackGraphCanvas(QWidget):
    """Custom-painted layered attack graph; nodes are clickable."""

    def __init__(self, on_select=None, parent=None):
        super().__init__(parent)
        self._rects: list[GraphNodeRect] = []
        self._edges = []
        self._scale = 1.0
        self.selected_id = ""
        self._on_select = on_select
        self.setMinimumHeight(300)

    # ------------------------------------------------------------- data
    def set_graph(self, nodes, edges):
        self._edges = [(e.src, e.dst, e.relation) for e in edges]
        self.selected_id = ""
        self._layout(nodes)
        self.updateGeometry()

    def _layout(self, nodes):
        # layered layout by BFS depth over edges
        depth: dict[str, int] = {}
        children: dict[str, list[str]] = {}
        ids = [n.node_id for n in nodes]
        for src, dst, _ in self._edges:
            children.setdefault(src, []).append(dst)
        roots = [i for i in ids if not any(d == i for _, d, _ in self._edges)]
        frontier = roots or (ids[:1] if ids else [])
        for r in frontier:
            depth.setdefault(r, 0)
        while frontier:
            nxt = []
            for cur in frontier:
                for ch in children.get(cur, []):
                    nd = depth[cur] + 1
                    if ch not in depth or depth[ch] < nd:
                        depth[ch] = nd
                        nxt.append(ch)
            frontier = [x for x in nxt if x in set(ids)]

        by_depth: dict[int, list] = {}
        for n in nodes:
            d = depth.get(n.node_id, 0)
            by_depth.setdefault(d, []).append(n)

        self._rects = []
        max_row = max((len(v) for v in by_depth.values()), default=0)
        width_needed = max_row * NODE_W + (max_row + 1) * GAP_X
        height_needed = (max(by_depth.keys(), default=0) + 1) * (NODE_H + GAP_Y)
        for d in sorted(by_depth.keys()):
            row = by_depth[d]
            row_w = len(row) * NODE_W + (len(row) - 1) * GAP_X
            x0 = (width_needed - row_w) / 2
            for j, n in enumerate(row):
                self._rects.append(GraphNodeRect(
                    n, x0 + j * (NODE_W + GAP_X), d * (NODE_H + GAP_Y)))
        self.setFixedSize(int(width_needed * self._scale) + GAP_X,
                          int(height_needed * self._scale) + GAP_Y)
        self.update()

    def set_scale(self, s: float):
        self._scale = max(0.5, min(2.2, s))
        nodes = [r.node for r in self._rects]
        self._layout(nodes)

    def scale_step(self, delta: float):
        self.set_scale(self._scale + delta)

    # ------------------------------------------------------------- painting
    def paintEvent(self, ev):  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.scale(self._scale, self._scale)
        p.fillRect(self.rect().translated(0, 0), QColor(BG))
        p.fillRect(QRectF(0, 0, self.width() / self._scale,
                          self.height() / self._scale), QColor(BG))

        pos = {r.node.node_id: (r.x + r.w / 2, r.y) for r in self._rects}
        bottom = {r.node.node_id: (r.x + r.w / 2, r.y + r.h)
                  for r in self._rects}

        # edges first
        arrow = QPolygonF()
        for src, dst, rel in self._edges:
            if src not in bottom or dst not in pos:
                continue
            x1, y1 = bottom[src]
            x2, y2 = pos[dst]
            sel = self.selected_id in (src, dst)
            pen = QPen(QColor(ACCENT if sel else "#3a4149"),
                       1.8 if sel else 1.2, Qt.SolidLine, Qt.RoundCap)
            p.setPen(pen)
            midy = (y1 + y2) / 2
            path_pts = [(x1, y1), (x1, midy), (x2, midy), (x2, y2 - 7)]
            for i in range(len(path_pts) - 1):
                p.drawLine(QPointF(*path_pts[i]), QPointF(*path_pts[i + 1]))
            arrow.clear()
            arrow.append(QPointF(x2 - 4.5, y2 - 8))
            arrow.append(QPointF(x2 + 4.5, y2 - 8))
            arrow.append(QPointF(x2, y2 - 1))
            p.setBrush(QColor(ACCENT if sel else "#3a4149"))
            p.setPen(Qt.NoPen)
            p.drawPolygon(arrow)
            if rel and sel:
                p.setPen(QPen(QColor(TEXT_DIM)))
                f = QFont()
                f.setPointSize(7)
                p.setFont(f)
                p.drawText(QPointF(x2 + 6, midy + 3), rel)

        # node boxes
        f_title = QFont()
        f_title.setBold(True)
        f_title.setPointSize(8)
        f_sub = QFont()
        f_sub.setPointSize(6.5)
        for r in self._rects:
            n = r.node
            col = QColor(verdict_color(n.verdict.value))
            sel = n.node_id == self.selected_id
            box = QRectF(r.x, r.y, r.w, r.h)
            p.setPen(QPen(QColor(ACCENT) if sel else col.darker(150),
                          2.2 if sel else 1.4))
            p.setBrush(QColor(PANEL2))
            p.drawRoundedRect(box, 7, 7)
            p.setPen(Qt.NoPen)
            p.setBrush(col.darker(320))
            p.drawRoundedRect(box.adjusted(0, 0, 5, 0), 7, 7)

            glyph = KIND_GLYPH.get(n.kind, "\u25cf")
            p.setPen(QPen(QColor(col)))
            f_g = QFont()
            f_g.setPointSize(10)
            p.setFont(f_g)
            p.drawText(QRectF(r.x + 8, r.y + 4, 20, 20), Qt.AlignVCenter, glyph)

            p.setFont(f_title)
            p.setPen(QColor("#d7dde3"))
            title = QRectF(r.x + 28, r.y + 4, r.w - 36, 18)
            p.drawText(title, Qt.AlignVCenter | Qt.AlignHCenter,
                       _elide(n.label, 24))
            p.setFont(f_sub)
            p.setPen(QColor(col))
            sub = QRectF(r.x + 8, r.y + 24, r.w - 16, 12)
            p.drawText(sub, Qt.AlignVCenter | Qt.AlignHCenter,
                       _elide(n.detail or n.value, 44))
            p.setPen(QColor(TEXT_DIM))
            p.drawText(QRectF(r.x + 8, r.y + 37, r.w - 16, 12),
                       Qt.AlignVCenter | Qt.AlignHCenter,
                       n.kind.upper() + ("  \u25b8" if sel else ""))
        p.end()

    # ------------------------------------------------------------- hit test
    def mousePressEvent(self, ev):  # noqa: N802
        sp = ev.position() / self._scale
        for r in reversed(self._rects):
            if r.x <= sp.x() <= r.x + r.w and r.y <= sp.y() <= r.y + r.h:
                self.selected_id = r.node.node_id
                self.update()
                if self._on_select:
                    self._on_select(r.node)
                return
        self.selected_id = ""
        self.update()


def _elide(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "\u2026"


class CorrelationPage(QWidget):
    """IOC Correlation & Attack Graph page."""

    def __init__(self, app_ctx, main_window=None):
        super().__init__()
        self.app_ctx = app_ctx
        self.main_window = main_window
        self._analysis = None
        self._corr = None

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        root.setSpacing(8)

        head = QHBoxLayout()
        tb = QVBoxLayout()
        t = QLabel("IOC CORRELATION & ATTACK GRAPH")
        t.setObjectName("CardTitle")
        t.setStyleSheet("font-size:14pt; font-weight:800; letter-spacing:1px;")
        d = QLabel("Conecta remitente, IP de origen, ASN, dominios, URLs y "
                   "redirecciones en una sola narrativa de ataque.")
        d.setStyleSheet(f"color:{TEXT_DIM}; font-size:9pt;")
        tb.addWidget(t)
        tb.addWidget(d)
        head.addLayout(tb)
        head.addStretch()
        self.btn_zoom_out = QPushButton("\u2212")
        self.btn_zoom_in = QPushButton("+")
        self.btn_rebuild = QPushButton("REBUILD GRAPH")
        self.btn_rebuild.setObjectName("Primary")
        for b, tip in ((self.btn_zoom_out, "Zoom out"), (self.btn_zoom_in, "Zoom in")):
            b.setFixedWidth(34)
        self.btn_rebuild.clicked.connect(lambda: self.refresh(force=True))
        self.btn_zoom_in.clicked.connect(lambda: self.canvas.scale_step(0.15))
        self.btn_zoom_out.clicked.connect(lambda: self.canvas.scale_step(-0.15))
        head.addWidget(self.btn_zoom_out)
        head.addWidget(self.btn_zoom_in)
        head.addWidget(self.btn_rebuild)
        root.addLayout(head)

        # banner
        banner_wrap = QVBoxLayout()
        self.banner_card = Card("CORRELATION VERDICT")
        brow = QHBoxLayout()
        left = QVBoxLayout()
        self.verdict_lbl = QLabel("NO ANALYSIS YET")
        vf = QFont()
        vf.setBold(True)
        vf.setPointSize(13)
        self.verdict_lbl.setFont(vf)
        self.sub_lbl = QLabel("Analiza un correo para construir el grafo.")
        self.sub_lbl.setStyleSheet(f"color:{TEXT_DIM}; font-size:9pt;")
        left.addWidget(self.verdict_lbl)
        left.addWidget(self.sub_lbl)
        right = QVBoxLayout()
        self.badge = SeverityBadge("UNKNOWN")
        self.conf_bar = RiskBar()
        self.conf_bar.setFixedWidth(220)
        right.addWidget(self.badge, alignment=Qt.AlignRight)
        right.addWidget(self.conf_bar, alignment=Qt.AlignRight)
        brow.addLayout(left, 1)
        brow.addLayout(right)
        self.camp_lbl = QLabel("")
        self.camp_lbl.setWordWrap(True)
        self.camp_lbl.setStyleSheet(
            f"background:{RED}; color:#0a0c0e; font-weight:800;"
            "border-radius:4px; padding:6px 10px;")
        self.camp_lbl.setVisible(False)
        self.banner_card.add_layout(brow)
        self.banner_card.add(self.camp_lbl)
        banner_wrap.addWidget(self.banner_card)
        root.addLayout(banner_wrap)

        # splitter: graph | inspector
        split = QSplitter(Qt.Horizontal)
        root.addWidget(split, 1)

        self.canvas = AttackGraphCanvas(on_select=self._node_selected)
        scroll = QScrollArea()
        scroll.setWidgetResizable(False)
        scroll.setWidget(self.canvas)
        split.addWidget(scroll)

        self.inspector_tabs = QTextEdit()
        self.inspector_tabs.setReadOnly(True)
        self.inspector_tabs.setFont(QFont("Consolas", 8))
        self.inspector_tabs.setStyleSheet(
            f"background:#07090b; border:1px solid {PANEL2};")
        self.evidence_view = QTextEdit()
        self.evidence_view.setReadOnly(True)
        self.evidence_view.setStyleSheet(
            f"background:#07090b; border:1px solid {PANEL2};")
        from PySide6.QtWidgets import QTabWidget
        tabs = QTabWidget()
        tabs.addTab(self.inspector_tabs, "NODE INTEL")
        tabs.addTab(self.evidence_view, "EVIDENCE")
        split.addWidget(tabs)
        split.setSizes([860, 480])

        self.empty = EmptyState(
            "\u2691", "No analysis loaded",
            "Ejecuta un análisis en Email Analyzer; esta página conectará "
            "automáticamente todos sus indicadores.")

    # ------------------------------------------------------------------
    def refresh(self, force: bool = False):
        a = getattr(self.app_ctx, "last_analysis", None)
        if not a:
            self.verdict_lbl.setText("NO ANALYSIS YET")
            return
        if a is self._analysis and self._corr is not None and not force:
            return
        self._analysis = a
        db = self.app_ctx.db
        from app.analyzers.correlation import correlate
        try:
            self._corr = correlate(a, db=db)
        except Exception as e:  # noqa: BLE001
            log.warning("correlation failed: %s", e)
            return
        self._render(a, self._corr)
        self.raise_()

    def _render(self, a, corr):
        color = verdict_color(corr.band.value.split(" /")[0])
        self.verdict_lbl.setText(f"\u26a1 {corr.verdict}")
        self.verdict_lbl.setStyleSheet(f"color:{color}; font-weight:800;")
        shared = ", ".join(sorted({
            n.label for n in corr.graph_nodes
            if n.kind in ("domain", "ip")})[:4])
        self.sub_lbl.setText(
            f"{corr.correlated_indicators} indicadores correlacionados · "
            f"{len(corr.graph_nodes)} nodos · {shared}")
        self.badge.set_severity(corr.band.value.replace(" / MALICIOUS", ""))
        self.badge.setText(corr.band.value.split(" /")[0])
        self.conf_bar.set_value(corr.confidence)

        camp = corr.campaign
        if camp is not None and (camp.detected or camp.cluster):
            icon = "\U0001F534" if camp.detected else "\u26a0"
            self.camp_lbl.setVisible(True)
            self.camp_lbl.setText(
                f" {icon} POSSIBLE CAMPAIGN DETECTED — {camp.note} · "
                f"{camp.emails} emails · {camp.recipients} recipients · "
                f"{camp.domains} domains · {camp.ips} IPs"
                + (f" · visto desde {camp.first_seen[:10]}" if camp.first_seen else ""))
            self.camp_lbl.setStyleSheet(
                f"background:{RED if camp.detected else '#7a5b00'};"
                " color:#ffffff; font-weight:700; font-size:9pt;"
                "border-radius:4px; padding:6px 10px;")
        else:
            self.camp_lbl.setVisible(False)

        self.canvas.set_graph(corr.graph_nodes, corr.graph_edges)

        ev_lines = []
        for i, e in enumerate(corr.evidence, 1):
            c = verdict_color(e.severity.value)
            ev_lines.append(
                f"<div style='margin-bottom:10px;'>"
                f"<span style='color:{c}; font-weight:800;'>"
                f"[{e.severity.value}] {i}. {e.title}</span><br/>"
                f"<span style='color:{TEXT_DIM};'>{e.detail}</span></div>")
        self.evidence_view.setHtml(
            "<div style='font-family:Consolas,monospace; font-size:9pt;'>"
            + ("\n".join(ev_lines)
               or "<span style='color:#8b949e'>Sin evidencia cruzada.</span>")
            + "</div>")
        self.inspector_tabs.setPlainText(
            "Click any node in the graph to inspect it.\n\n"
            "Nodes show the verdict each analyzer assigned; edges are real "
            "relationships found in headers/DNS/redirects.")

    # ------------------------------------------------------------------
    def _node_selected(self, node):
        a = self._analysis
        if not a:
            return
        lines = [
            f"NODE      : {node.node_id}",
            f"TYPE      : {node.kind.upper()}",
            f"LABEL     : {node.label}",
            f"VALUE     : {node.value}",
            f"VERDICT   : {node.verdict.value}",
            f"DETAIL    : {node.detail}",
            "-" * 66,
        ]
        if node.kind == "email":
            lines += self._intel_email(a)
        elif node.kind == "domain":
            dom = node.label
            di = a.domains.get(dom)
            if di is None:
                lines.append("(sin datos DNS/RDAP recolectados para este dominio)")
            else:
                lines += self._intel_domain(di)
        elif node.kind == "ip":
            lines += self._intel_ip(a)
        elif node.kind == "asn":
            asn = node.label.lower()
            lines += [
                f"ASN       : {asn.upper()}",
                f"ORG       : {a.ip_classification.asn_org or a.ip_reputation.isp or '-'}",
                f"COUNTRY   : {a.ip_classification.country or a.ip_reputation.country or '-'}",
                f"IP hosted : {a.origin_ip.ip or '-'}",
                f"Usage     : {a.ip_classification.classification}",
            ]
        elif node.kind in ("url", "redirect", "final"):
            u = self._find_url(node)
            if u is not None:
                lines += self._intel_url(u, node)
        self.inspector_tabs.setPlainText("\n".join(lines))

    @staticmethod
    def _intel_email(a):
        out = ["EMAIL INTELLIGENCE", "-" * 66]
        auth = a.authentication
        out.append(f"From      : {a.from_display} <{a.from_addr}>")
        out.append(f"Reply-To  : {a.reply_to or '-'}")
        out.append(f"Return-P  : {a.return_path or '-'}")
        out.append(f"SPF       : {auth.spf.result or 'none'} ({auth.spf.domain or '-'})")
        out.append(f"DKIM      : {auth.dkim.result or 'none'} ({auth.dkim.domain or '-'})")
        out.append(f"DMARC     : {auth.dmarc.result or 'none'} ({auth.dmarc.domain or '-'})")
        out.append(f"Risk      : {a.risk.score}/100 {a.risk.band.value}")
        if a.risk.why:
            out.append("Factors:")
            for f in sorted(a.risk.why, key=lambda x: -x.points)[:8]:
                out.append(f"  +{f.points:>3} {f.name}")
        return out

    @staticmethod
    def _intel_domain(di):
        out = ["DOMAIN / DNS / RDAP INTELLIGENCE", "-" * 66]
        out.append(f"A         : {', '.join(di.a) or '-'}")
        out.append(f"AAAA      : {', '.join(di.aaaa) or '-'}")
        out.append(f"MX        : {', '.join(di.mx[:4]) or '-'}")
        out.append(f"NS        : {', '.join(di.ns[:4]) or '-'}")
        out.append(f"TXT/SPF   : {(di.txt[0][:70] if di.txt else '-')}")
        out.append(f"CNAME     : {', '.join(di.cname[:3]) or '-'}")
        out.append(f"Registrar : {di.registrar or '-'}")
        out.append(f"Created   : {di.creation_date or '-'} "
                   + (f"(age {di.age_days}d)" if di.age_days is not None else ""))
        out.append(f"Expires   : {di.expiration_date or '-'}")
        out.append(f"RDAP      : {'available' if di.rdap_available else 'not available'}")
        if di.flags:
            out.append(f"Flags     : {', '.join(di.flags)}")
        if di.error:
            out.append(f"Error     : {di.error}")
        return out

    @staticmethod
    def _intel_ip(a):
        rep = a.ip_reputation
        cls = a.ip_classification
        out = ["ORIGIN IP INTELLIGENCE", "-" * 66]
        out.append(f"IP        : {a.origin_ip.ip}")
        out.append(f"Source    : {a.origin_ip.source_header or '-'} "
                   f"(confidence {int(a.origin_ip.confidence*100)}%)")
        out.append(f"PTR       : {cls.reverse_dns or '-'}")
        out.append(f"ASN       : {cls.asn_number or rep.asn or '-'} "
                   f"({cls.asn_org or rep.isp or '-'})")
        out.append(f"Country   : {rep.country or cls.country or '-'}")
        out.append(f"Type      : {cls.classification}"
                   + (" | TOR" if rep.is_tor else "")
                   + (" | PROXY" if rep.is_proxy else "")
                   + (" | HOSTING" if rep.is_hosting else ""))
        if rep.score is not None:
            out.append(f"AbuseIPDB : {rep.score}/100 -> {rep.band.value}"
                       + (" [DEMO]" if rep.demo else ""))
            out.append(f"Reports   : {rep.total_reports} (last {rep.last_report or '-'})")
            if rep.categories:
                out.append(f"Categories: {', '.join(rep.categories)}")
        elif rep.error:
            out.append(f"AbuseIPDB : {rep.error}")
        else:
            out.append("AbuseIPDB : NOT CONFIGURED (configura API key en Ajustes)")
        hops = a.origin_ip.hops
        if hops:
            out.append("Received chain:")
            for h in hops[-4:]:
                out.append(f"  [{h.index:02d}] {h.from_ip or '?'} via "
                           f"{h.with_proto or '?'} {h.tls}")
        return out

    @staticmethod
    def _intel_url(u, node=None):
        out = ["URL INTELLIGENCE", "-" * 66]
        out.append(f"URL       : {u.url}")
        if u.final_url:
            out.append(f"Final     : {u.final_url}")
        out.append(f"Domain    : {u.domain} (sub: {u.subdomain or '-'}, tld: {u.tld})")
        out.append(f"Score     : {u.risk_score}/100 -> {u.risk_level.value}")
        if u.flags:
            out.append(f"Flags     : {', '.join(u.flags)}")
        if u.urlscan_score is not None:
            out.append(f"urlscan.io : score {u.urlscan_score} -> "
                       f"{u.urlscan_verdict.value}")
        else:
            out.append("urlscan.io : NOT CONFIGURED / not run")
        safety = None
        out.append(f"Redirects : {u.redirect_count}")
        if u.redirect_chain:
            for h in u.redirect_chain:
                out.append(f"  {h.step:>2}. [{h.status_code or 'META'}] "
                           f"{h.url[:76]}")
        if u.error:
            out.append(f"Error     : {u.error}")
        return out

    def _find_url(self, node):
        a = self._analysis
        if node.kind == "url":
            try:
                idx = int(node.node_id.split(":")[1])
                return a.urls[idx]
            except (ValueError, IndexError):
                pass
            return next((u for u in a.urls if node.value in u.url), None)
        target = node.value
        for u in a.urls:
            chain_vals = [h.url for h in u.redirect_chain] + [u.final_url]
            if any(target and target in v for v in chain_vals if v):
                return u
        return None
