"""Bulk analysis page: process many .eml files asynchronously, export results."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from PySide6.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QMessageBox,
                               QPushButton, QVBoxLayout, QWidget)

from app.core.logging_setup import get_logger
from app.gui.theme import GREEN, RED, TEXT_DIM, YELLOW
from app.gui.widgets.common import Card, add_table_row, make_table
from app.gui.workers import SimpleWorker

log = get_logger("gui.bulk")


class BulkAnalysisPage(QWidget):
    def __init__(self, app_ctx):
        super().__init__()
        self.app_ctx = app_ctx
        self._worker = None
        self._results = []
        self._files: list[str] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        t = QLabel("BULK ANALYSIS")
        t.setStyleSheet("font-size:14pt; font-weight:800;")
        d = QLabel("Selecciona 10, 50 o 100+ correos .eml y procésalos de forma "
                   "asíncrona. Exporta CSV / JSON.")
        d.setStyleSheet(f"color:{TEXT_DIM};")
        root.addWidget(t); root.addWidget(d)

        row = QHBoxLayout()
        self.btn_select = QPushButton("Seleccionar .eml...")
        self.btn_run = QPushButton("ANALYZE ALL"); self.btn_run.setObjectName("Primary")
        self.btn_run.setEnabled(False)
        self.btn_csv = QPushButton("Export CSV"); self.btn_csv.setEnabled(False)
        self.btn_json = QPushButton("Export JSON"); self.btn_json.setEnabled(False)
        row.addWidget(self.btn_select)
        row.addWidget(self.btn_run)
        row.addStretch()
        row.addWidget(self.btn_csv); row.addWidget(self.btn_json)
        root.addLayout(row)

        card = Card("RESULTS")
        self.table = make_table(
            ["File", "Sender", "Origin IP", "URLs", "Score", "Verdict",
             "Status"], stretch_cols=[0, 5])
        card.add(self.table)
        root.addWidget(card, 1)
        self.status = QLabel("")
        self.status.setStyleSheet(f"color:{TEXT_DIM};")
        root.addWidget(self.status)

        self.btn_select.clicked.connect(self.select_files)
        self.btn_run.clicked.connect(self.run_all)
        self.btn_csv.clicked.connect(lambda: self.export("csv"))
        self.btn_json.clicked.connect(lambda: self.export("json"))

    # ------------------------------------------------------------------
    def select_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Seleccionar correos .eml", "", "Email files (*.eml);;All files (*)")
        if not paths:
            return
        self._files = paths
        self._results = []
        self.table.setRowCount(0)
        for p in paths:
            add_table_row(self.table, [Path(p).name, "-", "-", "-", "-", "-", "QUEUED"],
                          colors_by_col={6: "#8b949e"})
        self.btn_run.setEnabled(True)
        self.status.setText(f"{len(paths)} archivo(s) en cola")

    def run_all(self):
        if self._worker and self._worker.isRunning():
            return
        analyzer = self.app_ctx.analyzer

        async def job():
            out = []
            sem_count = max(1, min(4, self.app_ctx.settings.analysis.concurrent_requests))

            async def one(i: int, path: str):
                try:
                    raw = Path(path).read_bytes()
                    a = await analyzer.analyze(raw, progress=None,
                                               case_id=f"BULK-{i+1:04d}")
                    out.append((i, {
                        "file": Path(path).name,
                        "sender": a.from_addr,
                        "origin_ip": a.origin_ip.ip,
                        "urls": len(a.urls),
                        "score": a.risk.score,
                        "verdict": a.risk.band.value,
                        "status": "OK"}))
                except Exception as e:  # noqa: BLE001
                    out.append((i, {"file": Path(path).name, "sender": "",
                                    "origin_ip": "", "urls": 0, "score": -1,
                                    "verdict": "", "status": f"ERROR {type(e).__name__}"}))

            tasks = [one(i, p) for i, p in enumerate(self._files)]
            await asyncio.gather(*tasks)
            out.sort(key=lambda x: x[0])
            return [r for _, r in out]

        self.btn_run.setEnabled(False)
        log.info("Bulk analysis started: %d files", len(self._files))
        self.status.setText("Analyzing...")
        self._worker = SimpleWorker(job, parent=self)
        self._worker.result_ready.connect(self.on_done)
        self._worker.failed.connect(self.on_error)
        self._worker.start()

    def on_done(self, results):  # noqa: ANN001
        self._results = results
        self.table.setRowCount(0)
        mal = 0
        for r in results:
            color = RED if r["score"] >= 60 else YELLOW if r["score"] >= 40 \
                else GREEN if r["score"] >= 0 else "#8b949e"
            if r["score"] >= 60:
                mal += 1
            add_table_row(self.table, [
                r["file"], r["sender"], r["origin_ip"], str(r["urls"]),
                str(r["score"]) if r["score"] >= 0 else "-",
                r["verdict"] or "-", r["status"]],
                colors_by_col={4: color, 5: color})
        self.btn_run.setEnabled(True)
        self.btn_csv.setEnabled(True)
        self.btn_json.setEnabled(True)
        self.status.setText(f"Analysis completed — {len(results)} processed, "
                            f"{mal} malicious/high risk")
        log.info("Bulk analysis completed: %d files (%d high risk)",
                 len(results), mal)

    def on_error(self, err):  # noqa: ANN001
        self.btn_run.setEnabled(True)
        self.status.setText(f"Error: {err}")
        log.error("Bulk failed: %s", err)

    def export(self, fmt: str):
        if not self._results:
            return
        default = f"bulk_analysis.{fmt}"
        path, _ = QFileDialog.getSaveFileName(self, "Exportar", default,
                                              f"*.{fmt}")
        if not path:
            return
        try:
            if fmt == "csv":
                lines = ["file,sender,origin_ip,urls,score,verdict,status"]
                for r in self._results:
                    lines.append(",".join(str(r[k]).replace(",", ";") for k in
                                          ("file", "sender", "origin_ip", "urls",
                                           "score", "verdict", "status")))
                Path(path).write_text("\n".join(lines), encoding="utf-8")
            else:
                Path(path).write_text(json.dumps(self._results, indent=2),
                                      encoding="utf-8")
            log.info("Exported bulk results to %s", path)
        except OSError as e:
            QMessageBox.critical(self, "Error", f"No se pudo exportar:\n{e}")
