"""Background workers (QThread) so the UI never freezes."""
from __future__ import annotations

import asyncio
import traceback

from PySide6.QtCore import QThread, Signal


class AnalysisWorker(QThread):
    """Runs the async email pipeline off the GUI thread."""
    progress = Signal(int, str)
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, analyzer, raw: bytes, case_id: str = "", parent=None):
        super().__init__(parent)
        self._analyzer = analyzer
        self._raw = raw
        self._case_id = case_id

    def run(self) -> None:
        try:
            result = asyncio.run(self._analyzer.analyze(
                self._raw,
                progress=lambda pct, msg: self.progress.emit(pct, msg),
                case_id=self._case_id))
            self.finished_ok.emit(result)
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self.failed.emit(f"{type(e).__name__}: {e}")


class SimpleWorker(QThread):
    """Generic fn(*args, **kwargs) runner emitting result/failed."""
    result_ready = Signal(object)
    failed = Signal(str)

    def __init__(self, fn, *args, parent=None, **kwargs):
        super().__init__(parent)
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self) -> None:
        try:
            out = asyncio.run(self._fn(*self._args, **self._kwargs)) \
                if asyncio.iscoroutinefunction(self._fn) \
                else self._fn(*self._args, **self._kwargs)
            self.result_ready.emit(out)
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self.failed.emit(f"{type(e).__name__}: {e}")
