"""Structured logging with a Qt signal bridge for the live log console."""
from __future__ import annotations

import logging
from datetime import datetime

from PySide6.QtCore import QObject, Signal


class LogBus(QObject):
    """Bridge between python logging and the GUI live console."""
    message = Signal(str, str, str)  # ts, level, message

    def __init__(self) -> None:
        super().__init__()
        self._db = None

    def attach_db(self, db) -> None:  # noqa: ANN001
        self._db = db


_bus: LogBus | None = None


def log_bus() -> LogBus:
    global _bus
    if _bus is None:
        _bus = LogBus()
    return _bus


class BusHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            ts = datetime.now().strftime("%H:%M:%S")
            log_bus().message.emit(ts, record.levelname, record.getMessage())
            bus = log_bus()
            if bus._db is not None:
                bus._db.insert_log(datetime.now().isoformat(timespec="seconds"),
                                   record.levelname, record.name, record.getMessage())
        except Exception:
            pass


def setup_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")
    # console
    for h in list(root.handlers):
        root.removeHandler(h)
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    root.addHandler(ch)
    # GUI bus + DB
    bh = BusHandler()
    bh.setFormatter(fmt)
    root.addHandler(bh)
    logging.getLogger(__name__).info("Logging initialized (level=%s)", level)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def set_log_level(level: str) -> None:
    logging.getLogger().setLevel(getattr(logging, level.upper(), logging.INFO))
