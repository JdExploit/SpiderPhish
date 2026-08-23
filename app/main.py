"""SpiderPhish - application entry point.

Exposes run_app() so both `python main.py` and the single-file edition
can boot the GUI identically.
"""
from __future__ import annotations

from app.gui.main_window import run_app  # re-export

__all__ = ["run_app", "main"]


def main() -> int:
    return run_app()


if __name__ == "__main__":
    raise SystemExit(main())
