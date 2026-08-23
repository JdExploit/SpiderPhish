"""SpiderPhish dark SOC/DFIR theme - QSS + palette."""
from __future__ import annotations

# Palette ---------------------------------------------------------------
BG        = "#0a0c0e"   # near-black app background
BG2       = "#0e1114"   # secondary
PANEL     = "#12151a"   # card / panel
PANEL2    = "#171b21"   # elevated panel
BORDER    = "#1f242c"   # subtle border
BORDER2   = "#2a3038"
TEXT      = "#d7dde3"
TEXT_DIM  = "#8b949e"
ACCENT    = "#e5484d"   # SpiderPhish red
RED       = "#e5484d"
GREEN     = "#3fb950"
YELLOW    = "#d29922"
ORANGE    = "#db6d28"
BLUE      = "#58a6ff"
PURPLE    = "#bc8cff"

SEVERITY_COLORS = {
    "SAFE": GREEN, "MATCH": GREEN, "LOW": GREEN, "INFO": BLUE,
    "GUARDED": YELLOW, "SUSPICIOUS": YELLOW, "WARNING": YELLOW,
    "HIGH": RED, "CRITICAL": RED, "MALICIOUS": RED,
    "MISMATCH": ORANGE, "UNKNOWN": TEXT_DIM, "NOT ANALYZED": TEXT_DIM,
    "NOT CONFIGURED": TEXT_DIM, "ERROR": ORANGE,
}

FONT_FAMILY = "Segoe UI"


def build_qss() -> str:
    return f"""
* {{
    font-family: "{FONT_FAMILY}";
    font-size: 10pt;
    color: {TEXT};
}}
QMainWindow, QWidget#Root {{ background-color: {BG}; }}

/* ---------------- Sidebar ---------------- */
QWidget#Sidebar {{
    background-color: {BG2};
    border-right: 1px solid {BORDER};
}}
QLabel#Brand {{
    color: {TEXT};
    font-size: 15pt;
    font-weight: 800;
    letter-spacing: 1px;
}}
QLabel#BrandSub {{
    color: {ACCENT};
    font-size: 7.5pt;
    font-weight: 700;
    letter-spacing: 2px;
}}
QPushButton[nav="true"] {{
    text-align: left;
    padding: 7px 12px;
    border: none;
    border-left: 3px solid transparent;
    background: transparent;
    color: {TEXT_DIM};
    font-size: 9.5pt;
    font-weight: 600;
}}
QPushButton[nav="true"]:hover {{ color: {TEXT}; background: {PANEL}; }}
QPushButton[nav="true"]:checked {{
    color: {TEXT};
    background: {PANEL2};
    border-left: 3px solid {ACCENT};
}}
QLabel#NavSection {{
    color: {TEXT_DIM};
    font-size: 7.5pt;
    font-weight: 800;
    letter-spacing: 2px;
    padding: 10px 14px 3px 14px;
}}

/* ---------------- Top bar ---------------- */
QWidget#TopBar {{
    background-color: {BG2};
    border-bottom: 1px solid {BORDER};
}}
QLabel#TopTitle {{ color: {TEXT}; font-size: 11pt; font-weight: 700; }}
QLabel#TopTagline {{ color: {ACCENT}; font-size: 8pt; font-weight: 700; letter-spacing: 1.5px; }}
QWidget#TopTabs QPushButton {{
    background: transparent; border: none; color: {TEXT_DIM};
    padding: 6px 12px; font-size: 9pt; font-weight: 600;
}}
QWidget#TopTabs QPushButton:checked {{ color: {ACCENT}; border-bottom: 2px solid {ACCENT}; }}

/* ---------------- Status bar ---------------- */
QStatusBar {{ background: {BG2}; border-top: 1px solid {BORDER}; color: {TEXT_DIM}; font-size: 8.5pt; }}

/* ---------------- Panels / cards ---------------- */
QFrame#Card, QGroupBox#Card {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 6px;
}}
QLabel#CardTitle {{
    color: {TEXT}; font-weight: 700; font-size: 9.5pt; letter-spacing: 0.5px;
}}
QLabel#SectionLabel {{
    color: {ACCENT}; font-size: 8pt; font-weight: 800; letter-spacing: 1.5px;
}}

/* ---------------- Inputs ---------------- */
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background-color: {BG2};
    border: 1px solid {BORDER2};
    border-radius: 4px;
    padding: 5px 8px;
    selection-background-color: {ACCENT};
}}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{ border: 1px solid {ACCENT}; }}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background: {PANEL}; border: 1px solid {BORDER2};
    selection-background-color: {PANEL2};
}}

/* ---------------- Buttons ---------------- */
QPushButton {{
    background-color: {PANEL2};
    border: 1px solid {BORDER2};
    border-radius: 4px;
    padding: 6px 14px;
    font-weight: 600;
    color: {TEXT};
}}
QPushButton:hover {{ border-color: {ACCENT}; color: {TEXT}; }}
QPushButton:pressed {{ background: {BORDER}; }}
QPushButton:disabled {{ color: {TEXT_DIM}; border-color: {BORDER}; }}
QPushButton#Primary {{
    background-color: {ACCENT};
    border: 1px solid {ACCENT};
    color: white;
    font-weight: 800;
}}
QPushButton#Primary:hover {{ background: #f25559; }}
QPushButton#Danger {{ background: transparent; color: {RED}; border-color: {RED}; }}
QPushButton#Success {{ color: {GREEN}; border-color: {GREEN}; background: transparent; }}

/* ---------------- Tables ---------------- */
QTableWidget, QTableView {{
    background-color: {PANEL};
    alternate-background-color: {BG2};
    gridline-color: {BORDER};
    border: 1px solid {BORDER};
    selection-background-color: {PANEL2};
    selection-color: {TEXT};
}}
QHeaderView::section {{
    background-color: {BG2};
    color: {TEXT_DIM};
    padding: 5px 8px;
    border: none;
    border-right: 1px solid {BORDER};
    border-bottom: 1px solid {BORDER2};
    font-weight: 800;
    font-size: 8pt;
    letter-spacing: 1px;
}}
QTableCornerButton::section {{ background: {BG2}; border: none; }}

/* ---------------- Tabs ---------------- */
QTabWidget::pane {{ border: 1px solid {BORDER}; top: -1px; }}
QTabBar::tab {{
    background: {BG2};
    color: {TEXT_DIM};
    padding: 6px 14px;
    border: 1px solid {BORDER};
    border-bottom: none;
    margin-right: 2px;
    font-weight: 700; font-size: 8.5pt;
}}
QTabBar::tab:selected {{ color: {TEXT}; background: {PANEL}; border-top: 2px solid {ACCENT}; }}
QTabBar::tab:hover {{ color: {TEXT}; }}

/* ---------------- Scrollbars ---------------- */
QScrollBar:vertical {{ background: {BG2}; width: 10px; border: none; }}
QScrollBar::handle:vertical {{ background: {BORDER2}; min-height: 30px; border-radius: 5px; }}
QScrollBar::handle:vertical:hover {{ background: {ACCENT}; }}
QScrollBar:horizontal {{ background: {BG2}; height: 10px; border: none; }}
QScrollBar::handle:horizontal {{ background: {BORDER2}; min-width: 30px; border-radius: 5px; }}
QScrollBar::add-line,QScrollBar::sub-line {{ height:0; width:0; }}
QScrollBar::add-page,QScrollBar::sub-page {{ background:none; }}

/* ---------------- Progress bar ---------------- */
QProgressBar {{
    background: {BG2}; border: 1px solid {BORDER}; border-radius: 3px;
    text-align: center; color: {TEXT}; font-size: 8pt; font-weight: 700;
}}
QProgressBar::chunk {{ background-color: {ACCENT}; border-radius: 2px; }}

/* ---------------- Log console ---------------- */
QPlainTextEdit#LogConsole {{
    background-color: #07090b;
    border: 1px solid {BORDER};
    font-family: "Consolas";
    font-size: 8.6pt;
    color: {TEXT};
}}

/* ---------------- Tooltip / menu ---------------- */
QToolTip {{
    background: {PANEL2}; color: {TEXT}; border: 1px solid {ACCENT};
    padding: 4px 6px; font-size: 8.5pt;
}}
QMenu {{ background: {PANEL}; border: 1px solid {BORDER2}; }}
QMenu::item:selected {{ background: {PANEL2}; color: {ACCENT}; }}

QCheckBox::indicator, QRadioButton::indicator {{
    width: 13px; height: 13px; border: 1px solid {BORDER2};
    background: {BG2}; border-radius: 3px;
}}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}

QSplitter::handle {{ background: {BORDER}; width: 1px; height: 1px; }}

QListWidget {{
    background: {PANEL}; border: 1px solid {BORDER};
    outline: 0;
}}
QListWidget::item {{ padding: 6px; border-bottom: 1px solid {BORDER}; }}
QListWidget::item:selected {{ background: {PANEL2}; color: {TEXT}; border-left: 2px solid {ACCENT}; }}
"""
