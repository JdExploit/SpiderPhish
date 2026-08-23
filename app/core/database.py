"""SQLite persistence layer with schema versioning / migrations.

Tables: cases, emails, iocs, urls, domains, ip_reputation, analysis_results,
logs, settings_kv.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = 2

MIGRATIONS: dict[int, list[str]] = {
    1: [
        """CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            analyst TEXT DEFAULT '',
            severity TEXT DEFAULT 'UNKNOWN',
            sender TEXT DEFAULT '',
            origin_ip TEXT DEFAULT '',
            domains TEXT DEFAULT '[]',
            urls TEXT DEFAULT '[]',
            verdict TEXT DEFAULT '',
            risk_score INTEGER DEFAULT 0,
            notes TEXT DEFAULT '',
            tags TEXT DEFAULT '[]',
            analysis_json TEXT DEFAULT ''
        )""",
        """CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT REFERENCES cases(id),
            analyzed_at TEXT NOT NULL,
            subject TEXT DEFAULT '',
            from_addr TEXT DEFAULT '',
            return_path TEXT DEFAULT '',
            reply_to TEXT DEFAULT '',
            message_id TEXT DEFAULT '',
            size_bytes INTEGER DEFAULT 0
        )""",
        """CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            context TEXT DEFAULT '',
            severity TEXT DEFAULT 'INFO'
        )""",
        """CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            url TEXT NOT NULL,
            domain TEXT DEFAULT '',
            final_url TEXT DEFAULT '',
            redirect_count INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'NOT ANALYZED',
            flags TEXT DEFAULT '[]'
        )""",
        """CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            domain TEXT NOT NULL,
            registrar TEXT DEFAULT '',
            creation_date TEXT DEFAULT '',
            age_days INTEGER,
            flags TEXT DEFAULT '[]'
        )""",
        """CREATE TABLE IF NOT EXISTS ip_reputation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            ip TEXT NOT NULL,
            provider TEXT DEFAULT '',
            score INTEGER,
            verdict TEXT DEFAULT 'NOT ANALYZED',
            country TEXT DEFAULT '',
            isp TEXT DEFAULT ''
        )""",
        """CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            created_at TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            band TEXT DEFAULT 'SAFE',
            verdict TEXT DEFAULT '',
            summary_json TEXT DEFAULT '{}'
        )""",
        """CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            level TEXT NOT NULL,
            logger TEXT DEFAULT '',
            message TEXT NOT NULL,
            extra TEXT DEFAULT '{}'
        )""",
        """CREATE TABLE IF NOT EXISTS settings_kv (
            key TEXT PRIMARY KEY,
            value TEXT DEFAULT ''
        )""",
    ],
    2: [
        """CREATE TABLE IF NOT EXISTS ioc_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL,
            role TEXT DEFAULT '',
            verdict TEXT DEFAULT 'UNKNOWN',
            recipient TEXT DEFAULT '',
            seen_at TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_ioc_obs_value ON ioc_observations(value)",
        "CREATE INDEX IF NOT EXISTS idx_ioc_obs_aid ON ioc_observations(analysis_id)",
    ],
}


class Database:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self.migrate()

    # ------------------------------------------------------------------
    def migrate(self) -> None:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'")
            has_table = cur.fetchone() is not None
            version = 0
            if has_table:
                row = self._conn.execute("SELECT MAX(version) v FROM schema_version").fetchone()
                version = row["v"] or 0
            for v in range(version + 1, SCHEMA_VERSION + 1):
                for stmt in MIGRATIONS[v]:
                    self._conn.execute(stmt)
                if not has_table:
                    self._conn.execute(
                        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)")
                    has_table = True
                self._conn.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (?)", (v,))

    def execute(self, sql: str, params: tuple = ()) -> None:
        with self._lock, self._conn:
            self._conn.execute(sql, params)

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    # ------------------------------ DAO --------------------------------
    def save_case(self, rec: dict[str, Any]) -> None:
        self.execute(
            """INSERT OR REPLACE INTO cases
               (id, created_at, analyst, severity, sender, origin_ip, domains, urls,
                verdict, risk_score, notes, tags, analysis_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rec["id"], rec.get("created_at", datetime.now().isoformat(timespec="seconds")),
             rec.get("analyst", ""), rec.get("severity", ""), rec.get("sender", ""),
             rec.get("origin_ip", ""), json.dumps(rec.get("domains", [])),
             json.dumps(rec.get("urls", [])), rec.get("verdict", ""),
             rec.get("risk_score", 0), rec.get("notes", ""), json.dumps(rec.get("tags", [])),
             json.dumps(rec.get("analysis_json", {}))))

    def list_cases(self) -> list[dict[str, Any]]:
        rows = self.query("SELECT * FROM cases ORDER BY created_at DESC")
        out = []
        for r in rows:
            d = dict(r)
            d["domains"] = json.loads(d.get("domains") or "[]")
            d["urls"] = json.loads(d.get("urls") or "[]")
            d["tags"] = json.loads(d.get("tags") or "[]")
            out.append(d)
        return out

    def get_case(self, case_id: str) -> Optional[dict[str, Any]]:
        rows = self.query("SELECT * FROM cases WHERE id=?", (case_id,))
        if not rows:
            return None
        d = dict(rows[0])
        for k in ("domains", "urls", "tags"):
            d[k] = json.loads(d.get(k) or "[]")
        d["analysis_json"] = json.loads(d.get("analysis_json") or "{}")
        return d

    def delete_case(self, case_id: str) -> None:
        self.execute("DELETE FROM cases WHERE id=?", (case_id,))

    def next_case_id(self) -> str:
        year = datetime.now().year
        rows = self.query("SELECT COUNT(*) c FROM cases WHERE id LIKE ?", (f"CASE-{year}-%",))
        n = rows[0]["c"] + 1 if rows else 1
        return f"CASE-{year}-{n:05d}"

    def save_analysis_summary(self, case_id: str, analysis_dict: dict[str, Any]) -> None:
        self.execute(
            "INSERT INTO analysis_results (case_id, created_at, risk_score, band, verdict, summary_json) "
            "VALUES (?,?,?,?,?,?)",
            (case_id, datetime.now().isoformat(timespec="seconds"),
             analysis_dict.get("risk_score", 0), analysis_dict.get("band", ""),
             analysis_dict.get("verdict", ""), json.dumps(analysis_dict)))

    # --------------------- IOC observations (campaigns) -----------------
    def record_observations(self, analysis_id: str,
                            rows: list[tuple[str, str, str, str, str, str]]) -> None:
        """rows: (ioc_type, value, role, verdict, recipient, seen_at)."""
        if not rows:
            return
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO ioc_observations (analysis_id, ioc_type, value, role,"
                " verdict, recipient, seen_at) VALUES (?,?,?,?,?,?,?)",
                [(analysis_id, t, v, r, vd, rc, ts) for (t, v, r, vd, rc, ts) in rows])

    def _campaign_base(self, values: list[str], exclude_id: str) -> list[sqlite3.Row]:
        vals = [v for v in dict.fromkeys(values) if v][:200]
        if not vals:
            return []
        qmarks = ",".join("?" * len(vals))
        return self.query(
            f"""SELECT ioc_type, value,
                       COUNT(DISTINCT analysis_id) AS n_analysis,
                       GROUP_CONCAT(DISTINCT analysis_id) AS ids,
                       MIN(seen_at) AS first_seen, MAX(seen_at) AS last_seen
                FROM ioc_observations
                WHERE value IN ({qmarks}) AND analysis_id != ?
                GROUP BY ioc_type, value
                ORDER BY n_analysis DESC""",
            (*vals, exclude_id))

    def campaign_lookup(self, values: list[str], exclude_id: str = "") -> list[dict[str, Any]]:
        out = []
        for r in self._campaign_base(values, exclude_id):
            out.append({
                "ioc_type": r["ioc_type"], "value": r["value"],
                "past_analyses": int(r["n_analysis"]),
                "analysis_ids": [x for x in (r["ids"] or "").split(",") if x],
                "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            })
        return out

    def campaign_recipients(self, values: list[str], exclude_id: str = "") -> set[str]:
        vals = [v for v in dict.fromkeys(values) if v][:200]
        if not vals:
            return set()
        qmarks = ",".join("?" * len(vals))
        rows = self.query(
            f"""SELECT DISTINCT recipient FROM ioc_observations
                WHERE value IN ({qmarks}) AND analysis_id != ?
                      AND recipient != ''""",
            (*vals, exclude_id))
        return {r["recipient"] for r in rows}

    def insert_log(self, ts: str, level: str, logger: str, message: str) -> None:
        try:
            self.execute("INSERT INTO logs (ts, level, logger, message) VALUES (?,?,?,?)",
                         (ts, level, logger, message))
        except Exception:
            pass

    def dashboard_stats(self) -> dict[str, int]:
        def one(sql: str, params: tuple = ()) -> int:
            r = self.query(sql, params)
            return int(r[0][list(r[0].keys())[0]]) if r else 0
        stats = {}
        stats["cases"] = one("SELECT COUNT(*) FROM cases")
        stats["emails"] = one("SELECT COUNT(*) FROM emails")
        stats["malicious"] = one("SELECT COUNT(*) FROM analysis_results WHERE band IN ('HIGH','CRITICAL / MALICIOUS')")
        stats["suspicious"] = one("SELECT COUNT(*) FROM analysis_results WHERE band='SUSPICIOUS'")
        stats["safe"] = one("SELECT COUNT(*) FROM analysis_results WHERE band IN ('SAFE','LOW')")
        stats["malicious_urls"] = one("SELECT COUNT(*) FROM urls WHERE risk_level IN ('MALICIOUS','CRITICAL','HIGH')")
        stats["malicious_ips"] = one("SELECT COUNT(*) FROM ip_reputation WHERE verdict IN ('MALICIOUS','HIGH')")
        stats["iocs"] = one("SELECT COUNT(*) FROM iocs")
        return stats


_db: Optional[Database] = None


def _migrate_legacy_db(db_path: Path) -> None:
    """Rebrand migration: copy legacy jdexploit.db -> spiderphish.db."""
    if db_path.name != "spiderphish.db" or db_path.exists():
        return
    legacy = db_path.with_name("jdexploit.db")
    if not legacy.exists():
        return
    import shutil
    try:
        shutil.copy2(legacy, db_path)
        for ext in ("-wal", "-shm"):
            src = legacy.with_name(legacy.name + ext)
            if src.exists():
                shutil.copy2(src, db_path.with_name(db_path.name + ext))
    except OSError:
        pass


def get_db() -> Database:
    global _db
    if _db is None:
        from app.config.settings import AppSettings
        s = AppSettings.load()
        p = Path(s.storage.db_path)
        _migrate_legacy_db(p)
        _db = Database(p)
    return _db
