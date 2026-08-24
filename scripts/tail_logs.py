"""Shows the newest log entries (any level) from the live DB."""
import sqlite3

conn = sqlite3.connect("data/spiderphish.db")
conn.row_factory = sqlite3.Row
rows = conn.execute(
    "SELECT ts, level, logger, message FROM logs "
    "ORDER BY id DESC LIMIT 60").fetchall()
for r in reversed(rows):
    print(f"{r['ts']} | {r['level']:<8} | {r['logger']:<18} | {r['message'][:200]}")
