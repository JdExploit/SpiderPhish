import sqlite3
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

conn = sqlite3.connect("data/spiderphish.db")
rows = conn.execute(
    "SELECT ts, level, logger, message FROM logs "
    "WHERE id > (SELECT MAX(id) - 120 FROM logs) ORDER BY id"
).fetchall()
for ts, lv, lg, msg in rows:
    print(ts, "|", f"{lv:<8}", "|", lg, "|", msg[:150])
