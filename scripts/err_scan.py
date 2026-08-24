import sqlite3

conn = sqlite3.connect("data/spiderphish.db")
rows = conn.execute(
    "SELECT ts, logger, message FROM logs "
    "WHERE level IN ('ERROR','CRITICAL') ORDER BY id DESC LIMIT 20"
).fetchall()
for ts, lg, msg in rows:
    print(ts, "|", lg, "|", msg[:180])
total = conn.execute(
    "SELECT COUNT(*) FROM logs WHERE level='ERROR'").fetchone()[0]
print("--- total ERROR rows:", total)
