"""Dumps recent ERROR/WARNING logs + provider status from the live DB."""
import sqlite3
import sys

DB = "data/spiderphish.db"

conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

print("=== LAST 40 ERRORS/WARNINGS ===")
rows = conn.execute(
    "SELECT ts, level, logger, message FROM logs "
    "WHERE level IN ('ERROR','WARNING','CRITICAL') "
    "ORDER BY id DESC LIMIT 40").fetchall()
for r in rows:
    print(f"{r['ts']} | {r['level']:<8} | {r['logger']:<18} | {r['message'][:180]}")
print(f"--- shown: {len(rows)}")

print()
print("=== RECENT ANALYSIS RESULTS (provider outcomes) ===")
try:
    rows = conn.execute(
        "SELECT created_at, band, verdict, summary_json FROM analysis_results "
        "ORDER BY id DESC LIMIT 3").fetchall()
    for r in rows:
        s = json.loads(r["summary_json"]) if "summary_json" in r.keys() else {}
        import json
        try:
            s = json.loads(r["summary_json"] or "{}")
        except Exception:
            s = {}
        ipr = s.get("ip_reputation", {})
        print(f"\n[{r['created_at']}] {r['band']} | {r['verdict'][:60]}")
        print(f"  origin_ip={s.get('origin_ip', {}).get('ip', '?')}")
        print(f"  abuseipdb: score={ipr.get('score')} verdict={ipr.get('verdict')} "
              f"error='{ipr.get('error', '')[:120]}' demo={ipr.get('demo')}")
        for u in (s.get("urls") or [])[:3]:
            print(f"  url: {u.get('url','')[:70]} -> {u.get('risk_level')} "
                  f"urlscan_verdict={u.get('urlscan_verdict')} "
                  f"urlscan_err='{u.get('error','')[:80]}'")
        for e in (s.get("errors") or [])[:10]:
            print(f"  PIPELINE ERROR: {e[:150]}")
except Exception as e:
    print("analysis_results read failed:", e)

print()
print("=== SECURE STORE KEY PRESENCE (masked) ===")
sys.path.insert(0, ".")
from app.config.settings import SecureStore
store = SecureStore()
for k in store._KEY_NAMES:
    v = store.get(k)
    if v:
        print(f"{k}: SET ({v[:4]}...{v[-3:]}, len={len(v)})")
    else:
        print(f"{k}: NOT SET")
