import json
import sys

import httpx

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from app.config.settings import secure_store

key = secure_store().get("URLSCAN_API_KEY") or ""
uuid = "01a03555-c375-706e-a7bf-a0eff6e26b94"
with httpx.Client(headers={"API-Key": key}, timeout=30,
                  follow_redirects=True) as c:
    d = c.get(f"https://urlscan.io/api/v1/result/{uuid}").json()

data = d.get("data", {})
print("TOP KEYS:", sorted(data.keys()))
reqs = data.get("requests", [])
print("n_requests:", len(reqs))
if reqs:
    r0 = reqs[0]
    print("REQ KEYS:", sorted(r0.keys()))
    resp = r0.get("response", {})
    print("RESP KEYS:", sorted(resp.keys()))
# find any key containing 'redirect'
def walk(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if "redirect" in k.lower():
                print("FOUND KEY:", path + "/" + k,
                      "->", str(v)[:300])
            walk(v, path + "/" + k)
    elif isinstance(obj, list) and obj:
        walk(obj[0], path + "[0]")

walk(d)
