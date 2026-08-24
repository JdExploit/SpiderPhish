"""Verify the fixed domain-page job structure with a subdomain input."""
import asyncio
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import httpx

from app.config.settings import AppSettings
from app.integrations.registry import build_registry

s = AppSettings()
reg = build_registry()
timeout = s.analysis.timeout_seconds


async def job(domain):
    from app.analyzers.domain_analyzer import analyze_domain
    rows = []
    async with httpx.AsyncClient(timeout=timeout) as client:
        info = await analyze_domain(domain, client)
        rows.append(("A", ", ".join(info.a) or "-"))
        rows.append(("Registrar", info.registrar or "-"))
        rows.append(("Flags", ", ".join(info.flags) or "-"))
        if info.error:
            rows.append(("RDAP", info.error))
        vt = await reg.virustotal.lookup_domain(domain, client)
        otx = await reg.otx.lookup_domain(domain, client)
    st = getattr(vt.get("status"), "value", "?")
    detail = (f"malicious votes: {vt.get('malicious_votes')}"
              if st == "INFO" else vt.get("error") or st)
    rows.append(("VirusTotal", detail))
    so = getattr(otx.get("status"), "value", "?")
    rows.append(("OTX", f"{otx.get('pulse_count', 0)} pulses"
                 if so == "INFO" else otx.get("error") or so))
    return rows


for dom in ("open.spotify.com", "vitaldent.com"):
    print("==", dom)
    try:
        for r in asyncio.run(job(dom)):
            print("  ", r)
    except Exception as e:
        print("   EXCEPTION:", type(e).__name__, e)
