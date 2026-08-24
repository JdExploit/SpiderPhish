"""Reproduce reputation-page jobs headlessly to surface exceptions."""
import asyncio
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import httpx

from app.config.settings import AppSettings
from app.integrations.registry import build_registry
from app.gui.pages.ioc_lookup_page import classify

s = AppSettings()
reg = build_registry()
timeout = s.analysis.timeout_seconds


async def ip_job(ip):
    rows = []
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await reg.abuseipdb.lookup_ip(ip, client)
        rows.append(("abuseipdb", r.verdict.value, r.error))
        try:
            vt = await reg.virustotal.lookup_ip(ip, client)
            st = getattr(vt.get("status"), "value", "?")
            rows.append(("vt-ip", st, vt.get("error")))
        except Exception as e:
            rows.append(("vt-ip", "EXCEPTION", f"{type(e).__name__}: {e}"))
        try:
            otx = await reg.otx.lookup_ip(ip, client)
            rows.append(("otx-ip", getattr(otx.get('status'), 'value', '?'), otx.get("error")))
        except Exception as e:
            rows.append(("otx-ip", "EXCEPTION", f"{type(e).__name__}: {e}"))
        try:
            gn = await reg.greynoise.lookup_ip(ip, client)
            rows.append(("greynoise-ip", getattr(gn.get('status'), 'value', '?'), gn.get("error")))
        except Exception as e:
            rows.append(("greynoise-ip", "EXCEPTION", f"{type(e).__name__}: {e}"))
    return rows


async def dom_job(d):
    rows = []
    async with httpx.AsyncClient(timeout=timeout) as client:
        from app.analyzers.domain_analyzer import analyze_domain
        info = await analyze_domain(d, client)
        rows.append(("rdap", info.registrar or "-", str(info.age_days)))
        try:
            vt = await reg.virustotal.lookup_domain(d, client)
            rows.append(("vt-dom", getattr(vt.get("status"), "value", "?"), vt.get("error")))
        except Exception as e:
            rows.append(("vt-dom", "EXCEPTION", f"{type(e).__name__}: {e}"))
        try:
            otx = await reg.otx.lookup_domain(d, client)
            rows.append(("otx-dom", getattr(otx.get("status"), "value", "?"), otx.get("error")))
        except Exception as e:
            rows.append(("otx-dom", "EXCEPTION", f"{type(e).__name__}: {e}"))
    return rows


async def hash_job(h):
    rows = []
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            vt = await reg.virustotal.lookup_hash(h.lower(), client)
            rows.append(("vt-hash", getattr(vt.get("status"), "value", "?"),
                         vt.get("error"), bool(vt.get("found"))))
        except Exception as e:
            rows.append(("vt-hash", "EXCEPTION", f"{type(e).__name__}: {e}"))
    return rows


async def main():
    print("classify:", classify("8.8.8.8"), classify("example.com"),
          classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
    for r in await ip_job("50.16.16.211"):
        print("IP   ", r)
    for r in await ip_job("300.300.1.1"):
        print("IPbad", r)
    for r in await dom_job("vitaldent.com"):
        print("DOM  ", r)
    for r in await hash_job(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"):
        print("HASH ", r)

asyncio.run(main())
