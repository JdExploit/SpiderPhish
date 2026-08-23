"""AbuseIPDB v2 integration (real API)."""
from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from app.core.logging_setup import get_logger
from app.integrations.base import IPReputationProvider
from app.models.schemas import IPReputation, Status

log = get_logger("abuseipdb")

API_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBProvider(IPReputationProvider):
    name = "AbuseIPDB"

    def is_configured(self) -> bool:
        return bool(self.store.get("ABUSEIPDB_API_KEY"))

    async def lookup_ip(self, ip: str, client: httpx.AsyncClient,
                        max_age_days: int = 90) -> IPReputation:
        rep = IPReputation(provider=self.name, ip=ip)
        key = self.store.get("ABUSEIPDB_API_KEY")
        if not key:
            rep.verdict = Status.NOT_CONFIGURED
            rep.error = self.not_configured_error("an API key (free tier available)")
            return rep
        headers = {"Key": key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": "true"}
        for attempt in range(3):
            try:
                r = await client.get(API_URL, headers=headers, params=params)
                if r.status_code == 429:
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                data = r.json()
                if r.status_code != 200:
                    err = data.get("errors", [{}])[0].get("detail", r.text[:200])
                    log.warning("[WARN] AbuseIPDB error %s: %s", r.status_code, err)
                    rep.verdict = Status.ERROR
                    rep.error = f"HTTP {r.status_code}: {err}"
                    return rep
                d = data.get("data", {})
                reports = d.get("reports") or []
                categories: set[str] = set()
                last_report = ""
                for rp in reports:
                    cats = rp.get("categories") or []
                    from app.integrations.categories import ABUSE_CATEGORY_NAMES
                    for c in cats:
                        categories.add(ABUSE_CATEGORY_NAMES.get(c, str(c)))
                    lr = (rp.get("lastReportedAt") or "")
                    if lr > last_report:
                        last_report = lr
                return IPReputation(
                    provider=self.name,
                    ip=ip,
                    score=int(d.get("abuseConfidenceScore", 0)),
                    abuse_confidence=int(d.get("abuseConfidenceScore", 0)),
                    verdict=Status.INFO,
                    total_reports=int(d.get("totalReports", 0) or len(reports)),
                    last_report=last_report or str(d.get("lastReportedAt", "")),
                    country=str(d.get("countryCode", "")),
                    isp=str(d.get("isp", "")),
                    domain=str(d.get("domain", "")),
                    usage_type=str(d.get("usageType", "")),
                    asn=f"AS{d.get('asn', '')}" if d.get("asn") else "",
                    org=str(d.get("isp", "")),
                    categories=sorted(categories),
                    is_tor=bool(d.get("isTor")),
                    is_hosting=(str(d.get("usageType", "")).lower() in
                                ("data center/web hosting/transit", "data center/web hosting/transit")),
                )
            except httpx.HTTPError as e:
                last_exc = e
                await asyncio.sleep(1 + attempt)
            except Exception as e:  # noqa: BLE001
                rep.verdict = Status.ERROR
                rep.error = f"{type(e).__name__}: {e}"
                log.warning("AbuseIPDB unexpected error: %s", e)
                return rep
        rep.verdict = Status.ERROR
        rep.error = f"AbuseIPDB unavailable ({type(last_exc).__name__}) after retries"
        log.warning(rep.error)
        return rep


DEMO_ABUSE_SCORES: dict[str, int] = {
    # Demo mode only - clearly marked DEMO DATA in UI
}
