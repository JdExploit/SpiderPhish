"""AlienVault OTX integration (IP / domain indicators)."""
from __future__ import annotations

import httpx

from app.core.logging_setup import get_logger
from app.integrations.base import ThreatIntelProvider
from app.models.schemas import Status

log = get_logger("otx")

BASE = "https://otx.alienvault.com/api/v1"


class OTXProvider(ThreatIntelProvider):
    name = "AlienVault OTX"

    def is_configured(self) -> bool:
        return bool(self.store.get("OTX_API_KEY"))

    def _headers(self) -> dict:
        return {"X-OTX-API-KEY": self.store.get("OTX_API_KEY", "")}

    async def lookup_ip(self, ip: str, client: httpx.AsyncClient) -> dict:
        if not self.is_configured():
            return {"status": Status.NOT_CONFIGURED,
                    "error": self.not_configured_error("an OTX key (free)")}
        try:
            r = await client.get(f"{BASE}/indicators/IPv4/{ip}/general", headers=self._headers())
            if r.status_code != 200:
                return {"status": Status.ERROR, "error": f"HTTP {r.status_code}"}
            d = r.json()
            pulses = d.get("pulse_info", {}).get("pulses", [])
            return {
                "status": Status.INFO, "provider": self.name,
                "pulse_count": d.get("pulse_info", {}).get("count", 0),
                "pulses": [p.get("name", "") for p in pulses[:10]],
                "malware_families": d.get("malware_families", []),
            }
        except httpx.HTTPError as e:
            return {"status": Status.ERROR, "error": f"OTX unavailable: {e}"}

    async def lookup_domain(self, domain: str, client: httpx.AsyncClient) -> dict:
        if not self.is_configured():
            return {"status": Status.NOT_CONFIGURED,
                    "error": self.not_configured_error("an OTX key (free)")}
        try:
            r = await client.get(f"{BASE}/indicators/domain/{domain}/general", headers=self._headers())
            if r.status_code != 200:
                return {"status": Status.ERROR, "error": f"HTTP {r.status_code}"}
            d = r.json()
            pulses = d.get("pulse_info", {}).get("pulses", [])
            return {
                "status": Status.INFO, "provider": self.name,
                "pulse_count": d.get("pulse_info", {}).get("count", 0),
                "pulses": [p.get("name", "") for p in pulses[:10]],
                "alexa_rank": d.get("alexa"),
            }
        except httpx.HTTPError as e:
            return {"status": Status.ERROR, "error": f"OTX unavailable: {e}"}
