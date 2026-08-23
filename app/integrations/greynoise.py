"""GreyNoise community API integration (IP context: scan/noise activity)."""
from __future__ import annotations

import httpx

from app.core.logging_setup import get_logger
from app.integrations.base import ThreatIntelProvider
from app.models.schemas import Status

log = get_logger("greynoise")

COMMUNITY_URL = "https://api.greynoise.io/v3/community/"


class GreyNoiseProvider(ThreatIntelProvider):
    name = "GreyNoise"

    def is_configured(self) -> bool:
        return bool(self.store.get("GREYNOISE_API_KEY"))

    async def lookup_ip(self, ip: str, client: httpx.AsyncClient) -> dict:
        if not self.is_configured():
            return {"status": Status.NOT_CONFIGURED,
                    "error": self.not_configured_error("an API key")}
        try:
            r = await client.get(COMMUNITY_URL + ip,
                                 headers={"key": self.store.get("GREYNOISE_API_KEY", "")})
            if r.status_code == 404:
                return {"status": Status.INFO, "noise": False, "message": "not observed scanning"}
            if r.status_code != 200:
                return {"status": Status.ERROR, "error": f"HTTP {r.status_code}"}
            d = r.json()
            return {
                "status": Status.INFO, "provider": self.name,
                "noise": d.get("noise", False),
                "riot": d.get("riot", False),
                "classification": d.get("classification", ""),
                "name": d.get("name", ""),
                "link": d.get("link", ""),
                "last_seen": d.get("last_seen", ""),
            }
        except httpx.HTTPError as e:
            return {"status": Status.ERROR, "error": f"GreyNoise unavailable: {e}"}
