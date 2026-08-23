"""VirusTotal v3 integration (IP / domain / hash / URL lookups)."""
from __future__ import annotations

import base64

import httpx

from app.core.logging_setup import get_logger
from app.integrations.base import ThreatIntelProvider
from app.models.schemas import IPReputation, Status

log = get_logger("virustotal")

BASE = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(ThreatIntelProvider):
    name = "VirusTotal"

    def is_configured(self) -> bool:
        return bool(self.store.get("VIRUSTOTAL_API_KEY"))

    def _headers(self) -> dict:
        return {"x-apikey": self.store.get("VIRUSTOTAL_API_KEY", "")}

    async def lookup_ip(self, ip: str, client: httpx.AsyncClient) -> dict:
        if not self.is_configured():
            return {"status": Status.NOT_CONFIGURED,
                    "error": self.not_configured_error("an API key")}
        try:
            r = await client.get(f"{BASE}/ip_addresses/{ip}", headers=self._headers())
            if r.status_code != 200:
                return {"status": Status.ERROR, "error": f"HTTP {r.status_code}"}
            d = r.json().get("data", {}).get("attributes", {})
            stats = d.get("last_analysis_stats", {})
            return {
                "status": Status.INFO, "provider": self.name,
                "malicious_votes": stats.get("malicious", 0),
                "suspicious_votes": stats.get("suspicious", 0),
                "harmless_votes": stats.get("harmless", 0),
                "reputation": d.get("reputation"),
                "country": d.get("country"),
                "as_owner": d.get("as_owner"),
            }
        except httpx.HTTPError as e:
            return {"status": Status.ERROR, "error": f"VirusTotal unavailable: {e}"}

    async def lookup_domain(self, domain: str, client: httpx.AsyncClient) -> dict:
        if not self.is_configured():
            return {"status": Status.NOT_CONFIGURED,
                    "error": self.not_configured_error("an API key")}
        try:
            r = await client.get(f"{BASE}/domains/{domain}", headers=self._headers())
            if r.status_code != 200:
                return {"status": Status.ERROR, "error": f"HTTP {r.status_code}"}
            d = r.json().get("data", {}).get("attributes", {})
            stats = d.get("last_analysis_stats", {})
            cats = {}
            for engine, cat in (d.get("categories") or {}).items():
                cats[engine] = cat
            return {
                "status": Status.INFO, "provider": self.name,
                "malicious_votes": stats.get("malicious", 0),
                "suspicious_votes": stats.get("suspicious", 0),
                "harmless_votes": stats.get("harmless", 0),
                "categories": cats,
                "last_dns_records": [rec.get("value", "") for rec in (d.get("last_dns_records") or [])],
            }
        except httpx.HTTPError as e:
            return {"status": Status.ERROR, "error": f"VirusTotal unavailable: {e}"}

    async def lookup_hash(self, sha256: str, client: httpx.AsyncClient) -> dict:
        if not self.is_configured():
            return {"status": Status.NOT_CONFIGURED,
                    "error": self.not_configured_error("an API key")}
        try:
            r = await client.get(f"{BASE}/files/{sha256}", headers=self._headers())
            if r.status_code == 404:
                return {"status": Status.INFO, "found": False}
            if r.status_code != 200:
                return {"status": Status.ERROR, "error": f"HTTP {r.status_code}"}
            d = r.json().get("data", {}).get("attributes", {})
            stats = d.get("last_analysis_stats", {})
            names = d.get("names", [])
            popular = sorted(set(names), key=len)[:5]
            sigs = []
            for eng, res in (d.get("last_analysis_results") or {}).items():
                if res.get("category") == "malicious":
                    sigs.append(res.get("result", ""))
            return {
                "status": Status.INFO, "provider": self.name, "found": True,
                "malicious_votes": stats.get("malicious", 0),
                "suspicious_votes": stats.get("suspicious", 0),
                "undetected_votes": stats.get("undetected", 0),
                "signatures": [s for s in sigs if s][:15],
                "names": popular,
                "type_description": d.get("type_description", ""),
            }
        except httpx.HTTPError as e:
            return {"status": Status.ERROR, "error": f"VirusTotal unavailable: {e}"}

    @staticmethod
    def url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
