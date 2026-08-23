"""URLScan.io integration (real API v1)."""
from __future__ import annotations

import asyncio

import httpx

from app.core.logging_setup import get_logger
from app.integrations.base import URLReputationProvider
from app.models.schemas import Status

log = get_logger("urlscan")

SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
RESULT_URL = "https://urlscan.io/api/v1/result/"
SEARCH_URL = "https://urlscan.io/api/v1/search/"


class UrlScanProvider(URLReputationProvider):
    name = "URLScan.io"

    def is_configured(self) -> bool:
        return bool(self.store.get("URLSCAN_API_KEY"))

    async def submit(self, url: str, client: httpx.AsyncClient) -> dict:
        """Submit a URL for scanning. Sends the URL to an EXTERNAL service."""
        key = self.store.get("URLSCAN_API_KEY")
        if not key:
            return {"status": Status.NOT_CONFIGURED,
                    "error": self.not_configured_error("an API key")}
        try:
            r = await client.post(SUBMIT_URL, headers={"API-Key": key},
                                  json={"url": url, "visibility": "private"})
            data = r.json()
            if r.status_code not in (200, 400):  # 400 may be 'already submitted'
                return {"status": Status.ERROR,
                        "error": f"HTTP {r.status_code}: {str(data)[:200]}"}
            uuid = data.get("uuid", "")
            if r.status_code == 400 and "result" in data:
                uuid = data["result"].rsplit("/", 1)[-1]
            return {"status": Status.INFO, "uuid": uuid}
        except httpx.HTTPError as e:
            return {"status": Status.ERROR, "error": f"URLScan unavailable: {e}"}

    async def wait_result(self, uuid: str, client: httpx.AsyncClient,
                          timeout: float = 45.0) -> dict:
        import time
        deadline = asyncio.get_event_loop().time() + timeout
        last_err = ""
        while asyncio.get_event_loop().time() < deadline:
            try:
                r = await client.get(RESULT_URL + uuid)
                if r.status_code == 200:
                    return {"status": Status.INFO, "data": r.json()}
                last_err = f"HTTP {r.status_code}"
            except httpx.HTTPError as e:
                last_err = str(e)
            await asyncio.sleep(3)
        return {"status": Status.ERROR, "error": f"URLScan result timeout ({last_err})"}

    async def lookup_url(self, url: str, client: httpx.AsyncClient) -> dict:
        """Submit + poll result; returns normalized verdict info."""
        sub = await self.submit(url, client)
        if sub["status"] != Status.INFO:
            return sub
        res = await self.wait_result(sub["uuid"], client)
        if res["status"] != Status.INFO:
            return res
        d = res["data"]
        page = d.get("page", {})
        lists = d.get("lists", {})
        verds = d.get("verdicts", {})
        overall = verds.get("overall", {})
        urlscan_v = verds.get("urlscan", {})
        return {
            "status": Status.INFO,
            "provider": self.name,
            "score": urlscan_v.get("score"),
            "malicious": bool(overall.get("malicious")),
            "suspicious": bool(overall.get("suspicious")),
            "categories": overall.get("categories", []),
            "ip": page.get("ip", ""),
            "asn": f"AS{page.get('asn', '')}" if page.get("asn") else "",
            "asnname": page.get("ASNname") or page.get("asnname", ""),
            "country": page.get("country", ""),
            "server": page.get("server", ""),
            "final_url": page.get("url", ""),
            "domains": [x.get("domain") for x in lists.get("domains", [])][:20],
            "ips": [x.get("ip") for x in lists.get("ips", [])][:20],
            "technologies": [t.get("technology") for t in lists.get("technologies", [])][:15],
            "http_requests": len(d.get("data", {}).get("requests", [])),
            "screenshot_url": f"https://urlscan.io/screenshots/{sub['uuid']}.png",
            "dom_url": f"https://urlscan.io/dom/{sub['uuid']}/",
            "uuid": sub["uuid"],
        }

    async def search(self, query: str, client: httpx.AsyncClient, limit: int = 10) -> dict:
        key = self.store.get("URLSCAN_API_KEY")
        if not key:
            return {"status": Status.NOT_CONFIGURED,
                    "error": self.not_configured_error("an API key")}
        try:
            r = await client.get(SEARCH_URL, params={"q": query, "size": limit},
                                 headers={"API-Key": key})
            if r.status_code != 200:
                return {"status": Status.ERROR, "error": f"HTTP {r.status_code}"}
            results = r.json().get("results", [])
            out = []
            for it in results:
                p = it.get("page", {})
                t = it.get("task", {})
                out.append({
                    "url": p.get("url", ""), "domain": p.get("domain", ""),
                    "ip": p.get("ip", ""), "country": p.get("country", ""),
                    "time": t.get("time", ""), "uuid": it.get("_id", ""),
                    "malicious": bool(it.get("verdicts", {}).get("overall", {}).get("malicious")),
                })
            return {"status": Status.INFO, "results": out}
        except httpx.HTTPError as e:
            return {"status": Status.ERROR, "error": f"URLScan unavailable: {e}"}
