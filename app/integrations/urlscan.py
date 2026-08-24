"""URLScan.io integration (real API v1).

Follows official API best practices:
- 'API-Key' header on EVERY request (submit / result / search)
- custom User-Agent identifying the integration + version
- initial wait (~10 s) before polling results, then short intervals
- HTTP 404 = scan still running, HTTP 410 = deleted -> fail fast,
  HTTP 403 = access denied -> fail fast, HTTP 429 -> honor reset hint
- search for an existing scan of the exact URL before spending
  submission quota
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx

from app.core.logging_setup import get_logger
from app.integrations.base import URLReputationProvider
from app.models.schemas import Status

try:
    from app import __version__ as _APP_VERSION
except Exception:  # pragma: no cover - defensive
    _APP_VERSION = "1.0"

log = get_logger("urlscan")

SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
RESULT_URL = "https://urlscan.io/api/v1/result/"
SEARCH_URL = "https://urlscan.io/api/v1/search/"

USER_AGENT = f"SpiderPhish/{_APP_VERSION} (anti-phishing toolkit)"


def _headers(key: str) -> dict[str, str]:
    return {"API-Key": key or "", "User-Agent": USER_AGENT}


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
            r = await client.post(SUBMIT_URL, headers=_headers(key),
                                  json={"url": url, "visibility": "private"})
            data = r.json()
            if r.status_code == 400:
                # per docs: rejection reasons include blacklisted/spammy
                # URLs, non-resolvable hostnames... unless it is an
                # 'already submitted' response carrying a result link
                uuid = ""
                if isinstance(data.get("result"), str) and data["result"]:
                    uuid = data["result"].rstrip("/").rsplit("/", 1)[-1]
                if uuid:
                    return {"status": Status.INFO, "uuid": uuid}
                msg = data.get("message") or data.get("description") or ""
                return {"status": Status.ERROR,
                        "error": (f"URLScan rechazo el envio (HTTP 400): "
                                  f"{str(msg)[:160] or 'sin detalle'}")}
            if r.status_code != 200:
                return {"status": Status.ERROR,
                        "error": f"HTTP {r.status_code}: {str(data)[:200]}"}
            uuid = data.get("uuid", "")
            if not uuid:
                return {"status": Status.ERROR,
                        "error": "URLScan no devolvio UUID de escaneo"}
            return {"status": Status.INFO, "uuid": uuid}
        except httpx.HTTPError as e:
            return {"status": Status.ERROR, "error": f"URLScan unavailable: {e}"}

    async def wait_result(self, uuid: str, client: httpx.AsyncClient,
                          timeout: float = 120.0,
                          poll_interval: float = 4.0,
                          quiet_seconds: float | None = None) -> dict:
        """Poll the Result API.

        Official guidance: wait ~10 s after submission, poll at short
        intervals until finished; 404 while in progress is EXPECTED.
        """
        loop = asyncio.get_event_loop()
        if not uuid:
            return {"status": Status.ERROR,
                    "error": "URLScan: no scan UUID to poll (submission failed)"}
        deadline = loop.time() + timeout
        # initial quiet period so the scan has time to process
        quiet = (min(10.0, max(0.0, timeout * 0.25))
                 if quiet_seconds is None else max(0.0, quiet_seconds))
        await asyncio.sleep(quiet)
        last_err = ""
        while loop.time() < deadline:
            try:
                # private/unlisted scans require the API key to read results
                r = await client.get(RESULT_URL + uuid,
                                     headers=_headers(self.store.get("URLSCAN_API_KEY")))
                if r.status_code == 200:
                    return {"status": Status.INFO, "data": r.json()}
                if r.status_code == 403:
                    return {"status": Status.ERROR,
                            "error": ("URLScan denied result access (HTTP 403). "
                                      "Verifica que la cuenta este verificada en "
                                      "urlscan.io y que la API key sea valida.")}
                if r.status_code == 410:
                    return {"status": Status.ERROR,
                            "error": ("URLScan deleted this result (HTTP 410); "
                                      "vuelve a enviar la URL para re-escanearla.")}
                if r.status_code == 429:
                    # respect the reset window advertised by the API
                    reset_after = float(
                        r.headers.get("X-Rate-Limit-Reset-After", "5") or 5)
                    last_err = (f"HTTP 429 rate-limited "
                                f"(retry in {reset_after:.0f}s)")
                    await asyncio.sleep(min(reset_after, 15.0))
                    continue
                last_err = f"HTTP {r.status_code}"
            except httpx.HTTPError as e:
                last_err = str(e)
            await asyncio.sleep(poll_interval)
        return {"status": Status.ERROR,
                "error": (f"URLScan result timeout ({last_err}). El escaneo "
                          f"puede completarse mas tarde: "
                          f"https://urlscan.io/result/{uuid}/")}

    async def find_existing(self, url: str, client: httpx.AsyncClient,
                            max_age_days: int = 30) -> str | None:
        """Return UUID of an existing scan for this exact URL, if any.

        Official advice: consider searching before submitting again.
        Only fresh results are reused so verdicts stay relevant.
        """
        res = await self.search(f'page.url:"{url}"', client, limit=1)
        if res.get("status") != Status.INFO:
            return None
        for it in res.get("results", []):
            raw_time = it.get("time", "")
            try:
                scanned_at = datetime.fromisoformat(
                    raw_time.replace("Z", "+00:00"))
                age = datetime.now(timezone.utc) - scanned_at
                if age <= timedelta(days=max_age_days):
                    return it.get("uuid")
            except ValueError:
                continue
        return None

    async def lookup_url(self, url: str, client: httpx.AsyncClient) -> dict:
        """Reuse a recent scan if possible, otherwise submit + poll."""
        existing = await self.find_existing(url, client)
        if existing:
            log.info("URLScan: reusing recent scan %s for %s", existing[:8], url[:80])
            sub = {"status": Status.INFO, "uuid": existing}
        else:
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

        def _names(items, key: str) -> list[str]:
            out: list[str] = []
            for x in items or []:
                if isinstance(x, dict):
                    v = x.get(key)
                elif isinstance(x, str):
                    v = x
                else:
                    v = None
                if v:
                    out.append(str(v))
            return out[:20]

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
            # browser-grade redirect history incl. JS/client-side jumps
            "redirects": [
                {"from": rd.get("from", ""),
                 "to": rd.get("to", ""),
                 "status_code": rd.get("status"),
                 "initiator": rd.get("initiator", "")}
                for rd in (d.get("data", {}) or {}).get("redirects", []) or []
            ],
            "domains": _names(lists.get("domains"), "domain"),
            "ips": _names(lists.get("ips"), "ip"),
            "technologies": _names(lists.get("technologies"), "technology"),
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
