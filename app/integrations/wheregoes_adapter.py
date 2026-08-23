"""Redirect chain analysis.

WhereGoes.com offers no public API, so the adapter performs REAL redirect
following locally via httpx (primary), with SSRF guards. An optional remote
WhereGoes-style endpoint can be configured, but local analysis is default.
"""
from __future__ import annotations

from urllib.parse import urljoin

import httpx

from app.core.logging_setup import get_logger
from app.models.schemas import RedirectHop, Status
from app.utils.ioc_extraction import domain_of
from app.utils.net import UnsafeTargetError, validate_url

log = get_logger("wheregoes")

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
META_REFRESH_LIMIT = 3


class WhereGoesAdapter:
    name = "WhereGoes"

    def __init__(self, settings) -> None:  # noqa: ANN001
        self.settings = settings.analysis

    def is_configured(self) -> bool:
        return True  # local engine always available

    async def trace(self, url: str, client: httpx.AsyncClient,
                    check_ssrf: bool = True) -> dict:
        """Follow redirects manually; returns hops + final destination.

        check_ssrf=False is intended for unit tests using MockTransport only.
        """
        hops: list[RedirectHop] = []
        current = url
        allow_internal = self.settings.allow_internal_targets
        try:
            current = validate_url(current, allow_internal) if check_ssrf else current
        except UnsafeTargetError as e:
            return {"status": Status.ERROR, "error": str(e), "hops": []}

        total = max(1, self.settings.max_redirects)
        meta_refresh_seen = 0

        for step in range(1, total + 1):
            try:
                r = await client.get(current)
                hop = RedirectHop(
                    step=step,
                    url=str(r.url),
                    status_code=r.status_code,
                    reason=r.reason_phrase,
                    domain=domain_of(str(r.url)),
                    server=r.headers.get("server", ""),
                    location=r.headers.get("location", ""),
                    protocol=str(r.url).split("://")[0],
                )
                # extract connected IP when available (httpx internals vary);
                # fall back to DNS later if needed
                hops.append(hop)

                if r.status_code in REDIRECT_STATUSES and r.headers.get("location"):
                    nxt = urljoin(str(r.url), r.headers["location"])
                    try:
                        nxt = validate_url(nxt, allow_internal) if check_ssrf else nxt
                    except UnsafeTargetError as e:
                        return {"status": Status.ERROR, "error": str(e), "hops": hops,
                                "blocked_redirect": True}
                    current = nxt
                    continue
                if r.status_code == 200:
                    body_ct = r.headers.get("content-type", "")
                    if "text/html" in body_ct and meta_refresh_seen < META_REFRESH_LIMIT:
                        mr = _parse_meta_refresh(r.text or "")
                        if mr:
                            meta_refresh_seen += 1
                            nxt = urljoin(str(r.url), mr[1])
                            if check_ssrf:
                                nxt = validate_url(nxt, allow_internal)
                            hops.append(RedirectHop(
                                step=len(hops) + 1, url=nxt, status_code=None,
                                reason=f"meta-refresh ({mr[0]}s)",
                                domain=domain_of(nxt),
                                protocol=nxt.split("://")[0]))
                            current = nxt
                            continue
                break
            except httpx.HTTPError as e:
                log.warning("[WARN] redirect fetch failed at %s: %s", current, e)
                return {"status": Status.ERROR,
                        "error": f"Request failed at hop {step}: {type(e).__name__}",
                        "hops": hops}
            except UnsafeTargetError as e:
                return {"status": Status.ERROR, "error": str(e), "hops": hops}

        status = Status.INFO if hops else Status.ERROR
        err = "" if hops else "No response received"
        return {"status": status, "error": err, "hops": hops,
                "final_url": hops[-1].url if hops else url}


def _parse_meta_refresh(html: str):
    import re
    m = re.search(
        r"<meta[^>]+http-equiv=[\"']?refresh[\"']?[^>]+content=[\"'](\d+)\s*;\s*url=([^\"']+)",
        html, re.IGNORECASE)
    if m:
        return int(m.group(1)), m.group(2).strip()
    return None
