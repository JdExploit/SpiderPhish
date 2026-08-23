"""Redirect chain analyzer - thin wrapper over the WhereGoes adapter."""
from __future__ import annotations

import httpx

from app.integrations.wheregoes_adapter import WhereGoesAdapter
from app.core.logging_setup import get_logger

log = get_logger("redirect_analyzer")


class RedirectAnalyzer:
    def __init__(self, settings) -> None:  # noqa: ANN001
        self.adapter = WhereGoesAdapter(settings)

    async def trace(self, url: str, client: httpx.AsyncClient) -> dict:
        result = await self.adapter.trace(url, client)
        hops = result.get("hops", [])
        if len(hops) >= 2:
            log.warning("[WARN] Redirect chain detected (%d hops) for %s", len(hops), url)
        return result
