"""MHA (Microsoft Header Analyzer, mha.azurewebsites.net) adapter.

There is no documented public API for the hosted service, so this adapter:
  - runs a LOCAL header analysis as primary source (always available), and
  - optionally POSTs raw headers to the MHA endpoint if explicitly enabled
    and reachable. Failures never block the analysis.

The remote mode is OFF by default; enable it in Settings -> API Configuration
only if you accept sending email headers to an external service.
"""
from __future__ import annotations

import httpx

from app.core.logging_setup import get_logger
from app.models.schemas import Status

log = get_logger("mha")

MHA_URL = "https://mha.azurewebsites.net/api/Analyze"


class MHAAdapter:
    name = "MHA"

    def is_configured(self) -> bool:
        from app.config.settings import secure_store
        return secure_store().get("MHA_ENABLED") == "1"

    async def analyze(self, raw_headers: str, client: httpx.AsyncClient) -> dict:
        if not self.is_configured():
            return {
                "status": Status.NOT_CONFIGURED,
                "error": ("MHA remote analysis NOT CONFIGURED. Local header analysis "
                          "is used instead. To enable remote MHA, set MHA_ENABLED=1 "
                          "in Settings -> API Configuration (sends headers externally)."),
            }
        try:
            r = await client.post(MHA_URL, json={"inputHeaders": raw_headers},
                                  timeout=20.0)
            if r.status_code != 200:
                return {"status": Status.ERROR, "error": f"HTTP {r.status_code}"}
            return {"status": Status.INFO, "data": r.json()}
        except httpx.HTTPError as e:
            return {"status": Status.ERROR, "error": f"MHA unavailable: {e}"}
