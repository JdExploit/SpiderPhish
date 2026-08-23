"""Redirect parser tests using httpx MockTransport (no real network)."""
import httpx
import pytest

from app.config.settings import AnalysisSettings
from app.integrations.wheregoes_adapter import WhereGoesAdapter


def make_adapter(allow_internal=False) -> WhereGoesAdapter:
    return WhereGoesAdapter(type("S", (), {"analysis": AnalysisSettings(
        allow_internal_targets=allow_internal)})())


@pytest.mark.asyncio
async def test_redirect_chain_followed():
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "http://example-start.test/":
            return httpx.Response(302, headers={"Location": "http://mid1.test/a"})
        if url == "http://mid1.test/a":
            return httpx.Response(302, headers={"Location": "http://final.test/x"})
        if url == "http://final.test/x":
            return httpx.Response(200, text="ok", headers={"server": "nginx"})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, follow_redirects=False) as c:
        res = await make_adapter().trace("http://example-start.test/", c,
                                         check_ssrf=False)
    assert res["status"].value in ("INFO",)
    hops = res["hops"]
    assert [h.status_code for h in hops] == [200, 302, 302, 200] or \
           len(hops) >= 3
    assert res["final_url"] == "http://final.test/x"


@pytest.mark.asyncio
async def test_meta_refresh_detected():
    html = '<html><meta http-equiv="refresh" content="0; url=http://phish.test/s"></html>'

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith("http://start2.test"):
            return httpx.Response(200, text=html,
                                  headers={"content-type": "text/html"})
        return httpx.Response(200, text="landed")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, follow_redirects=False) as c:
        res = await make_adapter().trace("http://start2.test/", c,
                                         check_ssrf=False)
    urls = [h.url for h in res["hops"]]
    assert "http://phish.test/s" in urls


@pytest.mark.asyncio
async def test_private_target_blocked_ssrf():
    adapter = make_adapter(allow_internal=False)

    # literal private IP should be rejected before any request
    async def fail_request(*a, **k):  # noqa: ANN002, ANN003
        raise AssertionError("request must not be performed")

    class FakeClient:
        async def get(self, *a, **k):  # noqa: ANN002, ANN003
            raise AssertionError("request must not be performed")
    res = await adapter.trace("http://127.0.0.1/admin", FakeClient())
    assert res["status"].value == "ERROR"
    assert "SSRF" in res["error"] or "Blocked" in res["error"]
