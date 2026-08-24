"""Static JS-redirect detection + urlscan redirect history parsing."""
import asyncio

import httpx
import pytest

from app.integrations.urlscan import UrlScanProvider
from app.integrations.wheregoes_adapter import _parse_js_redirect
from app.models.schemas import Status


def test_detects_window_location_assign():
    html = ("<html><script>window.location="
            "'https://xml-v4.pushub.net/click?i=1';</script></html>")
    assert _parse_js_redirect(html) == "https://xml-v4.pushub.net/click?i=1"


def test_detects_location_href_and_replace():
    assert _parse_js_redirect(
        'location.href = "http://x.example/a";') == "http://x.example/a"
    assert _parse_js_redirect(
        "window.location.replace('https://y.tld/z')") == "https://y.tld/z"


def test_ignores_clean_html_and_js_scheme():
    assert _parse_js_redirect("<p>hello</p>") is None
    assert _parse_js_redirect("location.href='javascript:alert(1)'") is None


class _FakeStore(dict):
    def get(self, k, default=None):
        return dict.get(self, k, default)


RESULT = {
    "page": {"url": "https://final.example/"},
    "verdicts": {"overall": {}, "urlscan": {}},
    "lists": {},
    "data": {"requests": [],
             "redirects": [
                 {"from": "https://a.de/", "initiator": "script",
                  "to": "https://trackers.net/click"},
                 {"from": "https://trackers.net/click", "status": 302,
                  "to": "https://final.example/"}]},
}


@pytest.mark.asyncio
async def test_urlscan_lookup_includes_redirect_history(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/api/v1/result/"):
            return httpx.Response(200, json=RESULT)
        if path.rstrip("/").endswith("/scan"):
            return httpx.Response(200, json={"uuid": "u-1",
                                             "message": "Submission successful"})
        return httpx.Response(200, json={"results": []})

    orig = UrlScanProvider.wait_result

    async def fast(self, uuid, client, **kw):
        kw.setdefault("timeout", 5)
        kw.setdefault("poll_interval", 0.01)
        kw.setdefault("quiet_seconds", 0)
        return await orig(self, uuid, client, **kw)

    monkeypatch.setattr(UrlScanProvider, "wait_result", fast)
    prov = UrlScanProvider()
    prov.store = _FakeStore(URLSCAN_API_KEY="k")
    async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)) as client:
        out = await prov.lookup_url("https://a.de/", client)

    assert out["status"] == Status.INFO
    rd = out["redirects"]
    assert len(rd) == 2
    assert rd[0]["initiator"] == "script" and rd[0]["status_code"] is None
    assert rd[1]["status_code"] == 302
    assert rd[1]["to"] == "https://final.example/"
