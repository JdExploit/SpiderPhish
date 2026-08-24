"""Unit tests for the URLScan.io provider (official API v1 behaviors)."""
import json

import httpx
import pytest

from app.integrations.urlscan import USER_AGENT, UrlScanProvider
from app.models.schemas import Status


class _FakeStore(dict):
    def get(self, k, default=None):
        return dict.get(self, k, default)


def _provider() -> UrlScanProvider:
    prov = UrlScanProvider()
    prov.store = _FakeStore(URLSCAN_API_KEY="test-key")
    return prov


@pytest.mark.asyncio
async def test_submit_sends_api_key_and_user_agent():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["api_key"] = request.headers.get("API-Key")
        seen["ua"] = request.headers.get("User-Agent")
        seen["visibility"] = json.loads(request.content).get("visibility")
        return httpx.Response(200, json={"message": "Submission successful",
                                         "uuid": "abc-123"})

    async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)) as client:
        out = await _provider().submit("https://example.com", client)

    assert out == {"status": Status.INFO, "uuid": "abc-123"}
    assert seen["api_key"] == "test-key"
    assert seen["ua"] == USER_AGENT
    assert seen["visibility"] == "private"


@pytest.mark.asyncio
async def test_wait_result_404_then_200():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            assert request.headers.get("API-Key") == "test-key"
            return httpx.Response(404)
        return httpx.Response(200, json={"page": {"url": "https://x"},
                                         "verdicts": {}})

    async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)) as client:
        out = await _provider().wait_result("u1", client, timeout=5,
                                            poll_interval=0.01,
                                            quiet_seconds=0)
    assert out["status"] == Status.INFO
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_wait_result_410_fails_fast():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(410)

    async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)) as client:
        out = await _provider().wait_result("u2", client, timeout=30,
                                            poll_interval=0.01,
                                            quiet_seconds=0)
    assert out["status"] == Status.ERROR
    assert "410" in out["error"]
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_wait_result_429_respects_reset_hint():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"X-Rate-Limit-Reset-After": "0.05"})
        return httpx.Response(200, json={"page": {}, "verdicts": {}})

    async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)) as client:
        out = await _provider().wait_result("u3", client, timeout=5,
                                            poll_interval=0.01,
                                            quiet_seconds=0)
    assert out["status"] == Status.INFO
    assert calls["n"] >= 2


@pytest.mark.asyncio
async def test_find_existing_returns_fresh_uuid():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params.get("q") == 'page.url:"https://x"'
        assert request.url.params.get("size") == "1"
        assert request.headers.get("API-Key") == "test-key"
        return httpx.Response(200, json={"results": [
            {"_id": "fresh-uuid", "task": {"time": "2026-08-20T10:00:00.000Z"}}]})

    async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)) as client:
        uuid = await _provider().find_existing("https://x", client)
    assert uuid == "fresh-uuid"


@pytest.mark.asyncio
async def test_submit_rejection_400_returns_error_not_empty_uuid():
    """urlscan rejects static assets / spammy URLs with 400; we must NOT
    return INFO with an empty uuid and poll a garbage endpoint."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={
            "message": "Scan failed",
            "description": "Spammy submissions of URLs known to be "
                           "used only for spamming this service.",
            "status": 400})

    async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)) as client:
        out = await _provider().submit(
            "https://cdn.example.com/assets/email/banner.png", client)
    assert out["status"] == Status.ERROR
    assert "400" in out["error"]


@pytest.mark.asyncio
async def test_submit_already_submitted_400_with_result_link():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={
            "message": "already submitted",
            "result": "https://urlscan.io/result/abc-999/"})

    async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)) as client:
        out = await _provider().submit("https://example.com", client)
    assert out == {"status": Status.INFO, "uuid": "abc-999"}


@pytest.mark.asyncio
async def test_wait_result_empty_uuid_fails_fast():
    async with httpx.AsyncClient() as client:  # no requests expected
        out = await _provider().wait_result("", client)
    assert out["status"] == Status.ERROR
    assert "UUID" in out["error"]


@pytest.mark.asyncio
async def test_find_existing_ignores_stale():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": [
            {"_id": "old", "task": {"time": "2020-01-01T00:00:00.000Z"}}]})

    async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)) as client:
        prov = _provider()
        assert await prov.find_existing("https://x", client) is None
