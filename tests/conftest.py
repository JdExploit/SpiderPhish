"""Shared pytest fixtures: keep tests fully offline/deterministic.

User machines may have real API keys configured in the encrypted store;
tests must never hit external services or depend on them.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_external_intel(monkeypatch):
    """Force every threat-intel provider to look unconfigured."""
    from app.config.settings import SecureStore
    monkeypatch.setattr(SecureStore, "get", lambda self, name: None)
    yield
