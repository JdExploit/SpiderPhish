"""Threat intelligence provider interfaces.

New providers implement one of the abstract classes and register themselves
in PROVIDERS. The core never depends on concrete providers.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from app.models.schemas import IPReputation, Status


class ThreatIntelProvider(ABC):
    name: str = "base"

    def __init__(self) -> None:
        from app.config.settings import secure_store
        self.store = secure_store()

    @abstractmethod
    def is_configured(self) -> bool: ...

    def not_configured_error(self, what: str) -> str:
        return (f"{self.name}: NOT CONFIGURED - requires {what}. "
                f"Set it in Settings -> API Configuration.")


class IPReputationProvider(ThreatIntelProvider):
    @abstractmethod
    async def lookup_ip(self, ip: str, client: "httpx.AsyncClient") -> IPReputation: ...


class URLReputationProvider(ThreatIntelProvider):
    @abstractmethod
    async def lookup_url(self, url: str, client: "httpx.AsyncClient") -> dict: ...


class DomainReputationProvider(ThreatIntelProvider):
    @abstractmethod
    async def lookup_domain(self, domain: str, client: "httpx.AsyncClient") -> dict: ...


def _status_from_http(code: int) -> Status:
    return Status.ERROR if code >= 400 else Status.INFO
