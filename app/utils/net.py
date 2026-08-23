"""SSRF-safe HTTP client utilities.

- Only http/https schemes allowed.
- Literal private/reserved IPs blocked unless allow_internal_targets.
- Hostnames are resolved before connect; if any A/AAAA record points to a
  private/reserved address the request is refused (DNS-rebinding guard at
  resolution time).
- TLS verification on by default, bounded redirects, timeouts.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx

from app.core.logging_setup import get_logger

log = get_logger("net")


class UnsafeTargetError(ValueError):
    """Raised when a URL targets internal infrastructure (SSRF guard)."""


def _host_is_safe(host: str, allow_internal: bool) -> bool:
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False

    if literal:
        ip = ipaddress.ip_address(host)
        if not allow_internal and (ip.is_private or ip.is_loopback or ip.is_link_local
                                   or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise UnsafeTargetError(f"Blocked internal target: {host}")
        return True

    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as e:
        raise UnsafeTargetError(f"DNS resolution failed for {host}: {e}") from e
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            continue
        if not allow_internal and (ip.is_private or ip.is_loopback or ip.is_link_local
                                   or ip.is_reserved or ip.is_multicast):
            raise UnsafeTargetError(
                f"{host} resolves to internal/reserved address {addr} (SSRF blocked)")
    return True


def validate_url(url: str, allow_internal: bool = False) -> str:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise UnsafeTargetError(f"Scheme '{p.scheme}' not allowed")
    host = p.hostname or ""
    if not host:
        raise UnsafeTargetError("URL has no host")
    _host_is_safe(host, allow_internal)
    return url


class SafeClient:
    """Context-manager wrapper producing an httpx.Client with guards applied."""

    def __init__(self, settings) -> None:  # noqa: ANN001 - AppSettings.analysis
        a = settings
        self._allow_internal = a.allow_internal_targets
        self._timeout = a.timeout_seconds
        self._retries = a.retries
        self._max_redirects = a.max_redirects
        self._verify = a.verify_tls
        self._proxy = a.proxy or None

    def __enter__(self) -> httpx.Client:
        transport = httpx.HTTPTransport(retries=self._retries)
        self.client = httpx.Client(
            timeout=self._timeout,
            verify=self._verify,
            proxy=self._proxy,
            max_redirects=self._max_redirects,
            follow_redirects=False,   # we drive redirects manually in redirect_analyzer
            transport=transport,
            headers={"User-Agent": f"SpiderPhish/{__import__('app', fromlist=['__version__']).__version__} (+local-analysis)"},
        )
        return self.client

    def __exit__(self, *exc) -> None:
        try:
            self.client.close()
        except Exception:
            pass


def check_target(url: str, allow_internal: bool = False) -> None:
    validate_url(url, allow_internal)
