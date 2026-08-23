"""SSRF guard + net utilities tests."""
import pytest

from app.utils.net import UnsafeTargetError, check_target


def test_blocks_private_literal():
    with pytest.raises(UnsafeTargetError):
        check_target("http://192.168.1.1/x", allow_internal=False)


def test_blocks_loopback_and_metadata():
    for url in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data",
                "http://10.0.0.5/"):
        with pytest.raises(UnsafeTargetError):
            check_target(url, allow_internal=False)


def test_blocks_non_http_schemes():
    with pytest.raises(UnsafeTargetError):
        check_target("file:///etc/passwd")
    with pytest.raises(UnsafeTargetError):
        check_target("ftp://example.com")


def test_allows_public_when_configured():
    # public literal passes the guard (no DNS needed)
    check_target("https://8.8.8.8/dns-query", allow_internal=False)
