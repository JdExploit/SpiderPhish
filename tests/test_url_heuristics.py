"""URL heuristics + advanced detection tests (no network)."""
from app.utils.url_heuristics import (
    detect_brand_impersonation, is_punycode, score_url, url_flags)


def test_shortener_flag():
    assert "URL shortener" in url_flags("https://bit.ly/abc")


def test_ip_based_url():
    flags = url_flags("http://45.155.205.233/go.php")
    assert "IP-based URL" in flags


def test_plain_http_flag():
    assert "Plain HTTP (no TLS)" in url_flags("http://example.com/")


def test_credential_harvesting():
    score, flags = score_url("http://micros0ft-login.com/verify/account/login.php?id=8")
    joined = " | ".join(flags)
    assert "Credential harvesting" in joined
    assert any(f.startswith("Possible microsoft impersonation") or
               "impersonation" in f.lower() for f in flags)
    assert score >= 50


def test_suspicious_tld():
    assert any(".top" in f for f in url_flags("http://mailer-verify.top/x"))


def test_punycode_detection():
    assert is_punycode("xn--micros0ft-3we.com")
    assert not is_punycode("microsoft.com")


def test_brand_impersonation_lookalike():
    brand, reason = detect_brand_impersonation("micros0ft-login.com")
    assert brand == "microsoft"
    assert "Lookalike" in reason or "keyword" in reason.lower()


def test_brand_legit_domain_not_flagged():
    brand, _ = detect_brand_impersonation("login.microsoftonline.com")
    assert brand is None


def test_open_redirect_param():
    assert any("redirect" in f.lower() for f in
               url_flags("https://a.com/go?url=https://evil.com"))


def test_score_bounded():
    score, _ = score_url("http://xn--msft-3we.top/login/password?u=http://x")
    assert 0 <= score <= 100
