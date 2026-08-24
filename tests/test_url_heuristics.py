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


# --- regression tests from real-world misses (2026-08-24) -----------------

def test_random_path_and_digit_domain_flagged():
    score, flags = score_url("https://cloudsenterprise26.com/skjsadfi123uv12/")
    assert score >= 40
    assert any("High-entropy random path" in f for f in flags)
    assert any("appended digits" in f for f in flags)


def test_raw_ip_with_path_scored_high():
    score, flags = score_url("http://5.182.210.174/ece1eb")
    assert score >= 60
    assert "Hex-like path segment 'ece1eb'" in flags
    assert "File/path served from raw IP address" in flags


def test_bare_ip_https_suspicious():
    score, flags = score_url("https://139.59.240.15/kworker")
    assert score >= 30
    assert "File/path served from raw IP address" in flags


def test_numeric_subdomain_not_brand_lookalike():
    """'105' -> skeleton 'los' must not look like an 'ups' typo."""
    brand, reason = detect_brand_impersonation(
        "7f898d686d8c408e9baec6059bad89f4.105.eu.prod.marketingusercontent.com")
    assert brand is None or "ups" not in (reason or "")


def test_legit_sites_stay_clean():
    assert score_url("https://www.google.com")[0] == 0
    assert score_url("https://www.vitaldent.com/es/politica-de-cookies/")[0] == 0
