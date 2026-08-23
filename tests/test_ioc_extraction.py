"""IOC extraction tests."""
from app.utils.ioc_extraction import (
    domain_of, extract_domains, extract_emails, extract_hashes, extract_iocs,
    extract_ipv4, extract_ipv6, extract_urls, normalize_obfuscated_url)


def test_ipv4_extraction():
    text = "Connection from 45.155.205.233 and 8.8.8.8; bad 999.1.1.1"
    ips = extract_ipv4(text)
    assert ips == ["45.155.205.233", "8.8.8.8"]


def test_ipv6_extraction():
    assert "2a00:1450:4013:c16::200b" in extract_ipv6(
        "host [2a00:1450:4013:c16::200b]")


def test_url_extraction_with_obfuscation():
    urls = extract_urls("see hxxp://evil-site.com/login and https://ok.com/x")
    assert "http://evil-site.com/login" in urls
    assert "https://ok.com/x" in urls


def test_normalize_obfuscated_url():
    assert normalize_obfuscated_url("hXXps://a.b/c") == "https://a.b/c"


def test_domain_of_url():
    assert domain_of("http://cdn.evil.co.uk/path?q=1") == "evil.co.uk"
    assert domain_of("http://mail.google.com/a") == "google.com"


def test_extract_emails():
    assert extract_emails("contact a@b.com and x.y+z@mail.co.uk") == \
        ["a@b.com", "x.y+z@mail.co.uk"]


def test_hashes_by_type():
    h = extract_hashes(
        "md5 d41d8cd98f00b204e9800998ecf8427e "
        "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert h["md5"] == ["d41d8cd98f00b204e9800998ecf8427e"]
    assert h["sha256"][0].startswith("e3b0c44298fc")


def test_full_ioc_pipeline_counts():
    text = """
    From: phish@micros0ft-login.com
    Link: http://bit.ly/xyz -> http://45.155.205.233/go.php
    Domain evil-domain.top, file invoice.exe, hash
    44d88612fea8a8f36de82e1278abb02f
    """
    iocs = extract_iocs(text)
    types = {i.type.value for i in iocs}
    assert {"IPv4", "URL", "Domain", "Email", "MD5", "Filename"} <= types


def test_no_false_positive_version_string():
    # version-like numbers should not crash extraction
    assert isinstance(extract_ipv4("python 3.11.9 released"), list)
