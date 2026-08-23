"""Header parsing / Received chain / origin-IP detection tests."""
from pathlib import Path

from app.utils.email_parsing import (
    detect_origin_ip, extract_attachments, get_body_parts, header_map,
    parse_raw_email, parse_received_chain)
from app.models.schemas import Status

DATA = Path(__file__).parent / "data"


def load(name: str) -> bytes:
    return (DATA / name).read_bytes()


def test_parse_benign_headers():
    msg = parse_raw_email(load("benign.eml"))
    hmap = header_map(msg)
    assert hmap["subject"] == ["Reunion de proyecto el martes"]
    assert "authentication-results" in hmap
    text, html = get_body_parts(msg)
    assert "reunion" in text.lower()
    assert html == ""


def test_received_chain_order():
    hmap = header_map(parse_raw_email(load("benign.eml")))
    hops = parse_received_chain(hmap)
    assert len(hops) >= 2
    # oldest hop should be index 1 and come from google infra
    assert hops[0].index == 1
    assert any("google" in h.from_host for h in hops)
    assert any(h.from_ip == "209.85.220.41" or h.from_ip == ""
               for h in hops)


def test_origin_ip_x_originating():
    hmap = header_map(parse_raw_email(load("phishing.eml")))
    hops = parse_received_chain(hmap)
    origin = detect_origin_ip(hmap, hops)
    assert origin.ip == "45.155.205.233"
    assert origin.source_header == "X-Originating-IP"
    assert origin.confidence >= 0.9


def test_origin_ip_from_received_when_no_x_header():
    raw = load("benign.eml").replace(
        b"X-Originating-IP: [209.85.220.41]", b"")
    msg = parse_raw_email(raw)
    hmap = header_map(msg)
    hops = parse_received_chain(hmap)
    origin = detect_origin_ip(hmap, hops)
    # earliest external connecting IP wins (IPv6 in this fixture)
    assert origin.ip in {"209.85.220.41", "2a00:1450:4013:c16::200b"}
    assert origin.source_header.startswith("Received")


def test_phishing_auth_failures_parsed():
    hmap = header_map(parse_raw_email(load("phishing.eml")))
    from app.analyzers.authentication_analyzer import analyze_authentication
    auth = analyze_authentication(hmap)
    assert auth.spf.result == "fail"
    assert auth.dkim.result == "none"
    assert auth.dmarc.result == "fail"
    statuses = [i.status for i in auth.indicators]
    assert Status.CRITICAL in statuses


def test_benign_auth_pass():
    hmap = header_map(parse_raw_email(load("benign.eml")))
    from app.analyzers.authentication_analyzer import analyze_authentication
    auth = analyze_authentication(hmap)
    assert auth.spf.result == "pass"
    assert auth.dmarc.result == "pass"


def test_attachments_extraction_and_hashes():
    import hashlib
    from email.message import EmailMessage
    m = EmailMessage()
    m["From"] = "a@b.com"
    m["Subject"] = "t"
    m.set_content("body")
    m.add_attachment(b"AAAA", maintype="application", subtype="pdf",
                     filename="invoice.pdf")
    msg = parse_raw_email(m.as_bytes())
    atts = extract_attachments(msg)
    assert len(atts) == 1
    assert atts[0].filename == "invoice.pdf"
    assert atts[0].sha256 == hashlib.sha256(b"AAAA").hexdigest()
