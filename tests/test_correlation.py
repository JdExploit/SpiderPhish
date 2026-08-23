"""Tests for the IOC correlation engine and campaign detection."""
from __future__ import annotations

import pytest

from app.analyzers.campaigns import (
    detect_campaign, extract_observations, flat_values)
from app.analyzers.correlation import build_graph, correlate
from app.core.database import Database
from app.models.schemas import (
    AuthenticationAnalysis, AuthResult, DomainInfo, EmailAnalysis,
    IPReputation, IPTypeClassification, OriginIPResult, RedirectHop, RiskBand,
    Status, UrlInfo)


def _phishing_analysis() -> EmailAnalysis:
    url = UrlInfo(
        url="https://microsoft-login-secure.com/verify/session",
        final_url="https://microsoft-login-secure.com/login/confirm.php",
        domain="microsoft-login-secure.com", risk_score=85,
        risk_level=Status.CRITICAL,
        flags=["brand-impersonation", "suspicious-tld-pattern"],
        redirect_count=3,
        redirect_chain=[
            RedirectHop(step=1, url="http://track.example.net/t?id=1",
                        domain="example.net", status_code=302),
            RedirectHop(step=2, url="http://185.10.10.10/a",
                        domain="185.10.10.10", status_code=302),
            RedirectHop(step=3, url="https://microsoft-login-secure.com/x",
                        domain="microsoft-login-secure.com", status_code=200),
        ])
    a = EmailAnalysis(
        case_id="CASE-TEST-0001",
        from_display="Microsoft Support",
        from_addr="security@microsoft-support-verify.com",
        subject="Action required: password expired",
        origin_ip=OriginIPResult(ip="185.10.10.10", source_header="Received[1]",
                                 confidence=0.9),
        ip_classification=IPTypeClassification(
            classification="Hosting", asn_number="AS14061",
            asn_org="DigitalOcean"),
        ip_reputation=IPReputation(provider="AbuseIPDB", ip="185.10.10.10",
                                   score=92, total_reports=48,
                                   verdict=Status.MALICIOUS),
        authentication=AuthenticationAnalysis(
            spf=AuthResult(mechanism="spf", result="fail"),
            dkim=AuthResult(mechanism="dkim", result="none"),
            dmarc=AuthResult(mechanism="dmarc", result="fail")),
        urls=[url],
        domains={
            "microsoft-support-verify.com": DomainInfo(
                domain="microsoft-support-verify.com", age_days=4,
                a=["185.10.10.10"], registrar="NameSnp"),
            "microsoft-login-secure.com": DomainInfo(
                domain="microsoft-login-secure.com", age_days=11,
                a=["185.10.10.10"]),
        })
    a.risk.score = 95
    a.risk.band = RiskBand.CRITICAL
    return a


def test_graph_structure_and_infra_link():
    a = _phishing_analysis()
    nodes, edges = build_graph(a)
    ids = {n.node_id for n in nodes}
    assert "email" in ids
    assert "domain:microsoft-support-verify.com" in ids
    assert "ip:185.10.10.10" in ids
    assert "asn:as14061" in ids
    assert any(i.startswith("url:") for i in ids)
    assert any(i.startswith("hop:") for i in ids)

    # every edge connects existing nodes
    for e in edges:
        assert e.src in ids
        assert e.dst in ids


def test_correlation_high_confidence():
    a = _phishing_analysis()
    r = correlate(a)
    assert r.confidence >= 75
    assert r.verdict == "HIGH CONFIDENCE PHISHING"
    titles = " ".join(e.title for e in r.evidence).lower()
    assert "authentication failure" in titles
    assert "malicious reputation" in titles or "flagged" in titles
    assert "credential-harvesting" in titles or "credential harvest" in titles
    assert "newly registered" in titles
    # infra link evidence: DNS A record == origin IP
    assert any("same infrastructure" in e.detail for e in r.evidence)


def test_correlation_clean_email_low():
    a = EmailAnalysis(case_id="CASE-TEST-0002",
                      from_addr="ceo@legit-corp.com",
                      authentication=AuthenticationAnalysis(
                          spf=AuthResult(result="pass"),
                          dkim=AuthResult(result="pass"),
                          dmarc=AuthResult(result="pass")))
    a.risk.score = 5
    r = correlate(a)
    assert r.confidence < 40
    assert r.correlated_indicators == 0 or r.confidence <= 15
    assert "PHISHING" not in r.verdict or "NO STRONG" in r.verdict \
        or "LOW CONFIDENCE" in r.verdict


def test_campaign_detection(tmp_path):
    db = Database(tmp_path / "camp.db")
    rows_a = [("ip", "185.10.10.10", "origin_ip", "MALICIOUS",
               "victim1@corp.com", "2026-08-20T10:00:00"),
              ("domain", "microsoft-login-secure.com", "url_domain", "OBSERVED",
               "victim1@corp.com", "2026-08-20T10:00:00")]
    db.record_observations("CASE-PAST-0001", rows_a)
    rows_b = [("ip", "185.10.10.10", "origin_ip", "MALICIOUS",
               "victim2@corp.com", "2026-08-21T09:00:00")]
    db.record_observations("CASE-PAST-0002", rows_b)

    a = _phishing_analysis()
    camp = detect_campaign(db, a)
    assert camp is not None
    assert camp.detected is True
    assert camp.emails == 3          # 2 past + current
    assert camp.recipients >= 2      # victim1 + victim2 (+ current if any)
    assert camp.domains >= 1
    assert camp.ips == 1
    assert camp.first_seen.startswith("2026-08-20")
    assert any(c.value == "185.10.10.10" for c in camp.cluster)

    # observations of the current analysis are exportable too
    obs = extract_observations(a)
    types = {t for t, *_ in obs}
    assert {"ip", "domain", "url"} & types
    assert "185.10.10.10" in flat_values(a)
