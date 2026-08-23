"""Risk engine tests with synthetic analyses (no network)."""
from app.models.schemas import (
    AuthResult, AuthenticationAnalysis, EmailAnalysis, IPReputation, Status,
    UrlInfo)
from app.analyzers.risk_engine import compute_risk
from app.models.schemas import RiskBand


def _base() -> EmailAnalysis:
    return EmailAnalysis()


def test_safe_email_low_score():
    a = _base()
    a.authentication = AuthenticationAnalysis(
        spf=AuthResult(mechanism="spf", result="pass"),
        dkim=AuthResult(mechanism="dkim", result="pass"),
        dmarc=AuthResult(mechanism="dmarc", result="pass"))
    risk = compute_risk(a)
    assert risk.score <= 19
    assert risk.band == RiskBand.SAFE


def test_auth_failures_add_up():
    a = _base()
    a.authentication = AuthenticationAnalysis(
        spf=AuthResult(mechanism="spf", result="fail"),
        dkim=AuthResult(mechanism="dkim", result="none"),
        dmarc=AuthResult(mechanism="dmarc", result="fail"))
    risk = compute_risk(a)
    assert 40 <= risk.score <= 59   # 15+15+15 = 45 -> SUSPICIOUS
    names = {f.name for f in risk.factors}
    assert {"SPF failure", "DKIM failure", "DMARC failure"} <= names


def test_malicious_ip_and_url_reach_critical():
    a = _base()
    a.authentication.spf.result = "pass"
    a.ip_reputation = IPReputation(score=94, verdict=Status.INFO, ip="1.2.3.4")
    u = UrlInfo(url="http://x/login.php", domain="x",
                flags=["Credential harvesting indicators in path"],
                risk_score=90, risk_level=Status.CRITICAL,
                urlscan_malicious=True)
    a.urls = [u]
    risk = compute_risk(a)
    assert risk.score >= 80
    assert risk.band == RiskBand.CRITICAL
    assert risk.verdict == "MALICIOUS PHISHING EMAIL"


def test_score_capped_at_100():
    a = _base()
    a.authentication.spf.result = "fail"
    a.authentication.dkim.result = "none"
    a.authentication.dmarc.result = "hardfail"
    a.ip_reputation = IPReputation(score=100, verdict=Status.INFO, ip="1.2.3.4")
    for i in range(5):
        a.urls.append(UrlInfo(url=f"http://h{i}/login", domain=f"h{i}",
                              risk_score=95, risk_level=Status.CRITICAL))
    risk = compute_risk(a)
    assert risk.score == 100


def test_why_list_only_positive():
    a = _base()
    risk = compute_risk(a)
    assert all(f.points > 0 for f in risk.factors)
