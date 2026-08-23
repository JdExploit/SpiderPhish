"""Full pipeline integration test (works offline: network failures are
recorded, never crash)."""
from pathlib import Path

from app.config.settings import AppSettings
from app.analyzers.email_analyzer import EmailAnalyzer, browser_safety_status
from app.integrations.registry import build_registry
from app.models.schemas import Status

DATA = Path(__file__).parent / "data"


def _analyzer() -> EmailAnalyzer:
    s = AppSettings()
    s.analysis.timeout_seconds = 3
    s.analysis.retries = 0
    return EmailAnalyzer(s, build_registry())


async def test_phishing_pipeline_end_to_end():
    a = await _analyzer().analyze(DATA.joinpath("phishing.eml").read_bytes(),
                                  progress=None, case_id="CASE-TEST-1")
    # parsing
    assert a.from_addr == "security-alert@micros0ft-login.com"
    assert a.reply_to == "attacker-mailbox@mail.ru"
    assert "sign-in" in a.subject.lower()
    assert a.x_originating_ip != ""
    # origin IP
    assert a.origin_ip.ip == "45.155.205.233"
    # auth
    assert a.authentication.spf.result == "fail"
    assert a.authentication.dmarc.result == "fail"
    # identity indicators include Reply-To mismatch (critical)
    labels = {i.label for i in a.identity_indicators}
    assert "Reply-To != From" in labels
    # urls extracted (bit.ly shortener + verify link)
    domains = {u.domain for u in a.urls}
    assert any("bit.ly" in d for d in domains)
    # IOCs found
    ioc_types = {i.type.value for i in a.iocs}
    assert "IPv4" in ioc_types and "URL" in ioc_types
    # risk computed & high
    assert a.risk.score >= 40
    assert a.risk.verdict
    # recommendations generated
    assert any("DO NOT CLICK" in r.title for r in a.recommendations)


async def test_benign_pipeline_low_risk():
    a = await _analyzer().analyze(DATA.joinpath("benign.eml").read_bytes(),
                                  progress=None, case_id="CASE-TEST-2")
    assert a.authentication.spf.result == "pass"
    mismatch_critical = [i for i in a.identity_indicators
                         if i.status == Status.CRITICAL]
    assert not mismatch_critical


def test_browser_safety_mapping():
    from app.models.schemas import UrlInfo
    bad = UrlInfo(url="http://x", risk_level=Status.MALICIOUS)
    ok = UrlInfo(url="http://y", risk_level=Status.SAFE)
    unk = UrlInfo(url="http://z", risk_level=Status.NOT_ANALYZED)
    assert browser_safety_status(bad) == Status.MALICIOUS
    assert browser_safety_status(ok) == Status.SAFE
    assert browser_safety_status(unk) == Status.UNKNOWN
