"""Advanced detection (identity/brand/theme) unit tests."""
from app.analyzers.advanced_detection import (
    analyze_advanced, identity_indicators)
from app.models.schemas import Status


def test_reply_to_external_is_critical():
    inds = identity_indicators("ceo@corp.com", "", "ceo@corp.com",
                               "attacker@mail.ru")
    labels = {i.label: i.status for i in inds}
    assert labels.get("Reply-To != From") == Status.CRITICAL


def test_return_path_domain_mismatch():
    inds = identity_indicators("a@bank.com", "", "bounce@mailer.top", "")
    labels = {i.label for i in inds}
    assert "From != Return-Path" in labels


def test_matching_identity():
    inds = identity_indicators("user@gmail.com", "", "user@gmail.com",
                               "user@gmail.com")
    statuses = [i.status for i in inds if i.label.startswith(("From ==",))]
    assert all(s == Status.MATCH for s in statuses)


def test_theme_credential_harvesting():
    inds = analyze_advanced(
        subject="Reset your password now",
        body_text="Please confirm your password to avoid suspension.",
        body_html="", from_display="", from_addr="it@evil.com", urls_domains=[])
    names = {i.label for i in inds}
    assert any("Credential" in n or "password reset" in n.lower() for n in names)


def test_unicode_lookalike_display_name():
    # Cyrillic 'о' inside 'Microsoft'
    display = "Мicrоsoft Security"
    inds = analyze_advanced("", "", "", display, "x@notmicrosoft.ru", [])
    assert any("lookalike" in i.label.lower() or
               "Display Name spoofing" in i.label for i in inds)


def test_brand_impersonation_in_urls():
    inds = analyze_advanced("", "", "", "", "",
                            ["micros0ft-login.com"])
    assert any(i.label in ("Lookalike domain attack",) for i in inds)


def test_qr_phishing_detected():
    html = '<img src="https://cdn.evil.com/qrcode-883.png">'
    inds = analyze_advanced("", "", html, "", "", [])
    assert any("QR" in i.label for i in inds)
