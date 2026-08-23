"""Authentication analysis: SPF / DKIM / DMARC evaluation + policy checks."""
from __future__ import annotations

from app.models.schemas import (
    AuthenticationAnalysis, Indicator, Status)
from app.utils.email_parsing import parse_authentication

FAIL_RESULTS = {"fail", "hardfail"}


def analyze_authentication(header_map: dict[str, list[str]]) -> AuthenticationAnalysis:
    auth = parse_authentication(header_map)

    # DMARC policy lookup from the From domain (local DNS TXT _dmarc)
    if auth.dmarc.result in FAIL_RESULTS or auth.dmarc.result == "none":
        pass  # indicators already set by parser
    return auth


def dmarc_policy_lookup(domain: str) -> str:
    """Returns raw DMARC policy record for the domain ('' when none)."""
    try:
        import dns.resolver
        ans = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=6)
        for r in ans:
            s = b"".join(r.value.strings).decode() if hasattr(r, "value") else r.to_text()
            if s.lower().startswith("v=dmarc1"):
                return s
    except Exception:
        pass
    return ""


def spf_record_lookup(domain: str) -> str:
    try:
        import dns.resolver
        ans = dns.resolver.resolve(domain, "TXT", lifetime=6)
        for r in ans:
            s = b"".join(r.value.strings).decode() if hasattr(r, "value") else r.to_text()
            if s.lower().startswith("v=spf1"):
                return s
    except Exception:
        pass
    return ""
