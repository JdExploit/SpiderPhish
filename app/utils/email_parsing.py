"""Email parsing: headers, Received chain, origin-IP detection, authentication."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import parseaddr

from app.models.schemas import (
    AuthResult, AuthenticationAnalysis, AttachmentInfo, HeaderField,
    OriginIPResult, ReceivedHop, Status,
)
from app.utils import ioc_extraction

# Header fields surfaced in the UI (spec section 7/8)
KEY_HEADERS = [
    "From", "To", "Cc", "Reply-To", "Return-Path", "Sender", "Subject", "Date",
    "Message-ID", "MIME-Version", "Content-Type", "Delivered-To", "Received",
    "Received-SPF", "Authentication-Results", "DKIM-Signature", "ARC-Seal",
    "ARC-Authentication-Results", "ARC-Message-Signature", "X-Originating-IP",
    "X-Mailer", "User-Agent",
    "X-MS-Exchange-Organization-OriginalClientIPAddress",
    "X-MS-Exchange-Organization-OriginalArrivalTime",
    "X-Forefront-Antispam-Report", "X-Microsoft-Antispam",
]

RECEIVED_IP_RE = re.compile(
    r"(\[?(?P<ipv6>[0-9a-fA-F:]{6,45}])|(?P<ipv4>\b\d{1,3}(?:\.\d{1,3}){3}\b))")
FROM_CLAUSE_RE = re.compile(r"from\s+([^\s;()]+)", re.IGNORECASE)
BY_CLAUSE_RE = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)
WITH_CLAUSE_RE = re.compile(r"\bwith\s+([^\s;()]+)", re.IGNORECASE)


def _decode(value: str | None) -> str:
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def parse_raw_email(raw: bytes):
    """Parse raw email bytes into an EmailMessage (policy=default)."""
    return BytesParser(policy=policy.default).parsebytes(raw)


def header_map(msg) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for k, v in msg.items():
        out.setdefault(k.lower(), []).append(_decode(str(v)))
    return out


def first(hmap: dict[str, list[str]], name: str) -> str:
    vals = hmap.get(name.lower(), [])
    return vals[0] if vals else ""


def all_of(hmap: dict[str, list[str]], name: str) -> list[str]:
    return hmap.get(name.lower(), [])


def extract_header_fields(msg) -> tuple[list[HeaderField], dict[str, list[str]]]:
    fields = [HeaderField(name=str(k), value=_decode(str(v))) for k, v in msg.items()]
    hmap = {}
    for f in fields:
        hmap.setdefault(f.name.lower(), []).append(f.value)
    return fields, hmap


# ----------------------------------------------------------------------
def _ip_from_token(token: str) -> str:
    token = token.strip("[]() \t;")
    try:
        ip = ipaddress.ip_address(token)
        if not ip.is_multicast:
            return str(ip)
    except ValueError:
        pass
    # IPv6 embedded like ::ffff:1.2.3.4 handled by ip_address above when unbracketed
    m = re.match(r"^([0-9a-fA-F:.]+)$", token)
    if m and ":" in token:
        try:
            return str(ipaddress.ip_address(token))
        except ValueError:
            pass
    return ""


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.strip("[]"))
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        return False


def parse_received_chain(hmap: dict[str, list[str]]) -> list[ReceivedHop]:
    """Parse Received headers into hops.

    Received headers are prepended by each server, so index 0 = most recent hop.
    We return them ordered oldest -> newest for the SOURCE->RECIPIENT view.
    """
    raw_headers = all_of(hmap, "Received")
    hops: list[ReceivedHop] = []
    for idx, raw in enumerate(raw_headers):
        hop = ReceivedHop(index=idx)
        m = FROM_CLAUSE_RE.search(raw)
        if m:
            hop.from_host = m.group(1).strip()
        m = BY_CLAUSE_RE.search(raw)
        if m:
            hop.by_host = m.group(1).strip()
        m = WITH_CLAUSE_RE.search(raw)
        if m:
            hop.with_proto = m.group(1).strip()
        if ";" in raw:
            hop.date = raw.rsplit(";", 1)[-1].strip()
        # prefer IPs inside parentheses in the from clause (connecting IP)
        parens = re.findall(r"\(([^)]*)\)", raw)
        ips: list[str] = []
        for p in parens:
            ips.extend(ioc_extraction.extract_ipv4(p))
            for v6 in ioc_extraction.extract_ipv6(p):
                ips.append(v6)
        if not ips:
            head = raw.split("by", 1)[0]
            ips.extend(ioc_extraction.extract_ipv4(head))
            for v6 in ioc_extraction.extract_ipv6(head):
                ips.append(v6)
        if ips:
            hop.from_ip = ips[0]
            hop.is_private_source = is_private_ip(hop.from_ip)
        low = raw.lower()
        if "tls" in low or "version=tls" in low or "ssl" in low:
            hop.tls = "TLS"
        hops.append(hop)
    hops.reverse()  # oldest first
    for i, h in enumerate(hops):
        h.index = i + 1
    return hops


def detect_origin_ip(hmap: dict[str, list[str]], hops: list[ReceivedHop]) -> OriginIPResult:
    """Heuristic origin-IP detection (spec section 9).

    Priority:
      1. X-Originating-IP
      2. X-MS-Exchange-Organization-OriginalClientIPAddress
      3. First public IP in the earliest external 'Received: from' hop
      4. Any public IP found across the chain (lowest confidence)
    """
    res = OriginIPResult(hops=hops)

    xip = first(hmap, "X-Originating-IP")
    if xip:
        found = ioc_extraction.extract_ipv4(xip) or ioc_extraction.extract_ipv6(xip)
        if found:
            res.ip = found[0]
            res.source_header = "X-Originating-IP"
            res.confidence = 0.95
            return res

    msip = first(hmap, "X-MS-Exchange-Organization-OriginalClientIPAddress")
    if msip:
        found = ioc_extraction.extract_ipv4(msip) or ioc_extraction.extract_ipv6(msip)
        if found:
            res.ip = found[0]
            res.source_header = "X-MS-Exchange-Organization-OriginalClientIPAddress"
            res.confidence = 0.95
            return res

    for key in ("Connecting-IP", "Client-IP"):
        v = first(hmap, key)
        if v:
            found = ioc_extraction.extract_ipv4(v) or ioc_extraction.extract_ipv6(v)
            if found:
                res.ip = found[0]
                res.source_header = key
                res.confidence = 0.85
                return res

    # walk oldest -> newest; first public connecting IP wins
    for hop in hops:
        if hop.from_ip and not is_private_ip(hop.from_ip):
            res.ip = hop.from_ip
            res.source_header = f"Received[{hop.index}].from"
            res.confidence = 0.7
            return res

    # fallback: any public IP anywhere
    for hop in hops:
        for cand in [hop.from_ip]:
            if cand and not is_private_ip(cand):
                res.ip = cand
                res.source_header = f"Received[{hop.index}] (fallback)"
                res.confidence = 0.5
                return res

    res.notes.append("No public origin IP could be determined from headers.")
    return res


# ----------------------------------------------------------------------
AUTH_RESULT_RE = re.compile(
    r"(?P<mech>spf|dkim|dmarc)\s*[=:]?\s*(?P<result>pass|fail|softfail|neutral|none|temperror|permerror|hardfail)",
    re.IGNORECASE)
DKIM_HEADER_D_RE = re.compile(r"(?:header\.d|d\s*tag)\s*=\s*([\w.\-]+)", re.IGNORECASE)
SPF_DOMAIN_RE = re.compile(r"smtp\.mailfrom=([\w.\-]+)|envelope-from=([\w.\-@]+)")


def parse_authentication(hmap: dict[str, list[str]]) -> AuthenticationAnalysis:
    auth = AuthenticationAnalysis()

    ar_headers = all_of(hmap, "Authentication-Results")
    auth.raw_authentication_results = ar_headers
    spf_domains: set[str] = set()
    dkim_domains: set[str] = set()
    dmarc_domains: set[str] = set()

    for raw in ar_headers:
        for m in AUTH_RESULT_RE.finditer(raw):
            mech = m.group("mech").lower()
            result = m.group("result").lower()
            tail = raw[m.end():m.end() + 200]
            dm = DKIM_HEADER_D_RE.search(tail)
            sm = SPF_DOMAIN_RE.search(tail)
            domain = ""
            if mech == "spf":
                domain = (sm.group(1) if sm else "")
                spf_domains.add(domain)
                auth.spf = AuthResult(mechanism="spf", result=result, domain=domain, raw=raw)
            elif mech == "dkim":
                domain = dm.group(1) if dm else ""
                dkim_domains.add(domain)
                auth.dkim = AuthResult(mechanism="dkim", result=result, domain=domain, raw=raw)
            else:
                domain = (dm.group(1) if dm else "") or (sm.group(1) if sm else "")
                dmarc_domains.add(domain)
                auth.dmarc = AuthResult(mechanism="dmarc", result=result, domain=domain, raw=raw)

    rspf = all_of(hmap, "Received-SPF")
    auth.received_spf = "; ".join(rspf)
    if not auth.spf.result or auth.spf.result == "none":
        if rspf:
            m = AUTH_RESULT_RE.search(rspf[0])
            if m and m.group("mech").lower() == "pass":
                auth.spf = AuthResult(mechanism="spf", result="pass",
                                      raw=rspf[0], indicator=None)
    auth.arc_results = all_of(hmap, "ARC-Authentication-Results")

    auth.indicators = [
        Indicator_spf(auth.spf),
        Indicator_dkim(auth.dkim),
        Indicator_dmarc(auth.dmarc),
    ]
    return auth


def _auth_indicator(label: str, r: AuthResult, fail_detail: str) :
    from app.models.schemas import Indicator
    status_map = {
        "pass": Status.MATCH, "fail": Status.CRITICAL, "hardfail": Status.CRITICAL,
        "softfail": Status.SUSPICIOUS, "neutral": Status.SUSPICIOUS,
        "none": Status.UNKNOWN, "temperror": Status.ERROR, "permerror": Status.ERROR,
    }
    st = status_map.get(r.result.lower(), Status.UNKNOWN)
    detail = fail_detail if st in (Status.CRITICAL, Status.SUSPICIOUS) else (
        f"{r.domain}" if r.domain else "")
    return Indicator(label=label, status=st, detail=detail, actual=r.result.upper())


def Indicator_spf(r: AuthResult):
    return _auth_indicator("SPF", r, "Sender not authorized to use this domain")


def Indicator_dkim(r: AuthResult):
    return _auth_indicator("DKIM", r, "Message signature invalid or missing")


def Indicator_dmarc(r: AuthResult):
    return _auth_indicator("DMARC", r, "Domain policy failed - spoofing likely")


# ----------------------------------------------------------------------
def extract_attachments(msg) -> list[AttachmentInfo]:
    out: list[AttachmentInfo] = []
    try:
        for part in msg.walk():
            fname = part.get_filename()
            if not fname:
                continue
            payload = part.get_payload(decode=True) or b""
            info = AttachmentInfo(
                filename=_decode(fname),
                content_type=part.get_content_type(),
                size_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest() if payload else "",
                md5=hashlib.md5(payload).hexdigest() if payload else "",
                sha1=hashlib.sha1(payload).hexdigest() if payload else "",
                extension=fname.rsplit(".", 1)[-1].lower() if "." in fname else "",
            )
            info.dangerous = info.extension in {
                "exe", "scr", "js", "vbs", "bat", "cmd", "com", "ps1", "jar",
                "hta", "lnk", "iso", "img", "docm", "xlsm", "pptm", "zip", "7z", "rar"}
            out.append(info)
    except Exception:
        pass
    return out


def get_body_parts(msg) -> tuple[str, str]:
    """Returns (text_body, html_body)."""
    text_body, html_body = "", ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain" and not text_body:
                    text_body = _part_text(part)
                elif ct == "text/html" and not html_body:
                    html_body = _part_text(part)
        else:
            ct = msg.get_content_type()
            body = _part_text(msg)
            if ct == "text/html":
                html_body = body
            else:
                text_body = body
    except Exception:
        pass
    return text_body, html_body


def _part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            charset = part.get_content_charset() or "utf-8"
            try:
                return payload.decode(charset, errors="replace")
            except Exception:
                return payload.decode("utf-8", errors="replace")
        return str(payload or "")


def addr_domain(addr: str) -> str:
    _, a = parseaddr(addr)
    return a.split("@")[-1].lower().strip() if "@" in a else a.lower()
