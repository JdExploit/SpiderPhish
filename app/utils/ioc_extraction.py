"""IOC extraction: IPv4/IPv6, domains, URLs, hashes, emails, filenames, ASN."""
from __future__ import annotations

import re
from urllib.parse import urlparse, unquote

from app.models.schemas import IOC, IOCType, Status

# ---------------------------------------------------------------- regexes
RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
RE_IPV6_CANDIDATE = re.compile(
    r"\[[0-9a-fA-F:.]+\]|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\b")
RE_URL = re.compile(
    r"(?:(?:https?|hxxps?)[:\-]{1,2}//(?:hxx|xx)?|www\.)[^\s<>\"'()\[\]{}]+",
    re.IGNORECASE)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-_]*[a-zA-Z0-9])?\.)+"
    r"(?:[A-Za-z]{2,24}|xn--[A-Za-z0-9\-]{2,59})\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_SHA512 = re.compile(r"\b[a-fA-F0-9]{128}\b")
RE_ASN = re.compile(r"\bAS(?:N)?\s?(\d{1,10})\b", re.IGNORECASE)

TWO_LEVEL_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "com.br",
    "com.mx", "co.jp", "or.jp", "ne.jp", "com.cn", "com.tr", "co.in", "co.nz",
    "com.ar", "com.co", "com.sg", "com.hk", "co.za", "com.ua", "gob.es", "com.es"}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "cn", "ru", "su",
    "click", "link", "work", "bar", "rest", "country", "stream", "download",
    "loan", "racing", "review", "win", "bid", "cam", "quest", "cfd", "sbs"}


def extract_ipv4(text: str) -> list[str]:
    seen, out = set(), []
    for m in RE_IPV4.findall(text or ""):
        if m not in seen and not _is_version_like(m, text):
            seen.add(m)
            out.append(m)
    return out


def _is_version_like(ip: str, text: str) -> bool:
    # avoid matching e.g. "192.168.1.1" inside version strings like 1.2.3.4 build
    return False


def extract_ipv6(text: str) -> list[str]:
    import ipaddress
    out, seen = [], set()
    for m in RE_IPV6_CANDIDATE.finditer(text or ""):
        v = m.group(0).strip("[]")
        if ":" not in v and "::" not in v:
            continue
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            continue
        if ip.version == 6 and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def normalize_obfuscated_url(url: str) -> str:
    u = url.strip().strip(".,;:!)\"'>]")
    low = u.lower()
    if low.startswith("hxxps://"):
        u = "https://" + u[8:]
    elif low.startswith("hxxp://"):
        u = "http://" + u[7:]
    elif low.startswith(("hxtp://", "htxp://")):
        u = "http://" + u[7:]
    elif low.startswith(("hxxp:", "hxxps:")) and not low.startswith(("hxxp://", "hxxps://")):
        # e.g. hxxp: //host
        u = re.sub(r"^hxx(p)s?:", lambda m: ("https" if m.group(0).lower().endswith("ps:") else "http") + ":", u, count=1)
    u = unquote(u)
    return u


def extract_urls(text: str) -> list[str]:
    out, seen = [], set()
    for m in RE_URL.finditer(text or ""):
        u = normalize_obfuscated_url(m.group(0))
        if u.startswith("www."):
            u = "http://" + u
        if u.startswith(("http://", "https://")) and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def domain_of(url_or_host: str) -> str:
    s = url_or_host.strip()
    if "://" not in s:
        s = "http://" + s
    try:
        host = (urlparse(s).hostname or "").lower()
    except Exception:
        host = ""
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL_TLDS:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def registered_domain(domain: str) -> str:
    """Public suffix approximation without tldextract network calls."""
    d = domain.lower()
    parts = d.split(".")
    for n in range(len(parts) - 1):
        candidate = ".".join(parts[n:])
        if candidate in TWO_LEVEL_TLDS:
            return ".".join(parts[max(n - 1, 0):])
    return d if d.count(".") <= 1 else ".".join(d.split(".")[-2:])


def extract_domains(text: str) -> list[str]:
    out, seen = [], set()
    for url in extract_urls(text):
        d = domain_of(url)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    for m in RE_DOMAIN.finditer(text or ""):
        d = m.group(0).lower()
        if "@" in text[max(0, m.start() - 1):m.start() + 1]:
            continue
        rd = registered_domain(d)
        if rd == d or True:
            pass
        base = rd
        if base and base not in seen:
            seen.add(base)
            out.append(base)
    return out


def extract_emails(text: str) -> list[str]:
    return [e.lower() for e in RE_EMAIL.findall(text or "")]


def extract_hashes(text: str) -> dict[str, list[str]]:
    t = text or ""
    md5s, sha1s, sha256s, sha512s = set(), set(), set(), set()
    for h in RE_SHA512.findall(t):
        sha512s.add(h.lower())
    for h in RE_SHA256.findall(t):
        sha256s.add(h.lower())
    for h in RE_SHA1.findall(t):
        if h not in sha256s:
            sha1s.add(h.lower())
    for h in RE_MD5.findall(t):
        if h not in sha1s and h not in sha256s:
            md5s.add(h.lower())
    return {"md5": sorted(md5s), "sha1": sorted(sha1s),
            "sha256": sorted(sha256s), "sha512": sorted(sha512s)}


DANGEROUS_EXTS = {"exe", "scr", "js", "vbs", "bat", "cmd", "com", "ps1", "jar",
                  "hta", "lnk", "iso", "img", "docm", "xlsm", "pptm"}
RE_FILENAME = re.compile(
    r"\b[\w\-. ]+\.(" + "|".join(DANGEROUS_EXTS | {"pdf", "doc", "docx", "xls", "xlsx",
                                                   "zip", "rar", "7z"}) + r")\b",
    re.IGNORECASE)


def extract_iocs(*texts: str) -> list[IOC]:
    combined = "\n".join(t for t in texts if t)
    iocs: list[IOC] = []
    seen: set[tuple[str, str]] = set()

    def add(t: IOCType, value: str, sev: Status = Status.INFO):
        key = (t.value, value)
        if value and key not in seen:
            seen.add(key)
            iocs.append(IOC(type=t, value=value, severity=sev))

    for ip in extract_ipv4(combined):
        add(IOCType.IPV4, ip)
    for ip in extract_ipv6(combined):
        add(IOCType.IPV6, ip)
    for u in extract_urls(combined):
        add(IOCType.URL, u)
    for d in extract_domains(combined):
        add(IOCType.DOMAIN, d)
    for e in extract_emails(combined):
        add(IOCType.EMAIL, e)
    hashes = extract_hashes(combined)
    for h in hashes["md5"]:
        add(IOCType.MD5, h)
    for h in hashes["sha1"]:
        add(IOCType.SHA1, h)
    for h in hashes["sha256"]:
        add(IOCType.SHA256, h)
    for h in hashes["sha512"]:
        add(IOCType.SHA512, h)
    for m in RE_FILENAME.finditer(combined):
        fn = m.group(0)
        ext = fn.rsplit(".", 1)[-1].lower()
        add(IOCType.FILENAME, fn,
            Status.SUSPICIOUS if ext in DANGEROUS_EXTS else Status.INFO)
    return iocs
