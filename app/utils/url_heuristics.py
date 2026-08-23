"""URL risk heuristics + advanced domain detection (punycode, homograph, brands)."""
from __future__ import annotations

import ipaddress
import unicodedata
from urllib.parse import urlparse, unquote

from app.utils.ioc_extraction import (
    SUSPICIOUS_TLDS, TWO_LEVEL_TLDS, registered_domain)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly", "tiny.cc", "bit.do",
    "s.id", "lnkd.in", "v.gd", "clck.ru", "t.ly", "shrtco.de", "gg.gg"}

KNOWN_BRANDS = {
    "microsoft": ["microsoft", "msft", "outlook", "office365", "o365", "onedrive",
                  "sharepoint", "teams", "live.com", "hotmail"],
    "google": ["google", "gmail", "googlemail", "gdrive", "googleusercontent"],
    "apple": ["apple", "icloud", "me.com"],
    "amazon": ["amazon", "aws", "amazonses"],
    "paypal": ["paypal"],
    "dhl": ["dhl"],
    "fedex": ["fedex"],
    "ups": ["ups.com"],
    "hsbc": ["hsbc"],
    "bbva": ["bbva"],
    "santander": ["santander"],
    "santanderbank": ["santander"],
    "chase": ["chase"],
    "wellsfargo": ["wellsfargo"],
    "facebook": ["facebook", "meta"],
    "linkedin": ["linkedin"],
    "netflix": ["netflix"],
    "adobe": ["adobe"],
    "dropbox": ["dropbox"],
    "whatsapp": ["whatsapp"],
}

BRAND_BASE_DOMAINS = {
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "outlook.com", "live.com"},
    "google": {"google.com", "gmail.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "aws.amazon.com"},
    "paypal": {"paypal.com"},
    "dhl": {"dhl.com"}, "fedex": {"fedex.com"}, "ups": {"ups.com"},
    "facebook": {"facebook.com"}, "linkedin": {"linkedin.com"},
    "netflix": {"netflix.com"}, "adobe": {"adobe.com"}, "dropbox": {"dropbox.com"},
}

# Latin lookalikes for common brand letters (subset; NFKD handles accents)
CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "@": "a", "$": "s", "vv": "w", "|": "l", "!": "i",
}
CYRILLIC_LOOKALIKES = set("асеорхуксніѕјԁɡ")

CREDENTIAL_PATH_HINTS = [
    "login", "signin", "sign-in", "verify", "verification", "secure", "account",
    "update", "confirm", "webscr", "session", "auth", "password", "reset",
    "unlock", "validate", "recover", "billing", "invoice-payment", "oauth",
]
SUSPICIOUS_QUERY_PARAMS = ["redirect", "url=", "next=", "goto=", "continue=",
                           "dest=", "return=", "u=", "q=http"]


def _strip_accents_lower(s: str) -> str:
    return unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().lower()


def levenshtein(a: str, b: str, max_dist: int = 3) -> int:
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_punycode(host: str) -> bool:
    return any(part.lower().startswith("xn--") for part in host.split("."))


def has_non_ascii(host: str) -> bool:
    return any(ord(c) > 127 for c in host)


def homograph_skeleton(host: str) -> str:
    h = _strip_accents_lower(host)
    h = "".join(CONFUSABLES.get(ch, ch) for ch in h)
    return h


def detect_brand_impersonation(host: str) -> tuple[str | None, str]:
    """Returns (brand, reason) if host impersonates a known brand."""
    h = homograph_skeleton(host)
    labels = h.split(".")
    reg = registered_domain(h)
    for brand, bases in BRAND_BASE_DOMAINS.items():
        if reg in bases or reg.endswith("." + tuple(bases)[0]):
            continue
        core = brand[:6]
        for label in labels[:-1] or labels:
            if label == brand or label.startswith(brand):
                pass
            d = levenshtein(label, brand, 3)
            if 0 < d <= 2 and len(label) >= len(core) - 1 and not _legit_sub(label, brand):
                return brand, f"Lookalike label '{label}' ~ '{brand}' (distance {d})"
            for token in KNOWN_BRANDS.get(brand, []):
                if token in label and not _legit_token(token, reg):
                    return brand, f"Brand keyword '{token}' inside non-official domain"
    # Cyrillic / non-ascii check against brand names
    raw_host = host.lower()
    if has_non_ascii(raw_host):
        norm = unicodedata.normalize("NFKC", raw_host)
        for brand in BRAND_BASE_DOMAINS:
            if levenshtein(norm.split(".")[0], brand, 2) <= 2:
                return brand, "Non-ASCII characters mimicking brand name"
    return None, ""


def _legit_sub(label: str, brand: str) -> bool:
    # e.g. 'login' under microsoft official domains handled by caller via reg check
    return False


def _legit_token(token: str, reg: str) -> bool:
    for bases in BRAND_BASE_DOMAINS.values():
        if reg in bases:
            return True
        for b in bases:
            if reg.endswith("." + b) or reg == b:
                return True
    return False


def url_flags(url: str) -> list[str]:
    """Compute heuristic flags for a single URL."""
    flags: list[str] = []
    try:
        p = urlparse(url)
    except Exception:
        return ["Unparseable URL"]
    host = (p.hostname or "").lower()
    scheme = p.scheme.lower()

    if scheme == "http":
        flags.append("Plain HTTP (no TLS)")
    try:
        ipaddress.ip_address(host)
        flags.append("IP-based URL")
    except ValueError:
        pass
    if host in URL_SHORTENERS:
        flags.append("URL shortener")
    tld_guess = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld_guess in SUSPICIOUS_TLDS:
        flags.append(f"Suspicious TLD .{tld_guess}")
    if is_punycode(host):
        flags.append("Punycode/IDN hostname (xn--)")
    if has_non_ascii(host):
        flags.append("Non-ASCII characters in hostname")
    brand, reason = detect_brand_impersonation(host)
    if brand:
        flags.append(f"Possible {brand} impersonation ({reason})")
    path_q = unquote((p.path or "") + "?" + (p.query or "")).lower()
    hits = [h for h in CREDENTIAL_PATH_HINTS if h in path_q]
    if len(hits) >= 1 and ("login" in hits or "signin" in hits or "password" in hits
                           or "verify" in hits or "account" in hits or "auth" in hits):
        flags.append("Credential harvesting indicators in path (" + ", ".join(sorted(set(hits))[:3]) + ")")
    elif hits:
        flags.append("Suspicious path keywords (" + ", ".join(sorted(set(hits))[:3]) + ")")
    ql = (p.query or "").lower()
    if any(s in ql for s in SUSPICIOUS_QUERY_PARAMS):
        flags.append("Open-redirect style query parameter")
    if "@" in url.split("//")[-1].split("/")[0]:
        flags.append("'@' userinfo trick in authority")
    if url.count("%") >= 3:
        flags.append("Heavily encoded URL")
    if p.port and p.port not in (80, 443, 8443):
        flags.append(f"Non-standard port {p.port}")
    return flags


def score_url(url: str, extra_flags: list[str] | None = None) -> tuple[int, list[str]]:
    flags = url_flags(url)
    all_flags = flags + (extra_flags or [])
    weight = {
        "IP-based URL": 15,
        "URL shortener": 5,
        "Plain HTTP (no TLS)": 8,
        "Punycode/IDN hostname (xn--)": 15,
        "Non-ASCII characters in hostname": 15,
        "'@' userinfo trick in authority": 15,
        "Heavily encoded URL": 10,
        "Open-redirect style query parameter": 10,
    }
    score = 0
    for f in all_flags:
        if f.startswith("Credential harvesting"):
            score += 30
        elif f.startswith("Suspicious TLD"):
            score += 10
        elif f.startswith("Possible"):
            score += 20
        elif f.startswith("Suspicious path keywords"):
            score += 10
        else:
            score += weight.get(f, 0)
    if "Redirect chain detected" in all_flags:
        score += 15
    return min(score, 100), all_flags
