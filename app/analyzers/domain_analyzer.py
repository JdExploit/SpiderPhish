"""Domain analysis: DNS records, RDAP/WHOIS age and risk flags."""
from __future__ import annotations

import asyncio
import datetime as dt

import httpx

from app.core.logging_setup import get_logger
from app.models.schemas import DomainInfo

log = get_logger("domain_analyzer")

RDAP_URL = "https://rdap.org/domain/"


def _dns_records(domain: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 6
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
            try:
                ans = resolver.resolve(domain, rtype)
                vals = []
                for r in ans:
                    s = r.to_text()
                    if rtype == "MX":
                        parts = s.split()
                        vals.append(f"{parts[1]} (prio {parts[0]})" if len(parts) > 1 else s)
                    elif rtype == "SOA":
                        vals.append(s.split()[0])
                    else:
                        vals.append(s)
                if vals:
                    out[rtype] = vals[:10]
            except Exception:  # NXDOMAIN / no record
                continue
    except Exception as e:  # dnspython missing etc.
        log.warning("DNS error for %s: %s", domain, e)
    return out


async def analyze_domain(domain: str, client: httpx.AsyncClient) -> DomainInfo:
    info = DomainInfo(domain=domain)
    loop = asyncio.get_event_loop()
    recs = await loop.run_in_executor(None, _dns_records, domain)
    info.a = recs.get("A", [])
    info.aaaa = recs.get("AAAA", [])
    info.mx = recs.get("MX", [])
    info.ns = recs.get("NS", [])
    info.txt = recs.get("TXT", [])
    info.cname = recs.get("CNAME", [])
    info.soa = recs["SOA"][0] if recs.get("SOA") else ""
    info.caa = recs.get("CAA", [])

    # RDAP registration data
    try:
        r = await client.get(RDAP_URL + domain, timeout=12, follow_redirects=True,
                             headers={"Accept": "application/rdap+json"})
        if r.status_code == 200:
            d = r.json()
            info.rdap_available = True
            events = {e.get("eventAction"): e.get("eventDate", "") for e in d.get("events", [])}
            info.creation_date = str(events.get("registration", ""))[:19].replace("T", " ")
            info.expiration_date = str(events.get("expiration", ""))[:19].replace("T", " ")
            for ent in d.get("entities", []):
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if vcard and len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                info.registrar = str(item[3])
                                break
            if info.creation_date:
                try:
                    created = dt.datetime.fromisoformat(
                        events.get("registration", "").replace("Z", "+00:00"))
                    info.age_days = (dt.datetime.now(dt.timezone.utc) - created).days
                except Exception:
                    pass
        else:
            info.error = f"RDAP HTTP {r.status_code}"
    except httpx.HTTPError as e:
        info.error = f"RDAP error: {type(e).__name__}"

    flags = []
    if not info.a and not info.cname:
        flags.append("No A/CNAME record (possible parked or dead domain)")
    if info.age_days is not None:
        if info.age_days <= 30:
            flags.append(f"Very recently registered ({info.age_days} days)")
        elif info.age_days <= 180:
            flags.append(f"Recently registered ({info.age_days} days)")
    if info.registrar.lower().startswith(("namecheap", "namecheap inc", "porkbun",
                                          "hostinger")) and info.age_days is not None \
            and info.age_days < 365:
        flags.append(f"Budget registrar + young domain ({info.registrar})")
    if domain.startswith("xn--") or ".xn--" in domain:
        flags.append("Punycode domain")
    info.flags = flags
    return info
