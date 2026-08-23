"""IP analysis: reverse DNS (PTR), RDAP/ASN info and infrastructure type."""
from __future__ import annotations

import asyncio
import ipaddress

import httpx

from app.core.logging_setup import get_logger
from app.models.schemas import IPTypeClassification

log = get_logger("ip_analyzer")

RDAP_URL = "https://rdap.org/ip/"


async def _reverse_dns(ip: str) -> list[str]:
    def work() -> list[str]:
        try:
            return [str(r) for r in reversed(list(__import__("socket")
                    .gethostbyaddr(ip)[2]))] if False else []
        except Exception:
            return []
    # use dnspython for reliability
    try:
        import dns.resolver
        name = dns.reversename.from_address(ip)

        def resolve():
            answers = dns.resolver.resolve(name, "PTR", lifetime=6)
            return [str(r.target).rstrip(".") for r in answers]
        return await asyncio.get_event_loop().run_in_executor(None, resolve)
    except Exception:
        return []


async def analyze_ip(ip: str, client: httpx.AsyncClient) -> IPTypeClassification:
    cls = IPTypeClassification()
    if not ip:
        return cls
    ptrs = await _reverse_dns(ip)
    cls.reverse_dns = ", ".join(ptrs[:3])
    cls.hostname = ptrs[0] if ptrs else ""

    # RDAP (rdap.org aggregator) - real network data
    try:
        r = await client.get(RDAP_URL + ip, timeout=12, follow_redirects=True,
                             headers={"Accept": "application/rdap+json"})
        if r.status_code == 200:
            d = r.json()
            cls.country = str(d.get("country", ""))
            remarks = " ".join(str(x) for x in d.get("remarks", []))
            entities = d.get("entities", [])
            names = []
            for ent in entities:
                vcard = ent.get("vcardArray", [])
                if vcard and len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            names.append(str(item[3]))
            handle = str(d.get("handle", "") or "")
            cls.asn_org = names[0] if names else ""
            org_text = " ".join(names + [remarks, handle]).lower()
            if "asn" in d:
                cls.asn_number = f"AS{d['asn']}"
            elif "autnum" in d:
                cls.asn_number = f"AS{d['autnum']}"
            cls.sources.append("RDAP")

            # infrastructure classification heuristics from org text / PTR
            low_ptr = cls.reverse_dns.lower()
            text = f"{org_text} {low_ptr}"
            if any(k in text for k in ("tor exit", "torproject")):
                cls.classification = "Tor"
            elif any(k in text for k in ("proxy", "vpn", "privacy")):
                cls.classification = "VPN/Proxy"
            elif any(k in text for k in ("data center", "datacenter", "hosting",
                                         "cloud", "aws", "amazon", "azure",
                                         "digitalocean", "ovh", "hetzner",
                                         "linode", "vultr", "contabo")):
                cls.classification = "Hosting/Datacenter"
            elif any(k in text for k in ("telecom", "comcast", "verizon", "vodafone",
                                         "movistar", "telefonica", "orange", "jazztel",
                                         "charter", "spectrum", "at&t", "cox")):
                cls.classification = "ISP"
            else:
                cls.classification = "Corporate" if not ptrs else "Corporate/ISP"
        else:
            log.info("RDAP returned %s for %s", r.status_code, ip)
            cls.sources.append(f"RDAP HTTP {r.status_code}")
    except httpx.HTTPError as e:
        cls.sources.append(f"RDAP error: {type(e).__name__}")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        pass
    return cls
