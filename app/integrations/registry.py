"""Provider registry. Add new providers here without touching the core."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.core.logging_setup import get_logger
from app.integrations.abuseipdb import AbuseIPDBProvider
from app.integrations.greynoise import GreyNoiseProvider
from app.integrations.mha_adapter import MHAAdapter
from app.integrations.otx import OTXProvider
from app.integrations.urlscan import UrlScanProvider
from app.integrations.virustotal import VirusTotalProvider

log = get_logger("providers")


@dataclass
class ProviderRegistry:
    abuseipdb: AbuseIPDBProvider
    urlscan: UrlScanProvider
    virustotal: VirusTotalProvider
    otx: OTXProvider
    greynoise: GreyNoiseProvider
    mha: MHAAdapter


def build_registry() -> ProviderRegistry:
    return ProviderRegistry(
        abuseipdb=AbuseIPDBProvider(),
        urlscan=UrlScanProvider(),
        virustotal=VirusTotalProvider(),
        otx=OTXProvider(),
        greynoise=GreyNoiseProvider(),
        mha=MHAAdapter(),
    )


def configured_summary(reg: ProviderRegistry) -> dict[str, str]:
    out = {}
    for p in (reg.abuseipdb, reg.urlscan, reg.virustotal, reg.otx, reg.greynoise, reg.mha):
        out[p.name] = "CONFIGURED" if p.is_configured() else "NOT CONFIGURED"
    return out
