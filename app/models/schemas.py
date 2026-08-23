"""Pydantic data models shared across analyzers, integrations and GUI."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Status(str, Enum):
    """Explicit result statuses. Never collapse ERROR/UNKNOWN into SAFE."""
    UNKNOWN = "UNKNOWN"
    NOT_ANALYZED = "NOT ANALYZED"
    NOT_CONFIGURED = "NOT CONFIGURED"
    ERROR = "ERROR"
    SAFE = "SAFE"
    INFO = "INFO"
    LOW = "LOW"
    GUARDED = "GUARDED"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"
    MALICIOUS = "MALICIOUS"
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    CRITICAL = "CRITICAL"


class RiskBand(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL / MALICIOUS"

    @staticmethod
    def from_score(score: int) -> "RiskBand":
        if score >= 80:
            return RiskBand.CRITICAL
        if score >= 60:
            return RiskBand.HIGH
        if score >= 40:
            return RiskBand.SUSPICIOUS
        if score >= 20:
            return RiskBand.LOW
        return RiskBand.SAFE


class Indicator(BaseModel):
    label: str
    status: Status = Status.UNKNOWN
    detail: str = ""
    expected: str = ""
    actual: str = ""


class AuthResult(BaseModel):
    mechanism: str = ""          # spf / dkim / dmarc
    result: str = "none"         # pass/fail/softfail/none/temperror/permerror
    domain: str = ""
    raw: str = ""
    indicator: Optional[Indicator] = None


class AuthenticationAnalysis(BaseModel):
    spf: AuthResult = Field(default_factory=lambda: AuthResult(mechanism="spf"))
    dkim: AuthResult = Field(default_factory=lambda: AuthResult(mechanism="dkim"))
    dmarc: AuthResult = Field(default_factory=lambda: AuthResult(mechanism="dmarc"))
    received_spf: str = ""
    arc_results: list[str] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    raw_authentication_results: list[str] = Field(default_factory=list)


class ReceivedHop(BaseModel):
    index: int = 0
    from_host: str = ""
    from_ip: str = ""
    by_host: str = ""
    with_proto: str = ""
    date: str = ""
    tls: str = ""
    is_private_source: bool = False


class OriginIPResult(BaseModel):
    ip: str = ""
    source_header: str = ""
    confidence: float = 0.0     # 0..1
    hops: list[ReceivedHop] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class IPReputation(BaseModel):
    provider: str = ""
    ip: str = ""
    score: Optional[int] = None          # AbuseIPDB 0..100 (100=worst)
    abuse_confidence: Optional[int] = None
    verdict: Status = Status.NOT_ANALYZED
    total_reports: Optional[int] = None
    last_report: str = ""
    country: str = ""
    isp: str = ""
    domain: str = ""
    usage_type: str = ""
    asn: str = ""
    org: str = ""
    categories: list[str] = Field(default_factory=list)
    is_tor: bool = False
    is_proxy: bool = False
    is_hosting: bool = False
    demo: bool = False
    error: str = ""

    @property
    def band(self) -> Status:
        s = self.score
        if s is None:
            return self.verdict
        if s >= 80:
            return Status.MALICIOUS
        if s >= 60:
            return Status.HIGH
        if s >= 40:
            return Status.SUSPICIOUS
        if s >= 20:
            return Status.GUARDED
        return Status.LOW


class RedirectHop(BaseModel):
    step: int
    url: str
    status_code: Optional[int] = None
    reason: str = ""
    domain: str = ""
    ip: str = ""
    server: str = ""
    location: str = ""
    protocol: str = ""


class UrlInfo(BaseModel):
    url: str
    final_url: str = ""
    domain: str = ""
    subdomain: str = ""
    tld: str = ""
    scheme: str = ""
    port: Optional[int] = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    source: str = "text"                 # html href/src/text/header
    redirect_count: int = 0
    redirect_chain: list[RedirectHop] = Field(default_factory=list)
    risk_score: int = 0
    risk_level: Status = Status.NOT_ANALYZED
    flags: list[str] = Field(default_factory=list)
    urlscan_verdict: Status = Status.NOT_ANALYZED
    urlscan_score: Optional[int] = None
    urlscan_malicious: bool = False
    urlscan_suspicious: bool = False
    error: str = ""


class DomainInfo(BaseModel):
    domain: str
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)
    soa: str = ""
    caa: list[str] = Field(default_factory=list)
    ptr: list[str] = Field(default_factory=list)
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    age_days: Optional[int] = None
    rdap_available: bool = False
    flags: list[str] = Field(default_factory=list)
    error: str = ""


class IOCType(str, Enum):
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    DOMAIN = "Domain"
    URL = "URL"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA512 = "SHA512"
    EMAIL = "Email"
    FILENAME = "Filename"
    ASN = "ASN"


class IOC(BaseModel):
    type: IOCType
    value: str
    context: str = ""
    severity: Status = Status.INFO


class IPTypeClassification(BaseModel):
    classification: str = "Unknown"      # Residential/ISP/Cloud/Hosting/VPN/Proxy/Tor/Datacenter/Corporate
    reverse_dns: str = ""
    hostname: str = ""
    asn_number: str = ""
    asn_org: str = ""
    country: str = ""
    sources: list[str] = Field(default_factory=list)


class RiskFactor(BaseModel):
    name: str
    points: int
    detail: str = ""
    severity: Status = Status.INFO


class RiskAssessment(BaseModel):
    score: int = 0
    max_score: int = 100
    band: RiskBand = RiskBand.SAFE
    factors: list[RiskFactor] = Field(default_factory=list)
    verdict: str = ""

    @property
    def why(self) -> list[RiskFactor]:
        return [f for f in self.factors if f.points > 0]


class Recommendation(BaseModel):
    title: str
    detail: str = ""
    priority: Status = Status.INFO


# ---------------------------------------------------------------------------
# IOC Correlation / Attack Graph / Campaign models
# ---------------------------------------------------------------------------

class GraphNode(BaseModel):
    node_id: str
    kind: str                 # email / domain / ip / asn / url / redirect / final
    label: str = ""
    value: str = ""           # IOC value or short summary shown in the node
    verdict: Status = Status.UNKNOWN
    detail: str = ""          # one-liner rendered under the node


class GraphEdge(BaseModel):
    src: str
    dst: str
    relation: str = ""


class CorrelationEvidence(BaseModel):
    title: str
    detail: str = ""
    severity: Status = Status.INFO
    nodes: list[str] = Field(default_factory=list)   # involved node_ids


class CampaignMatch(BaseModel):
    ioc_type: str = ""
    value: str = ""
    past_analyses: int = 0
    analysis_ids: list[str] = Field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""


class CampaignResult(BaseModel):
    detected: bool = False
    note: str = ""                       # e.g. "IOC reuse observed (1 prior case)"
    emails: int = 0                      # distinct analyses sharing infrastructure (incl. current)
    recipients: int = 0                  # distinct recipients across those analyses
    domains: int = 0                     # shared domains in the cluster
    ips: int = 0                         # shared IPs in the cluster
    cluster: list[CampaignMatch] = Field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    confidence: int = 0                  # 0..100


class CorrelationResult(BaseModel):
    """Cross-IOC correlation for a single email analysis."""
    verdict: str = "NO CORRELATION"
    confidence: int = 0                 # 0..100
    band: RiskBand = RiskBand.SAFE
    correlated_indicators: int = 0      # how many independent categories agree
    evidence: list[CorrelationEvidence] = Field(default_factory=list)
    graph_nodes: list[GraphNode] = Field(default_factory=list)
    graph_edges: list[GraphEdge] = Field(default_factory=list)
    campaign: Optional[CampaignResult] = None


class AttachmentInfo(BaseModel):
    filename: str = ""
    content_type: str = ""
    size_bytes: int = 0
    sha256: str = ""
    md5: str = ""
    sha1: str = ""
    extension: str = ""
    dangerous: bool = False


class HeaderField(BaseModel):
    name: str
    value: str


class EmailAnalysis(BaseModel):
    """Aggregate result of the full analysis pipeline."""
    case_id: str = ""
    analyzed_at: str = Field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    analyst: str = "Operator"
    demo_mode: bool = False

    # Parsed email basics
    subject: str = ""
    from_display: str = ""
    from_addr: str = ""
    sender: str = ""
    return_path: str = ""
    reply_to: str = ""
    to_addrs: str = ""
    cc_addrs: str = ""
    delivered_to: str = ""
    date: str = ""
    message_id: str = ""
    mime_version: str = ""
    content_type: str = ""
    size_bytes: int = 0
    format: str = "text/plain"
    x_mailer: str = ""
    user_agent: str = ""
    x_originating_ip: str = ""

    headers: list[HeaderField] = Field(default_factory=list)
    header_map: dict[str, list[str]] = Field(default_factory=dict)

    authentication: AuthenticationAnalysis = Field(default_factory=AuthenticationAnalysis)
    origin_ip: OriginIPResult = Field(default_factory=OriginIPResult)
    ip_classification: IPTypeClassification = Field(default_factory=IPTypeClassification)
    ip_reputation: IPReputation = Field(default_factory=IPReputation)

    urls: list[UrlInfo] = Field(default_factory=list)
    domains: dict[str, DomainInfo] = Field(default_factory=dict)
    iocs: list[IOC] = Field(default_factory=list)
    attachments: list[AttachmentInfo] = Field(default_factory=list)

    identity_indicators: list[Indicator] = Field(default_factory=list)
    advanced_detections: list[Indicator] = Field(default_factory=list)
    browser_safety: dict[str, Status] = Field(default_factory=dict)

    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    recommendations: list[Recommendation] = Field(default_factory=list)

    correlation: Optional["CorrelationResult"] = None

    errors: list[str] = Field(default_factory=list)   # integration failures etc.

    @property
    def malicious_urls(self) -> int:
        return sum(1 for u in self.urls if u.risk_level in (Status.MALICIOUS, Status.HIGH, Status.CRITICAL))
