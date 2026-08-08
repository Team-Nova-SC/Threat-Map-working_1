from pydantic import BaseModel, ConfigDict
from typing import Optional, Dict, Any, List, Literal
from datetime import datetime

class ScanBase(BaseModel):
    indicator: str
    type: str
    refresh: bool = False

class ScanCreate(ScanBase):
    pass

class ScanResponse(ScanBase):
    id: str
    risk_score: int
    risk_level: str
    summary: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ProviderData(BaseModel):
    status: str
    source: str
    retrieved_at: datetime
    error: Optional[str] = None
    model_config = ConfigDict(extra="allow")


class IPReportData(BaseModel):
    report_schema: Literal["ip.v1"]
    virustotal: ProviderData
    abuseipdb: ProviderData
    greynoise: Optional[ProviderData] = None
    ipinfo: ProviderData
    alienvault_otx: ProviderData
    risk_confidence: Dict[str, Any]
    ai_insights: Optional[Dict[str, Any]] = None


class DomainReportData(BaseModel):
    report_schema: Literal["domain.v1"]
    virustotal: Dict[str, Any]
    urlscan: Dict[str, Any]
    alienvault_otx: Dict[str, Any]
    dns_records: Dict[str, Any]
    whois_records: Dict[str, Any]
    ssl_metadata: Dict[str, Any]
    risk_confidence: Dict[str, Any]
    model_config = ConfigDict(extra="allow")


class URLReportData(BaseModel):
    report_schema: Literal["url.v1"]
    virustotal: Dict[str, Any]
    urlscan: Dict[str, Any]
    alienvault_otx: Dict[str, Any]
    risk_confidence: Dict[str, Any]
    model_config = ConfigDict(extra="allow")


class HashReportData(BaseModel):
    report_schema: Literal["hash.v1"]
    virustotal: Dict[str, Any]
    alienvault_otx: Dict[str, Any]
    risk_confidence: Dict[str, Any]
    model_config = ConfigDict(extra="allow")


class IPScanResponse(ScanResponse):
    type: Literal["ip"]
    raw_data: IPReportData


class DomainScanResponse(ScanResponse):
    type: Literal["domain"]
    raw_data: DomainReportData


class URLScanResponse(ScanResponse):
    type: Literal["url"]
    raw_data: URLReportData


class HashScanResponse(ScanResponse):
    type: Literal["hash"]
    raw_data: HashReportData


class WatchlistBase(BaseModel):
    indicator: str
    type: str
    notes: Optional[str] = None
    custom_threshold: Optional[int] = None
    tags: Optional[str] = None
    schedule_frequency: Optional[str] = None
    webhook_url: Optional[str] = None

class WatchlistCreate(WatchlistBase):
    pass

class WatchlistUpdate(BaseModel):
    notes: Optional[str] = None
    custom_threshold: Optional[int] = None
    tags: Optional[str] = None
    schedule_frequency: Optional[str] = None
    webhook_url: Optional[str] = None

class WatchlistResponse(WatchlistBase):
    id: int
    added_at: datetime
    last_scanned_at: datetime
    last_risk_score: int

    model_config = ConfigDict(from_attributes=True)


class AlertBase(BaseModel):
    indicator: str
    alert_type: str
    title: str
    message: Optional[str] = None
    risk_score: int

class AlertResponse(AlertBase):
    id: int
    is_dismissed: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertUpdate(BaseModel):
    is_dismissed: bool


# Dashboard Summary Schemes
class StatCardData(BaseModel):
    value: str
    trend: str
    status: str

class DashboardStats(BaseModel):
    total_scans_24h: int
    critical_threats: int
    high_risk_assets: int
    monitored_iocs: int
    recent_scans: List[ScanResponse]
    alerts: List[AlertResponse]
    threat_distribution: Dict[str, int] # e.g. {"critical": 25, "high": 35, "medium": 30, "low": 10}
    malware_prevalence: List[Dict[str, Any]] # e.g. [{"name": "Ransom.LockBit", "percentage": 82, "trend": "up"}]
    map_points: Optional[List[Dict[str, Any]]] = None
