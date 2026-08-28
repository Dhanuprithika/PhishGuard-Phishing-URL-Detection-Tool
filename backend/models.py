from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any
from datetime import datetime

VerdictType = Literal["safe", "suspicious", "phishing"]
CheckStatus = Literal["pass", "warn", "fail", "scanning"]

class CheckItem(BaseModel):
    label: str
    status: CheckStatus
    detail: Optional[str] = None

class URLFeatures(BaseModel):
    url_length: int
    domain_length: int
    is_ip: bool
    num_dots: int
    num_hyphens: int
    num_at_symbols: int
    num_subdomains: int
    has_https: bool
    has_port: bool
    has_base64_or_hex: bool
    entropy: float
    suspicious_keywords_found: List[str] = []
    suspicious_tld: bool
    brand_impersonation: Optional[str] = None

class DomainIntelligence(BaseModel):
    domain: str
    subdomains: int
    ip_addresses: List[str] = []
    has_mx_records: bool = False
    has_dns: bool = True
    registration_age: str = "Unknown"
    registrar: Optional[str] = None
    country: Optional[str] = None

class CertificateInfo(BaseModel):
    has_https: bool
    valid: bool
    issuer: Optional[str] = None
    subject: Optional[str] = None
    days_until_expiration: Optional[int] = None
    error: Optional[str] = None

class ReputationInfo(BaseModel):
    blacklisted: bool
    blacklist_sources: List[str] = []
    ip_reputation: Literal["clean", "flagged", "unknown"] = "clean"
    known_threat: bool = False

class ScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    url: str
    verdict: VerdictType
    risk_score: int = Field(..., alias="riskScore")
    checks: List[CheckItem]
    indicators: List[str]
    explanation: str
    recommendation: str
    domain: str
    https: bool
    ip_reputation: Literal["clean", "flagged", "unknown"] = Field(..., alias="ipReputation")
    subdomains: int
    blacklisted: bool
    registration_age: str = Field(..., alias="registrationAge")
    scanned_at: datetime = Field(default_factory=datetime.utcnow, alias="scannedAt")
    
    # Detailed technical fields for deep analysis
    features: Optional[Dict[str, Any]] = None
    ml_confidence: Optional[float] = None

    class Config:
        populate_by_name = True
