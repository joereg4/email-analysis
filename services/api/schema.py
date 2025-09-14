from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AnalysisStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class ScanType(str, Enum):
    CLAMAV = "clamav"
    YARA = "yara"
    EXIF = "exif"
    OCR = "ocr"
    URL = "url"
    OPENAI = "openai"

# Base schemas
class EmailAnalysisBase(BaseModel):
    filename: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    recipients: Optional[List[str]] = None
    date_sent: Optional[datetime] = None
    message_id: Optional[str] = None

class EmailAnalysisCreate(EmailAnalysisBase):
    file_path: str
    file_hash: str

class EmailAnalysisUpdate(BaseModel):
    status: Optional[AnalysisStatus] = None
    risk_score: Optional[float] = None
    risk_level: Optional[RiskLevel] = None
    clamav_result: Optional[Dict[str, Any]] = None
    yara_matches: Optional[List[Dict[str, Any]]] = None
    exif_data: Optional[Dict[str, Any]] = None
    ocr_text: Optional[str] = None
    url_analysis: Optional[Dict[str, Any]] = None
    summary: Optional[str] = None
    ai_risk_assessment: Optional[str] = None
    recommendations: Optional[str] = None
    quarantined: Optional[bool] = None
    quarantine_reason: Optional[str] = None

class EmailAnalysis(EmailAnalysisBase):
    id: int
    file_path: str
    file_hash: str
    status: AnalysisStatus
    risk_score: float
    risk_level: RiskLevel
    clamav_result: Optional[Dict[str, Any]] = None
    yara_matches: Optional[List[Dict[str, Any]]] = None
    exif_data: Optional[Dict[str, Any]] = None
    ocr_text: Optional[str] = None
    url_analysis: Optional[Dict[str, Any]] = None
    summary: Optional[str] = None
    ai_risk_assessment: Optional[str] = None
    recommendations: Optional[str] = None
    quarantined: bool
    quarantine_reason: Optional[str] = None
    artifacts_path: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# Attachment schemas
class AttachmentBase(BaseModel):
    filename: str
    content_type: str
    size: int
    file_hash: str

class AttachmentCreate(AttachmentBase):
    email_id: int
    file_path: str

class Attachment(AttachmentBase):
    id: int
    email_id: int
    clamav_result: Optional[Dict[str, Any]] = None
    yara_matches: Optional[List[Dict[str, Any]]] = None
    exif_data: Optional[Dict[str, Any]] = None
    ocr_text: Optional[str] = None
    quarantined: bool
    quarantine_reason: Optional[str] = None
    file_path: str
    created_at: datetime

    class Config:
        from_attributes = True

# URL Analysis schemas
class URLAnalysisBase(BaseModel):
    url: str
    domain: str

class URLAnalysisCreate(URLAnalysisBase):
    email_id: int

class URLAnalysis(URLAnalysisBase):
    id: int
    email_id: int
    virustotal_result: Optional[Dict[str, Any]] = None
    whois_data: Optional[Dict[str, Any]] = None
    reputation_score: Optional[float] = None
    risk_level: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

# Scan Log schemas
class ScanLogBase(BaseModel):
    email_id: int
    scan_type: ScanType
    status: str

class ScanLogCreate(ScanLogBase):
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    duration_seconds: Optional[float] = None

class ScanLog(ScanLogBase):
    id: int
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    duration_seconds: Optional[float] = None
    created_at: datetime

    class Config:
        from_attributes = True

# API Response schemas
class AnalysisResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None

class FileUploadResponse(BaseModel):
    success: bool
    message: str
    analysis_id: Optional[int] = None
    file_hash: Optional[str] = None

class AnalysisSummary(BaseModel):
    total_emails: int
    pending: int
    processing: int
    completed: int
    failed: int
    quarantined: int
    high_risk: int
    critical_risk: int
