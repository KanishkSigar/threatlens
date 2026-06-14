"""
Pydantic Schemas
Request/Response models for API validation and serialization.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


# ─── Auth Schemas ──────────────────────────────────────────────

class UserRegisterRequest(BaseModel):
    """Schema for user registration."""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$")
    password: str = Field(..., min_length=8, max_length=128)


class UserLoginRequest(BaseModel):
    """Schema for user login."""
    username: str
    password: str


class TokenResponse(BaseModel):
    """Schema for JWT token response."""
    access_token: str
    token_type: str = "bearer"
    user_id: str
    username: str


class UserResponse(BaseModel):
    """Schema for user profile response."""
    id: str
    email: str
    username: str
    created_at: datetime

    class Config:
        from_attributes = True


# ─── Scan Schemas ──────────────────────────────────────────────

class URLScanRequest(BaseModel):
    """Schema for URL scan request."""
    url: str = Field(..., min_length=5, max_length=2048)


class EmailScanRequest(BaseModel):
    """Schema for email content scan request."""
    email_content: str = Field(..., min_length=10, max_length=50000)
    subject: Optional[str] = Field(None, max_length=500)
    sender: Optional[str] = Field(None, max_length=255)


class FeatureDetail(BaseModel):
    """Individual feature analysis detail."""
    name: str
    value: str | float | bool
    risk_contribution: str  # 'low', 'medium', 'high'
    description: str


class ScanResultResponse(BaseModel):
    """Schema for scan result response."""
    id: str
    scan_type: str
    input_data: str
    risk_score: float = Field(..., ge=0.0, le=100.0)
    verdict: str  # 'SAFE', 'SUSPICIOUS', 'PHISHING'
    confidence: float = Field(..., ge=0.0, le=1.0)
    risk_level: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    features: list[FeatureDetail]
    recommendations: list[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ScanHistoryItem(BaseModel):
    """Schema for scan history list item."""
    id: str
    scan_type: str
    input_data: str
    risk_score: float
    verdict: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanHistoryResponse(BaseModel):
    """Schema for paginated scan history response."""
    scans: list[ScanHistoryItem]
    total: int
    page: int
    page_size: int


# ─── Stats Schema ──────────────────────────────────────────────

class UserStatsResponse(BaseModel):
    """Schema for user threat statistics."""
    total_scans: int
    safe_count: int
    suspicious_count: int
    phishing_count: int
    urls_scanned: int
    emails_scanned: int
    average_risk_score: float
    last_scan_at: Optional[datetime] = None
