"""Repository and finding models."""

import uuid
from datetime import datetime
from typing import List, Dict, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Request to scan a repository."""
    repo_url: str = Field(..., description="Git repository URL to scan")
    branch: str = Field(default="main", description="Branch to scan")


class ScanResult(BaseModel):
    """A single secret finding."""
    rule_id: str = ""
    description: str = ""
    secret: str = ""
    file: str = ""
    line: int = 0
    column: int = 0
    match: str = ""
    severity: str = "MEDIUM"
    source: str = ""


class ScanResponse(BaseModel):
    """Response from a scan."""
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    repo_url: str = ""
    status: str = "pending"
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    findings: List[ScanResult] = []
    scanned_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    message: str = ""


class RepoRegister(BaseModel):
    """Register a repository for monitoring."""
    repo_url: str
    name: str = ""
    branch: str = "main"


class AlertConfig(BaseModel):
    """Configure alerting for a repo."""
    slack_webhook: Optional[str] = None
    discord_webhook: Optional[str] = None
    on_critical_only: bool = False


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
