"""Santhosh AI — Pydantic models for scan operations"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CommandSafety(str, Enum):
    SAFE = "SAFE"
    CAUTION = "CAUTION"
    RISKY = "RISKY"
    DANGEROUS = "DANGEROUS"


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class ScanPolicy(str, Enum):
    STRICT = "strict"
    BALANCED = "balanced"
    PERMISSIVE = "permissive"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    category: str
    engine: str
    rule_id: str
    risk_score: int = Field(ge=0, le=100)
    command_safety: Optional[CommandSafety] = None
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence: Optional[str] = None
    llm_analysis: Optional[str] = None
    false_positive_probability: float = 0.0
    tags: List[str] = []
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ScanRequest(BaseModel):
    policy: ScanPolicy = ScanPolicy.BALANCED
    engines: List[str] = []
    custom_rules: List[str] = []
    llm_enrichment: bool = True
    deep_scan: bool = False


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: ScanStatus = ScanStatus.PENDING
    policy: ScanPolicy
    target: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    files_analyzed: int = 0
    risk_score: int = 0
    fraud_score: int = 0
    analyzability_score: int = 100
    findings: List[Finding] = []
    findings_summary: Dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
    }
    engines_used: List[str] = []
    errors: List[str] = []
    metadata: Dict[str, Any] = {}


class ScanProgress(BaseModel):
    scan_id: str
    status: ScanStatus
    progress_pct: int
    current_engine: str
    files_processed: int
    findings_so_far: int
    elapsed_seconds: float
