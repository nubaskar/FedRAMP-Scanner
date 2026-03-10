"""
SQLAlchemy ORM models and Pydantic schemas for the FedRAMP Cloud Compliance Scanner.

Defines Client, Scan, and Finding tables plus all API request/response schemas.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.sqlite import JSON as SQLiteJSON
from sqlalchemy.orm import relationship

from app.db.database import Base


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# SQLAlchemy ORM Models
# ---------------------------------------------------------------------------

class Client(Base):
    """CSP with a cloud environment to be scanned for FedRAMP compliance."""

    __tablename__ = "clients"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False, index=True)
    environment = Column(String(50), nullable=False)  # aws_govcloud, azure_government, etc.
    fedramp_baseline = Column(String(10), nullable=False)  # Low, Moderate, High
    credentials_config = Column(SQLiteJSON, nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)

    scans = relationship("Scan", back_populates="client", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Client {self.name} ({self.environment}, {self.fedramp_baseline})>"


class Scan(Base):
    """A compliance scan run against a client's cloud environment."""

    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    client_id = Column(String(36), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    status = Column(String(20), nullable=False, default="pending")  # pending/running/completed/failed
    fedramp_baseline = Column(String(10), nullable=False)  # Low, Moderate, High
    environment = Column(String(50), nullable=False)
    started_at = Column(DateTime, default=func.now(), nullable=False)
    completed_at = Column(DateTime, nullable=True)
    summary = Column(SQLiteJSON, nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    client = relationship("Client", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan {self.id[:8]} status={self.status}>"


class Finding(Base):
    """A single compliance finding produced by a scan."""

    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    control_id = Column(String(20), nullable=False)      # e.g., "AC-2", "AC-2(1)"
    enhancement = Column(String(10), nullable=True)      # e.g., "(1)", "(2)" for enhancements
    family = Column(String(100), nullable=False)         # e.g., "Access Control"
    domain = Column(String(5), nullable=False)           # e.g., "AC"
    check_id = Column(String(100), nullable=False)       # e.g., "ac-2-aws-001"
    check_name = Column(String(500), nullable=False)
    status = Column(String(20), nullable=False)          # met/not_met/manual/error
    severity = Column(String(20), nullable=False)        # critical/high/medium/low
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    objective_coverage = Column(SQLiteJSON, nullable=True)  # NIST 800-53 assessment objective coverage
    created_at = Column(DateTime, default=func.now(), nullable=False)

    scan = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding {self.check_id} status={self.status}>"


# ---------------------------------------------------------------------------
# Pydantic Schemas — Requests
# ---------------------------------------------------------------------------

class ClientCreate(BaseModel):
    """Schema for creating a new client."""
    name: str = Field(..., min_length=1, max_length=255, description="Company name")
    environment: str = Field(
        ...,
        pattern=r"^(aws_commercial|aws_govcloud|azure_commercial|azure_government|gcp_commercial|gcp_assured_workloads)$",
        description="Cloud environment identifier",
    )
    fedramp_baseline: str = Field(..., pattern=r"^(Low|Moderate|High)$", description="FedRAMP target baseline")
    credentials_config: dict[str, Any] = Field(
        default_factory=dict,
        description="Cloud credentials (role_arn, tenant_id, etc.)",
    )


class ClientUpdate(BaseModel):
    """Schema for updating an existing client."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    environment: Optional[str] = Field(
        None,
        pattern=r"^(aws_commercial|aws_govcloud|azure_commercial|azure_government|gcp_commercial|gcp_assured_workloads)$",
    )
    fedramp_baseline: Optional[str] = Field(None, pattern=r"^(Low|Moderate|High)$")
    credentials_config: Optional[dict[str, Any]] = None


class ScanCreate(BaseModel):
    """Schema for starting a new scan."""
    client_id: str = Field(..., description="UUID of the client to scan")


# ---------------------------------------------------------------------------
# Pydantic Schemas — Responses
# ---------------------------------------------------------------------------

class ClientResponse(BaseModel):
    """Client data returned by the API (no credentials)."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    environment: str
    fedramp_baseline: str
    created_at: datetime
    updated_at: datetime


class ClientList(BaseModel):
    """Paginated list of clients."""
    clients: list[ClientResponse]
    total: int


class ScanResponse(BaseModel):
    """Scan metadata returned by the API."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    client_id: str
    status: str
    fedramp_baseline: str
    environment: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    summary: Optional[dict[str, Any]] = None


class FindingResponse(BaseModel):
    """Single finding returned by the API."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    control_id: str
    enhancement: Optional[str] = None
    family: str
    domain: str
    check_id: str
    check_name: str
    status: str
    severity: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    objective_coverage: Optional[dict[str, Any]] = None


class ScanDetail(BaseModel):
    """Full scan detail including all findings."""
    scan: ScanResponse
    findings: list[FindingResponse]


class ComplianceSummary(BaseModel):
    """Aggregated compliance statistics."""
    met: int = 0
    not_met: int = 0
    manual: int = 0
    error: int = 0
    total: int = 0
    compliance_pct: float = 0.0


class DashboardStats(BaseModel):
    """Dashboard overview statistics."""
    total_clients: int
    total_scans: int
    recent_scans: list[ScanResponse]
    compliance_summary: ComplianceSummary
