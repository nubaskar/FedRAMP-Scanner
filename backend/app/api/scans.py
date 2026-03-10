"""
Scans API — Start, list, and manage compliance scans.

Scans run asynchronously via FastAPI BackgroundTasks. Each scan evaluates
a client's cloud environment against CMMC practices and stores findings.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.schemas import (
    Client,
    Finding,
    FindingResponse,
    Scan,
    ScanCreate,
    ScanDetail,
    ScanResponse,
)
from app.scanner.engine import fetch_evidence, run_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])


# ---------------------------------------------------------------------------
# POST / — Start a new scan
# ---------------------------------------------------------------------------
@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def start_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Create a scan record and launch the scan engine in the background.

    The scan runs asynchronously — poll GET /{scan_id} for status updates.
    """
    client = db.query(Client).filter(Client.id == payload.client_id).first()
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    scan = Scan(
        client_id=client.id,
        cmmc_level=client.cmmc_level,
        environment=client.environment,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Launch scan in background
    background_tasks.add_task(run_scan, scan.id, client.id)

    return scan


# ---------------------------------------------------------------------------
# GET / — List scans (optional client_id filter)
# ---------------------------------------------------------------------------
@router.get("/", response_model=list[ScanResponse])
def list_scans(
    client_id: Optional[str] = Query(None, description="Filter by client UUID"),
    db: Session = Depends(get_db),
):
    """Return all scans, optionally filtered by client_id."""
    query = db.query(Scan).order_by(Scan.created_at.desc())
    if client_id:
        query = query.filter(Scan.client_id == client_id)
    return query.all()


# ---------------------------------------------------------------------------
# GET /{scan_id} — Full scan detail with findings
# ---------------------------------------------------------------------------
@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Return scan metadata and all findings."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.domain, Finding.practice_id)
        .all()
    )

    return ScanDetail(
        scan=ScanResponse.model_validate(scan),
        findings=[FindingResponse.model_validate(f) for f in findings],
    )


# ---------------------------------------------------------------------------
# GET /{scan_id}/summary — Aggregated counts
# ---------------------------------------------------------------------------
@router.get("/{scan_id}/summary")
def get_scan_summary(scan_id: str, db: Session = Depends(get_db)):
    """
    Return aggregated finding counts by status and by domain.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    # Status counts
    status_counts: dict[str, int] = {"met": 0, "not_met": 0, "manual": 0, "error": 0}
    domain_counts: dict[str, dict[str, int]] = {}
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for f in findings:
        status_counts[f.status] = status_counts.get(f.status, 0) + 1
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        if f.domain not in domain_counts:
            domain_counts[f.domain] = {"met": 0, "not_met": 0, "manual": 0, "error": 0}
        domain_counts[f.domain][f.status] = domain_counts[f.domain].get(f.status, 0) + 1

    total = len(findings)
    compliance_pct = round((status_counts["met"] / total * 100), 1) if total > 0 else 0.0

    return {
        "scan_id": scan_id,
        "status": scan.status,
        "total_findings": total,
        "compliance_pct": compliance_pct,
        "by_status": status_counts,
        "by_severity": severity_counts,
        "by_domain": domain_counts,
    }


# ---------------------------------------------------------------------------
# GET /{scan_id}/evidence/{practice_id} — Fetch live API evidence
# ---------------------------------------------------------------------------
@router.get("/{scan_id}/evidence/{practice_id}")
def get_evidence(scan_id: str, practice_id: str, db: Session = Depends(get_db)):
    """Fetch live API evidence for a specific practice from the client's cloud."""
    from datetime import datetime, timezone

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan must be completed before fetching evidence",
        )

    try:
        results = fetch_evidence(scan_id, practice_id, db)
        return {
            "practice_id": practice_id,
            "checks": results,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Could not fetch evidence: {str(e)}",
        )


# ---------------------------------------------------------------------------
# DELETE /{scan_id} — Remove scan and findings
# ---------------------------------------------------------------------------
@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Delete a scan and all associated findings."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    db.delete(scan)
    db.commit()
    return None
