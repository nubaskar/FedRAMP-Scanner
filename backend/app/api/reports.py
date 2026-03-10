"""
Reports API — Generate HTML and XLSX compliance reports for completed scans.

Includes /demo/html and /demo/xlsx endpoints that produce sample reports
with realistic mock findings for previewing report format without a live scan.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.schemas import Client, Finding, Scan
from app.reports.html_report import generate_html_report
from app.reports.xlsx_report import generate_xlsx_report

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _load_scan_data(scan_id: str, db: Session):
    """Load scan, findings, and client for report generation."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan is not completed (status={scan.status}). Reports can only be generated for completed scans.",
        )

    client = db.query(Client).filter(Client.id == scan.client_id).first()
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.domain, Finding.practice_id)
        .all()
    )

    return scan, findings, client


# ---------------------------------------------------------------------------
# GET / — List clients with completed scans for the Reports blade
# (MUST be defined before /{scan_id} routes to avoid path conflicts)
# ---------------------------------------------------------------------------
@router.get("/")
def list_reports(db: Session = Depends(get_db)):
    """Return all clients that have completed scans, with scan summaries."""
    clients = db.query(Client).order_by(Client.name).all()
    result = []
    for client in clients:
        scans = (
            db.query(Scan)
            .filter(Scan.client_id == client.id, Scan.status == "completed")
            .order_by(Scan.created_at.desc())
            .all()
        )
        if not scans:
            continue
        scan_list = []
        for s in scans:
            summary = s.summary or {}
            met = summary.get("met", 0)
            not_met = summary.get("not_met", 0)
            manual = summary.get("manual", 0)
            compliance_pct = summary.get("compliance_pct", 0.0)
            scan_list.append({
                "id": s.id,
                "created_at": s.created_at.isoformat() if s.created_at else s.started_at.isoformat(),
                "level": s.cmmc_level,
                "environment": s.environment,
                "compliance_pct": compliance_pct,
                "met": met,
                "not_met": not_met,
                "manual": manual,
            })
        result.append({
            "id": client.id,
            "name": client.name,
            "scans": scan_list,
        })
    return {"clients": result}


# ---------------------------------------------------------------------------
# GET /notifications — Recent scan completions and failures for the bell
# (MUST be defined before /{scan_id} routes to avoid path conflicts)
# ---------------------------------------------------------------------------
@router.get("/notifications")
def get_notifications(db: Session = Depends(get_db)):
    """Return recent completed/failed scans for the notification bell."""
    rows = (
        db.query(Scan, Client)
        .join(Client, Scan.client_id == Client.id)
        .filter(Scan.status.in_(["completed", "failed"]))
        .filter(Scan.completed_at.isnot(None))
        .order_by(Scan.completed_at.desc())
        .limit(20)
        .all()
    )

    notifications = []
    for scan, client in rows:
        summary = scan.summary or {}
        met = summary.get("met", 0)
        not_met = summary.get("not_met", 0)
        manual = summary.get("manual", 0)
        total_assessed = met + not_met
        compliance_pct = round((met / total_assessed * 100), 1) if total_assessed > 0 else 0.0

        notifications.append({
            "scan_id": scan.id,
            "client_name": client.name,
            "client_id": client.id,
            "status": scan.status,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "environment": scan.environment,
            "cmmc_level": scan.cmmc_level,
            "compliance_pct": summary.get("compliance_pct", compliance_pct),
            "met": met,
            "not_met": not_met,
            "manual": manual,
            "error_message": summary.get("error", None) if scan.status == "failed" else None,
        })

    return {"notifications": notifications, "total": len(notifications)}


# ---------------------------------------------------------------------------
# Demo report data — realistic mock findings for preview
# (MUST be defined before /{scan_id} routes to avoid path conflicts)
# ---------------------------------------------------------------------------

_DEMO_FINDINGS = [
    # AC — Access Control
    ("3.1.1", "Access Control", "AC", "ac-3.1.1-aws-001", "IAM users with console access have MFA enabled", "met", "high", "All 12 IAM users have MFA enabled", None),
    ("3.1.1", "Access Control", "AC", "ac-3.1.1-aws-002", "Root account has no access keys", "met", "critical", "Root account has 0 access keys", None),
    ("3.1.2", "Access Control", "AC", "ac-3.1.2-aws-001", "Least privilege IAM policies enforced", "not_met", "high", "Found 3 IAM policies with Action: * on Resource: *", "Remove wildcard permissions. Use specific actions and resources in IAM policies."),
    ("3.1.3", "Access Control", "AC", "ac-3.1.3-aws-001", "VPC flow logs monitor CUI data flows", "met", "high", "Flow logs enabled on all 4 VPCs", None),
    ("3.1.5", "Access Control", "AC", "ac-3.1.5-aws-001", "Separation of duties via IAM roles", "not_met", "medium", "2 users have both Admin and Developer roles", "Separate admin and developer access into distinct IAM roles."),
    ("3.1.7", "Access Control", "AC", "ac-3.1.7-aws-001", "Remote access sessions encrypted", "met", "high", "All SSH keys use RSA-4096 or Ed25519", None),
    ("3.1.12", "Access Control", "AC", "ac-3.1.12-aws-001", "Wireless access restricted", "manual", "medium", None, None),
    ("3.1.20", "Access Control", "AC", "ac-3.1.20-aws-001", "External connections verified", "met", "medium", "VPC peering limited to authorized accounts only", None),
    # AT — Awareness and Training
    ("3.2.1", "Awareness and Training", "AT", "at-3.2.1-manual", "Security awareness training program", "manual", "medium", None, None),
    ("3.2.2", "Awareness and Training", "AT", "at-3.2.2-manual", "Role-based security training", "manual", "medium", None, None),
    ("3.2.3", "Awareness and Training", "AT", "at-3.2.3-manual", "Insider threat awareness", "manual", "medium", None, None),
    # AU — Audit and Accountability
    ("3.3.1", "Audit and Accountability", "AU", "au-3.3.1-aws-001", "CloudTrail enabled in all regions", "met", "critical", "Multi-region trail active, logging to S3 with SSE-KMS", None),
    ("3.3.1", "Audit and Accountability", "AU", "au-3.3.1-aws-002", "CloudTrail log file validation enabled", "met", "high", "Log file validation enabled on all trails", None),
    ("3.3.2", "Audit and Accountability", "AU", "au-3.3.2-aws-001", "Audit records traceable to individual users", "met", "high", "CloudTrail events include userIdentity for all API calls", None),
    ("3.3.4", "Audit and Accountability", "AU", "au-3.3.4-aws-001", "CloudWatch alerts on audit failures", "not_met", "high", "No CloudWatch alarm configured for CloudTrail failures", "Create a CloudWatch alarm for CloudTrail log delivery failures."),
    ("3.3.5", "Audit and Accountability", "AU", "au-3.3.5-aws-001", "Audit log correlation capability", "met", "medium", "CloudTrail Lake enabled for cross-account log analysis", None),
    # CM — Configuration Management
    ("3.4.1", "Configuration Management", "CM", "cm-3.4.1-aws-001", "Baseline configurations documented", "met", "high", "AWS Config rules cover 47 resource types", None),
    ("3.4.2", "Configuration Management", "CM", "cm-3.4.2-aws-001", "Security configuration enforcement", "not_met", "high", "AWS Config found 8 non-compliant resources", "Remediate non-compliant resources flagged by AWS Config rules."),
    ("3.4.6", "Configuration Management", "CM", "cm-3.4.6-aws-001", "Least functionality enforced", "met", "medium", "Security groups block all unnecessary ports", None),
    # IA — Identification and Authentication
    ("3.5.1", "Identification and Authentication", "IA", "ia-3.5.1-aws-001", "System users uniquely identified", "met", "critical", "All 12 IAM users have unique identifiers, no shared accounts", None),
    ("3.5.2", "Identification and Authentication", "IA", "ia-3.5.2-aws-001", "Device identification for network access", "met", "high", "VPC endpoints enforce device-level TLS certificates", None),
    ("3.5.3", "Identification and Authentication", "IA", "ia-3.5.3-aws-001", "Multi-factor authentication", "not_met", "critical", "2 of 12 console users missing MFA", "Enable MFA for all IAM users with console access."),
    ("3.5.7", "Identification and Authentication", "IA", "ia-3.5.7-aws-001", "Password complexity enforced", "met", "high", "Password policy: min 14 chars, uppercase, lowercase, number, symbol", None),
    # IR — Incident Response
    ("3.6.1", "Incident Response", "IR", "ir-3.6.1-manual", "Incident response plan exists", "manual", "high", None, None),
    ("3.6.2", "Incident Response", "IR", "ir-3.6.2-aws-001", "Incident tracking and reporting", "met", "high", "GuardDuty active with SNS notifications configured", None),
    # MA — Maintenance
    ("3.7.1", "Maintenance", "MA", "ma-3.7.1-manual", "System maintenance performed", "manual", "medium", None, None),
    ("3.7.2", "Maintenance", "MA", "ma-3.7.2-manual", "Maintenance tools controlled", "manual", "medium", None, None),
    # MP — Media Protection
    ("3.8.1", "Media Protection", "MP", "mp-3.8.1-aws-001", "CUI media protected", "met", "high", "All S3 buckets have default AES-256 or KMS encryption", None),
    ("3.8.3", "Media Protection", "MP", "mp-3.8.3-aws-001", "CUI media sanitization", "manual", "medium", None, None),
    ("3.8.6", "Media Protection", "MP", "mp-3.8.6-aws-001", "Encryption at rest for CUI", "not_met", "critical", "2 of 15 EBS volumes not encrypted", "Enable default EBS encryption in all regions."),
    # PS — Personnel Security
    ("3.9.1", "Personnel Security", "PS", "ps-3.9.1-manual", "Personnel screening", "manual", "medium", None, None),
    ("3.9.2", "Personnel Security", "PS", "ps-3.9.2-manual", "CUI access termination procedures", "manual", "medium", None, None),
    # PE — Physical Protection
    ("3.10.1", "Physical Protection", "PE", "pe-3.10.1-manual", "Physical access limited to authorized individuals", "manual", "high", None, None),
    ("3.10.2", "Physical Protection", "PE", "pe-3.10.2-manual", "Physical access logs maintained", "manual", "medium", None, None),
    # RA — Risk Assessment
    ("3.11.1", "Risk Assessment", "RA", "ra-3.11.1-aws-001", "Periodic risk assessments", "met", "high", "Security Hub enabled with CIS AWS Foundations Benchmark", None),
    ("3.11.2", "Risk Assessment", "RA", "ra-3.11.2-aws-001", "Vulnerability scanning", "not_met", "high", "Inspector not enabled in us-gov-west-1", "Enable Amazon Inspector for vulnerability scanning in all regions."),
    # CA — Security Assessment
    ("3.12.1", "Security Assessment", "CA", "ca-3.12.1-manual", "Security controls assessed periodically", "manual", "high", None, None),
    ("3.12.4", "Security Assessment", "CA", "ca-3.12.4-aws-001", "POA&M managed for known deficiencies", "manual", "medium", None, None),
    # SC — System and Communications Protection
    ("3.13.1", "System and Communications Protection", "SC", "sc-3.13.1-aws-001", "Communications boundary monitoring", "met", "critical", "VPC flow logs and CloudTrail monitoring all network boundaries", None),
    ("3.13.5", "System and Communications Protection", "SC", "sc-3.13.5-aws-001", "Public access prevention for internal systems", "not_met", "critical", "3 security groups allow 0.0.0.0/0 inbound on port 22", "Restrict SSH access to specific CIDR ranges, remove 0.0.0.0/0."),
    ("3.13.8", "System and Communications Protection", "SC", "sc-3.13.8-aws-001", "CUI encrypted in transit", "met", "critical", "ALB enforces TLS 1.2+, all S3 buckets require HTTPS", None),
    ("3.13.11", "System and Communications Protection", "SC", "sc-3.13.11-aws-001", "FIPS-validated cryptography", "met", "high", "AWS GovCloud endpoints use FIPS 140-2 validated modules", None),
    ("3.13.16", "System and Communications Protection", "SC", "sc-3.13.16-aws-001", "CUI at rest encrypted", "met", "critical", "RDS instances use KMS encryption, S3 uses SSE-KMS", None),
    # SI — System and Information Integrity
    ("3.14.1", "System and Information Integrity", "SI", "si-3.14.1-aws-001", "Flaw remediation within defined timeframes", "not_met", "high", "14 SSM patches pending for 45+ days", "Apply pending SSM patches. Configure maintenance window for automated patching."),
    ("3.14.2", "System and Information Integrity", "SI", "si-3.14.2-aws-001", "Malicious code protection", "met", "high", "GuardDuty malware protection enabled across all accounts", None),
    ("3.14.3", "System and Information Integrity", "SI", "si-3.14.3-aws-001", "Security alerts and advisories monitored", "met", "medium", "Security Hub aggregates findings from GuardDuty, Inspector, Macie", None),
    ("3.14.6", "System and Information Integrity", "SI", "si-3.14.6-aws-001", "System monitoring for attacks", "met", "high", "GuardDuty threat detection active with CloudWatch integration", None),
    ("3.14.7", "System and Information Integrity", "SI", "si-3.14.7-aws-001", "Unauthorized access attempts identified", "met", "high", "CloudTrail Insights enabled for anomalous API detection", None),
]


def _build_demo_data():
    """Build mock client, scan, and findings objects for demo reports."""
    import json
    from pathlib import Path

    now = datetime.now(timezone.utc)
    client = SimpleNamespace(
        id="demo-client-001",
        name="Northrop Systems",
        environment="aws_govcloud",
        cmmc_level="L2",
    )
    scan = SimpleNamespace(
        id="demo-scan-001",
        client_id=client.id,
        status="completed",
        cmmc_level="L2",
        environment="aws_govcloud",
        started_at=now - timedelta(minutes=12),
        completed_at=now,
        summary={
            "total": len(_DEMO_FINDINGS),
            "met": sum(1 for f in _DEMO_FINDINGS if f[5] == "met"),
            "not_met": sum(1 for f in _DEMO_FINDINGS if f[5] == "not_met"),
            "manual": sum(1 for f in _DEMO_FINDINGS if f[5] == "manual"),
            "error": 0,
        },
        created_at=now,
    )

    # Load real objectives for demo coverage data
    practices_file = Path(__file__).resolve().parent.parent.parent.parent / "config" / "nist_practices.json"
    practice_objectives = {}
    try:
        with open(practices_file) as f:
            pdata = json.load(f)
        for fam in pdata.get("families", {}).values():
            for pid, pd in fam.get("practices", {}).items():
                practice_objectives[pid] = pd.get("objectives", {})
    except Exception:
        pass

    findings = []
    for i, row in enumerate(_DEMO_FINDINGS):
        practice_id = row[0]
        status = row[5]

        # Build realistic coverage data from real objectives
        objs = practice_objectives.get(practice_id, {})
        if objs:
            details = []
            covered = 0
            for key in sorted(objs.keys()):
                obj = objs[key]
                automatable = obj.get("automatable", False)
                if automatable is False:
                    obj_status = "documentation_required"
                    covered += 1
                elif status == "met":
                    obj_status = "met"
                    covered += 1
                elif status == "not_met":
                    obj_status = "not_met"
                    covered += 1
                elif status == "manual":
                    obj_status = "documentation_required"
                    covered += 1
                else:
                    obj_status = "not_tested"
                details.append({
                    "id": key,
                    "text": obj["text"],
                    "status": obj_status,
                    "source": "automated_check" if automatable is not False else "documentation",
                    "automatable": automatable,
                })
            total = len(objs)
            cov_pct = round(covered / total * 100, 1) if total > 0 else 0.0
            coverage = {
                "total_objectives": total,
                "covered_objectives": covered,
                "coverage_pct": cov_pct,
                "objective_details": details,
            }
        else:
            coverage = None

        findings.append(SimpleNamespace(
            id=f"demo-finding-{i:03d}",
            scan_id=scan.id,
            practice_id=practice_id,
            family=row[1],
            domain=row[2],
            check_id=row[3],
            check_name=row[4],
            status=status,
            severity=row[6],
            evidence=row[7],
            remediation=row[8],
            objective_coverage=coverage,
            created_at=now,
        ))
    return scan, findings, client


# ---------------------------------------------------------------------------
# GET /demo/html — Demo HTML report (no database needed)
# ---------------------------------------------------------------------------
@router.get("/demo/html", response_class=HTMLResponse)
def get_demo_html_report():
    """Generate a sample HTML report with realistic mock findings."""
    scan, findings, client = _build_demo_data()
    html = generate_html_report(scan, findings, client)
    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# GET /demo/xlsx — Demo XLSX report (no database needed)
# ---------------------------------------------------------------------------
@router.get("/demo/xlsx")
def get_demo_xlsx_report():
    """Generate a sample XLSX report with realistic mock findings."""
    scan, findings, client = _build_demo_data()
    xlsx_bytes = generate_xlsx_report(scan, findings, client)
    return Response(
        content=xlsx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="CMMC_Demo_Report_Northrop_Systems.xlsx"'},
    )


# ---------------------------------------------------------------------------
# GET /{scan_id}/html — HTML report (must be after /demo routes)
# ---------------------------------------------------------------------------
@router.get("/{scan_id}/html", response_class=HTMLResponse)
def get_html_report(scan_id: str, db: Session = Depends(get_db)):
    """Generate and return a self-contained HTML compliance report."""
    scan, findings, client = _load_scan_data(scan_id, db)
    html = generate_html_report(scan, findings, client)
    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# GET /{scan_id}/xlsx — XLSX report (must be after /demo routes)
# ---------------------------------------------------------------------------
@router.get("/{scan_id}/xlsx")
def get_xlsx_report(scan_id: str, db: Session = Depends(get_db)):
    """Generate and return an XLSX compliance report."""
    scan, findings, client = _load_scan_data(scan_id, db)
    xlsx_bytes = generate_xlsx_report(scan, findings, client)

    filename = f"CMMC_Compliance_Report_{client.name}_{scan_id[:8]}.xlsx"
    return Response(
        content=xlsx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
