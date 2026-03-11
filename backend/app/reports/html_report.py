"""
HTML Report Generator — Produces a self-contained, print-friendly HTML
compliance report with Securitybricks branding.

The report includes executive summary, per-domain breakdown with CSS bar
charts, detailed findings table, and remediation guidance.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from jinja2 import Template


# ---------------------------------------------------------------------------
# Color scheme constants
# ---------------------------------------------------------------------------
COLOR_MET = "#28a745"
COLOR_NOT_MET = "#dc3545"
COLOR_MANUAL = "#ffc107"
COLOR_ERROR = "#6c757d"
BRAND_NAVY = "#0D4F4F"
BRAND_BLUE = "#0E8585"
BRAND_LIGHT_BG = "#E8F5F5"


def generate_html_report(scan, findings, client) -> str:
    """
    Generate a self-contained HTML compliance report.

    Args:
        scan: Scan ORM object with id, fedramp_baseline, environment, started_at, completed_at, summary.
        findings: List of Finding ORM objects.
        client: Client ORM object with name, environment, fedramp_baseline.

    Returns:
        Complete HTML string with inline CSS and no external dependencies.
    """
    # Aggregate data
    status_counts = {"met": 0, "not_met": 0, "manual": 0, "error": 0}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    domain_data: dict[str, dict[str, Any]] = {}
    not_met_findings = []

    # Coverage aggregation
    total_objectives = 0
    covered_objectives = 0

    for f in findings:
        status_counts[f.status] = status_counts.get(f.status, 0) + 1
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        if f.domain not in domain_data:
            domain_data[f.domain] = {
                "name": f.family,
                "met": 0,
                "not_met": 0,
                "manual": 0,
                "error": 0,
                "total": 0,
                "total_objectives": 0,
                "covered_objectives": 0,
            }
        domain_data[f.domain][f.status] = domain_data[f.domain].get(f.status, 0) + 1
        domain_data[f.domain]["total"] += 1

        # Aggregate coverage
        cov = getattr(f, "objective_coverage", None) or {}
        if isinstance(cov, dict) and cov.get("total_objectives"):
            total_objectives += cov["total_objectives"]
            covered_objectives += cov["covered_objectives"]
            domain_data[f.domain]["total_objectives"] += cov["total_objectives"]
            domain_data[f.domain]["covered_objectives"] += cov["covered_objectives"]

        if f.status == "not_met":
            not_met_findings.append(f)

    total = sum(status_counts.values())
    compliance_pct = round((status_counts["met"] / total * 100), 1) if total > 0 else 0.0

    # Sort domains by code
    sorted_domains = sorted(domain_data.items(), key=lambda x: x[0])

    # Environment display names
    env_names = {
        "aws_commercial": "AWS Commercial",
        "aws_govcloud": "AWS GovCloud",
        "azure_commercial": "Azure Commercial",
        "azure_government": "Azure Government",
        "gcp_commercial": "GCP Commercial",
        "gcp_assured_workloads": "GCP Assured Workloads",
    }
    environment_display = env_names.get(client.environment, client.environment)

    # Format dates
    scan_date = scan.started_at.strftime("%B %d, %Y %H:%M UTC") if scan.started_at else "N/A"
    completed_date = scan.completed_at.strftime("%B %d, %Y %H:%M UTC") if scan.completed_at else "N/A"
    report_date = datetime.utcnow().strftime("%B %d, %Y %H:%M UTC")

    # Overall objective coverage
    overall_coverage_pct = round((covered_objectives / total_objectives * 100), 1) if total_objectives > 0 else 0.0

    template = Template(HTML_TEMPLATE)
    return template.render(
        client_name=client.name,
        environment=environment_display,
        fedramp_baseline=scan.fedramp_baseline,
        scan_id=scan.id,
        scan_date=scan_date,
        completed_date=completed_date,
        report_date=report_date,
        total=total,
        met=status_counts["met"],
        not_met=status_counts["not_met"],
        manual=status_counts["manual"],
        error=status_counts["error"],
        compliance_pct=compliance_pct,
        severity_critical=severity_counts["critical"],
        severity_high=severity_counts["high"],
        severity_medium=severity_counts["medium"],
        severity_low=severity_counts["low"],
        domains=sorted_domains,
        findings=findings,
        not_met_findings=not_met_findings,
        total_objectives=total_objectives,
        covered_objectives=covered_objectives,
        overall_coverage_pct=overall_coverage_pct,
        COLOR_MET=COLOR_MET,
        COLOR_NOT_MET=COLOR_NOT_MET,
        COLOR_MANUAL=COLOR_MANUAL,
        COLOR_ERROR=COLOR_ERROR,
        BRAND_NAVY=BRAND_NAVY,
        BRAND_BLUE=BRAND_BLUE,
        BRAND_LIGHT_BG=BRAND_LIGHT_BG,
    )


# ---------------------------------------------------------------------------
# HTML Template — self-contained with inline CSS
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FedRAMP Compliance Report - {{ client_name }}</title>
<style>
    /* Reset and base */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        color: #1A1A1A;
        line-height: 1.6;
        background: #f5f7fa;
        font-size: 11pt;
    }

    /* Print styles */
    @media print {
        body { background: white; font-size: 10pt; }
        .page-break { page-break-before: always; }
        .no-print { display: none !important; }
        .container { box-shadow: none; max-width: 100%; }
        table { page-break-inside: auto; }
        tr { page-break-inside: avoid; }
    }

    .container {
        max-width: 1100px;
        margin: 20px auto;
        background: white;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }

    /* Header */
    .report-header {
        background: {{ BRAND_NAVY }};
        color: white;
        padding: 30px 40px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .report-header h1 {
        font-size: 22pt;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .report-header .subtitle {
        font-size: 11pt;
        opacity: 0.9;
    }
    .report-header .brand {
        text-align: right;
        font-size: 14pt;
        font-weight: 700;
        letter-spacing: 1px;
    }
    .report-header .brand-sub {
        font-size: 9pt;
        opacity: 0.8;
        margin-top: 4px;
    }

    /* Content sections */
    .content { padding: 30px 40px; }
    h2 {
        font-size: 16pt;
        color: {{ BRAND_NAVY }};
        border-bottom: 2px solid {{ BRAND_BLUE }};
        padding-bottom: 8px;
        margin: 30px 0 16px 0;
    }
    h2:first-child { margin-top: 0; }
    h3 {
        font-size: 13pt;
        color: {{ BRAND_BLUE }};
        margin: 20px 0 10px 0;
    }

    /* Client info grid */
    .info-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 12px 30px;
        margin-bottom: 24px;
        background: {{ BRAND_LIGHT_BG }};
        padding: 16px 20px;
        border-radius: 6px;
    }
    .info-item { display: flex; gap: 8px; }
    .info-label { font-weight: 600; color: {{ BRAND_NAVY }}; min-width: 120px; }
    .info-value { color: #333; }

    /* Summary cards */
    .summary-cards {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 12px;
        margin-bottom: 24px;
    }
    .card {
        text-align: center;
        padding: 16px 8px;
        border-radius: 8px;
        color: white;
        font-weight: 600;
    }
    .card .count { font-size: 28pt; display: block; line-height: 1.2; }
    .card .label { font-size: 9pt; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.95; }
    .card-total { background: {{ BRAND_NAVY }}; }
    .card-met { background: {{ COLOR_MET }}; }
    .card-notmet { background: {{ COLOR_NOT_MET }}; }
    .card-manual { background: {{ COLOR_MANUAL }}; color: #333; }
    .card-error { background: {{ COLOR_ERROR }}; }

    /* Compliance gauge */
    .gauge-container {
        text-align: center;
        margin: 20px 0;
    }
    .gauge {
        display: inline-block;
        width: 160px;
        height: 160px;
        border-radius: 50%;
        background: conic-gradient(
            {{ COLOR_MET }} 0% {{ compliance_pct }}%,
            #e0e0e0 {{ compliance_pct }}% 100%
        );
        position: relative;
    }
    .gauge-inner {
        position: absolute;
        top: 15px; left: 15px; right: 15px; bottom: 15px;
        background: white;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-direction: column;
    }
    .gauge-pct { font-size: 28pt; font-weight: 700; color: {{ BRAND_NAVY }}; }
    .gauge-label { font-size: 9pt; color: #666; }

    /* Domain breakdown */
    .domain-table { width: 100%; border-collapse: collapse; margin: 16px 0; }
    .domain-table th {
        background: {{ BRAND_NAVY }};
        color: white;
        padding: 10px 14px;
        text-align: left;
        font-size: 10pt;
        font-weight: 600;
    }
    .domain-table td {
        padding: 10px 14px;
        border-bottom: 1px solid #e0e0e0;
        font-size: 10pt;
    }
    .domain-table tr:nth-child(even) td { background: {{ BRAND_LIGHT_BG }}; }
    .domain-table tr:hover td { background: #dce8f3; }

    /* Bar chart */
    .bar-container {
        display: flex;
        height: 20px;
        border-radius: 4px;
        overflow: hidden;
        background: #e0e0e0;
        min-width: 200px;
    }
    .bar-segment {
        height: 100%;
        transition: width 0.3s;
    }
    .bar-met { background: {{ COLOR_MET }}; }
    .bar-notmet { background: {{ COLOR_NOT_MET }}; }
    .bar-manual { background: {{ COLOR_MANUAL }}; }
    .bar-error { background: {{ COLOR_ERROR }}; }

    /* Findings table */
    .findings-table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 9.5pt; }
    .findings-table th {
        background: {{ BRAND_NAVY }};
        color: white;
        padding: 8px 10px;
        text-align: left;
        font-weight: 600;
        font-size: 9pt;
    }
    .findings-table td {
        padding: 8px 10px;
        border-bottom: 1px solid #e0e0e0;
        vertical-align: top;
    }
    .findings-table tr:nth-child(even) td { background: {{ BRAND_LIGHT_BG }}; }

    /* Status badges */
    .badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 8.5pt;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.3px;
    }
    .badge-met { background: {{ COLOR_MET }}; color: white; }
    .badge-not_met { background: {{ COLOR_NOT_MET }}; color: white; }
    .badge-manual { background: {{ COLOR_MANUAL }}; color: #333; }
    .badge-error { background: {{ COLOR_ERROR }}; color: white; }

    /* Severity badges */
    .sev-critical { color: {{ COLOR_NOT_MET }}; font-weight: 700; }
    .sev-high { color: #e67e22; font-weight: 600; }
    .sev-medium { color: {{ COLOR_MANUAL }}; font-weight: 600; }
    .sev-low { color: {{ COLOR_MET }}; font-weight: 600; }

    /* Remediation section */
    .remediation-item {
        background: #fff5f5;
        border-left: 4px solid {{ COLOR_NOT_MET }};
        padding: 12px 16px;
        margin: 10px 0;
        border-radius: 0 6px 6px 0;
    }
    .remediation-item h4 {
        color: {{ COLOR_NOT_MET }};
        font-size: 10pt;
        margin-bottom: 6px;
    }
    .remediation-item .evidence {
        font-size: 9pt;
        color: #666;
        margin-bottom: 6px;
        font-style: italic;
    }
    .remediation-item .fix {
        font-size: 9.5pt;
        color: #333;
    }

    /* Footer */
    .report-footer {
        background: {{ BRAND_LIGHT_BG }};
        padding: 16px 40px;
        text-align: center;
        font-size: 9pt;
        color: #666;
        border-top: 2px solid {{ BRAND_NAVY }};
    }

    /* Severity summary */
    .severity-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 10px;
        margin: 12px 0 20px 0;
    }
    .sev-card {
        text-align: center;
        padding: 10px;
        border-radius: 6px;
        border: 1px solid #e0e0e0;
    }
    .sev-card .count { font-size: 20pt; font-weight: 700; display: block; }
    .sev-card .label { font-size: 8pt; text-transform: uppercase; color: #666; }

    /* Objective coverage */
    .coverage-badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 10px;
        font-size: 8pt;
        font-weight: 600;
    }
    .cov-high { background: #d4edda; color: #155724; }
    .cov-medium { background: #fff3cd; color: #856404; }
    .cov-low { background: #f8d7da; color: #721c24; }
    .obj-table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 9pt; }
    .obj-table td { padding: 4px 8px; border-bottom: 1px solid #eee; }
    .obj-status-met { color: {{ COLOR_MET }}; font-weight: 600; }
    .obj-status-not_met { color: {{ COLOR_NOT_MET }}; font-weight: 600; }
    .obj-status-doc { color: {{ COLOR_MANUAL }}; font-weight: 600; }
    .obj-status-gap { color: {{ COLOR_ERROR }}; font-weight: 600; }
</style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <div class="report-header">
        <div>
            <h1>FedRAMP Compliance Report</h1>
            <div class="subtitle">Cloud Security Assessment Results</div>
        </div>
        <div>
            <div class="brand">SECURITYBRICKS</div>
            <div class="brand-sub">Cloud Compliance Solutions</div>
        </div>
    </div>

    <div class="content">

        <!-- Client Information -->
        <h2>Assessment Overview</h2>
        <div class="info-grid">
            <div class="info-item">
                <span class="info-label">Organization:</span>
                <span class="info-value">{{ client_name }}</span>
            </div>
            <div class="info-item">
                <span class="info-label">FedRAMP Baseline:</span>
                <span class="info-value">{{ fedramp_baseline }}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Environment:</span>
                <span class="info-value">{{ environment }}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Scan ID:</span>
                <span class="info-value" style="font-family: monospace; font-size: 9pt;">{{ scan_id[:8] }}...</span>
            </div>
            <div class="info-item">
                <span class="info-label">Scan Started:</span>
                <span class="info-value">{{ scan_date }}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Scan Completed:</span>
                <span class="info-value">{{ completed_date }}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Report Generated:</span>
                <span class="info-value">{{ report_date }}</span>
            </div>
        </div>

        <!-- Executive Summary -->
        <h2>Executive Summary</h2>
        <div class="summary-cards">
            <div class="card card-total">
                <span class="count">{{ total }}</span>
                <span class="label">Total Checks</span>
            </div>
            <div class="card card-met">
                <span class="count">{{ met }}</span>
                <span class="label">Met</span>
            </div>
            <div class="card card-notmet">
                <span class="count">{{ not_met }}</span>
                <span class="label">Not Met</span>
            </div>
            <div class="card card-manual">
                <span class="count">{{ manual }}</span>
                <span class="label">Manual Review</span>
            </div>
            <div class="card card-error">
                <span class="count">{{ error }}</span>
                <span class="label">Error</span>
            </div>
        </div>

        <div style="display: flex; justify-content: center; gap: 40px; flex-wrap: wrap;">
            <div class="gauge-container">
                <div class="gauge">
                    <div class="gauge-inner">
                        <span class="gauge-pct">{{ compliance_pct }}%</span>
                        <span class="gauge-label">Automated<br>Compliance</span>
                    </div>
                </div>
            </div>
            {% if total_objectives > 0 %}
            <div class="gauge-container">
                <div class="gauge" style="background: conic-gradient({{ BRAND_BLUE }} 0% {{ overall_coverage_pct }}%, #e0e0e0 {{ overall_coverage_pct }}% 100%);">
                    <div class="gauge-inner">
                        <span class="gauge-pct" style="font-size: 22pt;">{{ covered_objectives }}/{{ total_objectives }}</span>
                        <span class="gauge-label">800-53A<br>Objectives</span>
                    </div>
                </div>
            </div>
            {% endif %}
        </div>

        <h3>Findings by Severity</h3>
        <div class="severity-grid">
            <div class="sev-card">
                <span class="count sev-critical">{{ severity_critical }}</span>
                <span class="label">Critical</span>
            </div>
            <div class="sev-card">
                <span class="count sev-high">{{ severity_high }}</span>
                <span class="label">High</span>
            </div>
            <div class="sev-card">
                <span class="count sev-medium">{{ severity_medium }}</span>
                <span class="label">Medium</span>
            </div>
            <div class="sev-card">
                <span class="count sev-low">{{ severity_low }}</span>
                <span class="label">Low</span>
            </div>
        </div>

        <!-- Domain Breakdown -->
        <div class="page-break"></div>
        <h2>Per-Domain Breakdown</h2>
        <table class="domain-table">
            <thead>
                <tr>
                    <th style="width: 60px;">Domain</th>
                    <th>Family</th>
                    <th style="width: 50px;">Met</th>
                    <th style="width: 65px;">Not Met</th>
                    <th style="width: 60px;">Manual</th>
                    <th style="width: 50px;">Error</th>
                    <th style="width: 70px;">Rate</th>
                    <th style="width: 100px;">Obj. Coverage</th>
                    <th style="width: 180px;">Compliance Bar</th>
                </tr>
            </thead>
            <tbody>
                {% for code, data in domains %}
                {% set domain_total = data.met + data.not_met + data.manual + data.error %}
                {% set domain_pct = (data.met / domain_total * 100)|round(1) if domain_total > 0 else 0 %}
                {% set d_cov_pct = (data.covered_objectives / data.total_objectives * 100)|round(0)|int if data.total_objectives > 0 else 0 %}
                <tr>
                    <td><strong>{{ code }}</strong></td>
                    <td>{{ data.name }}</td>
                    <td style="color: {{ COLOR_MET }}; font-weight: 600;">{{ data.met }}</td>
                    <td style="color: {{ COLOR_NOT_MET }}; font-weight: 600;">{{ data.not_met }}</td>
                    <td style="color: #856404; font-weight: 600;">{{ data.manual }}</td>
                    <td style="color: {{ COLOR_ERROR }};">{{ data.error }}</td>
                    <td><strong>{{ domain_pct }}%</strong></td>
                    <td>
                        {% if data.total_objectives > 0 %}
                        <span class="coverage-badge {% if d_cov_pct >= 80 %}cov-high{% elif d_cov_pct >= 50 %}cov-medium{% else %}cov-low{% endif %}">
                            {{ data.covered_objectives }}/{{ data.total_objectives }} ({{ d_cov_pct }}%)
                        </span>
                        {% else %}&mdash;{% endif %}
                    </td>
                    <td>
                        <div class="bar-container">
                            {% if domain_total > 0 %}
                            <div class="bar-segment bar-met" style="width: {{ (data.met / domain_total * 100)|round(1) }}%;"></div>
                            <div class="bar-segment bar-notmet" style="width: {{ (data.not_met / domain_total * 100)|round(1) }}%;"></div>
                            <div class="bar-segment bar-manual" style="width: {{ (data.manual / domain_total * 100)|round(1) }}%;"></div>
                            <div class="bar-segment bar-error" style="width: {{ (data.error / domain_total * 100)|round(1) }}%;"></div>
                            {% endif %}
                        </div>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <!-- Detailed Findings -->
        <div class="page-break"></div>
        <h2>Detailed Findings</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th style="width: 60px;">Control ID</th>
                    <th style="width: 45px;">Domain</th>
                    <th>Check</th>
                    <th style="width: 70px;">Status</th>
                    <th style="width: 65px;">Severity</th>
                    <th style="width: 85px;">Obj. Coverage</th>
                    <th style="width: 25%;">Evidence</th>
                </tr>
            </thead>
            <tbody>
                {% for f in findings %}
                {% set cov = f.objective_coverage if f.objective_coverage else {} %}
                {% set f_cov_pct = (cov.covered_objectives / cov.total_objectives * 100)|round(0)|int if cov.get('total_objectives', 0) > 0 else 0 %}
                <tr>
                    <td style="font-family: monospace;">{{ f.control_id }}</td>
                    <td><strong>{{ f.domain }}</strong></td>
                    <td>{{ f.check_name }}</td>
                    <td><span class="badge badge-{{ f.status }}">{{ f.status|replace('_', ' ') }}</span></td>
                    <td><span class="sev-{{ f.severity }}">{{ f.severity|upper }}</span></td>
                    <td>
                        {% if cov.get('total_objectives', 0) > 0 %}
                        <span class="coverage-badge {% if f_cov_pct >= 80 %}cov-high{% elif f_cov_pct >= 50 %}cov-medium{% else %}cov-low{% endif %}">
                            {{ cov.covered_objectives }}/{{ cov.total_objectives }}
                        </span>
                        {% else %}&mdash;{% endif %}
                    </td>
                    <td style="font-size: 8.5pt; word-break: break-word;">{{ (f.evidence or '')[:500] }}{% if f.evidence and f.evidence|length > 500 %}...{% endif %}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <!-- Assessment Objective Coverage Detail -->
        {% set findings_with_coverage = [] %}
        {% for f in findings %}
            {% if f.objective_coverage and f.objective_coverage.get('total_objectives', 0) > 0 %}
                {% if findings_with_coverage.append(f) %}{% endif %}
            {% endif %}
        {% endfor %}
        {% if findings_with_coverage %}
        <div class="page-break"></div>
        <h2>NIST 800-53A Assessment Objective Coverage</h2>
        <p style="margin-bottom: 16px; color: #666;">
            Per-control breakdown of NIST SP 800-53A assessment objectives (the "determine if" statements
            that 3PAO assessors evaluate). Coverage shows which objectives are tested by automated checks,
            which require documentation evidence, and which have gaps.
        </p>
        {% for f in findings_with_coverage %}
        {% set cov = f.objective_coverage %}
        {% set f_cov_pct = (cov.covered_objectives / cov.total_objectives * 100)|round(0)|int if cov.total_objectives > 0 else 0 %}
        <div style="margin-bottom: 12px; border: 1px solid #e0e0e0; border-radius: 6px; overflow: hidden;">
            <div style="background: {{ BRAND_LIGHT_BG }}; padding: 8px 12px; display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <strong style="font-family: monospace;">{{ f.control_id }}</strong>
                    <span style="color: #666; margin-left: 8px;">{{ f.check_name[:80] }}</span>
                </div>
                <div>
                    <span class="badge badge-{{ f.status }}">{{ f.status|replace('_', ' ') }}</span>
                    <span class="coverage-badge {% if f_cov_pct >= 80 %}cov-high{% elif f_cov_pct >= 50 %}cov-medium{% else %}cov-low{% endif %}" style="margin-left: 8px;">
                        {{ cov.covered_objectives }}/{{ cov.total_objectives }} objectives ({{ f_cov_pct }}%)
                    </span>
                </div>
            </div>
            <table class="obj-table">
                {% for obj in cov.get('objective_details', []) %}
                <tr>
                    <td style="width: 40px; font-family: monospace; font-weight: 600;">{{ obj.id }}</td>
                    <td>{{ obj.text }}</td>
                    <td style="width: 120px; text-align: right;">
                        {% if obj.status == 'met' %}<span class="obj-status-met">MET</span>
                        {% elif obj.status == 'not_met' %}<span class="obj-status-not_met">NOT MET</span>
                        {% elif obj.status == 'documentation_required' %}<span class="obj-status-doc">DOC REQUIRED</span>
                        {% elif obj.status == 'not_tested' %}<span class="obj-status-gap">NOT TESTED</span>
                        {% elif obj.status == 'error' %}<span class="obj-status-gap">ERROR</span>
                        {% else %}<span class="obj-status-doc">{{ obj.status|upper }}</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endfor %}
        {% endif %}

        {% if not_met_findings %}
        <!-- Remediation Guidance -->
        <div class="page-break"></div>
        <h2>Remediation Guidance</h2>
        <p style="margin-bottom: 16px; color: #666;">
            The following findings require remediation to achieve FedRAMP {{ fedramp_baseline }} compliance.
            Items are ordered by severity.
        </p>
        {% for f in not_met_findings|sort(attribute='severity') %}
        <div class="remediation-item">
            <h4>[{{ f.control_id }}] {{ f.check_name }} ({{ f.severity|upper }})</h4>
            {% if f.evidence %}
            <div class="evidence">Evidence: {{ (f.evidence or '')[:500] }}{% if f.evidence and f.evidence|length > 500 %}...{% endif %}</div>
            {% endif %}
            {% if f.remediation %}
            <div class="fix"><strong>Remediation:</strong> {{ f.remediation }}</div>
            {% endif %}
        </div>
        {% endfor %}
        {% endif %}

    </div>

    <!-- Footer -->
    <div class="report-footer">
        <p>
            <strong>CONFIDENTIAL</strong> &mdash; This report was generated by Securitybricks FedRAMP Cloud Compliance Scanner v1.0.
            <br>
            Report Date: {{ report_date }} | Scan ID: {{ scan_id }}
            <br>
            This report is intended for authorized personnel only. Do not distribute without proper authorization.
        </p>
    </div>

</div>
</body>
</html>"""
