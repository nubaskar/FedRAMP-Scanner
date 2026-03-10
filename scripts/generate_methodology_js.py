"""
Generate the Assessment Methodology tab HTML content for help.js.

This script reads config files and produces a JavaScript function
that returns the HTML content for the Assessment Methodology tab
in the frontend Help blade.

Usage:
    cd FedRAMP-SCANNER
    python scripts/generate_methodology_js.py > /tmp/methodology_tab.js
"""
from __future__ import annotations

import json
import glob
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"


def _numeric_key(item):
    """Sort key for control/family IDs like '3.1.1' numerically, not lexicographically."""
    key = item[0] if isinstance(item, tuple) else item
    return [int(n) for n in key.split(".")]

def load_data():
    with open(CONFIG_DIR / "nist_800_53_controls.json") as f:
        pd = json.load(f)
    all_checks = {}
    for fpath in sorted(glob.glob(str(CONFIG_DIR / "checks" / "*.json"))):
        with open(fpath) as f:
            cdata = json.load(f)
        all_checks[cdata["domain"]] = cdata
    return pd, all_checks

def esc(s):
    """Escape for JS string inside single quotes."""
    return (s
        .replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", "\\n")
        .replace('"', '\\"')
    )

def esc_html(s):
    """Escape HTML entities."""
    return (s
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

def generate():
    pd, all_checks = load_data()

    # Compute all stats
    stats = {"total_controls": 0, "automated": 0, "manual": 0,
             "total_objectives": 0, "obj_true": 0, "obj_partial": 0, "obj_false": 0,
             "aws": 0, "azure": 0, "gcp": 0, "doc_reqs": 0}
    domain_stats = {}

    for fam_id, family in sorted(pd["families"].items(), key=_numeric_key):
        domain = family["domain"]
        name = family["name"]
        ds = {"name": name, "controls": 0, "automated": 0, "manual": 0,
              "objectives": 0, "aws": 0, "azure": 0, "gcp": 0}

        for pid, p in family["controls"].items():
            stats["total_controls"] += 1
            ds["controls"] += 1
            if p.get("automated", False):
                stats["automated"] += 1; ds["automated"] += 1
            else:
                stats["manual"] += 1; ds["manual"] += 1

            for obj in p.get("objectives", {}).values():
                stats["total_objectives"] += 1; ds["objectives"] += 1
                a = obj.get("automatable")
                if a is True: stats["obj_true"] += 1
                elif a == "partial": stats["obj_partial"] += 1
                else: stats["obj_false"] += 1

            if domain in all_checks and pid in all_checks[domain].get("checks", {}):
                pdata = all_checks[domain]["checks"][pid]
                for _ in pdata.get("aws", []): stats["aws"] += 1; ds["aws"] += 1
                for _ in pdata.get("azure", []): stats["azure"] += 1; ds["azure"] += 1
                for _ in pdata.get("gcp", []): stats["gcp"] += 1; ds["gcp"] += 1
                stats["doc_reqs"] += len(pdata.get("objectives_requiring_documentation", []))

        domain_stats[domain] = ds

    total_checks = stats["aws"] + stats["azure"] + stats["gcp"]

    # Build HTML parts
    parts = []
    a = parts.append

    # --- Hero Banner ---
    a('<div class="methodology-hero">')
    a('<div class="methodology-hero-inner">')
    a('<h2 class="methodology-hero-title">Assessment Methodology</h2>')
    a('<p class="methodology-hero-subtitle">')
    a("FedRAMP Cloud Compliance Scanner  - FedRAMP Assessor (3PAO) Reference")
    a('</p>')
    a('</div></div>')

    # --- Overview Card ---
    a('<div class="card mb-lg">')
    a('<div class="card-body">')
    a('<h3 class="help-section-title">How This Scanner Works</h3>')
    a('<p class="help-section-desc">')
    a("The FedRAMP Cloud Compliance Scanner evaluates CSP cloud environments against ")
    a("all 110 NIST SP 800-53 Rev 5 controls. For each control, the scanner maps its NIST SP 800-53A ")
    a("assessment objectives to cloud-specific API checks across AWS, Azure, and GCP.")
    a('</p>')
    a('<p class="help-section-desc">')
    a("This document explains <strong>how</strong> each control is evaluated, <strong>which</strong> cloud APIs are queried, ")
    a("<strong>why</strong> each check maps to specific assessment objectives, and <strong>what</strong> 3PAOs must do ")
    a("for the 39 controls that require manual review.")
    a('</p>')

    # Key stats grid
    a('<div class="help-stats-grid">')
    stat_items = [
        ("Controls", str(stats["total_controls"]), "NIST 800-53 Rev 5", "controls"),
        ("Objectives", str(stats["total_objectives"]), "NIST 800-53A", "objectives"),
        ("Automated", str(stats["automated"]), "controls", "automated"),
        ("Manual", str(stats["manual"]), "controls", "manual"),
        ("AWS", str(stats["aws"]), "checks", "aws"),
        ("Azure", str(stats["azure"]), "checks", "azure"),
        ("GCP", str(stats["gcp"]), "checks", "gcp"),
        ("Total", str(total_checks), "cloud checks", "total"),
    ]
    for label, value, sublabel, color_id in stat_items:
        a(f'<div class="help-stat-card" data-stat="{color_id}">'
          f'<div class="help-stat-value">{value}</div>'
          f'<div class="help-stat-label">{label}</div>'
          f'<div class="help-stat-sublabel">{sublabel}</div>'
          f'</div>')
    a('</div>')
    a('</div></div>')

    # --- Authoritative Sources ---
    a('<div class="card mb-lg">')
    a('<div class="card-body">')
    a('<h3 class="help-section-title">Authoritative Sources &amp; Traceability</h3>')
    a('<p class="help-section-desc">Every check in the scanner traces back through the following chain:</p>')
    a('<div class="help-traceability-chain">')
    chain_steps = [
        ("shield-alt", "FedRAMP Level", "L1 / L2 / L3 certification tier"),
        ("book", "NIST SP 800-53 Rev 5 Control", "One of 110 security requirements"),
        ("clipboard-check", "800-53A Assessment Objective", "Specific &ldquo;determine if&rdquo; statement"),
        ("search", "Scanner Check", "Cloud-specific configuration test"),
        ("cloud", "Cloud API Call", "Read-only query to AWS, Azure, or GCP"),
        ("check-circle", "Compliance Determination", "Met / Not Met / Manual Review"),
    ]
    for i, (icon, title, desc) in enumerate(chain_steps):
        a(f'<div class="help-chain-step" data-step="{i+1}">')
        a(f'<div class="help-chain-number">{i+1}</div>')
        a(f'<div class="help-chain-content">')
        a(f'<div class="help-chain-title">{title}</div>')
        a(f'<div class="help-chain-desc">{desc}</div>')
        a('</div>')
        a('</div>')
    a('</div>')

    # Source table
    a('<table class="data-table mt-md">')
    a('<thead><tr><th>Source</th><th>Version</th><th>Purpose</th><th>Reference</th></tr></thead>')
    a('<tbody>')
    for src, ver, purpose, url, url_label in [
        ("NIST SP 800-53 Rev 5", "Feb 2020", "110 security controls across 14 families",
         "https://csrc.nist.gov/publications/detail/sp/800-53 Rev 5/rev-2/final", "csrc.nist.gov"),
        ("NIST SP 800-53A", "Jun 2018", "319 assessment objectives (&quot;determine if&quot; statements)",
         "https://csrc.nist.gov/publications/detail/sp/800-53 Rev 5a/final", "csrc.nist.gov"),
        ("NIST SP 800-172", "Feb 2021", "Enhanced security controls for Level 3",
         "https://csrc.nist.gov/publications/detail/sp/800-172/final", "csrc.nist.gov"),
        ("FAR 52.204-21", "2016", "17 basic safeguarding controls for Level 1",
         "https://www.acquisition.gov/far/52.204-21", "acquisition.gov"),
        ("FedRAMP Model", "Dec 2021", "Three-level certification model",
         "https://dodcio.defense.gov/FedRAMP/", "dodcio.defense.gov"),
        ("AWS Config Rules", "Current", "~200 rules mapped to NIST 800-53 Rev 5",
         "https://docs.aws.amazon.com/config/latest/developerguide/operational-best-controls-for-nist_800-53 Rev 5.html", "docs.aws.amazon.com"),
        ("Azure Policy", "Current", "~200 policy definitions for NIST 800-53 Rev 5 R2",
         "https://learn.microsoft.com/en-us/azure/governance/policy/samples/nist-sp-800-53 Rev 5-r2", "learn.microsoft.com"),
        ("GCP CIS Benchmark", "Current", "GCP security controls aligned to NIST controls",
         "https://cloud.google.com/security/compliance/cis-benchmarks", "cloud.google.com"),
    ]:
        a(f'<tr><td><strong>{src}</strong></td><td>{ver}</td><td>{purpose}</td>'
          f'<td><a href="{url}" target="_blank" rel="noopener noreferrer">{url_label}</a></td></tr>')
    a('</tbody></table>')
    a('</div></div>')

    # --- Three-Tier Model ---
    a('<div class="card mb-lg">')
    a('<div class="card-body">')
    a('<h3 class="help-section-title">Three-Tier Evaluation Model</h3>')
    a('<p class="help-section-desc">Each of the 319 NIST SP 800-53A assessment objectives is classified into one of three tiers:</p>')
    a('<table class="data-table">')
    a('<thead><tr><th>Tier</th><th>Classification</th><th>Count</th><th>Scanner Handling</th></tr></thead>')
    a('<tbody>')
    a(f'<tr><td><span class="tag tag-met">Tier 1</span></td><td>Fully Automatable</td><td>{stats["obj_true"]}</td><td>Automated check provides definitive Met/Not Met</td></tr>')
    a(f'<tr><td><span class="tag tag-manual">Tier 2</span></td><td>Partially Automatable</td><td>{stats["obj_partial"]}</td><td>Check provides evidence; 3PAO verifies organizational context</td></tr>')
    a(f'<tr><td><span class="tag tag-not-met">Tier 3</span></td><td>Not Automatable</td><td>{stats["obj_false"]}</td><td>Flagged as Documentation Required; 3PAO assesses manually</td></tr>')
    a('</tbody></table>')
    a('</div></div>')

    # --- Coverage Matrix ---
    a('<div class="card mb-lg">')
    a('<div class="card-body">')
    a('<h3 class="help-section-title">Coverage Matrix by Domain</h3>')
    a('<p class="help-section-desc">')
    a("The table below shows the scanner's coverage across all 14 FedRAMP control families. Each domain is broken down by the number of ")
    a("NIST 800-53 Rev 5 controls, how many are automated vs. manual, the total 800-53A assessment objectives, and the cloud-specific ")
    a("checks implemented for each provider. The <strong>Automation Rate</strong> bar shows the percentage of controls in each domain ")
    a("that are fully automated by the scanner.")
    a('</p>')
    a('<div class="help-matrix-legend">')
    a('<span class="help-legend-item"><span class="help-legend-dot" style="background:#5B63D3"></span> Controls &amp; Objectives</span>')
    a('<span class="help-legend-item"><span class="help-legend-dot" style="background:#059669"></span> Automated</span>')
    a('<span class="help-legend-item"><span class="help-legend-dot" style="background:#D97706"></span> Manual</span>')
    a('<span class="help-legend-item"><span class="help-legend-dot" style="background:#FF9900"></span> AWS</span>')
    a('<span class="help-legend-item"><span class="help-legend-dot" style="background:#0078D4"></span> Azure</span>')
    a('<span class="help-legend-item"><span class="help-legend-dot" style="background:#34A853"></span> GCP</span>')
    a('</div>')
    a('<div class="table-container"><table class="data-table help-coverage-table">')
    a('<thead><tr><th>Domain</th><th>Name</th><th>Controls</th><th>Auto</th><th>Manual</th><th>Objectives</th><th>AWS</th><th>Azure</th><th>GCP</th><th>Automation Rate</th></tr></thead>')
    a('<tbody>')

    domain_order = ["AC", "AT", "AU", "CM", "IA", "IR", "MA", "MP", "PE", "PS", "RA", "CA", "SC", "SI"]
    for dc in domain_order:
        if dc in domain_stats:
            d = domain_stats[dc]
            auto_pct = round(d["automated"] * 100 / d["controls"]) if d["controls"] > 0 else 0
            # Color the bar based on automation percentage
            if auto_pct >= 75:
                bar_color = "#059669"
            elif auto_pct >= 40:
                bar_color = "#D97706"
            else:
                bar_color = "#E31B23"
            a(f'<tr>'
              f'<td><strong>{dc}</strong></td>'
              f'<td>{esc_html(d["name"])}</td>'
              f'<td class="cm-controls">{d["controls"]}</td>'
              f'<td class="cm-auto">{d["automated"]}</td>'
              f'<td class="cm-manual">{d["manual"]}</td>'
              f'<td class="cm-objectives">{d["objectives"]}</td>'
              f'<td class="cm-aws">{d["aws"]}</td>'
              f'<td class="cm-azure">{d["azure"]}</td>'
              f'<td class="cm-gcp">{d["gcp"]}</td>'
              f'<td class="cm-bar-cell">'
              f'<div class="cm-bar-wrap">'
              f'<div class="cm-bar" style="width:{auto_pct}%;background:{bar_color}"></div>'
              f'</div>'
              f'<span class="cm-bar-label">{auto_pct}%</span>'
              f'</td>'
              f'</tr>')

    # Total row
    total_auto_pct = round(stats["automated"] * 100 / stats["total_controls"]) if stats["total_controls"] > 0 else 0
    a(f'<tr class="table-total">'
      f'<td><strong>Total</strong></td><td></td>'
      f'<td class="cm-controls"><strong>{stats["total_controls"]}</strong></td>'
      f'<td class="cm-auto"><strong>{stats["automated"]}</strong></td>'
      f'<td class="cm-manual"><strong>{stats["manual"]}</strong></td>'
      f'<td class="cm-objectives"><strong>{stats["total_objectives"]}</strong></td>'
      f'<td class="cm-aws"><strong>{stats["aws"]}</strong></td>'
      f'<td class="cm-azure"><strong>{stats["azure"]}</strong></td>'
      f'<td class="cm-gcp"><strong>{stats["gcp"]}</strong></td>'
      f'<td class="cm-bar-cell"><strong>{total_auto_pct}%</strong></td>'
      f'</tr>')
    a('</tbody></table></div>')
    a('</div></div>')

    # --- Domain-by-Domain Reference (all 110 controls) ---
    a('<div class="card mb-lg">')
    a('<div class="card-body">')
    a('<h3 class="help-section-title">Complete Control Reference (All 110 Controls)</h3>')
    a('<p class="help-section-desc">')
    a('Expand each domain below to see all controls with their assessment objectives, automated checks, ')
    a('and cloud API details.')
    a('</p>')
    a('<div class="help-accordion">')

    for fam_id, family in sorted(pd["families"].items(), key=_numeric_key):
        domain = family["domain"]
        name = family["name"]
        ds = domain_stats[domain]
        controls = sorted(family["controls"].items(), key=_numeric_key)

        a('<div class="help-accordion-item">')
        a('<div class="help-accordion-header">')
        a('<svg class="help-accordion-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>')
        a(f'<span class="tag tag-domain">{domain}</span>')
        a(f'<span class="help-accordion-title">{esc_html(name)}  - {ds["controls"]} controls ({ds["automated"]} auto, {ds["manual"]} manual)</span>')
        a('</div>')
        a('<div class="help-accordion-body"><div class="help-accordion-body-inner">')

        for pid, p in controls:
            level = p.get("level", "L2")
            is_auto = p.get("automated", False)
            auto_tag = "auto" if is_auto else "manual-tag"
            auto_label = "Automated" if is_auto else "Manual"
            objs = p.get("objectives", {})

            a(f'<div class="help-control-card">')
            a(f'<h5 class="help-control-id">{pid} '
              f'<span class="tag tag-{level.lower()}">{level}</span> '
              f'<span class="tag tag-{auto_tag}">{auto_label}</span></h5>')
            a(f'<p class="help-control-req">{esc_html(p["requirement"])}</p>')

            # Objectives
            if objs:
                a('<details>')
                a(f'<summary>{len(objs)} Assessment Objectives</summary>')
                a('<table class="data-table help-compact-table">')
                a('<thead><tr><th>ID</th><th>Objective</th><th>Type</th></tr></thead>')
                a('<tbody>')
                for oid, obj in sorted(objs.items()):
                    aval = obj.get("automatable")
                    if aval is True: alabel = '<span class="tag tag-met">Auto</span>'
                    elif aval == "partial": alabel = '<span class="tag tag-manual">Partial</span>'
                    else: alabel = '<span class="tag tag-not-met">Manual</span>'
                    a(f'<tr><td>{pid}{oid}</td><td>{esc_html(obj["text"])}</td><td>{alabel}</td></tr>')
                a('</tbody></table>')
                a('</details>')

            # Checks
            if domain in all_checks and pid in all_checks[domain].get("checks", {}):
                pdata = all_checks[domain]["checks"][pid]
                has_checks = any(pdata.get(c) for c in ["aws", "azure", "gcp"])
                if has_checks:
                    check_count = sum(len(pdata.get(c, [])) for c in ["aws", "azure", "gcp"])
                    a('<details>')
                    a(f'<summary>{check_count} Cloud Checks (AWS / Azure / GCP)</summary>')
                    a('<table class="data-table help-compact-table">')
                    a('<thead><tr><th>Cloud</th><th>Check</th><th>Service</th><th>API Call</th><th>Severity</th><th>Objectives</th></tr></thead>')
                    a('<tbody>')
                    for cloud in ["aws", "azure", "gcp"]:
                        for c in pdata.get(cloud, []):
                            so = ", ".join(c.get("supports_objectives", []))
                            sev = c.get("severity", "")
                            sev_class = f"tag-{sev}" if sev in ("critical", "high", "medium", "low") else ""
                            a(f'<tr class="csp-{cloud}"><td>{cloud.upper()}</td><td>{esc_html(c["name"])}</td>'
                              f'<td>{esc_html(c.get("service", ""))}</td>'
                              f'<td><code>{esc_html(c.get("api_call", "N/A"))}</code></td>'
                              f'<td><span class="tag {sev_class}">{sev}</span></td>'
                              f'<td>{so}</td></tr>')
                    a('</tbody></table>')
                    a('</details>')

                # Doc requirements
                dreqs = pdata.get("objectives_requiring_documentation", [])
                if dreqs:
                    a('<details>')
                    a(f'<summary>{len(dreqs)} Documentation Requirements</summary>')
                    a('<ul class="help-doc-reqs">')
                    for dr in dreqs:
                        a(f'<li><strong>{pid}{dr["id"]}:</strong> {esc_html(dr.get("evidence_needed", "Documentation required"))}</li>')
                    a('</ul>')
                    a('</details>')

            # Manual guidance
            if not is_auto and p.get("manual_guidance"):
                a(f'<div class="help-info-box"><strong>3PAO Guidance:</strong> {esc_html(p["manual_guidance"])}</div>')

            a('</div>')  # control-card

        a('</div></div>')  # accordion body
        a('</div>')  # accordion item

    a('</div>')  # accordion
    a('</div></div>')  # card

    # --- 3PAO Manual Assessment Guide ---
    a('<div class="card mb-lg">')
    a('<div class="card-body">')
    a('<h3 class="help-section-title">3PAO Manual Assessment Guide</h3>')
    a('<p class="help-section-desc">')
    a(f'For the {stats["manual"]} controls requiring manual assessment, the scanner flags them as ')
    a('"Manual Review Required." The 3PAO must independently evaluate these using the guidance below. ')
    a('For each control, this guide provides the 800-53A objectives, assessment steps, and evidence artifacts to request.')
    a('</p>')
    a('<div class="help-accordion">')

    for fam_id, family in sorted(pd["families"].items(), key=_numeric_key):
        domain = family["domain"]
        name = family["name"]
        manual_controls = {
            pid: p for pid, p in sorted(family["controls"].items(), key=_numeric_key)
            if not p.get("automated", False)
        }
        if not manual_controls:
            continue

        a(f'<div class="help-accordion-item">')
        a(f'<div class="help-accordion-header">')
        a('<svg class="help-accordion-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>')
        a(f'<span class="tag tag-domain">{domain}</span>')
        a(f'<span class="help-accordion-title">{esc_html(name)} ({len(manual_controls)} manual controls)</span>')
        a('</div>')
        a('<div class="help-accordion-body"><div class="help-accordion-body-inner">')

        for pid, p in sorted(manual_controls.items(), key=_numeric_key):
            a(f'<div class="help-control-card">')
            a(f'<h5 class="help-control-id">{pid} <span class="tag tag-{p.get("level", "L2").lower()}">{p.get("level", "L2")}</span></h5>')
            a(f'<p class="help-control-req">{esc_html(p["requirement"])}</p>')

            # Assessment objectives
            objs = p.get("objectives", {})
            if objs:
                a('<div class="help-control-objectives">')
                a('<strong>Assessment Objectives:</strong>')
                a('<ul>')
                for oid, obj in sorted(objs.items()):
                    a(f'<li><strong>{pid}{oid}:</strong> Determine if {esc_html(obj["text"])}</li>')
                a('</ul>')
                a('</div>')

            # Assessment guidance
            mg = p.get("manual_guidance", "")
            if mg:
                a(f'<div class="help-info-box"><strong>3PAO Guidance:</strong> {esc_html(mg)}</div>')

            # Documentation requirements
            if domain in all_checks and pid in all_checks[domain].get("checks", {}):
                pdata = all_checks[domain]["checks"][pid]
                dreqs = pdata.get("objectives_requiring_documentation", [])
                if dreqs:
                    a('<div class="help-evidence-list">')
                    a('<strong>Evidence Artifacts to Request:</strong>')
                    a('<ul>')
                    for dr in dreqs:
                        a(f'<li><strong>{pid}{dr["id"]}:</strong> {esc_html(dr.get("evidence_needed", "Documentation required"))}</li>')
                    a('</ul>')
                    a('</div>')

                # Supporting automated checks
                has_supporting = any(pdata.get(c) for c in ["aws", "azure", "gcp"])
                if has_supporting:
                    a('<details class="help-supporting-checks">')
                    a('<summary>Supporting Automated Checks</summary>')
                    a('<table class="data-table help-compact-table">')
                    a('<thead><tr><th>Cloud</th><th>Check</th><th>API Call</th></tr></thead>')
                    a('<tbody>')
                    for cloud in ["aws", "azure", "gcp"]:
                        for c in pdata.get(cloud, []):
                            a(f'<tr class="csp-{cloud}"><td>{cloud.upper()}</td><td>{esc_html(c["name"])}</td><td><code>{esc_html(c.get("api_call", "N/A"))}</code></td></tr>')
                    a('</tbody></table>')
                    a('</details>')

            a('</div>')  # help-control-card

        a('</div></div>')  # accordion body
        a('</div>')  # accordion item

    a('</div>')  # accordion
    a('</div></div>')  # card

    # --- Document Info Footer ---
    a('<div class="card mb-lg">')
    a('<div class="card-body">')
    a('<h3 class="help-section-title">Document Information</h3>')
    a('<p class="help-section-desc">')
    a("This methodology reference is auto-generated from the scanner's configuration files ")
    a("(<code>config/nist_800_53_controls.json</code> and <code>config/checks/*.json</code>). ")
    a("All check definitions, objective mappings, and coverage data are derived directly from the scanner's authoritative data sources.")
    a('</p>')
    a('<p class="help-section-desc">')
    a("For offline distribution, this document is also available as ")
    a("<code>docs/assessment-methodology.md</code> (Markdown) and ")
    a("<code>docs/assessment-methodology.docx</code> (Word) in the project repository.")
    a('</p>')
    a('</div></div>')

    return "\n".join(parts)


if __name__ == "__main__":
    html = generate()
    # Write to file using JSON encoding for safe JS string escaping
    output = ROOT / "frontend" / "js" / "methodology-data.js"
    with open(output, "w") as f:
        f.write("/* Auto-generated from config files. Regenerate: python scripts/generate_methodology_js.py */\n")
        f.write("/* eslint-disable */\n")
        # json.dumps properly escapes all special chars for JS string literals
        f.write("window._methodologyHTML = ")
        f.write(json.dumps(html))
        f.write(";\n")

    print(f"Generated: {output}")
    print(f"HTML size: {len(html):,} characters")
