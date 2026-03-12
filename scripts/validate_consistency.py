"""
Cross-validate all FedRAMP Scanner data sources for consistency.

Checks:
  1. Every control ID in config/checks/*.json exists in nist_800_53_controls.json
  2. Automated flags in master list match actual check implementations
  3. Methodology page counts match actual data
  4. QA validation page counts match actual data
  5. CLI check reference report counts match actual data
  6. No orphan checks (checks without master list entries)

Usage:
    python scripts/validate_consistency.py
"""
from __future__ import annotations

import json
import glob
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
FRONTEND_DIR = ROOT / "frontend" / "js"
REPORTS_DIR = ROOT / "reports"

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
WARN = "\033[93mWARN\033[0m"

errors = 0
warnings = 0


def check(condition: bool, msg: str, *, warn_only: bool = False):
    """Assert a condition, printing PASS/FAIL/WARN."""
    global errors, warnings
    if condition:
        print(f"  [{PASS}] {msg}")
    elif warn_only:
        warnings += 1
        print(f"  [{WARN}] {msg}")
    else:
        errors += 1
        print(f"  [{FAIL}] {msg}")


def dot_to_paren(dot_id: str) -> str:
    m = re.match(r'^([A-Z]{2}-\d+)\.(\d+)$', dot_id)
    if m:
        return f'{m.group(1)}({m.group(2)})'
    return dot_id


def paren_to_dot(paren_id: str) -> str:
    m = re.match(r'^([A-Z]{2}-\d+)\((\d+)\)$', paren_id)
    if m:
        return f'{m.group(1)}.{m.group(2)}'
    return paren_id


def is_enhancement(cid: str) -> bool:
    return bool(re.match(r'^[A-Z]{2}-\d+[\(.]', cid))


def find_family(cid: str) -> str | None:
    m = re.match(r'^([A-Z]{2})-', cid)
    return m.group(1) if m else None


def find_parent(cid: str) -> str | None:
    m = re.match(r'^([A-Z]{2}-\d+)', cid)
    return m.group(1) if m else None


def main():
    global errors, warnings

    # ---- Load data ----
    print("Loading data sources...")
    with open(CONFIG_DIR / "nist_800_53_controls.json") as f:
        master = json.load(f)

    all_checks = {}
    check_control_ids = {}  # cid -> {domain, aws, azure, gcp}
    for fpath in sorted(glob.glob(str(CONFIG_DIR / "checks" / "*.json"))):
        with open(fpath) as f:
            cdata = json.load(f)
        domain = cdata["domain"]
        all_checks[domain] = cdata
        for cid, cval in cdata.get("checks", {}).items():
            check_control_ids[cid] = {
                "domain": domain,
                "aws": len(cval.get("aws", [])),
                "azure": len(cval.get("azure", [])),
                "gcp": len(cval.get("gcp", [])),
            }

    total_aws = sum(v["aws"] for v in check_control_ids.values())
    total_azure = sum(v["azure"] for v in check_control_ids.values())
    total_gcp = sum(v["gcp"] for v in check_control_ids.values())

    print(f"  Check configs: {len(check_control_ids)} control IDs, "
          f"AWS={total_aws}, Azure={total_azure}, GCP={total_gcp}")

    # ---- Check 1: Every check config control exists in master ----
    print("\n[1] Check config control IDs exist in master list")
    orphans = []
    for cid in sorted(check_control_ids):
        family = find_family(cid)
        if not family or family not in master["families"]:
            orphans.append(cid)
            continue
        fam = master["families"][family]
        if is_enhancement(cid):
            dot_id = paren_to_dot(cid)
            parent = find_parent(cid)
            found = (parent in fam["controls"] and
                     dot_id in fam["controls"][parent].get("enhancements", {}))
        else:
            found = cid in fam["controls"]
        if not found:
            orphans.append(cid)

    check(len(orphans) == 0,
          f"All {len(check_control_ids)} check config control IDs found in master list"
          + (f" (missing: {orphans})" if orphans else ""))

    # ---- Check 2: Automated flags match check implementations ----
    print("\n[2] Automated flags match actual check implementations")
    check_ids_base = {c for c in check_control_ids if not is_enhancement(c)}
    check_ids_dot = {paren_to_dot(c) for c in check_control_ids}

    flag_mismatches_base = []
    flag_mismatches_enh = []

    for fam_id, fam in master["families"].items():
        for pid, p in fam["controls"].items():
            has_checks = pid in check_ids_base
            is_auto = p.get("automated", False)
            if has_checks != is_auto:
                flag_mismatches_base.append((pid, has_checks, is_auto))

            for eid, e in p.get("enhancements", {}).items():
                has_checks = eid in check_ids_dot
                is_auto = e.get("automated", False)
                if has_checks != is_auto:
                    flag_mismatches_enh.append((eid, has_checks, is_auto))

    check(len(flag_mismatches_base) == 0,
          f"All base control automated flags match check existence"
          + (f" (mismatches: {[m[0] for m in flag_mismatches_base]})" if flag_mismatches_base else ""))
    check(len(flag_mismatches_enh) == 0,
          f"All enhancement automated flags match check existence"
          + (f" (mismatches: {[m[0] for m in flag_mismatches_enh]})" if flag_mismatches_enh else ""))

    # ---- Check 3: Methodology page counts ----
    print("\n[3] Methodology page counts match actual data")
    methodology_path = FRONTEND_DIR / "methodology-data.js"
    if methodology_path.exists():
        with open(methodology_path) as f:
            mjs = f.read()
        mhtml = json.loads(mjs.split("window._methodologyHTML = ")[1].rstrip(";\n"))

        stats_pattern = r'<div class="help-stat-value">(\d+)</div>\s*<div class="help-stat-label">(.*?)</div>'
        stats = {label: int(val) for val, label in re.findall(stats_pattern, mhtml)}

        check(stats.get("AWS") == total_aws,
              f"Methodology AWS count: {stats.get('AWS')} == actual {total_aws}")
        check(stats.get("Azure") == total_azure,
              f"Methodology Azure count: {stats.get('Azure')} == actual {total_azure}")
        check(stats.get("GCP") == total_gcp,
              f"Methodology GCP count: {stats.get('GCP')} == actual {total_gcp}")
        check(stats.get("Controls") == 324,
              f"Methodology total controls: {stats.get('Controls')} == 324")
        check(stats.get("Automated", 0) + stats.get("Manual", 0) == 324,
              f"Methodology auto+manual = {stats.get('Automated', 0)}+{stats.get('Manual', 0)} == 324")
    else:
        check(False, "methodology-data.js exists")

    # ---- Check 4: QA validation page counts ----
    print("\n[4] QA validation page counts match actual data")
    qa_path = FRONTEND_DIR / "qa-validation-data.js"
    if qa_path.exists():
        with open(qa_path) as f:
            qjs = f.read()
        qhtml = json.loads(qjs.split("window._qaValidationHTML = ")[1].rstrip(";\n"))

        qa_stats_pattern = r'<div class="help-stat-value">(.*?)</div>\s*<div class="help-stat-label">(.*?)</div>'
        qa_stats = {label: val for val, label in re.findall(qa_stats_pattern, qhtml)}

        total_checks = total_aws + total_azure + total_gcp
        check(qa_stats.get("Cloud Checks") == str(total_checks),
              f"QA cloud checks: {qa_stats.get('Cloud Checks')} == actual {total_checks}")
        check(qa_stats.get("Errors") == "0",
              f"QA errors: {qa_stats.get('Errors')} == 0")
        check(qa_stats.get("Result") == "PASS",
              f"QA result: {qa_stats.get('Result')} == PASS")
    else:
        check(False, "qa-validation-data.js exists")

    # ---- Check 5: CLI check reference report counts ----
    print("\n[5] CLI check reference report counts")
    html_report = REPORTS_DIR / "fedramp_cli_check_reference.html"
    if html_report.exists():
        with open(html_report) as f:
            rhtml = f.read()
        # Extract counts from tab headers (format: AWS<span class="badge">203 Checks</span>)
        aws_match = re.search(r'AWS.*?(\d+)\s*Checks', rhtml)
        azure_match = re.search(r'(?:Azure|AZURE).*?(\d+)\s*Checks', rhtml)
        gcp_match = re.search(r'GCP.*?(\d+)\s*Checks', rhtml)

        if aws_match:
            check(int(aws_match.group(1)) == total_aws,
                  f"Report AWS count: {aws_match.group(1)} == actual {total_aws}")
        if azure_match:
            check(int(azure_match.group(1)) == total_azure,
                  f"Report Azure count: {azure_match.group(1)} == actual {total_azure}")
        if gcp_match:
            check(int(gcp_match.group(1)) == total_gcp,
                  f"Report GCP count: {gcp_match.group(1)} == actual {total_gcp}")
    else:
        check(False, "CLI check reference HTML report exists", warn_only=True)

    # ---- Check 6: Assessment methodology doc counts ----
    print("\n[6] Assessment methodology doc (docs/assessment-methodology.md)")
    doc_path = ROOT / "docs" / "assessment-methodology.md"
    if doc_path.exists():
        with open(doc_path) as f:
            doc_content = f.read()

        total_checks = total_aws + total_azure + total_gcp
        doc_total_match = re.search(r'Total Cloud-Specific Technical Checks \| (\d+)', doc_content)
        doc_aws_match = re.search(r'AWS Checks \| (\d+)', doc_content)
        doc_azure_match = re.search(r'Azure Checks \| (\d+)', doc_content)
        doc_gcp_match = re.search(r'GCP Checks \| (\d+)', doc_content)
        doc_auto_match = re.search(r'Controls with Automated Checks \| (\d+)', doc_content)
        doc_families_match = re.search(r'across all (\d+) FedRAMP control families', doc_content)

        if doc_total_match:
            check(int(doc_total_match.group(1)) == total_checks,
                  f"Doc total checks: {doc_total_match.group(1)} == actual {total_checks}")
        if doc_aws_match:
            check(int(doc_aws_match.group(1)) == total_aws,
                  f"Doc AWS checks: {doc_aws_match.group(1)} == actual {total_aws}")
        if doc_azure_match:
            check(int(doc_azure_match.group(1)) == total_azure,
                  f"Doc Azure checks: {doc_azure_match.group(1)} == actual {total_azure}")
        if doc_gcp_match:
            check(int(doc_gcp_match.group(1)) == total_gcp,
                  f"Doc GCP checks: {doc_gcp_match.group(1)} == actual {total_gcp}")
        if doc_auto_match:
            check(int(doc_auto_match.group(1)) == 93,
                  f"Doc automated controls: {doc_auto_match.group(1)} == 93")
        if doc_families_match:
            check(int(doc_families_match.group(1)) == 20,
                  f"Doc families count: {doc_families_match.group(1)} == 20")
    else:
        check(False, "assessment-methodology.md exists", warn_only=True)

    # ---- Check 7: README.md counts ----
    print("\n[7] README.md counts")
    readme_path = ROOT / "README.md"
    if readme_path.exists():
        with open(readme_path) as f:
            readme = f.read()

        readme_auto_match = re.search(r'\*\*(\d+) automated\*\*', readme)
        readme_manual_match = re.search(r'\*\*(\d+) manual\*\*', readme)
        readme_93_match = re.search(r'automates the evaluation of (\d+) of the (\d+)', readme)

        if readme_auto_match:
            check(int(readme_auto_match.group(1)) == 93,
                  f"README automated: {readme_auto_match.group(1)} == 93")
        if readme_manual_match:
            check(int(readme_manual_match.group(1)) == 231,
                  f"README manual: {readme_manual_match.group(1)} == 231")
        if readme_93_match:
            check(int(readme_93_match.group(1)) == 93,
                  f"README overview automated: {readme_93_match.group(1)} == 93")
    else:
        check(False, "README.md exists")

    # ---- Check 8: Provider parity for automated controls ----
    print("\n[8] Provider parity for automated controls")
    parity_issues = []
    for cid, counts in check_control_ids.items():
        providers = []
        if counts["aws"] > 0: providers.append("aws")
        if counts["azure"] > 0: providers.append("azure")
        if counts["gcp"] > 0: providers.append("gcp")
        if len(providers) < 3:
            missing = [p for p in ["aws", "azure", "gcp"] if p not in providers]
            parity_issues.append((cid, missing))

    check(len(parity_issues) == 0,
          f"All {len(check_control_ids)} automated controls have checks for all 3 CSPs"
          + (f" ({len(parity_issues)} controls missing providers)" if parity_issues else ""),
          warn_only=True)
    if parity_issues:
        for cid, missing in parity_issues[:5]:
            print(f"    {cid}: missing {', '.join(missing)}")
        if len(parity_issues) > 5:
            print(f"    ... and {len(parity_issues) - 5} more")

    # ---- Summary ----
    print(f"\n{'='*60}")
    print(f"Cross-Validation Summary")
    print(f"{'='*60}")
    print(f"  Check config controls: {len(check_control_ids)}")
    print(f"  AWS checks: {total_aws}")
    print(f"  Azure checks: {total_azure}")
    print(f"  GCP checks: {total_gcp}")
    print(f"  Total checks: {total_aws + total_azure + total_gcp}")
    print(f"  Errors: {errors}")
    print(f"  Warnings: {warnings}")
    print(f"  Result: {'PASS' if errors == 0 else 'FAIL'}")
    print(f"{'='*60}")

    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
