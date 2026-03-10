#!/usr/bin/env python3
"""
Transform check definition files from FedRAMP/NIST 800-53 Rev 5 format to FedRAMP/NIST 800-53 format.
"""

import json
import os
import re
from pathlib import Path
from collections import defaultdict

# Project root
PROJECT_ROOT = Path("/Users/udayabaskarnachimuthu/Library/CloudStorage/OneDrive-Securitybricks,Inc/Work/Architecture-Design/FedRAMP-SCANNER")

# Mapping from NIST 800-53 Rev 5 control IDs to NIST 800-53 control IDs
PRACTICE_TO_CONTROL = {
    # Access Control (3.1.x → AC-x)
    "3.1.1": "AC-2",       # Account Management
    "3.1.2": "AC-3",       # Access Enforcement
    "3.1.3": "AC-4",       # Information Flow Enforcement
    "3.1.4": "AC-5",       # Separation of Duties
    "3.1.5": "AC-6",       # Least Privilege
    "3.1.6": "AC-6(3)",    # Network Access to Non-privileged
    "3.1.7": "AC-2(9)",    # Restrictions on Use of Shared Accounts
    "3.1.8": "AC-7",       # Unsuccessful Logon Attempts
    "3.1.9": "AC-8",       # System Use Notification
    "3.1.10": "AC-11",     # Device Lock
    "3.1.11": "AC-12",     # Session Termination
    "3.1.12": "AC-17(1)",  # Monitoring and Control
    "3.1.13": "AC-17(2)",  # Protection of Confidentiality
    "3.1.14": "AC-17(3)",  # Managed Access Control Points
    "3.1.15": "AC-18",     # Wireless Access
    "3.1.16": "AC-19",     # Access Control for Mobile Devices
    "3.1.17": "AC-19(5)",  # Full Device Encryption
    "3.1.18": "AC-20",     # Use of External Systems
    "3.1.19": "AC-20(1)",  # Limits on Authorized Use
    "3.1.20": "AC-21",     # Information Sharing
    "3.1.21": "AC-3(8)",   # Revocation of Access
    "3.1.22": "AC-4(4)",   # Content Check Information Flows
    # Awareness and Training (3.2.x → AT-x)
    "3.2.1": "AT-2",       # Literacy Training and Awareness
    "3.2.2": "AT-3",       # Role-Based Training
    "3.2.3": "AT-2(2)",    # Insider Threat
    # Audit and Accountability (3.3.x → AU-x)
    "3.3.1": "AU-2",       # Event Logging
    "3.3.2": "AU-3",       # Content of Audit Records
    "3.3.3": "AU-3(1)",    # Additional Audit Information
    "3.3.4": "AU-5",       # Response to Audit Logging Failures
    "3.3.5": "AU-6",       # Audit Record Review
    "3.3.6": "AU-7",       # Audit Record Reduction
    "3.3.7": "AU-8",       # Time Stamps
    "3.3.8": "AU-9",       # Protection of Audit Information
    "3.3.9": "AU-9(4)",    # Access by Subset of Privileged Users
    # Configuration Management (3.4.x → CM-x)
    "3.4.1": "CM-2",       # Baseline Configuration
    "3.4.2": "CM-6",       # Configuration Settings
    "3.4.3": "CM-3",       # Configuration Change Control
    "3.4.4": "CM-3(4)",    # Security Representative
    "3.4.5": "CM-5",       # Access Restrictions for Change
    "3.4.6": "CM-7",       # Least Functionality
    "3.4.7": "CM-7(1)",    # Periodic Review
    "3.4.8": "CM-7(5)",    # Authorized Software
    "3.4.9": "CM-8",       # System Component Inventory
    # Identification and Authentication (3.5.x → IA-x)
    "3.5.1": "IA-2",       # Identification and Authentication
    "3.5.2": "IA-3",       # Device Identification
    "3.5.3": "IA-2(1)",    # Multi-Factor Authentication
    "3.5.4": "IA-2(2)",    # Non-Privileged MFA
    "3.5.5": "IA-4",       # Identifier Management
    "3.5.6": "IA-4(4)",    # Identify User Status
    "3.5.7": "IA-5",       # Authenticator Management
    "3.5.8": "IA-5(1)",    # Password-Based Authentication
    "3.5.9": "IA-5(2)",    # PKI-Based Authentication
    "3.5.10": "IA-8",      # Identification - Non-Org Users
    "3.5.11": "IA-11",     # Re-Authentication
    # Incident Response (3.6.x → IR-x)
    "3.6.1": "IR-2",       # Incident Response Training
    "3.6.2": "IR-4",       # Incident Handling
    "3.6.3": "IR-5",       # Incident Monitoring
    # Maintenance (3.7.x → MA-x)
    "3.7.1": "MA-2",       # Controlled Maintenance
    "3.7.2": "MA-3",       # Maintenance Tools
    "3.7.3": "MA-3(1)",    # Inspect Tools
    "3.7.4": "MA-3(2)",    # Inspect Media
    "3.7.5": "MA-4",       # Nonlocal Maintenance
    "3.7.6": "MA-5",       # Maintenance Personnel
    # Media Protection (3.8.x → MP-x)
    "3.8.1": "MP-2",       # Media Access
    "3.8.2": "MP-4",       # Media Storage
    "3.8.3": "MP-6",       # Media Sanitization
    "3.8.4": "MP-6(1)",    # Review/Approve/Track
    "3.8.5": "MP-3",       # Media Marking
    "3.8.6": "MP-5",       # Media Transport
    "3.8.7": "MP-7",       # Media Use
    "3.8.8": "MP-7(1)",    # Prohibit Use Without Owner
    "3.8.9": "MP-4(2)",    # Automated Restricted Access
    # Personnel Security (3.9.x → PS-x)
    "3.9.1": "PS-3",       # Personnel Screening
    "3.9.2": "PS-4",       # Personnel Termination
    # Physical Protection (3.10.x → PE-x)
    "3.10.1": "PE-2",      # Physical Access Authorizations
    "3.10.2": "PE-6",      # Monitoring Physical Access
    "3.10.3": "PE-3",      # Physical Access Control
    "3.10.4": "PE-5",      # Access Control for Output Devices
    "3.10.5": "PE-6(1)",   # Intrusion Alarms
    "3.10.6": "PE-17",     # Alternate Work Site
    # Risk Assessment (3.11.x → RA-x)
    "3.11.1": "RA-3",      # Risk Assessment
    "3.11.2": "RA-5",      # Vulnerability Monitoring and Scanning
    "3.11.3": "RA-5(5)",   # Privileged Access
    # Security Assessment (3.12.x → CA-x)
    "3.12.1": "CA-2",      # Control Assessments
    "3.12.2": "CA-5",      # Plan of Action and Milestones
    "3.12.3": "CA-7",      # Continuous Monitoring
    "3.12.4": "CA-5",      # Plan of Action and Milestones
    # System and Communications Protection (3.13.x → SC-x)
    "3.13.1": "SC-7",      # Boundary Protection
    "3.13.2": "SC-7(5)",   # Deny by Default
    "3.13.3": "SC-7(7)",   # Split Tunneling
    "3.13.4": "SC-7(8)",   # Route Traffic to Proxy
    "3.13.5": "SC-7(4)",   # External Connections
    "3.13.6": "SC-7(21)",  # Isolation of System Components
    "3.13.7": "SC-7(7)",   # Split Tunneling for Remote
    "3.13.8": "SC-8",      # Transmission Confidentiality
    "3.13.9": "SC-10",     # Network Disconnect
    "3.13.10": "SC-12",    # Cryptographic Key Establishment
    "3.13.11": "SC-13",    # Cryptographic Protection
    "3.13.12": "SC-15",    # Collaborative Computing
    "3.13.13": "SC-18",    # Mobile Code
    "3.13.14": "SC-28",    # Protection of Information at Rest
    "3.13.15": "SC-23",    # Session Authenticity
    "3.13.16": "SC-28(1)", # Cryptographic Protection at Rest
    # System and Information Integrity (3.14.x → SI-x)
    "3.14.1": "SI-2",      # Flaw Remediation
    "3.14.2": "SI-3",      # Malicious Code Protection
    "3.14.3": "SI-5",      # Security Alerts and Advisories
    "3.14.4": "SI-3(1)",   # Central Management
    "3.14.5": "SI-3(2)",   # Automatic Updates
    "3.14.6": "SI-4",      # System Monitoring
    "3.14.7": "SI-4(4)",   # Inbound and Outbound Traffic
}

# NIST 800-53 family names
FAMILY_NAMES = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "PII Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}


def load_nist_controls():
    """Load NIST 800-53 controls to get baselines."""
    controls_file = PROJECT_ROOT / "config" / "nist_800_53_controls.json"
    with open(controls_file, 'r') as f:
        data = json.load(f)

    # Build a mapping of control_id → baselines
    baselines_map = {}
    for family_code, family_data in data.get("families", {}).items():
        for control_id, control_data in family_data.get("controls", {}).items():
            baselines_map[control_id] = control_data.get("baselines", [])
            # Also handle enhancements
            for enh_id, enh_data in control_data.get("enhancements", {}).items():
                baselines_map[enh_id] = enh_data.get("baselines", [])

    return baselines_map


def transform_check_id(old_check_id, old_control_id, control_id):
    """
    Transform check_id from control-based to control-based format.
    Examples:
      ac-3.1.1-aws-001 → ac-2-aws-001
      au-3.3.1-aws-001 → au-2-aws-001
      ac-3.1.6-aws-001 → ac-6-3-aws-001 (for AC-6(3))
    """
    # Pattern: {domain}-{control_id}-{platform}-{seq}
    pattern = r'^([a-z]+)-(\d+\.\d+\.\d+)-([a-z]+)-(\d+)$'
    match = re.match(pattern, old_check_id)

    if not match:
        print(f"  WARNING: Could not parse check_id: {old_check_id}")
        return old_check_id

    domain, control, platform, seq = match.groups()

    # Convert control_id to check_id format
    # AC-2 → ac-2
    # AC-6(3) → ac-6-3
    control_lower = control_id.lower()
    if '(' in control_lower:
        # Handle enhancements: AC-6(3) → ac-6-3
        control_lower = control_lower.replace('(', '-').replace(')', '')

    new_check_id = f"{control_lower}-{platform}-{seq}"
    return new_check_id


def transform_check_definition(old_control_id, check_data, control_id, baselines):
    """Transform a single check definition from control format to control format."""
    transformed = {
        "cmmc_source": old_control_id,
        "baselines": baselines
    }

    # Process each platform
    for platform in ["aws", "azure", "gcp"]:
        if platform in check_data:
            transformed[platform] = []
            for check in check_data[platform]:
                new_check = check.copy()
                # Transform check_id
                old_check_id = check.get("check_id", "")
                new_check_id = transform_check_id(old_check_id, old_control_id, control_id)
                new_check["check_id"] = new_check_id
                # Add control_id field
                new_check["control_id"] = control_id
                transformed[platform].append(new_check)

    # Copy manual fields if present
    if check_data.get("manual_only"):
        transformed["manual_only"] = check_data["manual_only"]
    if check_data.get("manual_guidance"):
        transformed["manual_guidance"] = check_data["manual_guidance"]
    if check_data.get("evidence_requests"):
        transformed["evidence_requests"] = check_data["evidence_requests"]
    if check_data.get("objectives_requiring_documentation"):
        transformed["objectives_requiring_documentation"] = check_data["objectives_requiring_documentation"]

    return transformed


def transform_check_file(input_path, output_path, baselines_map):
    """Transform a single check file."""
    print(f"\nProcessing: {input_path.name}")

    with open(input_path, 'r') as f:
        data = json.load(f)

    domain = data.get("domain", "")

    # Update domain name if needed
    if domain in FAMILY_NAMES:
        data["name"] = FAMILY_NAMES[domain]

    old_checks = data.get("checks", {})
    new_checks = {}

    # Track mappings for multiple controls to same control
    control_to_controls = defaultdict(list)

    for control_id, check_data in old_checks.items():
        if control_id not in PRACTICE_TO_CONTROL:
            print(f"  WARNING: No mapping for control {control_id}, skipping")
            continue

        control_id = PRACTICE_TO_CONTROL[control_id]
        control_to_controls[control_id].append((control_id, check_data))

    # Transform checks
    stats = {
        "controls_mapped": 0,
        "controls_created": 0,
        "checks_transformed": 0,
        "controls_merged": 0
    }

    for control_id, controls in control_to_controls.items():
        baselines = baselines_map.get(control_id, [])

        if len(controls) == 1:
            # Single control maps to this control
            old_control_id, check_data = controls[0]
            new_checks[control_id] = transform_check_definition(
                old_control_id, check_data, control_id, baselines
            )
            stats["controls_mapped"] += 1
            stats["controls_created"] += 1

            # Count transformed checks
            for platform in ["aws", "azure", "gcp"]:
                if platform in check_data:
                    stats["checks_transformed"] += len(check_data[platform])
        else:
            # Multiple controls map to same control - merge them
            print(f"  INFO: Merging {len(controls)} controls into {control_id}")
            merged = {
                "cmmc_source": [p[0] for p in controls],
                "baselines": baselines
            }

            # Merge platform checks
            for platform in ["aws", "azure", "gcp"]:
                platform_checks = []
                for old_control_id, check_data in controls:
                    if platform in check_data:
                        for check in check_data[platform]:
                            new_check = check.copy()
                            old_check_id = check.get("check_id", "")
                            new_check_id = transform_check_id(old_check_id, old_control_id, control_id)
                            new_check["check_id"] = new_check_id
                            new_check["control_id"] = control_id
                            platform_checks.append(new_check)
                            stats["checks_transformed"] += 1

                if platform_checks:
                    merged[platform] = platform_checks

            # Merge manual fields (concatenate if multiple)
            manual_only_list = [check_data.get("manual_only") for _, check_data in controls if check_data.get("manual_only")]
            if manual_only_list:
                merged["manual_only"] = True

            manual_guidance_list = [check_data.get("manual_guidance") for _, check_data in controls if check_data.get("manual_guidance")]
            if manual_guidance_list:
                merged["manual_guidance"] = " | ".join(manual_guidance_list)

            evidence_requests_list = []
            for _, check_data in controls:
                if check_data.get("evidence_requests"):
                    evidence_requests_list.extend(check_data["evidence_requests"])
            if evidence_requests_list:
                merged["evidence_requests"] = evidence_requests_list

            objectives_list = []
            for _, check_data in controls:
                if check_data.get("objectives_requiring_documentation"):
                    objectives_list.extend(check_data["objectives_requiring_documentation"])
            if objectives_list:
                merged["objectives_requiring_documentation"] = objectives_list

            new_checks[control_id] = merged
            stats["controls_mapped"] += len(controls)
            stats["controls_created"] += 1
            stats["controls_merged"] += 1

    # Update the checks
    data["checks"] = new_checks

    # Write transformed file
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"  ✓ Transformed {stats['controls_mapped']} controls → {stats['controls_created']} controls")
    print(f"    - {stats['checks_transformed']} platform checks updated")
    if stats["controls_merged"] > 0:
        print(f"    - {stats['controls_merged']} controls merged from multiple controls")

    return stats


def transform_engine_file(engine_path):
    """Transform check_ids in engine.py CHECK_METHODS dicts."""
    print(f"\nProcessing: {engine_path.name}")

    with open(engine_path, 'r') as f:
        content = f.read()

    # Build a mapping of old check_id → new check_id
    check_id_map = {}
    for control_id, control_id in PRACTICE_TO_CONTROL.items():
        # Generate patterns for this mapping
        # e.g., ac-3.1.1 → ac-2
        domain = control_id.split('.')[0]  # "3" → won't work, need to extract from control
        domain_code = control_id.split('-')[0].lower()  # "AC-2" → "ac"

        # Old pattern: {domain}-3.X.Y
        old_pattern = f"{domain_code}-{control_id}"
        # New pattern: {domain}-{control_number}
        new_pattern = control_id.lower().replace('(', '-').replace(')', '')

        # Match all variants: aws, azure, gcp with any sequence number
        for platform in ["aws", "azure", "gcp"]:
            for seq in range(1, 100):  # Support up to 099 sequence numbers
                old_id = f"{old_pattern}-{platform}-{seq:03d}"
                new_id = f"{new_pattern}-{platform}-{seq:03d}"
                check_id_map[old_id] = new_id

    # Replace check_ids in content
    replacements = 0
    for old_id, new_id in check_id_map.items():
        if old_id in content:
            content = content.replace(f'"{old_id}"', f'"{new_id}"')
            replacements += 1

    # Write updated file
    with open(engine_path, 'w') as f:
        f.write(content)

    print(f"  ✓ Updated {replacements} check_id references")
    return replacements


def main():
    """Main transformation script."""
    print("=" * 80)
    print("NIST 800-53 Rev 5 → NIST 800-53 Check File Transformation")
    print("=" * 80)

    # Load baselines
    print("\nLoading NIST 800-53 control baselines...")
    baselines_map = load_nist_controls()
    print(f"  ✓ Loaded baselines for {len(baselines_map)} controls")

    # Get all check files
    checks_dir = PROJECT_ROOT / "config" / "checks"
    check_files = sorted(checks_dir.glob("*.json"))

    # Filter to only the 14 mapped domains
    mapped_domains = set()
    for control_id in PRACTICE_TO_CONTROL.keys():
        # Extract domain from control (3.1.x → AC, 3.2.x → AT, etc.)
        major = control_id.split('.')[1]
        domain_map = {
            "1": "ac", "2": "at", "3": "au", "4": "cm", "5": "ia",
            "6": "ir", "7": "ma", "8": "mp", "9": "ps", "10": "pe",
            "11": "ra", "12": "ca", "13": "sc", "14": "si"
        }
        if major in domain_map:
            mapped_domains.add(domain_map[major])

    check_files = [f for f in check_files if f.stem.lower() in mapped_domains]

    print(f"\nFound {len(check_files)} check files to transform:")
    for f in check_files:
        print(f"  - {f.name}")

    # Transform each file
    print("\n" + "=" * 80)
    print("Transforming check files...")
    print("=" * 80)

    total_stats = {
        "files_processed": 0,
        "controls_mapped": 0,
        "controls_created": 0,
        "checks_transformed": 0
    }

    for check_file in check_files:
        output_path = check_file  # Overwrite in place
        stats = transform_check_file(check_file, output_path, baselines_map)

        total_stats["files_processed"] += 1
        total_stats["controls_mapped"] += stats["controls_mapped"]
        total_stats["controls_created"] += stats["controls_created"]
        total_stats["checks_transformed"] += stats["checks_transformed"]

    # Transform engine.py
    print("\n" + "=" * 80)
    print("Updating engine.py CHECK_METHODS...")
    print("=" * 80)

    engine_path = PROJECT_ROOT / "backend" / "app" / "scanner" / "engine.py"
    if engine_path.exists():
        replacements = transform_engine_file(engine_path)
        total_stats["engine_replacements"] = replacements
    else:
        print(f"  WARNING: engine.py not found at {engine_path}")

    # Print summary
    print("\n" + "=" * 80)
    print("TRANSFORMATION COMPLETE")
    print("=" * 80)
    print(f"\nSummary:")
    print(f"  Files processed:       {total_stats['files_processed']}")
    print(f"  Controls mapped:      {total_stats['controls_mapped']}")
    print(f"  Controls created:      {total_stats['controls_created']}")
    print(f"  Platform checks:       {total_stats['checks_transformed']}")
    print(f"  Engine.py updates:     {total_stats.get('engine_replacements', 0)}")
    print(f"\nAll check files have been transformed to NIST 800-53 format.")
    print(f"Original files were overwritten in: {checks_dir}")


if __name__ == "__main__":
    main()
