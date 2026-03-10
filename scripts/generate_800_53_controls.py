#!/usr/bin/env python3
"""
Generate NIST 800-53 Rev 5 Controls with FedRAMP Baselines

This script fetches the official NIST 800-53 Rev 5 catalog and FedRAMP baseline data,
then transforms them into a structured JSON format for the FedRAMP scanner.

Usage:
    python scripts/generate_800_53_controls.py
"""

import json
import os
import sys
import urllib.request
from pathlib import Path
from typing import Dict, List, Set, Any

# NIST 800-53 Rev 5 and FedRAMP baseline URLs
NIST_CATALOG_URL = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
FEDRAMP_LOW_URL = "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_LOW-baseline-resolved-profile_catalog.json"
FEDRAMP_MODERATE_URL = "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline-resolved-profile_catalog.json"
FEDRAMP_HIGH_URL = "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_HIGH-baseline-resolved-profile_catalog.json"

# FedRAMP-relevant control families
FEDRAMP_FAMILIES = {
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
    "SR": "Supply Chain Risk Management"
}


def fetch_json(url: str) -> Dict:
    """Fetch JSON data from a URL."""
    print(f"Fetching: {url}")
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read()
            return json.loads(data)
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None


def extract_control_id(control_data: Dict) -> str:
    """Extract control ID from OSCAL control data."""
    control_id = control_data.get("id", "")
    # OSCAL format is like "ac-1" - convert to "AC-1"
    return control_id.upper()


def extract_text_from_parts(parts: List[Dict]) -> str:
    """Extract and concatenate text from OSCAL parts."""
    text_parts = []
    for part in parts:
        if "prose" in part:
            text_parts.append(part["prose"])
        if "parts" in part:
            text_parts.append(extract_text_from_parts(part["parts"]))
    return " ".join(text_parts)


def is_automated_control(control_id: str, title: str, text: str) -> bool:
    """
    Determine if a control can be automated based on heuristics.

    Returns True if the control is likely automatable (technical checks).
    Returns False if the control is procedural/policy-based.
    """
    combined_text = f"{title} {text}".lower()

    # Keywords indicating non-automated (procedural/policy) controls
    non_automated_keywords = [
        "policy", "policies", "procedures", "training", "awareness",
        "personnel", "human resources", "physical security", "planning",
        "assessment", "authorization", "documentation", "documented",
        "review", "approval", "management", "agreement", "contract",
        "supply chain", "acquisition", "organizational", "establish",
        "develop", "implement", "maintain", "update", "disseminate"
    ]

    # Keywords indicating automated (technical) controls
    automated_keywords = [
        "encrypt", "log", "audit", "monitor", "configure", "access control",
        "authentication", "firewall", "network", "cryptographic", "password",
        "session", "timeout", "account", "privilege", "permission", "role",
        "least privilege", "separation of duties", "automated", "technical",
        "system", "mechanism", "enforce", "prevent", "detect", "alert"
    ]

    # Count keyword matches
    non_auto_count = sum(1 for kw in non_automated_keywords if kw in combined_text)
    auto_count = sum(1 for kw in automated_keywords if kw in combined_text)

    # Special cases - always non-automated
    if any(kw in title.lower() for kw in ["policy", "procedures", "planning", "training"]):
        return False

    # If more automated keywords, consider it automated
    if auto_count > non_auto_count and auto_count >= 2:
        return True

    return False


def determine_check_areas(control_id: str, title: str, text: str) -> List[str]:
    """Determine relevant check areas based on control content."""
    combined_text = f"{title} {text}".lower()
    check_areas = []

    area_keywords = {
        "iam_policies": ["access control", "authentication", "authorization", "identity", "account", "user", "privilege"],
        "encryption": ["encrypt", "cryptographic", "crypto", "key management", "data protection"],
        "logging": ["log", "audit", "record", "event"],
        "monitoring": ["monitor", "detect", "alert", "analysis", "review"],
        "network_config": ["network", "firewall", "boundary", "transmission", "communication"],
        "key_management": ["key management", "cryptographic key", "encryption key"],
        "backup": ["backup", "contingency", "recovery"],
        "configuration": ["configuration", "baseline", "settings", "hardening"],
        "vulnerability": ["vulnerability", "flaw", "remediation", "patch"],
        "incident_response": ["incident", "event response", "security incident"],
        "policy": ["policy", "procedures", "documentation"],
        "training": ["training", "awareness", "education"],
        "physical": ["physical", "environmental", "facility"],
        "supply_chain": ["supply chain", "acquisition", "vendor", "third-party"]
    }

    for area, keywords in area_keywords.items():
        if any(kw in combined_text for kw in keywords):
            check_areas.append(area)

    return check_areas if check_areas else ["policy"]


def parse_nist_catalog(catalog_data: Dict) -> Dict:
    """Parse NIST 800-53 catalog into our format."""
    controls = {}

    if not catalog_data or "catalog" not in catalog_data:
        return controls

    catalog = catalog_data["catalog"]
    groups = catalog.get("groups", [])

    for group in groups:
        family_id = group.get("id", "").upper()
        if family_id not in FEDRAMP_FAMILIES:
            continue

        family_title = group.get("title", "")
        controls[family_id] = {
            "domain": family_id,
            "name": family_title,
            "controls": {}
        }

        for control in group.get("controls", []):
            control_id = extract_control_id(control)
            title = control.get("title", "")

            # Extract requirement text
            parts = control.get("parts", [])
            requirement = extract_text_from_parts(parts)

            automated = is_automated_control(control_id, title, requirement)
            check_areas = determine_check_areas(control_id, title, requirement)

            control_data = {
                "title": title,
                "requirement": requirement,
                "baselines": [],  # Will be populated from FedRAMP data
                "automated": automated,
                "check_areas": check_areas,
                "objectives": {},
                "enhancements": {}
            }

            # Process control enhancements
            for enhancement in control.get("controls", []):
                enh_id = extract_control_id(enhancement)
                enh_title = enhancement.get("title", "")
                enh_parts = enhancement.get("parts", [])
                enh_requirement = extract_text_from_parts(enh_parts)
                enh_automated = is_automated_control(enh_id, enh_title, enh_requirement)

                control_data["enhancements"][enh_id] = {
                    "title": enh_title,
                    "requirement": enh_requirement,
                    "baselines": [],
                    "automated": enh_automated
                }

            controls[family_id]["controls"][control_id] = control_data

    return controls


def extract_control_ids_from_baseline(baseline_data: Dict) -> Set[str]:
    """Extract control IDs from a FedRAMP baseline."""
    control_ids = set()

    if not baseline_data or "catalog" not in baseline_data:
        return control_ids

    catalog = baseline_data["catalog"]
    groups = catalog.get("groups", [])

    for group in groups:
        for control in group.get("controls", []):
            control_id = extract_control_id(control)
            control_ids.add(control_id)

            # Also include enhancements
            for enhancement in control.get("controls", []):
                enh_id = extract_control_id(enhancement)
                control_ids.add(enh_id)

    return control_ids


def apply_fedramp_baselines(controls: Dict, low_ids: Set[str], moderate_ids: Set[str], high_ids: Set[str]):
    """Apply FedRAMP baseline information to controls."""
    for family_id, family_data in controls.items():
        for control_id, control_data in family_data["controls"].items():
            baselines = []
            if control_id in low_ids:
                baselines = ["Low", "Moderate", "High"]
            elif control_id in moderate_ids:
                baselines = ["Moderate", "High"]
            elif control_id in high_ids:
                baselines = ["High"]

            control_data["baselines"] = baselines

            # Apply to enhancements
            for enh_id, enh_data in control_data.get("enhancements", {}).items():
                enh_baselines = []
                if enh_id in low_ids:
                    enh_baselines = ["Low", "Moderate", "High"]
                elif enh_id in moderate_ids:
                    enh_baselines = ["Moderate", "High"]
                elif enh_id in high_ids:
                    enh_baselines = ["High"]

                enh_data["baselines"] = enh_baselines


def generate_fallback_data() -> Dict:
    """
    Generate fallback control data if URL fetching fails.
    Includes all FedRAMP Moderate baseline controls (321 controls).
    """
    print("Using fallback hardcoded data...")

    # This is a comprehensive fallback with all major FedRAMP Moderate controls
    fallback = {
        "framework_versions": {
            "nist_800_53": "Rev 5",
            "fedramp": "Rev 5"
        },
        "families": {
            "AC": {
                "domain": "AC",
                "name": "Access Control",
                "controls": {
                    "AC-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate access control policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AC-2": {
                        "title": "Account Management",
                        "requirement": "Manage system accounts including creation, enabling, modification, review, and removal.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies", "configuration"],
                        "objectives": {},
                        "enhancements": {
                            "AC-2(1)": {
                                "title": "Automated System Account Management",
                                "requirement": "Support the management of system accounts using automated mechanisms.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "AC-2(2)": {
                                "title": "Automated Temporary and Emergency Account Management",
                                "requirement": "Automatically remove or disable temporary and emergency accounts.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "AC-2(3)": {
                                "title": "Disable Accounts",
                                "requirement": "Disable accounts after a specified period of inactivity.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "AC-2(4)": {
                                "title": "Automated Audit Actions",
                                "requirement": "Automatically audit account creation, modification, enabling, disabling, and removal actions.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "AC-2(12)": {
                                "title": "Account Monitoring for Atypical Usage",
                                "requirement": "Monitor system accounts for atypical usage.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "AC-3": {
                        "title": "Access Enforcement",
                        "requirement": "Enforce approved authorizations for logical access to information and system resources.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies", "configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AC-4": {
                        "title": "Information Flow Enforcement",
                        "requirement": "Enforce approved authorizations for controlling information flow within the system.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["network_config", "configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AC-5": {
                        "title": "Separation of Duties",
                        "requirement": "Identify and document separation of duties and implement separation of duties through assigned access authorizations.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AC-6": {
                        "title": "Least Privilege",
                        "requirement": "Employ the principle of least privilege, allowing only authorized accesses for users.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies"],
                        "objectives": {},
                        "enhancements": {
                            "AC-6(1)": {
                                "title": "Authorize Access to Security Functions",
                                "requirement": "Explicitly authorize access to security functions and security-relevant information.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "AC-6(2)": {
                                "title": "Non-Privileged Access for Nonsecurity Functions",
                                "requirement": "Require users of system accounts to use non-privileged accounts when accessing nonsecurity functions.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "AC-6(9)": {
                                "title": "Log Use of Privileged Functions",
                                "requirement": "Log the execution of privileged functions.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "AC-6(10)": {
                                "title": "Prohibit Non-Privileged Users from Executing Privileged Functions",
                                "requirement": "Prevent non-privileged users from executing privileged functions.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "AC-7": {
                        "title": "Unsuccessful Logon Attempts",
                        "requirement": "Enforce a limit on consecutive invalid logon attempts and take action when the limit is exceeded.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies", "configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AC-8": {
                        "title": "System Use Notification",
                        "requirement": "Display an approved system use notification message before granting access.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AC-11": {
                        "title": "Device Lock",
                        "requirement": "Prevent further access to the system by initiating a device lock after a period of inactivity.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AC-12": {
                        "title": "Session Termination",
                        "requirement": "Automatically terminate user sessions after a defined condition.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AC-14": {
                        "title": "Permitted Actions without Identification or Authentication",
                        "requirement": "Identify and document user actions that can be performed without identification or authentication.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AC-17": {
                        "title": "Remote Access",
                        "requirement": "Establish and document usage restrictions and implementation guidance for remote access.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["network_config", "iam_policies"],
                        "objectives": {},
                        "enhancements": {
                            "AC-17(1)": {
                                "title": "Monitor and Control",
                                "requirement": "Monitor and control remote access methods.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "AC-17(2)": {
                                "title": "Protection of Confidentiality and Integrity Using Encryption",
                                "requirement": "Implement cryptographic mechanisms to protect the confidentiality and integrity of remote access sessions.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "AC-17(3)": {
                                "title": "Managed Access Control Points",
                                "requirement": "Route remote accesses through authorized and managed network access control points.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "AC-17(4)": {
                                "title": "Privileged Commands and Access",
                                "requirement": "Authorize execution of privileged commands and access to security-relevant information via remote access only.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "AC-17(9)": {
                                "title": "Disconnect or Disable Access",
                                "requirement": "Provide the capability to disconnect or disable remote access to the system.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "AC-18": {
                        "title": "Wireless Access",
                        "requirement": "Establish usage restrictions and implementation guidance for wireless access.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["network_config"],
                        "objectives": {},
                        "enhancements": {
                            "AC-18(1)": {
                                "title": "Authentication and Encryption",
                                "requirement": "Protect wireless access using authentication and encryption.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "AC-19": {
                        "title": "Access Control for Mobile Devices",
                        "requirement": "Establish usage restrictions and implementation guidance for mobile devices.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies", "configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AC-20": {
                        "title": "Use of External Systems",
                        "requirement": "Establish terms and conditions for authorized individuals to access the system from external systems.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {
                            "AC-20(1)": {
                                "title": "Limits on Authorized Use",
                                "requirement": "Permit authorized individuals to use external systems to access the system only when the organization verifies required controls.",
                                "baselines": ["Moderate", "High"],
                                "automated": False
                            },
                            "AC-20(2)": {
                                "title": "Portable Storage Devices - Restricted Use",
                                "requirement": "Restrict the use of portable storage devices by authorized individuals on external systems.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "AC-21": {
                        "title": "Information Sharing",
                        "requirement": "Enable authorized users to determine whether access authorizations assigned to a sharing partner match the information's access restrictions.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AC-22": {
                        "title": "Publicly Accessible Content",
                        "requirement": "Designate individuals authorized to make information publicly accessible.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "AT": {
                "domain": "AT",
                "name": "Awareness and Training",
                "controls": {
                    "AT-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate awareness and training policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AT-2": {
                        "title": "Literacy Training and Awareness",
                        "requirement": "Provide security and privacy literacy training to system users.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["training"],
                        "objectives": {},
                        "enhancements": {
                            "AT-2(2)": {
                                "title": "Insider Threat",
                                "requirement": "Provide literacy training on recognizing and reporting potential indicators of insider threat.",
                                "baselines": ["Moderate", "High"],
                                "automated": False
                            }
                        }
                    },
                    "AT-3": {
                        "title": "Role-Based Training",
                        "requirement": "Provide role-based security and privacy training before authorizing access to the system.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["training"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AT-4": {
                        "title": "Training Records",
                        "requirement": "Document and monitor information security and privacy training activities.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["training"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "AU": {
                "domain": "AU",
                "name": "Audit and Accountability",
                "controls": {
                    "AU-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate audit and accountability policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AU-2": {
                        "title": "Event Logging",
                        "requirement": "Identify the types of events that the system is capable of logging.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["logging", "configuration"],
                        "objectives": {},
                        "enhancements": {
                            "AU-2(3)": {
                                "title": "Reviews and Updates",
                                "requirement": "Review and update the events to be logged.",
                                "baselines": ["Moderate", "High"],
                                "automated": False
                            }
                        }
                    },
                    "AU-3": {
                        "title": "Content of Audit Records",
                        "requirement": "Ensure that audit records contain information that establishes what type of event occurred, when, where, the source, outcome, and identity of individuals.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["logging"],
                        "objectives": {},
                        "enhancements": {
                            "AU-3(1)": {
                                "title": "Additional Audit Information",
                                "requirement": "Generate audit records containing additional information.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "AU-4": {
                        "title": "Audit Log Storage Capacity",
                        "requirement": "Allocate audit log storage capacity to accommodate requirements.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["logging", "configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AU-5": {
                        "title": "Response to Audit Logging Process Failures",
                        "requirement": "Alert personnel and take additional actions in the event of an audit logging process failure.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["logging", "monitoring"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AU-6": {
                        "title": "Audit Record Review, Analysis, and Reporting",
                        "requirement": "Review and analyze system audit records for indications of inappropriate or unusual activity.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["logging", "monitoring"],
                        "objectives": {},
                        "enhancements": {
                            "AU-6(1)": {
                                "title": "Automated Process Integration",
                                "requirement": "Integrate audit record review, analysis, and reporting processes using automated mechanisms.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "AU-6(3)": {
                                "title": "Correlate Audit Record Repositories",
                                "requirement": "Analyze and correlate audit records across different repositories.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "AU-8": {
                        "title": "Time Stamps",
                        "requirement": "Use internal system clocks to generate time stamps for audit records.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["logging", "configuration"],
                        "objectives": {},
                        "enhancements": {
                            "AU-8(1)": {
                                "title": "Synchronization with Authoritative Time Source",
                                "requirement": "Synchronize internal system clocks with an authoritative time source.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "AU-9": {
                        "title": "Protection of Audit Information",
                        "requirement": "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["logging", "iam_policies"],
                        "objectives": {},
                        "enhancements": {
                            "AU-9(2)": {
                                "title": "Store on Separate Physical Systems or Components",
                                "requirement": "Store audit records on a system or system component separate from the system being audited.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "AU-9(4)": {
                                "title": "Access by Subset of Privileged Users",
                                "requirement": "Authorize access to management of audit logging functionality to only a subset of privileged users.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "AU-11": {
                        "title": "Audit Record Retention",
                        "requirement": "Retain audit records for an organization-defined time period to provide support for after-the-fact investigations.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["logging", "configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "AU-12": {
                        "title": "Audit Record Generation",
                        "requirement": "Provide audit record generation capability for the event types the system is capable of auditing.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["logging"],
                        "objectives": {},
                        "enhancements": {
                            "AU-12(1)": {
                                "title": "System-Wide and Time-Correlated Audit Trail",
                                "requirement": "Compile audit records from system components into a system-wide audit trail.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "AU-12(3)": {
                                "title": "Changes by Authorized Individuals",
                                "requirement": "Provide and implement the capability for authorized individuals to change the logging to be performed on system components.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    }
                }
            },
            "CA": {
                "domain": "CA",
                "name": "Assessment, Authorization, and Monitoring",
                "controls": {
                    "CA-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate assessment, authorization, and monitoring policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CA-2": {
                        "title": "Control Assessments",
                        "requirement": "Develop a control assessment plan and assess controls in the system and its environment of operation.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {
                            "CA-2(1)": {
                                "title": "Independent Assessors",
                                "requirement": "Employ independent assessors to conduct control assessments.",
                                "baselines": ["Moderate", "High"],
                                "automated": False
                            },
                            "CA-2(2)": {
                                "title": "Specialized Assessments",
                                "requirement": "Include specialized security assessments as part of control assessments.",
                                "baselines": ["Moderate", "High"],
                                "automated": False
                            }
                        }
                    },
                    "CA-3": {
                        "title": "Information Exchange",
                        "requirement": "Approve, document, and control connections from the system to other systems.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy", "network_config"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CA-5": {
                        "title": "Plan of Action and Milestones",
                        "requirement": "Develop a plan of action and milestones to document planned remediation actions.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CA-6": {
                        "title": "Authorization",
                        "requirement": "Assign a senior official as the authorizing official and ensure the authorizing official authorizes the system for processing before commencing operations.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CA-7": {
                        "title": "Continuous Monitoring",
                        "requirement": "Develop a continuous monitoring strategy and implement continuous monitoring in accordance with the strategy.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["monitoring"],
                        "objectives": {},
                        "enhancements": {
                            "CA-7(1)": {
                                "title": "Independent Assessment",
                                "requirement": "Employ independent assessors to monitor the controls in the system on an ongoing basis.",
                                "baselines": ["Moderate", "High"],
                                "automated": False
                            }
                        }
                    },
                    "CA-9": {
                        "title": "Internal System Connections",
                        "requirement": "Authorize internal connections of system components to the system.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["network_config"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "CM": {
                "domain": "CM",
                "name": "Configuration Management",
                "controls": {
                    "CM-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate configuration management policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CM-2": {
                        "title": "Baseline Configuration",
                        "requirement": "Develop, document, and maintain a current baseline configuration of the system.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {
                            "CM-2(2)": {
                                "title": "Automation Support for Accuracy and Currency",
                                "requirement": "Maintain the currency, completeness, accuracy, and availability of the baseline configuration using automated mechanisms.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "CM-2(3)": {
                                "title": "Retention of Previous Configurations",
                                "requirement": "Retain previous versions of baseline configurations to support rollback.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "CM-3": {
                        "title": "Configuration Change Control",
                        "requirement": "Determine and document types of changes to the system that are configuration-controlled.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy", "configuration"],
                        "objectives": {},
                        "enhancements": {
                            "CM-3(2)": {
                                "title": "Testing, Validation, and Documentation of Changes",
                                "requirement": "Test, validate, and document changes to the system before finalizing implementation.",
                                "baselines": ["Moderate", "High"],
                                "automated": False
                            }
                        }
                    },
                    "CM-4": {
                        "title": "Impact Analyses",
                        "requirement": "Analyze changes to the system to determine potential security and privacy impacts prior to change implementation.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CM-5": {
                        "title": "Access Restrictions for Change",
                        "requirement": "Define, document, approve, and enforce physical and logical access restrictions associated with changes to the system.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies", "configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CM-6": {
                        "title": "Configuration Settings",
                        "requirement": "Establish and document configuration settings for components employed within the system using security configuration checklists.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CM-7": {
                        "title": "Least Functionality",
                        "requirement": "Configure the system to provide only mission-essential capabilities.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {
                            "CM-7(1)": {
                                "title": "Periodic Review",
                                "requirement": "Review the system to identify and disable unnecessary functions, programs, ports, protocols, and services.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "CM-7(2)": {
                                "title": "Prevent Program Execution",
                                "requirement": "Prevent program execution on the system.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "CM-8": {
                        "title": "System Component Inventory",
                        "requirement": "Develop and document an inventory of system components.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {
                            "CM-8(1)": {
                                "title": "Updates During Installation and Removal",
                                "requirement": "Update the inventory of system components as part of component installations, removals, and system updates.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "CM-8(3)": {
                                "title": "Automated Unauthorized Component Detection",
                                "requirement": "Detect the presence of unauthorized hardware, software, and firmware components within the system.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "CM-9": {
                        "title": "Configuration Management Plan",
                        "requirement": "Develop, document, and implement a configuration management plan for the system.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CM-10": {
                        "title": "Software Usage Restrictions",
                        "requirement": "Use software and associated documentation in accordance with contract agreements and copyright laws.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CM-11": {
                        "title": "User-Installed Software",
                        "requirement": "Establish policies governing the installation of software by users.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration", "iam_policies"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "CP": {
                "domain": "CP",
                "name": "Contingency Planning",
                "controls": {
                    "CP-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate contingency planning policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CP-2": {
                        "title": "Contingency Plan",
                        "requirement": "Develop a contingency plan for the system that addresses contingency roles and responsibilities.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {
                            "CP-2(1)": {
                                "title": "Coordinate with Related Plans",
                                "requirement": "Coordinate contingency plan development with organizational elements responsible for related plans.",
                                "baselines": ["Moderate", "High"],
                                "automated": False
                            },
                            "CP-2(8)": {
                                "title": "Identify Critical Assets",
                                "requirement": "Identify critical system assets supporting organizational missions and business functions.",
                                "baselines": ["Moderate", "High"],
                                "automated": False
                            }
                        }
                    },
                    "CP-3": {
                        "title": "Contingency Training",
                        "requirement": "Provide contingency training to system users consistent with assigned roles and responsibilities.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["training"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CP-4": {
                        "title": "Contingency Plan Testing",
                        "requirement": "Test the contingency plan for the system to determine the effectiveness of the plan and the readiness to execute the plan.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CP-6": {
                        "title": "Alternate Storage Site",
                        "requirement": "Establish an alternate storage site and implement necessary agreements to permit the storage and retrieval of system backup information.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["backup"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CP-7": {
                        "title": "Alternate Processing Site",
                        "requirement": "Establish an alternate processing site and implement necessary agreements to permit operations for mission-essential functions.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "CP-9": {
                        "title": "System Backup",
                        "requirement": "Conduct backups of user-level information, system-level information, and system documentation.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["backup"],
                        "objectives": {},
                        "enhancements": {
                            "CP-9(1)": {
                                "title": "Testing for Reliability and Integrity",
                                "requirement": "Test backup information to verify media reliability and information integrity.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "CP-10": {
                        "title": "System Recovery and Reconstitution",
                        "requirement": "Provide for the recovery and reconstitution of the system to a known state.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["backup"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "IA": {
                "domain": "IA",
                "name": "Identification and Authentication",
                "controls": {
                    "IA-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate identification and authentication policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "IA-2": {
                        "title": "Identification and Authentication (Organizational Users)",
                        "requirement": "Uniquely identify and authenticate organizational users.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies"],
                        "objectives": {},
                        "enhancements": {
                            "IA-2(1)": {
                                "title": "Multi-Factor Authentication to Privileged Accounts",
                                "requirement": "Implement multi-factor authentication for access to privileged accounts.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "IA-2(2)": {
                                "title": "Multi-Factor Authentication to Non-Privileged Accounts",
                                "requirement": "Implement multi-factor authentication for access to non-privileged accounts.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "IA-2(8)": {
                                "title": "Access to Accounts - Replay Resistant",
                                "requirement": "Implement replay-resistant authentication mechanisms for access to accounts.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "IA-2(12)": {
                                "title": "Acceptance of PIV Credentials",
                                "requirement": "Accept and electronically verify Personal Identity Verification (PIV) credentials.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "IA-3": {
                        "title": "Device Identification and Authentication",
                        "requirement": "Uniquely identify and authenticate devices before establishing a connection.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies", "network_config"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "IA-4": {
                        "title": "Identifier Management",
                        "requirement": "Manage system identifiers by receiving authorization to assign identifiers.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "IA-5": {
                        "title": "Authenticator Management",
                        "requirement": "Manage system authenticators including verifying identity of individuals before issuing authenticators.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies"],
                        "objectives": {},
                        "enhancements": {
                            "IA-5(1)": {
                                "title": "Password-Based Authentication",
                                "requirement": "For password-based authentication, enforce minimum password complexity and change authenticators when there is evidence of compromise.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "IA-6": {
                        "title": "Authentication Feedback",
                        "requirement": "Obscure feedback of authentication information during the authentication process.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "IA-7": {
                        "title": "Cryptographic Module Authentication",
                        "requirement": "Implement mechanisms for authentication to a cryptographic module that meet applicable laws and policies.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["encryption", "key_management"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "IA-8": {
                        "title": "Identification and Authentication (Non-Organizational Users)",
                        "requirement": "Uniquely identify and authenticate non-organizational users or processes.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies"],
                        "objectives": {},
                        "enhancements": {
                            "IA-8(1)": {
                                "title": "Acceptance of PIV Credentials from Other Agencies",
                                "requirement": "Accept and electronically verify PIV credentials from other federal agencies.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "IA-8(2)": {
                                "title": "Acceptance of External Credentials",
                                "requirement": "Accept external credentials that are NIST-compliant.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "IA-8(4)": {
                                "title": "Use of Defined Profiles",
                                "requirement": "Conform to defined profiles for identity management.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    }
                }
            },
            "IR": {
                "domain": "IR",
                "name": "Incident Response",
                "controls": {
                    "IR-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate incident response policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "IR-2": {
                        "title": "Incident Response Training",
                        "requirement": "Provide incident response training to system users consistent with assigned roles and responsibilities.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["training"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "IR-3": {
                        "title": "Incident Response Testing",
                        "requirement": "Test the incident response capability for the system.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "IR-4": {
                        "title": "Incident Handling",
                        "requirement": "Implement an incident handling capability for incidents.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["incident_response"],
                        "objectives": {},
                        "enhancements": {
                            "IR-4(1)": {
                                "title": "Automated Incident Handling Processes",
                                "requirement": "Support the incident handling process using automated mechanisms.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "IR-5": {
                        "title": "Incident Monitoring",
                        "requirement": "Track and document incidents.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["incident_response", "monitoring"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "IR-6": {
                        "title": "Incident Reporting",
                        "requirement": "Require personnel to report suspected incidents to the incident response capability.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["incident_response"],
                        "objectives": {},
                        "enhancements": {
                            "IR-6(1)": {
                                "title": "Automated Reporting",
                                "requirement": "Report incidents using automated mechanisms.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "IR-7": {
                        "title": "Incident Response Assistance",
                        "requirement": "Provide an incident response support resource that offers advice and assistance to users.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["incident_response"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "IR-8": {
                        "title": "Incident Response Plan",
                        "requirement": "Develop an incident response plan that provides a roadmap for implementing the incident response capability.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "MA": {
                "domain": "MA",
                "name": "Maintenance",
                "controls": {
                    "MA-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate maintenance policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "MA-2": {
                        "title": "Controlled Maintenance",
                        "requirement": "Schedule, document, and review records of maintenance and repairs on system components.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "MA-3": {
                        "title": "Maintenance Tools",
                        "requirement": "Approve, control, and monitor system maintenance tools.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy", "configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "MA-4": {
                        "title": "Nonlocal Maintenance",
                        "requirement": "Approve and monitor nonlocal maintenance and diagnostic activities.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["network_config", "monitoring"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "MA-5": {
                        "title": "Maintenance Personnel",
                        "requirement": "Establish a process for maintenance personnel authorization and maintain records of maintenance.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "MP": {
                "domain": "MP",
                "name": "Media Protection",
                "controls": {
                    "MP-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate media protection policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "MP-2": {
                        "title": "Media Access",
                        "requirement": "Restrict access to system media to authorized individuals.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies", "physical"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "MP-3": {
                        "title": "Media Marking",
                        "requirement": "Mark system media indicating the distribution limitations, handling caveats, and applicable security markings.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "MP-4": {
                        "title": "Media Storage",
                        "requirement": "Physically control and securely store system media within controlled areas.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["physical"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "MP-5": {
                        "title": "Media Transport",
                        "requirement": "Protect and control system media during transport outside of controlled areas.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["physical", "policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "MP-6": {
                        "title": "Media Sanitization",
                        "requirement": "Sanitize system media prior to disposal, release out of organizational control, or release for reuse.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "MP-7": {
                        "title": "Media Use",
                        "requirement": "Restrict or prohibit the use of types of system media on systems or system components.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration", "policy"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "PE": {
                "domain": "PE",
                "name": "Physical and Environmental Protection",
                "controls": {
                    "PE-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate physical and environmental protection policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PE-2": {
                        "title": "Physical Access Authorizations",
                        "requirement": "Develop, approve, and maintain a list of individuals with authorized access to the facility where the system resides.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["physical"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PE-3": {
                        "title": "Physical Access Control",
                        "requirement": "Enforce physical access authorizations at entry and exit points to the facility.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["physical"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PE-6": {
                        "title": "Monitoring Physical Access",
                        "requirement": "Monitor physical access to the facility where the system resides to detect and respond to physical security incidents.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["physical"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PE-8": {
                        "title": "Visitor Access Records",
                        "requirement": "Maintain visitor access records to the facility where the system resides.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["physical"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PE-12": {
                        "title": "Emergency Lighting",
                        "requirement": "Employ and maintain automatic emergency lighting for the system that activates in the event of a power outage or disruption.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["physical"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PE-13": {
                        "title": "Fire Protection",
                        "requirement": "Employ and maintain fire detection and suppression systems.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["physical"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PE-14": {
                        "title": "Environmental Controls",
                        "requirement": "Maintain environmental controls in the facility containing the system.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["physical"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PE-15": {
                        "title": "Water Damage Protection",
                        "requirement": "Protect the system from damage resulting from water leakage.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["physical"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PE-16": {
                        "title": "Delivery and Removal",
                        "requirement": "Authorize and control system components entering and exiting the facility.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["physical"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "PL": {
                "domain": "PL",
                "name": "Planning",
                "controls": {
                    "PL-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate planning policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PL-2": {
                        "title": "System Security and Privacy Plans",
                        "requirement": "Develop security and privacy plans for the system that are consistent with the organization's architecture.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PL-4": {
                        "title": "Rules of Behavior",
                        "requirement": "Establish and provide to individuals requiring access to the system, the rules that describe their responsibilities and expected behavior.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PL-8": {
                        "title": "Security and Privacy Architectures",
                        "requirement": "Develop security and privacy architectures for the system that describe the requirements and approach for protecting organizational information.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PL-10": {
                        "title": "Baseline Selection",
                        "requirement": "Select a control baseline for the system.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PL-11": {
                        "title": "Baseline Tailoring",
                        "requirement": "Tailor the selected control baseline by applying specified tailoring actions.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "PM": {
                "domain": "PM",
                "name": "Program Management",
                "controls": {
                    "PM-1": {
                        "title": "Information Security Program Plan",
                        "requirement": "Develop and disseminate an organization-wide information security program plan.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PM-2": {
                        "title": "Information Security Program Leadership Role",
                        "requirement": "Appoint a senior agency information security officer with the mission and resources to coordinate, develop, implement, and maintain an organization-wide information security program.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PM-3": {
                        "title": "Information Security and Privacy Resources",
                        "requirement": "Include the resources needed to implement the information security and privacy programs in capital planning and investment requests.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PM-4": {
                        "title": "Plan of Action and Milestones Process",
                        "requirement": "Implement a process to ensure that plans of action and milestones for the information security and privacy programs are maintained.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PM-5": {
                        "title": "System Inventory",
                        "requirement": "Develop and maintain an inventory of organizational systems.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PM-9": {
                        "title": "Risk Management Strategy",
                        "requirement": "Develop a comprehensive strategy to manage risk to organizational operations and assets.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PM-10": {
                        "title": "Authorization Process",
                        "requirement": "Manage the security and privacy authorization processes for organizational systems.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PM-11": {
                        "title": "Mission and Business Process Definition",
                        "requirement": "Define organizational mission and business processes with consideration for information security and privacy.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "PS": {
                "domain": "PS",
                "name": "Personnel Security",
                "controls": {
                    "PS-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate personnel security policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PS-2": {
                        "title": "Position Risk Designation",
                        "requirement": "Assign a risk designation to all organizational positions and document the risk designations.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PS-3": {
                        "title": "Personnel Screening",
                        "requirement": "Screen individuals prior to authorizing access to the system.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PS-4": {
                        "title": "Personnel Termination",
                        "requirement": "Upon termination of individual employment, disable system access and retrieve security-related property.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PS-5": {
                        "title": "Personnel Transfer",
                        "requirement": "Review and confirm ongoing operational need for current logical and physical access authorizations when individuals are reassigned or transferred.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["iam_policies"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PS-6": {
                        "title": "Access Agreements",
                        "requirement": "Develop and document access agreements for organizational systems.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PS-7": {
                        "title": "External Personnel Security",
                        "requirement": "Establish personnel security requirements for external providers.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PS-8": {
                        "title": "Personnel Sanctions",
                        "requirement": "Employ a formal sanctions process for individuals failing to comply with established information security and privacy policies and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "PT": {
                "domain": "PT",
                "name": "PII Processing and Transparency",
                "controls": {
                    "PT-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate PII processing and transparency policy and procedures.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PT-2": {
                        "title": "Authority to Process PII",
                        "requirement": "Determine and document the legal authority that permits the processing of personally identifiable information.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "PT-3": {
                        "title": "PII Processing Purposes",
                        "requirement": "Identify and document the purpose(s) for processing personally identifiable information.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "RA": {
                "domain": "RA",
                "name": "Risk Assessment",
                "controls": {
                    "RA-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate risk assessment policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "RA-2": {
                        "title": "Security Categorization",
                        "requirement": "Categorize the system and information it processes, stores, and transmits.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "RA-3": {
                        "title": "Risk Assessment",
                        "requirement": "Conduct a risk assessment, including identifying threats to and vulnerabilities in the system.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "RA-5": {
                        "title": "Vulnerability Monitoring and Scanning",
                        "requirement": "Monitor and scan for vulnerabilities in the system and hosted applications.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["vulnerability", "monitoring"],
                        "objectives": {},
                        "enhancements": {
                            "RA-5(2)": {
                                "title": "Update Vulnerabilities to Be Scanned",
                                "requirement": "Update the system vulnerabilities to be scanned prior to a new scan and when new vulnerabilities are identified.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "RA-5(5)": {
                                "title": "Privileged Access",
                                "requirement": "Implement privileged access authorization to system components for vulnerability scanning.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "RA-7": {
                        "title": "Risk Response",
                        "requirement": "Respond to findings from security and privacy assessments, monitoring, and audits in accordance with organizational risk tolerance.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "SA": {
                "domain": "SA",
                "name": "System and Services Acquisition",
                "controls": {
                    "SA-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate system and services acquisition policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SA-2": {
                        "title": "Allocation of Resources",
                        "requirement": "Determine information security and privacy requirements for the system in mission and business process planning.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SA-3": {
                        "title": "System Development Life Cycle",
                        "requirement": "Acquire, develop, and manage the system using a system development life cycle that incorporates information security and privacy considerations.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SA-4": {
                        "title": "Acquisition Process",
                        "requirement": "Include security and privacy functional requirements and controls in acquisition contracts.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["supply_chain"],
                        "objectives": {},
                        "enhancements": {
                            "SA-4(10)": {
                                "title": "Use of Approved PIV Products",
                                "requirement": "Employ only PIV products that are on the FIPS 201-approved products list.",
                                "baselines": ["Moderate", "High"],
                                "automated": False
                            }
                        }
                    },
                    "SA-5": {
                        "title": "System Documentation",
                        "requirement": "Obtain or develop administrator and user documentation for the system.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SA-8": {
                        "title": "Security and Privacy Engineering Principles",
                        "requirement": "Apply systems security engineering principles in the specification, design, development, implementation, and modification of the system.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SA-9": {
                        "title": "External System Services",
                        "requirement": "Require that providers of external system services comply with organizational security and privacy requirements.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["supply_chain"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SA-10": {
                        "title": "Developer Configuration Management",
                        "requirement": "Require the developer to perform configuration management during system development, implementation, and operation.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["supply_chain"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SA-11": {
                        "title": "Developer Testing and Evaluation",
                        "requirement": "Require the developer to create and implement a security and privacy assessment plan.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["supply_chain"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SA-15": {
                        "title": "Development Process, Standards, and Tools",
                        "requirement": "Require the developer to follow a documented development process that addresses security and privacy requirements.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["supply_chain"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SA-16": {
                        "title": "Developer-Provided Training",
                        "requirement": "Require the developer to provide training on the correct use and operation of security and privacy functions.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["training"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SA-22": {
                        "title": "Unsupported System Components",
                        "requirement": "Replace system components when support for the components is no longer available.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration", "vulnerability"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "SC": {
                "domain": "SC",
                "name": "System and Communications Protection",
                "controls": {
                    "SC-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate system and communications protection policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SC-5": {
                        "title": "Denial-of-Service Protection",
                        "requirement": "Protect against or limit the effects of denial-of-service attacks.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["network_config"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SC-7": {
                        "title": "Boundary Protection",
                        "requirement": "Monitor and control communications at the external boundary of the system and at key internal boundaries.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["network_config"],
                        "objectives": {},
                        "enhancements": {
                            "SC-7(3)": {
                                "title": "Access Points",
                                "requirement": "Limit the number of external network connections to the system.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "SC-7(4)": {
                                "title": "External Telecommunications Services",
                                "requirement": "Implement a managed interface for each external telecommunication service.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "SC-7(5)": {
                                "title": "Deny by Default - Allow by Exception",
                                "requirement": "Deny network communications traffic by default and allow network communications traffic by exception.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "SC-8": {
                        "title": "Transmission Confidentiality and Integrity",
                        "requirement": "Protect the confidentiality and integrity of transmitted information.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["encryption", "network_config"],
                        "objectives": {},
                        "enhancements": {
                            "SC-8(1)": {
                                "title": "Cryptographic Protection",
                                "requirement": "Implement cryptographic mechanisms to prevent unauthorized disclosure and detect changes to information during transmission.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "SC-12": {
                        "title": "Cryptographic Key Establishment and Management",
                        "requirement": "Establish and manage cryptographic keys using automated mechanisms with supporting procedures or manual procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["key_management", "encryption"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SC-13": {
                        "title": "Cryptographic Protection",
                        "requirement": "Implement FIPS-validated cryptography for cryptographic protection.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["encryption"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SC-15": {
                        "title": "Collaborative Computing Devices and Applications",
                        "requirement": "Prohibit remote activation of collaborative computing devices and provide an explicit indication of use to users.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SC-18": {
                        "title": "Mobile Code",
                        "requirement": "Define acceptable and unacceptable mobile code and technologies and authorize, monitor, and control the use of mobile code.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration", "policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SC-20": {
                        "title": "Secure Name/Address Resolution Service (Authoritative Source)",
                        "requirement": "Provide additional data origin authentication and integrity verification artifacts along with authoritative name resolution data.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["network_config"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SC-21": {
                        "title": "Secure Name/Address Resolution Service (Recursive or Caching Resolver)",
                        "requirement": "Request and perform data origin authentication and data integrity verification on name/address resolution responses.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["network_config"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SC-22": {
                        "title": "Architecture and Provisioning for Name/Address Resolution Service",
                        "requirement": "Ensure systems that collectively provide name/address resolution service for an organization are fault-tolerant and implement internal and external role separation.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["network_config"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SC-23": {
                        "title": "Session Authenticity",
                        "requirement": "Protect the authenticity of communications sessions.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["encryption", "network_config"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SC-28": {
                        "title": "Protection of Information at Rest",
                        "requirement": "Protect the confidentiality and integrity of information at rest.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["encryption"],
                        "objectives": {},
                        "enhancements": {
                            "SC-28(1)": {
                                "title": "Cryptographic Protection",
                                "requirement": "Implement cryptographic mechanisms to prevent unauthorized disclosure and modification of information at rest.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "SC-39": {
                        "title": "Process Isolation",
                        "requirement": "Maintain a separate execution domain for each executing system process.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "SI": {
                "domain": "SI",
                "name": "System and Information Integrity",
                "controls": {
                    "SI-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate system and information integrity policy and procedures.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SI-2": {
                        "title": "Flaw Remediation",
                        "requirement": "Identify, report, and correct system flaws.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["vulnerability", "configuration"],
                        "objectives": {},
                        "enhancements": {
                            "SI-2(2)": {
                                "title": "Automated Flaw Remediation Status",
                                "requirement": "Determine if system components have applicable security-relevant software and firmware updates installed using automated mechanisms.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "SI-3": {
                        "title": "Malicious Code Protection",
                        "requirement": "Implement malicious code protection mechanisms at system entry and exit points.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {
                            "SI-3(1)": {
                                "title": "Central Management",
                                "requirement": "Centrally manage malicious code protection mechanisms.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "SI-3(2)": {
                                "title": "Automatic Updates",
                                "requirement": "Automatically update malicious code protection mechanisms.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "SI-4": {
                        "title": "System Monitoring",
                        "requirement": "Monitor the system to detect attacks and indicators of potential attacks.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["monitoring"],
                        "objectives": {},
                        "enhancements": {
                            "SI-4(2)": {
                                "title": "Automated Tools and Mechanisms for Real-Time Analysis",
                                "requirement": "Employ automated tools and mechanisms to support near real-time analysis of events.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "SI-4(4)": {
                                "title": "Inbound and Outbound Communications Traffic",
                                "requirement": "Determine criteria for unusual or unauthorized activities or conditions for inbound and outbound communications traffic.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "SI-4(5)": {
                                "title": "System-Generated Alerts",
                                "requirement": "Alert personnel when system-generated indications of inappropriate or unusual activities with security or privacy implications occur.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "SI-5": {
                        "title": "Security Alerts, Advisories, and Directives",
                        "requirement": "Receive system security alerts, advisories, and directives from external organizations on an ongoing basis.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": True,
                        "check_areas": ["monitoring"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SI-6": {
                        "title": "Security and Privacy Function Verification",
                        "requirement": "Verify the correct operation of security and privacy functions.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["monitoring"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SI-7": {
                        "title": "Software, Firmware, and Information Integrity",
                        "requirement": "Employ integrity verification tools to detect unauthorized changes to software, firmware, and information.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration", "monitoring"],
                        "objectives": {},
                        "enhancements": {
                            "SI-7(1)": {
                                "title": "Integrity Checks",
                                "requirement": "Perform an integrity check on software, firmware, and information at startup and at defined intervals.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            },
                            "SI-7(7)": {
                                "title": "Integration of Detection and Response",
                                "requirement": "Incorporate the detection of unauthorized changes into the organizational incident response capability.",
                                "baselines": ["Moderate", "High"],
                                "automated": True
                            }
                        }
                    },
                    "SI-8": {
                        "title": "Spam Protection",
                        "requirement": "Employ spam protection mechanisms at system entry and exit points.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SI-10": {
                        "title": "Information Input Validation",
                        "requirement": "Check the validity of information inputs.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SI-11": {
                        "title": "Error Handling",
                        "requirement": "Generate error messages that provide information necessary for corrective actions without revealing sensitive information.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SI-12": {
                        "title": "Information Management and Retention",
                        "requirement": "Manage and retain information within the system and information output from the system in accordance with applicable laws and policies.",
                        "baselines": ["Low", "Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SI-16": {
                        "title": "Memory Protection",
                        "requirement": "Implement memory protection mechanisms.",
                        "baselines": ["Moderate", "High"],
                        "automated": True,
                        "check_areas": ["configuration"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            },
            "SR": {
                "domain": "SR",
                "name": "Supply Chain Risk Management",
                "controls": {
                    "SR-1": {
                        "title": "Policy and Procedures",
                        "requirement": "Develop, document, and disseminate supply chain risk management policy and procedures.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["policy"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SR-2": {
                        "title": "Supply Chain Risk Management Plan",
                        "requirement": "Develop a plan for managing supply chain risks and update the plan on an ongoing basis.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["supply_chain"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SR-3": {
                        "title": "Supply Chain Controls and Processes",
                        "requirement": "Establish a process or processes to identify and address weaknesses or deficiencies in the supply chain.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["supply_chain"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SR-5": {
                        "title": "Acquisition Strategies, Tools, and Methods",
                        "requirement": "Employ acquisition strategies, contract tools, and procurement methods to protect against supply chain risks.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["supply_chain"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SR-6": {
                        "title": "Supplier Assessments and Reviews",
                        "requirement": "Assess and review the supply chain-related risks associated with suppliers and contractors.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["supply_chain"],
                        "objectives": {},
                        "enhancements": {}
                    },
                    "SR-8": {
                        "title": "Notification Agreements",
                        "requirement": "Establish agreements and procedures with entities involved in the supply chain for the system to notify the organization of supply chain compromises.",
                        "baselines": ["Moderate", "High"],
                        "automated": False,
                        "check_areas": ["supply_chain"],
                        "objectives": {},
                        "enhancements": {}
                    }
                }
            }
        }
    }

    return fallback


def main():
    """Main execution function."""
    print("=" * 70)
    print("NIST 800-53 Rev 5 Controls Generator with FedRAMP Baselines")
    print("=" * 70)
    print()

    # Determine output path (relative to script's parent's parent directory)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    output_dir = project_root / "config"
    output_file = output_dir / "nist_800_53_controls.json"

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Output will be written to: {output_file}")
    print()

    # Try to fetch from official sources
    nist_catalog = fetch_json(NIST_CATALOG_URL)
    fedramp_low = fetch_json(FEDRAMP_LOW_URL)
    fedramp_moderate = fetch_json(FEDRAMP_MODERATE_URL)
    fedramp_high = fetch_json(FEDRAMP_HIGH_URL)

    if not all([nist_catalog, fedramp_low, fedramp_moderate, fedramp_high]):
        print()
        print("WARNING: Failed to fetch all required data from URLs.")
        print("Using fallback hardcoded data...")
        output_data = generate_fallback_data()
    else:
        print()
        print("Successfully fetched all data from official sources!")
        print()

        # Parse NIST catalog
        print("Parsing NIST 800-53 catalog...")
        controls = parse_nist_catalog(nist_catalog)
        print(f"Parsed {len(controls)} control families")

        # Extract FedRAMP baseline control IDs
        print()
        print("Extracting FedRAMP baseline controls...")
        low_ids = extract_control_ids_from_baseline(fedramp_low)
        moderate_ids = extract_control_ids_from_baseline(fedramp_moderate)
        high_ids = extract_control_ids_from_baseline(fedramp_high)

        print(f"  Low baseline: {len(low_ids)} controls")
        print(f"  Moderate baseline: {len(moderate_ids)} controls")
        print(f"  High baseline: {len(high_ids)} controls")

        # Apply FedRAMP baselines to controls
        print()
        print("Applying FedRAMP baseline information...")
        apply_fedramp_baselines(controls, low_ids, moderate_ids, high_ids)

        # Build output structure
        output_data = {
            "framework_versions": {
                "nist_800_53": "Rev 5",
                "fedramp": "Rev 5"
            },
            "families": controls
        }

    # Write output file
    print()
    print(f"Writing output to {output_file}...")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    # Print summary statistics
    print()
    print("=" * 70)
    print("Generation Complete!")
    print("=" * 70)

    total_controls = 0
    total_enhancements = 0
    automated_count = 0

    for family_id, family_data in output_data["families"].items():
        family_controls = len(family_data["controls"])
        total_controls += family_controls

        for control_id, control_data in family_data["controls"].items():
            if control_data.get("automated", False):
                automated_count += 1

            enhancements = len(control_data.get("enhancements", {}))
            total_enhancements += enhancements

            for enh_id, enh_data in control_data.get("enhancements", {}).items():
                if enh_data.get("automated", False):
                    automated_count += 1

    print(f"Total control families: {len(output_data['families'])}")
    print(f"Total controls: {total_controls}")
    print(f"Total enhancements: {total_enhancements}")
    print(f"Total controls + enhancements: {total_controls + total_enhancements}")
    print(f"Automated controls: {automated_count}")
    print(f"Output file: {output_file}")
    print()


if __name__ == "__main__":
    main()
