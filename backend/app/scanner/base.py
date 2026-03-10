"""
Base scanner interface for cloud-specific compliance check implementations.

All cloud scanners (AWS, Azure, GCP) inherit from BaseScanner and implement
the connect(), run_check(), and disconnect() methods.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CheckResult:
    """Result of a single compliance check against a cloud environment."""

    check_id: str
    control_id: str
    check_name: str
    status: str      # "met", "not_met", "manual", "error"
    severity: str    # "critical", "high", "medium", "low"
    evidence: str = ""
    remediation: str = ""
    enhancement: str | None = None
    raw_evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "control_id": self.control_id,
            "check_name": self.check_name,
            "status": self.status,
            "severity": self.severity,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "enhancement": self.enhancement,
            "raw_evidence": self.raw_evidence,
        }


class BaseScanner:
    """
    Base class for cloud-specific scanners.

    Subclasses must implement connect() and run_check(). The engine
    instantiates the appropriate scanner, calls connect(), then iterates
    through check definitions calling run_check() for each.
    """

    def __init__(self, credentials: dict, environment: str, region: str = ""):
        self.credentials = credentials
        self.environment = environment
        self.region = region
        self._connected = False

    def connect(self) -> bool:
        """
        Establish connection to the cloud environment.

        Returns True if the connection was successful, False otherwise.
        Implementations should store SDK clients as instance attributes.
        """
        raise NotImplementedError("Subclasses must implement connect()")

    def run_check(self, check_def: dict) -> CheckResult:
        """
        Run a single compliance check and return the result.

        Args:
            check_def: Dictionary from config/checks/*.json containing:
                - check_id: Unique identifier (e.g., "ac-2-aws-001")
                - control_id: NIST 800-53 control (e.g., "AC-2")
                - check_name: Human-readable name
                - check_type: "automated" or "manual"
                - method: Name of the check method to call
                - severity: Default severity level
                - remediation: Default remediation guidance

        Returns:
            CheckResult with status, evidence, and remediation.
        """
        raise NotImplementedError("Subclasses must implement run_check()")

    def disconnect(self):
        """Clean up SDK clients and connections."""
        self._connected = False

    def _result(self, check_def: dict, status: str, evidence: str,
                raw_evidence: dict | None = None) -> CheckResult:
        """Create a CheckResult from check_def and assessment outcome."""
        return CheckResult(
            check_id=check_def["check_id"],
            control_id=check_def["control_id"],
            check_name=check_def["check_name"],
            status=status,
            severity=check_def["severity"],
            evidence=evidence,
            remediation="" if status == "met" else check_def.get("remediation", ""),
            raw_evidence=raw_evidence or {},
        )

    @property
    def is_connected(self) -> bool:
        return self._connected
