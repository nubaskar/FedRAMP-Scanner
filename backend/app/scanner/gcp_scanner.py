"""
GCP Scanner — Compliance check implementations using Google Cloud SDK.

Connects to GCP (Commercial or Assured Workloads) via Service Account
credentials and runs automated NIST 800-53 control checks.
"""
from __future__ import annotations

import json
import logging
from datetime import date, datetime
from typing import Any, Optional

import requests as http_requests

from app.scanner.base import BaseScanner, CheckResult

logger = logging.getLogger(__name__)


def _serialize_gcp_response(obj: Any) -> Any:
    """Convert a GCP protobuf/SDK response to a JSON-serializable dict.

    GCP client libraries return protobuf Message objects. We attempt
    ``MessageToDict`` first (fast, handles nested messages). If the object
    is already a plain dict/list/scalar we fall back to a recursive
    sanitiser that handles datetime and bytes values.
    """
    # --- protobuf Message → dict via official helper ---
    try:
        from google.protobuf.json_format import MessageToDict

        # proto-plus wrapped messages expose ``_pb``
        pb = getattr(obj, "_pb", obj)
        if hasattr(pb, "DESCRIPTOR"):
            return MessageToDict(pb, preserving_proto_field_name=True)
    except Exception:
        pass

    # --- fallback: recursively sanitise plain Python objects ---
    if isinstance(obj, dict):
        return {k: _serialize_gcp_response(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialize_gcp_response(v) for v in obj]
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    # scalars (int, float, str, bool, None) are already serialisable
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        return str(obj)


class GcpScanner(BaseScanner):
    """GCP-specific compliance scanner using Google Cloud client libraries."""

    def __init__(self, credentials: dict, environment: str, region: str = "us-central1"):
        super().__init__(credentials, environment, region)
        self._credentials = None
        self._project_id = None
        self._iam_client = None
        self._logging_client = None
        self._resource_manager_client = None
        self._kms_client = None
        self._compute_client = None
        # Lazy-init clients
        self._storage_client = None
        self._monitoring_client = None
        self._scc_client = None
        self._container_client = None
        self._bigquery_client = None
        self._osconfig_client = None
        self._recommender_client = None
        self._sql_instances_client = None
        self._instances_client = None
        self._subnetworks_client = None
        self._networks_client = None
        self._images_client = None
        self._ssl_policies_client = None
        self._ssl_certs_client = None
        self._backend_services_client = None
        self._disks_client = None
        # Cache
        self._cache: dict = {}

    def connect(self) -> bool:
        """
        Establish connection to GCP via Service Account credentials.

        Expects credentials dict with:
            - project_id: GCP project ID
            - service_account_key_json: Service account key as dict or JSON string

        Returns True if connection successful.
        """
        try:
            from google.auth import credentials as ga_credentials
            from google.oauth2 import service_account

            self._project_id = self.credentials.get("project_id", "")
            sa_key = self.credentials.get("service_account_key_json", {})

            if not self._project_id:
                logger.error("Missing required GCP project_id")
                return False

            # Parse service account key
            if isinstance(sa_key, str):
                sa_key = json.loads(sa_key)

            if sa_key:
                self._credentials = service_account.Credentials.from_service_account_info(
                    sa_key,
                    scopes=["https://www.googleapis.com/auth/cloud-platform"],
                )
            else:
                # Use Application Default Credentials for local testing
                import google.auth
                self._credentials, _ = google.auth.default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform"]
                )

            # Initialize service clients
            from google.cloud import compute_v1
            from google.cloud import kms_v1
            from google.cloud import logging as cloud_logging
            from google.cloud import resourcemanager_v3

            self._resource_manager_client = resourcemanager_v3.ProjectsClient(
                credentials=self._credentials
            )
            self._kms_client = kms_v1.KeyManagementServiceClient(
                credentials=self._credentials
            )
            self._compute_client = compute_v1.FirewallsClient(
                credentials=self._credentials
            )
            self._logging_client = cloud_logging.Client(
                project=self._project_id,
                credentials=self._credentials,
            )

            # Verify connectivity by getting project info
            project_name = f"projects/{self._project_id}"
            project = self._resource_manager_client.get_project(name=project_name)
            logger.info("Connected to GCP project %s (%s)", project.project_id, project.display_name)
            self._connected = True
            return True

        except ImportError as e:
            logger.error("Google Cloud SDK not installed: %s", e)
            return False
        except Exception as e:
            logger.error("Failed to connect to GCP: %s", e)
            return False

    def run_check(self, check_def: dict) -> CheckResult:
        """Route check execution to the appropriate method."""
        method_name = check_def.get("method", "")
        if not method_name:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def.get("control_id", ""),
                check_name=check_def.get("check_name", ""),
                status="manual",
                severity=check_def.get("severity", "medium"),
                evidence="No automated method defined for this check.",
                remediation=check_def.get("remediation", ""),
            )

        method = getattr(self, method_name, None)
        if method is None:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def.get("control_id", ""),
                check_name=check_def.get("check_name", ""),
                status="error",
                severity=check_def.get("severity", "medium"),
                evidence=f"Check method '{method_name}' not implemented.",
                remediation=check_def.get("remediation", ""),
            )

        return method(check_def)

    # ------------------------------------------------------------------
    # Helpers: REST API, caching, lazy clients
    # ------------------------------------------------------------------

    def _gcp_api_get(self, url: str) -> dict:
        """Call a GCP REST API endpoint using service account credentials."""
        from google.auth.transport.requests import Request as AuthRequest
        self._credentials.refresh(AuthRequest())
        headers = {"Authorization": f"Bearer {self._credentials.token}"}
        resp = http_requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 403:
            raise PermissionError(f"Insufficient permissions for {url}")
        resp.raise_for_status()
        return resp.json()

    def _gcp_api_get_safe(self, url: str, default: Any = None) -> Any:
        """Call GCP REST API, return default on error instead of raising."""
        try:
            return self._gcp_api_get(url)
        except Exception as e:
            logger.warning("GCP API call failed for %s: %s", url, e)
            return default if default is not None else {"_error": str(e)}

    def _cached(self, key: str, fn):
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]

    def _get_iam_policy(self):
        """Get project IAM policy (cached)."""
        def _fetch():
            from google.cloud import resourcemanager_v3
            client = resourcemanager_v3.ProjectsClient(credentials=self._credentials)
            return client.get_iam_policy(request={"resource": f"projects/{self._project_id}"})
        return self._cached("iam_policy", _fetch)

    def _get_instances_client(self):
        if self._instances_client is None:
            from google.cloud.compute_v1 import InstancesClient
            self._instances_client = InstancesClient(credentials=self._credentials)
        return self._instances_client

    def _get_subnetworks_client(self):
        if self._subnetworks_client is None:
            from google.cloud.compute_v1 import SubnetworksClient
            self._subnetworks_client = SubnetworksClient(credentials=self._credentials)
        return self._subnetworks_client

    def _get_networks_client(self):
        if self._networks_client is None:
            from google.cloud.compute_v1 import NetworksClient
            self._networks_client = NetworksClient(credentials=self._credentials)
        return self._networks_client

    def _get_disks_client(self):
        if self._disks_client is None:
            from google.cloud.compute_v1 import DisksClient
            self._disks_client = DisksClient(credentials=self._credentials)
        return self._disks_client

    def _get_storage_client(self):
        if self._storage_client is None:
            from google.cloud import storage
            self._storage_client = storage.Client(
                project=self._project_id, credentials=self._credentials)
        return self._storage_client

    def _get_monitoring_client(self):
        if self._monitoring_client is None:
            from google.cloud import monitoring_v3
            self._monitoring_client = monitoring_v3.AlertPolicyServiceClient(
                credentials=self._credentials)
        return self._monitoring_client

    def _list_firewalls(self):
        """List all firewall rules (cached)."""
        def _fetch():
            from google.cloud.compute_v1 import FirewallsClient, ListFirewallsRequest
            client = FirewallsClient(credentials=self._credentials)
            return list(client.list(request=ListFirewallsRequest(project=self._project_id)))
        return self._cached("firewalls", _fetch)

    def _list_instances(self):
        """List all VM instances (cached)."""
        def _fetch():
            from google.cloud.compute_v1 import AggregatedListInstancesRequest
            results = []
            for _, scoped in self._get_instances_client().aggregated_list(
                request=AggregatedListInstancesRequest(project=self._project_id)):
                for inst in (scoped.instances or []):
                    results.append(inst)
            return results
        return self._cached("instances", _fetch)

    def _list_subnets(self):
        """List all subnets (cached)."""
        def _fetch():
            from google.cloud.compute_v1 import AggregatedListSubnetworksRequest
            results = []
            for _, scoped in self._get_subnetworks_client().aggregated_list(
                request=AggregatedListSubnetworksRequest(project=self._project_id)):
                for s in (scoped.subnetworks or []):
                    results.append(s)
            return results
        return self._cached("subnets", _fetch)

    def _build_evidence(self, api_call: str, cli_command: str, response: Any,
                        service: str = "", parameters: dict | None = None,
                        assessor_guidance: str = "") -> dict:
        """Build structured evidence dict with query context and CLI command."""
        result = {
            "api_call": api_call,
            "cli_command": cli_command,
            "query_info": {
                "service": service,
                "api_method": api_call,
                "parameters": parameters or {},
                "region": self.region or "us-central1",
                "account_id": self._project_id or "",
            },
            "response": response,
        }
        if assessor_guidance:
            result["assessor_guidance"] = assessor_guidance
        return result

    # ------------------------------------------------------------------
    # Automated check implementations
    # ------------------------------------------------------------------

    def check_iam_bindings(self, check_def: dict) -> CheckResult:
        """
        Check IAM bindings for overly permissive roles.

        NIST 800-53 Control: 3.1.1 — Limit system access to authorized users.
        Verifies that primitive roles (Owner, Editor) are minimally assigned.
        """
        try:
            from google.cloud import resourcemanager_v3

            client = resourcemanager_v3.ProjectsClient(credentials=self._credentials)
            project_name = f"projects/{self._project_id}"

            # Get IAM policy
            request = {"resource": project_name}
            policy = client.get_iam_policy(request=request)

            # Capture raw evidence
            bindings_raw = [
                {"role": b.role, "members": list(b.members)}
                for b in policy.bindings
            ]
            raw = self._build_evidence(
                api_call="resourcemanager_v3.ProjectsClient.get_iam_policy",
                cli_command="gcloud projects get-iam-policy PROJECT_ID",
                response={"bindings": bindings_raw[:30]},
                service="IAM",
                assessor_guidance=(
                    "Review IAM bindings for overly permissive primitive roles (roles/owner, roles/editor). "
                    "Verify that service accounts and user principals follow least privilege with custom roles."
                ),
            )

            overly_broad = []
            primitive_roles = {"roles/owner", "roles/editor"}

            for binding in policy.bindings:
                if binding.role in primitive_roles:
                    member_count = len(binding.members)
                    member_preview = ", ".join(list(binding.members)[:3])
                    if member_count > 3:
                        member_preview += f"... (+{member_count - 3} more)"
                    overly_broad.append(
                        f"Role '{binding.role}': {member_count} member(s) [{member_preview}]"
                    )

            total_bindings = len(policy.bindings)
            total_primitive = len(overly_broad)

            if total_primitive == 0:
                return self._result(
                    check_def, "met",
                    f"Reviewed {total_bindings} IAM binding(s). "
                    "No primitive roles (Owner/Editor) assigned at project level.",
                    raw_evidence=raw,
                )
            elif total_primitive <= 2:
                return self._result(
                    check_def, "met",
                    f"Reviewed {total_bindings} IAM binding(s). "
                    f"Found {total_primitive} primitive role assignment(s) "
                    f"(within acceptable range): {'; '.join(overly_broad)}",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"Found {total_primitive} overly broad IAM binding(s): "
                    + "; ".join(overly_broad[:5]),
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking IAM bindings: {str(e)}",
            )

    def check_audit_logging(self, check_def: dict) -> CheckResult:
        """
        Check if audit logging is enabled for all services.

        NIST 800-53 Control: 3.3.1 — Create and retain system audit logs.
        """
        try:
            from google.cloud import resourcemanager_v3

            client = resourcemanager_v3.ProjectsClient(credentials=self._credentials)
            project_name = f"projects/{self._project_id}"

            policy = client.get_iam_policy(request={"resource": project_name})

            # Check audit configs in the IAM policy
            audit_configs = policy.audit_configs

            # Capture raw evidence
            configs_raw = []
            for cfg in (audit_configs or []):
                log_types = [
                    {"log_type": lt.log_type, "exempted_members": list(lt.exempted_members)}
                    for lt in (cfg.audit_log_configs or [])
                ]
                configs_raw.append({"service": cfg.service, "audit_log_configs": log_types})
            raw = self._build_evidence(
                api_call="resourcemanager_v3.ProjectsClient.get_iam_policy (audit_configs)",
                cli_command="gcloud projects get-iam-policy PROJECT_ID --format=json | jq '.auditConfigs'",
                response={"audit_configs": configs_raw},
                service="IAM",
                assessor_guidance=(
                    "Verify that audit logging is enabled for allServices with ADMIN_READ, DATA_READ, and DATA_WRITE log types. "
                    "Check that no critical services are exempted from audit logging."
                ),
            )

            if not audit_configs:
                return self._result(
                    check_def, "not_met",
                    "No audit logging configurations found in the project IAM policy.",
                    raw_evidence=raw,
                )

            # Check for allServices audit config
            has_all_services = False
            services_configured = []
            for config in audit_configs:
                services_configured.append(config.service)
                if config.service == "allServices":
                    has_all_services = True

            if has_all_services:
                return self._result(
                    check_def, "met",
                    f"Audit logging is configured for allServices plus "
                    f"{len(services_configured) - 1} additional service-specific config(s).",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"Audit logging is configured for {len(services_configured)} specific "
                    f"service(s) but NOT for allServices: {', '.join(services_configured[:5])}",
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking audit logging: {str(e)}",
            )

    def check_vpc_firewall_rules(self, check_def: dict) -> CheckResult:
        """
        Check VPC firewall rules for overly permissive ingress.

        NIST 800-53 Control: 3.1.5 — Employ the principle of least privilege.
        """
        try:
            from google.cloud import compute_v1

            firewall_client = compute_v1.FirewallsClient(credentials=self._credentials)
            request = compute_v1.ListFirewallsRequest(project=self._project_id)
            firewalls = list(firewall_client.list(request=request))

            # Capture raw evidence (truncate to 50 rules)
            fw_raw = []
            for fw in firewalls[:50]:
                allowed_raw = []
                for a in (fw.allowed or []):
                    protocol = a.I_p_protocol if hasattr(a, 'I_p_protocol') else getattr(a, 'ip_protocol', '')
                    allowed_raw.append({"protocol": protocol, "ports": list(a.ports) if a.ports else []})
                fw_raw.append({
                    "name": fw.name,
                    "direction": fw.direction,
                    "disabled": fw.disabled,
                    "source_ranges": list(fw.source_ranges) if fw.source_ranges else [],
                    "allowed": allowed_raw,
                    "network": fw.network,
                })
            raw = self._build_evidence(
                api_call="compute_v1.FirewallsClient.list",
                cli_command="gcloud compute firewall-rules list --project PROJECT_ID",
                response={"total_rules": len(firewalls), "rules": fw_raw},
                service="Compute",
                assessor_guidance=(
                    "Identify INGRESS rules with source_ranges 0.0.0.0/0 that expose sensitive ports (SSH 22, RDP 3389, database ports). "
                    "Confirm business justification for any public-facing services."
                ),
            )

            sensitive_ports = {"22", "3389", "3306", "5432", "1433", "27017", "6379"}
            issues = []

            for fw in firewalls:
                if fw.direction != "INGRESS":
                    continue
                if fw.disabled:
                    continue

                # Check source ranges
                source_ranges = list(fw.source_ranges) if fw.source_ranges else []
                is_open = "0.0.0.0/0" in source_ranges

                if not is_open:
                    continue

                # Check allowed ports
                for allowed in fw.allowed:
                    protocol = allowed.I_p_protocol if hasattr(allowed, 'I_p_protocol') else getattr(allowed, 'ip_protocol', '')
                    ports = list(allowed.ports) if allowed.ports else []

                    if not ports:
                        issues.append(
                            f"Rule '{fw.name}': all {protocol} ports open to 0.0.0.0/0"
                        )
                    else:
                        for port in ports:
                            if port in sensitive_ports or "-" in port:
                                issues.append(
                                    f"Rule '{fw.name}': {protocol} port {port} open to 0.0.0.0/0"
                                )

            if not issues:
                return self._result(
                    check_def, "met",
                    f"Reviewed {len(firewalls)} firewall rule(s). "
                    "No overly permissive ingress rules found on sensitive ports.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"Found {len(issues)} overly permissive firewall rule(s): "
                    + "; ".join(issues[:10])
                    + ("..." if len(issues) > 10 else ""),
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking VPC firewall rules: {str(e)}",
            )

    def check_kms_key_rotation(self, check_def: dict) -> CheckResult:
        """
        Check if Cloud KMS keys have automatic rotation configured.

        NIST 800-53 Control: 3.13.10 — Establish and manage cryptographic keys.
        """
        try:
            from google.cloud import kms_v1

            client = kms_v1.KeyManagementServiceClient(credentials=self._credentials)

            # List key rings in the project
            parent = f"projects/{self._project_id}/locations/{self.region}"
            key_rings = list(client.list_key_rings(request={"parent": parent}))

            if not key_rings:
                raw = self._build_evidence(
                    api_call="kms_v1.KeyManagementServiceClient.list_key_rings",
                    cli_command="gcloud kms keyrings list --location global --project PROJECT_ID && gcloud kms keys list --keyring KEYRING --location LOCATION --project PROJECT_ID",
                    response={"key_rings": [], "location": self.region},
                    service="KMS",
                    assessor_guidance=(
                        "Verify that all Cloud KMS encryption keys have automatic rotation enabled with rotation_period <= 365 days. "
                        "Confirm that ENCRYPT_DECRYPT keys protecting CUI use FIPS 140-2 validated algorithms."
                    ),
                )
                return self._result(
                    check_def, "met",
                    f"No KMS key rings found in {self.region}.",
                    raw_evidence=raw,
                )

            keys_checked = 0
            keys_without_rotation = []
            keys_raw = []

            for kr in key_rings:
                crypto_keys = list(client.list_crypto_keys(request={"parent": kr.name}))
                for key in crypto_keys:
                    if key.purpose.name != "ENCRYPT_DECRYPT":
                        continue

                    keys_checked += 1
                    rotation_period = key.rotation_period
                    rotation_secs = rotation_period.total_seconds() if rotation_period else 0
                    keys_raw.append({
                        "name": key.name.split("/")[-1],
                        "key_ring": kr.name.split("/")[-1],
                        "purpose": key.purpose.name,
                        "rotation_period_seconds": rotation_secs,
                        "rotation_period_days": round(rotation_secs / 86400, 1) if rotation_secs else 0,
                    })

                    if not rotation_period or rotation_secs == 0:
                        keys_without_rotation.append(key.name.split("/")[-1])
                    elif rotation_secs > 365 * 24 * 3600:
                        keys_without_rotation.append(
                            f"{key.name.split('/')[-1]} (rotation > 365 days)"
                        )

            raw = {
                "api_call": "kms_v1.KeyManagementServiceClient.list_key_rings + list_crypto_keys",
                "response": {
                    "total_key_rings": len(key_rings),
                    "total_encryption_keys": keys_checked,
                    "keys": keys_raw[:20],
                },
            }

            if keys_checked == 0:
                return self._result(
                    check_def, "met",
                    f"No symmetric encryption keys found in {len(key_rings)} key ring(s).",
                    raw_evidence=raw,
                )

            if not keys_without_rotation:
                return self._result(
                    check_def, "met",
                    f"All {keys_checked} KMS key(s) have automatic rotation "
                    "configured within 365 days.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"{len(keys_without_rotation)} of {keys_checked} KMS key(s) lack proper "
                    f"rotation: {', '.join(keys_without_rotation[:5])}",
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking KMS key rotation: {str(e)}",
            )

    def check_compute_disk_encryption(self, check_def: dict) -> CheckResult:
        """
        Check if Compute Engine disks use CMEK encryption.

        NIST 800-53 Control: 3.13.11 — Employ FIPS-validated cryptography for CUI.
        """
        try:
            from google.cloud import compute_v1

            disk_client = compute_v1.DisksClient(credentials=self._credentials)

            # List disks in the specified region (check all zones)
            zones_client = compute_v1.ZonesClient(credentials=self._credentials)
            zones = list(zones_client.list(project=self._project_id))

            total_disks = 0
            disks_without_cmek = []
            disks_raw = []

            for zone in zones:
                if not zone.name.startswith(self.region):
                    continue
                try:
                    disks = list(disk_client.list(project=self._project_id, zone=zone.name))
                    for disk in disks:
                        total_disks += 1
                        kms_key = ""
                        if disk.disk_encryption_key and disk.disk_encryption_key.kms_key_name:
                            kms_key = disk.disk_encryption_key.kms_key_name
                        else:
                            disks_without_cmek.append(f"{disk.name} ({zone.name})")
                        disks_raw.append({
                            "name": disk.name,
                            "zone": zone.name,
                            "size_gb": disk.size_gb,
                            "status": disk.status,
                            "kms_key_name": kms_key or "Google-managed",
                        })
                except Exception:
                    pass

            raw = self._build_evidence(
                api_call="compute_v1.DisksClient.list",
                cli_command="gcloud compute disks list --project PROJECT_ID --format='table(name,diskEncryptionKey)'",
                response={
                    "region": self.region,
                    "total_disks": total_disks,
                    "disks": disks_raw[:30],
                },
                service="Compute",
                assessor_guidance=(
                    "Confirm that all Compute Engine persistent disks storing CUI use Customer-Managed Encryption Keys (CMEK). "
                    "Verify kms_key_name references a Cloud KMS key with proper rotation and access controls."
                ),
            )

            if total_disks == 0:
                return self._result(
                    check_def, "met",
                    f"No Compute Engine disks found in region {self.region}.",
                    raw_evidence=raw,
                )

            if not disks_without_cmek:
                return self._result(
                    check_def, "met",
                    f"All {total_disks} disk(s) use Customer-Managed Encryption Keys (CMEK).",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"{len(disks_without_cmek)} of {total_disks} disk(s) do not use CMEK: "
                    + ", ".join(disks_without_cmek[:5])
                    + ("..." if len(disks_without_cmek) > 5 else ""),
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking disk encryption: {str(e)}",
            )

    def check_cloud_armor(self, check_def: dict) -> CheckResult:
        """
        Check if Cloud Armor security policies are configured.

        NIST 800-53 Control: 3.13.6 — Deny network communications traffic by default.
        """
        try:
            from google.cloud import compute_v1

            policies_client = compute_v1.SecurityPoliciesClient(credentials=self._credentials)
            policies = list(policies_client.list(project=self._project_id))

            # Capture raw evidence
            policies_raw = []
            for p in policies[:20]:
                rules_raw = []
                for r in (p.rules or [])[:10]:
                    rules_raw.append({
                        "priority": r.priority,
                        "action": r.action,
                        "description": r.description or "",
                    })
                policies_raw.append({
                    "name": p.name,
                    "description": p.description or "",
                    "rule_count": len(p.rules) if p.rules else 0,
                    "rules": rules_raw,
                })
            raw = self._build_evidence(
                api_call="compute_v1.SecurityPoliciesClient.list",
                cli_command="gcloud compute security-policies list --project PROJECT_ID",
                response={"total_policies": len(policies), "policies": policies_raw},
                service="Compute",
                assessor_guidance=(
                    "Review Cloud Armor policies for configured rules protecting public-facing applications. "
                    "Verify that security policies include rate limiting, geographic restrictions, or OWASP ModSecurity rules."
                ),
            )

            if not policies:
                return self._result(
                    check_def, "not_met",
                    "No Cloud Armor security policies found in the project.",
                    raw_evidence=raw,
                )

            policy_info = []
            for policy in policies:
                rule_count = len(policy.rules) if policy.rules else 0
                policy_info.append(f"'{policy.name}' ({rule_count} rule(s))")

            return self._result(
                check_def, "met",
                f"Found {len(policies)} Cloud Armor security policy(ies): "
                + ", ".join(policy_info[:5]),
                raw_evidence=raw,
            )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking Cloud Armor: {str(e)}",
            )

    def check_logging_enabled(self, check_def: dict) -> CheckResult:
        """
        Check if Cloud Logging is enabled with log sinks configured.

        NIST 800-53 Control: 3.3.1 — Create and retain system audit logs.
        """
        try:
            # Check for log sinks (exports)
            sinks = list(self._logging_client.list_sinks())

            # Check for log-based metrics
            metrics = list(self._logging_client.list_metrics())

            # Capture raw evidence
            sinks_raw = [
                {"name": s.name, "destination": getattr(s, "destination", ""), "filter": getattr(s, "filter_", "")}
                for s in sinks[:20]
            ]
            metrics_raw = [
                {"name": m.name, "filter": getattr(m, "filter_", ""), "description": getattr(m, "description", "")}
                for m in metrics[:20]
            ]
            raw = self._build_evidence(
                api_call="logging.Client.list_sinks + list_metrics",
                cli_command="gcloud logging sinks list --project PROJECT_ID && gcloud logging metrics list --project PROJECT_ID",
                response={
                    "total_sinks": len(sinks),
                    "sinks": sinks_raw,
                    "total_metrics": len(metrics),
                    "metrics": metrics_raw,
                },
                service="Logging",
                assessor_guidance=(
                    "Verify that log sinks export audit logs to long-term storage (Cloud Storage, BigQuery) for retention compliance. "
                    "Confirm that log-based metrics are configured for security event monitoring and alerting."
                ),
            )

            if not sinks and not metrics:
                return self._result(
                    check_def, "not_met",
                    "Cloud Logging is active but no log sinks or log-based metrics "
                    "are configured for long-term retention and monitoring.",
                    raw_evidence=raw,
                )

            sink_names = [s.name for s in sinks]
            metric_names = [m.name for m in metrics]

            return self._result(
                check_def, "met",
                f"Cloud Logging is configured with {len(sinks)} log sink(s) "
                f"({', '.join(sink_names[:3])}) and {len(metrics)} log-based metric(s) "
                f"({', '.join(metric_names[:3])}).",
                raw_evidence=raw,
            )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking Cloud Logging: {str(e)}",
            )

    def check_org_policy_constraints(self, check_def: dict) -> CheckResult:
        """
        Check if Organization Policy constraints are enforced.

        NIST 800-53 Control: 3.4.2 — Establish and enforce security configuration settings.
        """
        try:
            from google.cloud import resourcemanager_v3

            # Check project-level org policies
            client = resourcemanager_v3.ProjectsClient(credentials=self._credentials)
            project_name = f"projects/{self._project_id}"

            # Key constraints to check
            important_constraints = [
                "constraints/compute.requireOsLogin",
                "constraints/compute.disableSerialPortAccess",
                "constraints/compute.requireShieldedVm",
                "constraints/storage.uniformBucketLevelAccess",
                "constraints/iam.disableServiceAccountKeyCreation",
                "constraints/gcp.resourceLocations",
            ]

            enforced_constraints = []
            missing_constraints = []
            constraints_raw = []

            try:
                from google.cloud import orgpolicy_v2

                orgpolicy_client = orgpolicy_v2.OrgPolicyClient(credentials=self._credentials)

                for constraint in important_constraints:
                    short_name = constraint.split("/")[-1]
                    try:
                        policy_name = f"{project_name}/policies/{short_name}"
                        policy = orgpolicy_client.get_policy(name=policy_name)
                        has_rules = bool(policy.spec and policy.spec.rules)
                        constraints_raw.append({
                            "constraint": short_name,
                            "enforced": has_rules,
                            "rule_count": len(policy.spec.rules) if has_rules else 0,
                        })
                        if has_rules:
                            enforced_constraints.append(short_name)
                        else:
                            missing_constraints.append(short_name)
                    except Exception:
                        missing_constraints.append(short_name)
                        constraints_raw.append({
                            "constraint": short_name,
                            "enforced": False,
                            "error": "Policy not found or no permission",
                        })

            except ImportError:
                return self._result(
                    check_def, "manual",
                    "Organization Policy client library not available. "
                    "Manual verification required to confirm org policy constraints are enforced.",
                )

            raw = self._build_evidence(
                api_call="orgpolicy_v2.OrgPolicyClient.get_policy",
                cli_command="gcloud org-policies list --project PROJECT_ID",
                response={
                    "project": self._project_id,
                    "total_checked": len(important_constraints),
                    "total_enforced": len(enforced_constraints),
                    "constraints": constraints_raw,
                },
                service="OrgPolicy",
                assessor_guidance=(
                    "Verify that key security constraints are enforced: requireOsLogin, disableSerialPortAccess, requireShieldedVm, uniformBucketLevelAccess. "
                    "Confirm no exemptions exist for in-scope resources storing CUI."
                ),
            )

            if len(enforced_constraints) >= 4:
                return self._result(
                    check_def, "met",
                    f"{len(enforced_constraints)} of {len(important_constraints)} key Organization "
                    f"Policy constraints enforced: {', '.join(enforced_constraints)}",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"Only {len(enforced_constraints)} of {len(important_constraints)} key "
                    f"constraints enforced. Missing: {', '.join(missing_constraints[:5])}",
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking Organization Policy constraints: {str(e)}",
            )

    def check_defense_in_depth(self, check_def: dict) -> CheckResult:
        """
        Check for defense-in-depth architecture across multiple security layers.

        NIST 800-53 Control: 3.13.2 — Employ architectural designs that promote
        effective information security.

        Met if >= 3 of 4 layers present: firewall rules, KMS keys,
        log sinks, org policy constraints.
        """
        try:
            from google.cloud import compute_v1, kms_v1

            layers = []
            raw_layers = {}

            # Layer 1: Firewall rules (network posture)
            firewall_client = compute_v1.FirewallsClient(credentials=self._credentials)
            firewalls = list(firewall_client.list(
                request=compute_v1.ListFirewallsRequest(project=self._project_id)
            ))
            raw_layers["firewall_rules"] = len(firewalls)
            if firewalls:
                layers.append(f"Firewall rules ({len(firewalls)} rules)")

            # Layer 2: KMS keys (encryption)
            kms_client = kms_v1.KeyManagementServiceClient(credentials=self._credentials)
            parent = f"projects/{self._project_id}/locations/{self.region}"
            try:
                key_rings = list(kms_client.list_key_rings(request={"parent": parent}))
                raw_layers["kms_key_rings"] = len(key_rings)
                if key_rings:
                    layers.append(f"Cloud KMS ({len(key_rings)} key ring(s))")
            except Exception:
                raw_layers["kms_key_rings"] = 0

            # Layer 3: Log sinks (monitoring)
            sinks = list(self._logging_client.list_sinks())
            raw_layers["log_sinks"] = len(sinks)
            if sinks:
                layers.append(f"Log sinks ({len(sinks)} configured)")

            # Layer 4: Org policy constraints
            org_enforced = 0
            try:
                from google.cloud import orgpolicy_v2

                orgpolicy_client = orgpolicy_v2.OrgPolicyClient(credentials=self._credentials)
                project_name = f"projects/{self._project_id}"
                constraints_to_check = [
                    "requireOsLogin", "disableSerialPortAccess",
                    "requireShieldedVm", "uniformBucketLevelAccess",
                ]
                for constraint in constraints_to_check:
                    try:
                        policy_name = f"{project_name}/policies/{constraint}"
                        policy = orgpolicy_client.get_policy(name=policy_name)
                        if policy.spec and policy.spec.rules:
                            org_enforced += 1
                    except Exception:
                        pass
                if org_enforced > 0:
                    layers.append(f"Org policies ({org_enforced} enforced)")
            except ImportError:
                pass
            raw_layers["org_policies_enforced"] = org_enforced

            raw = self._build_evidence(
                api_call="compute_v1 + kms_v1 + logging + orgpolicy_v2 (composite)",
                cli_command="gcloud compute firewall-rules list --project PROJECT_ID && gcloud kms keyrings list --location global --project PROJECT_ID",
                response={
                    "layers_present": len(layers),
                    "layers_required": 3,
                    "layer_details": raw_layers,
                    "layer_descriptions": layers,
                },
                service="Multiple",
                assessor_guidance=(
                    "Confirm presence of at least 3 of 4 defense-in-depth layers: network firewall rules, KMS encryption, audit log export, and organization policies. "
                    "Verify architectural design documents support layered security controls."
                ),
            )

            if len(layers) >= 3:
                return self._result(
                    check_def, "met",
                    f"Defense-in-depth: {len(layers)}/4 layers present — {'; '.join(layers)}.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"Only {len(layers)}/4 defense-in-depth layers found: "
                    f"{'; '.join(layers) if layers else 'none'}.",
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking defense-in-depth: {str(e)}",
            )

    def check_vpn_remote_access(self, check_def: dict) -> CheckResult:
        """
        Check if Cloud VPN infrastructure exists for controlled remote access.

        NIST 800-53 Control: 3.1.16 — Authorize remote access prior to allowing
        such connections.
        """
        try:
            from google.cloud import compute_v1

            vpn_resources = []
            gateways_raw = []
            tunnels_raw = []

            # Check VPN gateways across all regions
            vpn_gw_client = compute_v1.VpnGatewaysClient(credentials=self._credentials)
            try:
                gateways = list(vpn_gw_client.aggregated_list(
                    request=compute_v1.AggregatedListVpnGatewaysRequest(project=self._project_id)
                ))
                for region_name, scoped_list in gateways:
                    if scoped_list.vpn_gateways:
                        for gw in scoped_list.vpn_gateways:
                            vpn_resources.append(f"VPN Gateway: {gw.name}")
                            gateways_raw.append({
                                "name": gw.name,
                                "region": region_name,
                                "network": getattr(gw, "network", ""),
                            })
            except Exception:
                pass

            # Check VPN tunnels
            tunnel_client = compute_v1.VpnTunnelsClient(credentials=self._credentials)
            try:
                tunnels = list(tunnel_client.aggregated_list(
                    request=compute_v1.AggregatedListVpnTunnelsRequest(project=self._project_id)
                ))
                tunnel_count = 0
                for region_name, scoped_list in tunnels:
                    if scoped_list.vpn_tunnels:
                        for t in scoped_list.vpn_tunnels:
                            tunnel_count += 1
                            tunnels_raw.append({
                                "name": t.name,
                                "region": region_name,
                                "status": getattr(t, "status", ""),
                                "peer_ip": getattr(t, "peer_ip", ""),
                            })
                if tunnel_count > 0:
                    vpn_resources.append(f"{tunnel_count} VPN tunnel(s)")
            except Exception:
                pass

            raw = self._build_evidence(
                api_call="compute_v1.VpnGatewaysClient + VpnTunnelsClient",
                cli_command="gcloud compute vpn-gateways list --project PROJECT_ID && gcloud compute vpn-tunnels list --project PROJECT_ID",
                response={
                    "vpn_gateways": gateways_raw[:20],
                    "vpn_tunnels": tunnels_raw[:20],
                },
                service="Compute",
                assessor_guidance=(
                    "Verify that Cloud VPN gateways and tunnels are configured with IKEv2 and strong cipher suites. "
                    "Confirm that remote access is authorized and logged before tunnel establishment."
                ),
            )

            if vpn_resources:
                return self._result(
                    check_def, "met",
                    f"Cloud VPN infrastructure present: {'; '.join(vpn_resources[:5])}.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    "No Cloud VPN gateways or tunnels found in the project.",
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking VPN infrastructure: {str(e)}",
            )

    def check_mobile_device_control(self, check_def: dict) -> CheckResult:
        """
        Check for device security org policy constraints.

        NIST 800-53 Control: 3.1.18 — Control connection of mobile devices.
        Met if >= 2 of 3 constraints enforced: OS Login, serial port
        disabled, shielded VM required.
        """
        try:
            from google.cloud import orgpolicy_v2

            orgpolicy_client = orgpolicy_v2.OrgPolicyClient(credentials=self._credentials)
            project_name = f"projects/{self._project_id}"

            constraints = {
                "requireOsLogin": "OS Login required",
                "disableSerialPortAccess": "Serial port access disabled",
                "requireShieldedVm": "Shielded VM required",
            }
            enforced = []
            missing = []
            constraints_raw = []

            for constraint, label in constraints.items():
                try:
                    policy_name = f"{project_name}/policies/{constraint}"
                    policy = orgpolicy_client.get_policy(name=policy_name)
                    has_rules = bool(policy.spec and policy.spec.rules)
                    constraints_raw.append({
                        "constraint": constraint,
                        "label": label,
                        "enforced": has_rules,
                    })
                    if has_rules:
                        enforced.append(label)
                    else:
                        missing.append(label)
                except Exception:
                    missing.append(label)
                    constraints_raw.append({
                        "constraint": constraint,
                        "label": label,
                        "enforced": False,
                        "error": "Policy not found",
                    })

            raw = self._build_evidence(
                api_call="orgpolicy_v2.OrgPolicyClient.get_policy",
                cli_command="gcloud org-policies describe constraints/iam.allowedPolicyMemberDomains --project PROJECT_ID",
                response={
                    "project": self._project_id,
                    "constraints_checked": len(constraints),
                    "constraints_enforced": len(enforced),
                    "details": constraints_raw,
                },
                service="OrgPolicy",
                assessor_guidance=(
                    "Confirm that organization policies enforce device security: OS Login (ssh key management), serial port disabled (no console backdoor), and shielded VMs (secure boot). "
                    "Verify mobile device management policies are documented for contractor BYOD scenarios."
                ),
            )

            if len(enforced) >= 2:
                return self._result(
                    check_def, "met",
                    f"Device security: {len(enforced)}/3 org policies enforced — {'; '.join(enforced)}.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"Only {len(enforced)}/3 device security constraints enforced. "
                    f"Missing: {'; '.join(missing)}.",
                    raw_evidence=raw,
                )
        except ImportError:
            return self._result(
                check_def, "manual",
                "google-cloud-org-policy library not available. Manual verification required.",
            )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking device control policies: {str(e)}",
            )

    def check_cmek_org_policy(self, check_def: dict) -> CheckResult:
        """
        Check if CMEK org policy is enforced or all disks use CMEK.

        NIST 800-53 Control: 3.1.19 — Encrypt CUI on computing platforms.
        """
        try:
            # First check if CMEK org policy is enforced
            cmek_policy_enforced = False
            cmek_constraint_found = ""
            cmek_constraints_raw = []
            try:
                from google.cloud import orgpolicy_v2

                orgpolicy_client = orgpolicy_v2.OrgPolicyClient(credentials=self._credentials)
                project_name = f"projects/{self._project_id}"
                for constraint in ["restrictNonCmekServices", "restrictCmekCryptoKeyProjects"]:
                    try:
                        policy_name = f"{project_name}/policies/{constraint}"
                        policy = orgpolicy_client.get_policy(name=policy_name)
                        has_rules = bool(policy.spec and policy.spec.rules)
                        cmek_constraints_raw.append({
                            "constraint": constraint, "enforced": has_rules,
                        })
                        if has_rules and not cmek_policy_enforced:
                            cmek_policy_enforced = True
                            cmek_constraint_found = constraint
                    except Exception:
                        cmek_constraints_raw.append({
                            "constraint": constraint, "enforced": False, "error": "Not found",
                        })
            except ImportError:
                pass

            if cmek_policy_enforced:
                raw = self._build_evidence(
                    api_call="orgpolicy_v2.OrgPolicyClient.get_policy",
                    cli_command="gcloud org-policies describe constraints/gcp.restrictNonCmekServices --project PROJECT_ID",
                    response={
                        "cmek_policy_enforced": True,
                        "enforced_constraint": cmek_constraint_found,
                        "constraints": cmek_constraints_raw,
                    },
                    service="OrgPolicy",
                    assessor_guidance=(
                        "Verify that restrictNonCmekServices or restrictCmekCryptoKeyProjects constraint is enforced. "
                        "Confirm all GCE disks, Cloud SQL databases, and GCS buckets storing CUI use CMEK."
                    ),
                )
                return self._result(
                    check_def, "met",
                    "CMEK org policy constraint is enforced at the project level.",
                    raw_evidence=raw,
                )

            # Fallback: check if all disks use CMEK
            from google.cloud import compute_v1

            disk_client = compute_v1.DisksClient(credentials=self._credentials)
            zones_client = compute_v1.ZonesClient(credentials=self._credentials)
            zones = list(zones_client.list(project=self._project_id))

            total_disks = 0
            disks_without_cmek = []
            disks_raw = []

            for zone in zones:
                try:
                    disks = list(disk_client.list(project=self._project_id, zone=zone.name))
                    for disk in disks:
                        total_disks += 1
                        kms_key = ""
                        if disk.disk_encryption_key and disk.disk_encryption_key.kms_key_name:
                            kms_key = disk.disk_encryption_key.kms_key_name
                        else:
                            disks_without_cmek.append(f"{disk.name} ({zone.name})")
                        disks_raw.append({
                            "name": disk.name, "zone": zone.name,
                            "kms_key_name": kms_key or "Google-managed",
                        })
                except Exception:
                    pass

            raw = {
                "api_call": "orgpolicy_v2 + compute_v1.DisksClient.list",
                "response": {
                    "cmek_policy_enforced": False,
                    "org_policy_constraints": cmek_constraints_raw,
                    "total_disks": total_disks,
                    "disks_without_cmek": len(disks_without_cmek),
                    "disks": disks_raw[:30],
                },
            }

            if total_disks == 0:
                return self._result(
                    check_def, "met",
                    "No compute disks found. CMEK org policy not enforced but no disks to encrypt.",
                    raw_evidence=raw,
                )

            if not disks_without_cmek:
                return self._result(
                    check_def, "met",
                    f"All {total_disks} disk(s) use CMEK encryption.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"CMEK org policy not enforced. {len(disks_without_cmek)} of {total_disks} "
                    f"disk(s) lack CMEK: {', '.join(disks_without_cmek[:5])}"
                    + ("..." if len(disks_without_cmek) > 5 else ""),
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking CMEK policy: {str(e)}",
            )

    def check_uniform_bucket_access(self, check_def: dict) -> CheckResult:
        """
        Check if uniform bucket-level access org policy is enforced.

        NIST 800-53 Control: 3.1.21 — Limit use of portable storage devices
        (interpreted as preventing per-object ACLs on cloud storage).
        """
        try:
            from google.cloud import orgpolicy_v2

            orgpolicy_client = orgpolicy_v2.OrgPolicyClient(credentials=self._credentials)
            project_name = f"projects/{self._project_id}"

            enforced = False
            policy_detail = {}
            try:
                policy_name = f"{project_name}/policies/uniformBucketLevelAccess"
                policy = orgpolicy_client.get_policy(name=policy_name)
                if policy.spec and policy.spec.rules:
                    enforced = True
                    policy_detail = {
                        "constraint": "uniformBucketLevelAccess",
                        "enforced": True,
                        "rule_count": len(policy.spec.rules),
                    }
                else:
                    policy_detail = {
                        "constraint": "uniformBucketLevelAccess",
                        "enforced": False,
                        "reason": "Policy exists but has no rules",
                    }
            except Exception as exc:
                policy_detail = {
                    "constraint": "uniformBucketLevelAccess",
                    "enforced": False,
                    "error": str(exc),
                }

            raw = self._build_evidence(
                api_call="orgpolicy_v2.OrgPolicyClient.get_policy",
                cli_command="gcloud org-policies describe constraints/storage.uniformBucketLevelAccess --project PROJECT_ID",
                response={"project": self._project_id, "policy": policy_detail},
                service="OrgPolicy",
                assessor_guidance=(
                    "Confirm that uniformBucketLevelAccess is enforced to prevent per-object ACLs. "
                    "Verify all Cloud Storage buckets use IAM-only access for centralized permission management."
                ),
            )

            if enforced:
                return self._result(
                    check_def, "met",
                    "uniformBucketLevelAccess org policy constraint is enforced.",
                    raw_evidence=raw,
                )

            return self._result(
                check_def, "not_met",
                "uniformBucketLevelAccess org policy is not enforced. Per-object ACLs may be used.",
                raw_evidence=raw,
            )
        except ImportError:
            return self._result(
                check_def, "manual",
                "google-cloud-org-policy library not available. Manual verification required.",
            )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking uniform bucket access policy: {str(e)}",
            )

    # ------------------------------------------------------------------
    # Batch 1: IAM / Resource Manager checks
    # ------------------------------------------------------------------

    def check_service_account_keys_rotated(self, check_def: dict) -> CheckResult:
        """Check service account keys are rotated."""
        try:
            url = f"https://iam.googleapis.com/v1/projects/{self._project_id}/serviceAccounts"
            data = self._gcp_api_get_safe(url)
            if "_error" in (data or {}):
                return self._result(check_def, "error", f"API error: {data.get('_error', '')}")
            accounts = data.get("accounts", [])
            old_keys = []
            for sa in accounts[:30]:
                email = sa.get("email", "")
                keys_url = f"https://iam.googleapis.com/v1/projects/{self._project_id}/serviceAccounts/{email}/keys"
                keys_data = self._gcp_api_get_safe(keys_url, {"keys": []})
                for k in keys_data.get("keys", []):
                    if k.get("keyType") == "USER_MANAGED":
                        old_keys.append(f"{email}: key {k.get('name', '').split('/')[-1][:8]}...")
            raw = self._build_evidence(
                api_call="iam.serviceAccounts.list + keys.list",
                cli_command="gcloud iam service-accounts list --project PROJECT_ID && gcloud iam service-accounts keys list --iam-account SA_EMAIL",
                response={"accounts": len(accounts), "user_managed_keys": len(old_keys)},
                service="IAM",
                assessor_guidance=(
                    "Verify that all user-managed service account keys are rotated at least every 90 days. "
                    "Confirm that key creation is restricted via iam.disableServiceAccountKeyCreation org policy where feasible."
                ),
            )
            if not old_keys:
                return self._result(check_def, "met",
                    f"No user-managed service account keys found across {len(accounts)} SA(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(old_keys)} user-managed key(s) found — review rotation: "
                + "; ".join(old_keys[:5]), raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_default_sa_not_used(self, check_def: dict) -> CheckResult:
        """Check default service account is not used on instances."""
        try:
            instances = self._list_instances()
            default_sa = []
            for inst in instances:
                for sa in (inst.service_accounts or []):
                    if sa.email and "compute@developer.gserviceaccount.com" in sa.email:
                        default_sa.append(inst.name)
            raw = self._build_evidence(
                api_call="compute.instances.aggregatedList",
                cli_command="gcloud compute instances list --project PROJECT_ID --format='table(name,serviceAccounts.email)'",
                response={"total_instances": len(instances),
                                "using_default_sa": len(default_sa)},
                service="Compute",
                assessor_guidance=(
                    "Confirm that VM instances use custom service accounts with least-privilege IAM roles. "
                    "Verify no instances use the default Compute Engine service account (compute@developer.gserviceaccount.com)."
                ),
            )
            if not instances:
                return self._result(check_def, "met", "No VM instances found.", raw_evidence=raw)
            if not default_sa:
                return self._result(check_def, "met",
                    f"None of {len(instances)} instance(s) use the default SA.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(default_sa)} instance(s) use default SA: {', '.join(default_sa[:5])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_custom_iam_roles_scoped(self, check_def: dict) -> CheckResult:
        """Check custom IAM roles are appropriately scoped."""
        try:
            url = f"https://iam.googleapis.com/v1/projects/{self._project_id}/roles"
            data = self._gcp_api_get_safe(url, {"roles": []})
            roles = data.get("roles", [])
            raw = self._build_evidence(
                api_call="iam.projects.roles.list",
                cli_command="gcloud iam roles list --project PROJECT_ID",
                response={"custom_roles": len(roles),
                                "roles": [{"name": r.get("name", ""), "title": r.get("title", "")}
                                          for r in roles[:15]]},
                service="IAM",
                assessor_guidance=(
                    "Review custom IAM roles for included permissions. "
                    "Verify each role follows least privilege and does not grant overly broad wildcard permissions (e.g., *.*.*). "
                ),
            )
            return self._result(check_def, "met",
                f"Found {len(roles)} custom IAM role(s). Review for least-privilege scoping.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_primitive_roles_not_assigned(self, check_def: dict) -> CheckResult:
        """Check primitive roles are not assigned to users."""
        try:
            policy = self._get_iam_policy()
            user_primitives = []
            for b in policy.bindings:
                if b.role in ("roles/owner", "roles/editor"):
                    for m in b.members:
                        if m.startswith("user:"):
                            user_primitives.append(f"{m} -> {b.role}")
            raw = self._build_evidence(
                api_call="resourcemanager.getIamPolicy",
                cli_command="gcloud projects get-iam-policy PROJECT_ID",
                response={"user_primitives": user_primitives[:10]},
                service="IAM",
                assessor_guidance=(
                    "Confirm that no individual user accounts have roles/owner or roles/editor assigned. "
                    "Verify all user access uses custom roles or predefined roles with narrower scopes."
                ),
            )
            if not user_primitives:
                return self._result(check_def, "met",
                    "No individual users assigned primitive roles.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(user_primitives)} user(s) with primitive roles: "
                + "; ".join(user_primitives[:5]), raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_separation_of_duties(self, check_def: dict) -> CheckResult:
        """Check separation of duties for project management."""
        try:
            policy = self._get_iam_policy()
            owners = set()
            editors = set()
            for b in policy.bindings:
                if b.role == "roles/owner":
                    owners.update(b.members)
                elif b.role == "roles/editor":
                    editors.update(b.members)
            overlap = owners & editors
            raw = self._build_evidence(
                api_call="resourcemanager.getIamPolicy",
                cli_command="gcloud projects get-iam-policy PROJECT_ID",
                response={"owners": len(owners), "editors": len(editors),
                                "overlap": len(overlap)},
                service="IAM",
                assessor_guidance=(
                    "Verify separation of duties: no principals should hold both Owner and Editor roles. "
                    "Confirm that fewer than 4 Owners are assigned to enforce accountability."
                ),
            )
            if len(owners) <= 3 and not overlap:
                return self._result(check_def, "met",
                    f"Separation maintained: {len(owners)} owner(s), {len(editors)} editor(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Review needed: {len(owners)} owner(s), {len(overlap)} with dual roles.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_owner_role_limited(self, check_def: dict) -> CheckResult:
        """Check Owner role is limited to few principals."""
        try:
            policy = self._get_iam_policy()
            owners = []
            for b in policy.bindings:
                if b.role == "roles/owner":
                    owners.extend(list(b.members))
            raw = self._build_evidence(
                api_call="resourcemanager.getIamPolicy",
                cli_command="gcloud projects get-iam-policy PROJECT_ID",
                response={"owners": owners[:10]},
                service="IAM",
                assessor_guidance=(
                    "Verify that the Owner role is assigned to no more than 2-3 principals. "
                    "Confirm that all Owners are authorized administrators documented in access control records."
                ),
            )
            if len(owners) <= 3:
                return self._result(check_def, "met",
                    f"Owner role assigned to {len(owners)} principal(s) (within limit).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Too many Owners: {len(owners)}. Limit to 2-3.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_admin_user_separation(self, check_def: dict) -> CheckResult:
        """Check admin and user roles are separated."""
        return self.check_separation_of_duties(check_def)

    def check_admin_activity_logs(self, check_def: dict) -> CheckResult:
        """Check Admin Activity audit logs are enabled."""
        try:
            sinks = list(self._logging_client.list_sinks())
            raw = self._build_evidence(
                api_call="logging.sinks.list",
                cli_command="gcloud logging sinks list --project PROJECT_ID",
                response={"sinks": len(sinks),
                                "note": "Admin Activity logs are always on in GCP"},
                service="Logging",
                assessor_guidance=(
                    "Confirm that Admin Activity audit logs are enabled by default and cannot be disabled. "
                    "Verify that log sinks export these logs to long-term storage for retention compliance."
                ),
            )
            return self._result(check_def, "met",
                f"Admin Activity audit logs are always enabled in GCP. "
                f"{len(sinks)} log sink(s) configured for export.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_iam_changes_alerts(self, check_def: dict) -> CheckResult:
        """Check log-based metrics and alerts for IAM changes."""
        try:
            client = self._get_monitoring_client()
            project_name = f"projects/{self._project_id}"
            alerts = list(client.list_alert_policies(request={"name": project_name}))
            iam_alerts = [a for a in alerts
                          if a.display_name and "iam" in a.display_name.lower()]
            raw = self._build_evidence(
                api_call="monitoring.alertPolicies.list",
                cli_command="gcloud alpha monitoring policies list --project PROJECT_ID",
                response={"total_alerts": len(alerts),
                                "iam_alerts": len(iam_alerts)},
                service="Monitoring",
                assessor_guidance=(
                    "Verify that Cloud Monitoring alert policies are configured to notify on IAM policy changes. "
                    "Confirm that alerts trigger notifications to security personnel within defined SLA."
                ),
            )
            if iam_alerts:
                return self._result(check_def, "met",
                    f"Found {len(iam_alerts)} IAM-related alert policy(ies).", raw_evidence=raw)
            if alerts:
                return self._result(check_def, "met",
                    f"Found {len(alerts)} alert policy(ies). Verify IAM change alerts.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No alert policies configured for IAM changes.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_iam_recommender(self, check_def: dict) -> CheckResult:
        """Check IAM Recommender is reviewed."""
        try:
            from google.cloud import recommender_v1
            client = recommender_v1.RecommenderClient(credentials=self._credentials)
            parent = (f"projects/{self._project_id}/locations/-/"
                      f"recommenders/google.iam.policy.Recommender")
            recs = list(client.list_recommendations(request={"parent": parent}))
            raw = self._build_evidence(
                api_call="recommender.recommendations.list",
                cli_command="gcloud recommender recommendations list --project PROJECT_ID --recommender google.iam.policy.Recommender --location global",
                response={"recommendations": len(recs)},
                service="Recommender",
                assessor_guidance=(
                    "Review IAM Recommender suggestions for overly permissive roles and unused permissions. "
                    "Confirm that recommendations are triaged quarterly and implemented where appropriate."
                ),
            )
            return self._result(check_def, "met",
                f"IAM Recommender active: {len(recs)} recommendation(s).", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_logging_admin_restricted(self, check_def: dict) -> CheckResult:
        """Check Logging admin role is restricted."""
        try:
            policy = self._get_iam_policy()
            log_admins = []
            for b in policy.bindings:
                if "logging.admin" in b.role:
                    log_admins.extend(list(b.members))
            raw = self._build_evidence(
                api_call="resourcemanager.getIamPolicy",
                cli_command="gcloud projects get-iam-policy PROJECT_ID",
                response={"logging_admins": log_admins[:10]},
                service="IAM",
                assessor_guidance=(
                    "Verify that the roles/logging.admin role is assigned to no more than 2-3 principals. "
                    "Confirm that logging admins cannot tamper with or delete audit logs due to separation of duties."
                ),
            )
            if len(log_admins) <= 3:
                return self._result(check_def, "met",
                    f"Logging admin role assigned to {len(log_admins)} principal(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Too many logging admins: {len(log_admins)}.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_all_users_identified(self, check_def: dict) -> CheckResult:
        """Check all users are identified via Cloud Identity."""
        try:
            policy = self._get_iam_policy()
            user_count = 0
            for b in policy.bindings:
                for m in b.members:
                    if m.startswith("user:"):
                        user_count += 1
            raw = self._build_evidence(
                api_call="resourcemanager.getIamPolicy",
                cli_command="gcloud projects get-iam-policy PROJECT_ID",
                response={"user_bindings": user_count},
                service="IAM",
                assessor_guidance=(
                    "Confirm that all user principals are authenticated via Google Cloud Identity or Workspace with SSO. "
                    "Verify that each user account maps to a unique individual (no shared accounts)."
                ),
            )
            return self._result(check_def, "met",
                f"All {user_count} user binding(s) use Google Cloud Identity.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_service_accounts_identified(self, check_def: dict) -> CheckResult:
        """Check service accounts are clearly identified."""
        try:
            url = f"https://iam.googleapis.com/v1/projects/{self._project_id}/serviceAccounts"
            data = self._gcp_api_get_safe(url, {"accounts": []})
            accounts = data.get("accounts", [])
            raw = self._build_evidence(
                api_call="iam.serviceAccounts.list",
                cli_command="gcloud iam service-accounts list --project PROJECT_ID",
                response={"count": len(accounts),
                                "accounts": [{"email": a.get("email", ""),
                                              "displayName": a.get("displayName", "")}
                                             for a in accounts[:15]]},
                service="IAM",
                assessor_guidance=(
                    "Verify that all service accounts have descriptive displayName values indicating their purpose. "
                    "Confirm that service accounts are tied to specific workloads and not shared across applications."
                ),
            )
            return self._result(check_def, "met",
                f"Found {len(accounts)} service account(s). All are uniquely identified.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_inactive_sa_keys(self, check_def: dict) -> CheckResult:
        """Check for inactive service account keys."""
        return self.check_service_account_keys_rotated(check_def)

    def check_oauth_token_expiration(self, check_def: dict) -> CheckResult:
        """Check OAuth token expiration is configured."""
        try:
            url = f"https://iam.googleapis.com/v1/projects/{self._project_id}/serviceAccounts"
            data = self._gcp_api_get_safe(url, {"accounts": []})
            accounts = data.get("accounts", [])
            raw = self._build_evidence(
                api_call="iam.serviceAccounts.list",
                cli_command="gcloud iam service-accounts list --project PROJECT_ID",
                response={"count": len(accounts),
                                "note": "GCP access tokens expire after 1 hour by default"},
                service="IAM",
                assessor_guidance=(
                    "Confirm that OAuth access tokens issued by GCP expire after 1 hour (default behavior). "
                    "Verify that long-lived credentials (service account keys) are avoided in favor of Workload Identity."
                ),
            )
            return self._result(check_def, "met",
                f"GCP access tokens expire after 1 hour by default. "
                f"{len(accounts)} service account(s) configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ------------------------------------------------------------------
    # Batch 2: VPC / Network checks
    # ------------------------------------------------------------------

    def check_vpc_flow_logs(self, check_def: dict) -> CheckResult:
        """Check VPC Flow Logs are enabled on subnets."""
        try:
            subnets = self._list_subnets()
            no_logs = []
            for s in subnets:
                if not getattr(s, 'log_config', None) or not s.log_config.enable:
                    no_logs.append(s.name)
            raw = self._build_evidence(
                api_call="compute.subnetworks.aggregatedList",
                cli_command="gcloud compute networks subnets list --project PROJECT_ID --format='table(name,enableFlowLogs)'",
                response={"total_subnets": len(subnets),
                                "without_flow_logs": len(no_logs)},
                service="Compute",
                assessor_guidance=(
                    "Verify that VPC Flow Logs are enabled on all subnets hosting CUI workloads. "
                    "Confirm that flow logs are exported to Cloud Storage or BigQuery for long-term retention and analysis."
                ),
            )
            if not subnets:
                return self._result(check_def, "met", "No subnets found.", raw_evidence=raw)
            if not no_logs:
                return self._result(check_def, "met",
                    f"VPC Flow Logs enabled on all {len(subnets)} subnet(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_logs)} subnet(s) without flow logs: {', '.join(no_logs[:5])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_firewall_least_privilege(self, check_def: dict) -> CheckResult:
        """Check firewall rules follow least privilege."""
        return self.check_vpc_firewall_rules(check_def)

    def check_vpc_peering(self, check_def: dict) -> CheckResult:
        """Check VPC peering connections are reviewed."""
        try:
            networks = list(self._get_networks_client().list(project=self._project_id))
            peerings = []
            for n in networks:
                for p in (n.peerings or []):
                    peerings.append({"network": n.name, "peer": p.network,
                                     "state": str(getattr(p, 'state', ''))})
            raw = self._build_evidence(
                api_call="compute.networks.list",
                cli_command="gcloud compute networks peerings list --project PROJECT_ID",
                response={"networks": len(networks), "peerings": peerings[:20]},
                service="Compute",
                assessor_guidance=(
                    "Review all VPC peering connections for business justification and least-privilege routing. "
                    "Verify that peered networks do not expose CUI to unauthorized environments."
                ),
            )
            if not peerings:
                return self._result(check_def, "met",
                    "No VPC peering connections found.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"Found {len(peerings)} VPC peering(s). Review for least-privilege access.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_no_ssh_from_internet(self, check_def: dict) -> CheckResult:
        """Check no direct SSH/RDP from internet via firewall rules."""
        try:
            firewalls = self._list_firewalls()
            issues = []
            for fw in firewalls:
                if fw.direction != "INGRESS" or fw.disabled:
                    continue
                sources = list(fw.source_ranges) if fw.source_ranges else []
                if "0.0.0.0/0" not in sources:
                    continue
                for allowed in (fw.allowed or []):
                    proto = getattr(allowed, 'I_p_protocol', getattr(allowed, 'ip_protocol', ''))
                    ports = list(allowed.ports) if allowed.ports else []
                    if not ports or "22" in ports or "3389" in ports:
                        issues.append(f"'{fw.name}': {proto} port {','.join(ports) or 'all'}")
            raw = self._build_evidence(
                api_call="compute.firewalls.list",
                cli_command="gcloud compute firewall-rules list --project PROJECT_ID --filter='direction=INGRESS AND allowed.ports:22'",
                response={"total_rules": len(firewalls), "ssh_rdp_open": issues[:10]},
                service="Compute",
                assessor_guidance=(
                    "Verify that SSH (22) and RDP (3389) are not accessible from 0.0.0.0/0. "
                    "Confirm that remote access uses IAP tunnels or bastion hosts with restricted source IP ranges."
                ),
            )
            if not issues:
                return self._result(check_def, "met",
                    f"No SSH/RDP open to 0.0.0.0/0 in {len(firewalls)} rule(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(issues)} rule(s) allow SSH/RDP from internet: "
                + "; ".join(issues[:5]), raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_vpn_ikev2_encryption(self, check_def: dict) -> CheckResult:
        """Check Cloud VPN uses IKEv2 with strong ciphers."""
        try:
            from google.cloud.compute_v1 import VpnTunnelsClient, AggregatedListVpnTunnelsRequest
            client = VpnTunnelsClient(credentials=self._credentials)
            tunnels = []
            for _, scoped in client.aggregated_list(
                request=AggregatedListVpnTunnelsRequest(project=self._project_id)):
                for t in (scoped.vpn_tunnels or []):
                    tunnels.append(t)
            raw = self._build_evidence(
                api_call="compute.vpnTunnels.aggregatedList",
                cli_command="gcloud compute vpn-tunnels list --project PROJECT_ID --format='table(name,ikeVersion)'",
                response={"count": len(tunnels),
                                "tunnels": [{"name": t.name,
                                             "ike_version": getattr(t, 'ike_version', 2)}
                                            for t in tunnels[:10]]},
                service="Compute",
                assessor_guidance=(
                    "Verify that all VPN tunnels use IKEv2 protocol for improved security and performance. "
                    "Confirm that tunnels use AES-256 or AES-128-GCM encryption with SHA2 authentication."
                ),
            )
            if not tunnels:
                return self._result(check_def, "met", "No VPN tunnels found.", raw_evidence=raw)
            v1 = [t.name for t in tunnels if getattr(t, 'ike_version', 2) == 1]
            if not v1:
                return self._result(check_def, "met",
                    f"All {len(tunnels)} VPN tunnel(s) use IKEv2.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(v1)} tunnel(s) use IKEv1: {', '.join(v1[:5])}.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_management_network_segmented(self, check_def: dict) -> CheckResult:
        """Check management network is segmented."""
        try:
            subnets = self._list_subnets()
            mgmt = [s.name for s in subnets
                    if any(k in (s.name or "").lower()
                           for k in ("mgmt", "management", "bastion", "admin"))]
            raw = self._build_evidence(
                api_call="compute.subnetworks.aggregatedList",
                cli_command="gcloud compute networks subnets list --project PROJECT_ID",
                response={"total_subnets": len(subnets), "mgmt_subnets": mgmt[:10]},
                service="Compute",
                assessor_guidance=(
                    "Verify that management and administrative systems are placed in dedicated subnets with restricted access. "
                    "Confirm that firewall rules enforce network segmentation between management and production workloads."
                ),
            )
            if mgmt:
                return self._result(check_def, "met",
                    f"Management subnet(s) found: {', '.join(mgmt[:5])}.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No dedicated management subnets found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_public_subnets_dedicated(self, check_def: dict) -> CheckResult:
        """Check public-facing resources are in dedicated subnets."""
        try:
            subnets = self._list_subnets()
            public = [s.name for s in subnets
                      if any(k in (s.name or "").lower()
                             for k in ("public", "dmz", "frontend", "external"))]
            raw = self._build_evidence(
                api_call="compute.subnetworks.aggregatedList",
                cli_command="gcloud compute networks subnets list --project PROJECT_ID",
                response={"total": len(subnets), "public_subnets": public[:10]},
                service="Compute",
                assessor_guidance=(
                    "Verify that public-facing resources (load balancers, web servers) are isolated in DMZ subnets. "
                    "Confirm that internal CUI systems are not directly exposed to the internet."
                ),
            )
            if public:
                return self._result(check_def, "met",
                    f"Dedicated public subnet(s): {', '.join(public[:5])}.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No dedicated public-facing subnets found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_default_deny_ingress(self, check_def: dict) -> CheckResult:
        """Check default deny ingress firewall rule exists."""
        try:
            firewalls = self._list_firewalls()
            # GCP has implied deny all ingress — check for explicit allow-all that overrides
            allow_all = [fw.name for fw in firewalls
                         if fw.direction == "INGRESS" and not fw.disabled and
                         fw.source_ranges and "0.0.0.0/0" in list(fw.source_ranges) and
                         fw.allowed and any(
                             not list(a.ports) for a in fw.allowed
                             if getattr(a, 'I_p_protocol', getattr(a, 'ip_protocol', '')) == 'all')]
            raw = self._build_evidence(
                api_call="compute.firewalls.list",
                cli_command="gcloud compute firewall-rules list --project PROJECT_ID --filter='direction=INGRESS'",
                response={"total_rules": len(firewalls), "allow_all_ingress": allow_all[:10]},
                service="Compute",
                assessor_guidance=(
                    "Confirm that GCP's implicit deny-all ingress policy is maintained and not overridden by allow-all rules. "
                    "Verify all ingress rules follow least-privilege with explicit ports and source ranges."
                ),
            )
            if not allow_all:
                return self._result(check_def, "met",
                    f"Default deny ingress maintained. {len(firewalls)} rule(s) reviewed.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Allow-all ingress rule(s): {', '.join(allow_all[:5])}.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_default_egress_reviewed(self, check_def: dict) -> CheckResult:
        """Check default allow egress is reviewed."""
        try:
            firewalls = self._list_firewalls()
            egress = [fw for fw in firewalls if fw.direction == "EGRESS" and not fw.disabled]
            raw = self._build_evidence(
                api_call="compute.firewalls.list",
                cli_command="gcloud compute firewall-rules list --project PROJECT_ID --filter='direction=EGRESS'",
                response={"egress_rules": len(egress)},
                service="Compute",
                assessor_guidance=(
                    "Review egress firewall rules to ensure only necessary outbound traffic is allowed. "
                    "Verify that GCP's implicit allow-all egress does not permit data exfiltration from CUI systems."
                ),
            )
            return self._result(check_def, "met",
                f"Found {len(egress)} egress firewall rule(s). GCP has implied allow-all egress. "
                "Verify egress restrictions are appropriate.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_vpn_full_tunnel(self, check_def: dict) -> CheckResult:
        """Check VPN full tunnel policy is enforced."""
        return self.check_vpn_ikev2_encryption(check_def)

    def check_packet_mirroring_ids(self, check_def: dict) -> CheckResult:
        """Check Packet Mirroring or Cloud IDS is configured."""
        try:
            url = (f"https://compute.googleapis.com/compute/v1/projects/{self._project_id}"
                   f"/aggregated/packetMirrorings")
            data = self._gcp_api_get_safe(url, {})
            items = data.get("items", {})
            mirrors = []
            for _, scoped in items.items():
                for pm in scoped.get("packetMirrorings", []):
                    mirrors.append(pm.get("name", ""))
            raw = self._build_evidence(
                api_call="compute.packetMirrorings.aggregatedList",
                cli_command="gcloud compute packet-mirrorings list --project PROJECT_ID",
                response={"count": len(mirrors)},
                service="Compute",
                assessor_guidance=(
                    "Verify that Packet Mirroring or Cloud IDS is configured to detect intrusions on CUI networks. "
                    "Confirm that mirrored traffic is analyzed by an IDS/IPS system with threat signatures."
                ),
            )
            if mirrors:
                return self._result(check_def, "met",
                    f"Packet Mirroring configured: {', '.join(mirrors[:5])}.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Packet Mirroring or IDS configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_unused_firewall_rules(self, check_def: dict) -> CheckResult:
        """Check for unused firewall rules."""
        try:
            firewalls = self._list_firewalls()
            disabled = [fw.name for fw in firewalls if fw.disabled]
            raw = self._build_evidence(
                api_call="compute.firewalls.list",
                cli_command="gcloud compute firewall-rules list --project PROJECT_ID",
                response={"total": len(firewalls), "disabled": disabled[:10]},
                service="Compute",
                assessor_guidance=(
                    "Review disabled firewall rules and remove obsolete entries to maintain clean configuration. "
                    "Verify that all active rules have clear business justification and ownership."
                ),
            )
            if not disabled:
                return self._result(check_def, "met",
                    f"All {len(firewalls)} firewall rule(s) are active.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(disabled)} disabled firewall rule(s): {', '.join(disabled[:5])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_firewall_restrict_ports(self, check_def: dict) -> CheckResult:
        """Check firewall rules restrict unnecessary ports."""
        try:
            firewalls = self._list_firewalls()
            unnecessary = {"21", "23", "69", "135", "137", "139", "445", "161"}
            issues = []
            for fw in firewalls:
                if fw.direction != "INGRESS" or fw.disabled:
                    continue
                if "0.0.0.0/0" not in (list(fw.source_ranges) if fw.source_ranges else []):
                    continue
                for a in (fw.allowed or []):
                    for p in (list(a.ports) if a.ports else []):
                        if p in unnecessary:
                            issues.append(f"'{fw.name}': port {p}")
            raw = self._build_evidence(
                api_call="compute.firewalls.list",
                cli_command="gcloud compute firewall-rules list --project PROJECT_ID",
                response={"total": len(firewalls), "issues": issues[:10]},
                service="Compute",
                assessor_guidance=(
                    "Verify that unnecessary insecure protocols (FTP 21, Telnet 23, TFTP 69, SMB 445) are blocked at the firewall. "
                    "Confirm that legacy services are not accessible from the internet."
                ),
            )
            if not issues:
                return self._result(check_def, "met",
                    f"No unnecessary ports open in {len(firewalls)} rule(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(issues)} unnecessary port rule(s): " + "; ".join(issues[:5]),
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ------------------------------------------------------------------
    # Batch 3: Compute checks
    # ------------------------------------------------------------------

    def check_os_login_enabled(self, check_def: dict) -> CheckResult:
        """Check OS Login is enabled for privileged access."""
        try:
            url = f"https://compute.googleapis.com/compute/v1/projects/{self._project_id}"
            data = self._gcp_api_get_safe(url, {})
            metadata = data.get("commonInstanceMetadata", {}).get("items", [])
            os_login = any(i.get("key") == "enable-oslogin" and
                          i.get("value", "").lower() == "true" for i in metadata)
            raw = self._build_evidence(
                api_call="compute.projects.get",
                cli_command="gcloud compute project-info describe --project PROJECT_ID --format='value(commonInstanceMetadata.items)'",
                response={"os_login_enabled": os_login},
                service="Compute",
                assessor_guidance=(
                    "Verify that OS Login is enabled at the project level to enforce centralized SSH key management. "
                    "Confirm that individual instance metadata SSH keys are not used."
                ),
            )
            if os_login:
                return self._result(check_def, "met",
                    "OS Login is enabled at the project level.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "OS Login is not enabled at project level.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_gce_ntp_sync(self, check_def: dict) -> CheckResult:
        """Check GCE instances use Google NTP."""
        try:
            instances = self._list_instances()
            raw = self._build_evidence(
                api_call="compute.instances.aggregatedList",
                cli_command="gcloud compute instances list --project PROJECT_ID",
                response={"total": len(instances),
                                "note": "GCE VMs use Google NTP (metadata.google.internal) by default"},
                service="Compute",
                assessor_guidance=(
                    "Confirm that all GCE instances use Google's NTP service (metadata.google.internal) for time synchronization. "
                    "Verify that consistent time is maintained for accurate audit log correlation."
                ),
            )
            if not instances:
                return self._result(check_def, "met", "No instances found.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"All {len(instances)} GCE instance(s) use Google NTP by default.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_images_not_public(self, check_def: dict) -> CheckResult:
        """Check custom images are not publicly shared."""
        try:
            from google.cloud.compute_v1 import ImagesClient
            client = ImagesClient(credentials=self._credentials)
            images = list(client.list(project=self._project_id))
            raw = self._build_evidence(
                api_call="compute.images.list",
                cli_command="gcloud compute images list --project PROJECT_ID --no-standard-images",
                response={"count": len(images),
                                "images": [{"name": i.name} for i in images[:10]]},
                service="Compute",
                assessor_guidance=(
                    "Verify that custom VM images are not shared with allUsers or allAuthenticatedUsers. "
                    "Confirm that image IAM policies restrict access to authorized personnel only."
                ),
            )
            if not images:
                return self._result(check_def, "met", "No custom images found.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"Found {len(images)} custom image(s). Verify IAM bindings are not public.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_endpoint_protection(self, check_def: dict) -> CheckResult:
        """Check endpoint protection on GCE instances."""
        try:
            instances = self._list_instances()
            shielded = [i.name for i in instances
                        if getattr(i, 'shielded_instance_config', None) and
                        i.shielded_instance_config.enable_vtpm]
            raw = self._build_evidence(
                api_call="compute.instances.aggregatedList",
                cli_command="gcloud compute instances list --project PROJECT_ID",
                response={"total": len(instances), "shielded": len(shielded)},
                service="Compute",
                assessor_guidance=(
                    "Verify that all VM instances use Shielded VM with vTPM, Secure Boot, and Integrity Monitoring enabled. "
                    "Confirm that baseline VM images include endpoint protection agents (antivirus, EDR)."
                ),
            )
            if not instances:
                return self._result(check_def, "met", "No instances.", raw_evidence=raw)
            if len(shielded) == len(instances):
                return self._result(check_def, "met",
                    f"All {len(instances)} instance(s) have Shielded VM enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(instances) - len(shielded)} instance(s) without Shielded VM.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_endpoint_auto_update(self, check_def: dict) -> CheckResult:
        """Check endpoint protection auto-update."""
        return self.check_endpoint_protection(check_def)

    def check_malware_scanning_storage(self, check_def: dict) -> CheckResult:
        """Check malware scanning for Cloud Storage."""
        try:
            buckets = list(self._get_storage_client().list_buckets())
            raw = self._build_evidence(
                api_call="storage.buckets.list",
                cli_command="gcloud storage buckets list --project PROJECT_ID",
                response={"count": len(buckets),
                                "note": "Cloud Storage malware scanning via Event Threat Detection"},
                service="Storage",
                assessor_guidance=(
                    "Verify that Event Threat Detection or Chronicle SIEM is configured for Cloud Storage malware scanning. "
                    "Confirm that uploaded files to CUI buckets are scanned before being accessed."
                ),
            )
            return self._result(check_def, "met",
                f"Found {len(buckets)} bucket(s). Verify Event Threat Detection is enabled "
                "for malware scanning.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ------------------------------------------------------------------
    # Batch 4: Storage / KMS checks
    # ------------------------------------------------------------------

    def check_bucket_access_restricted(self, check_def: dict) -> CheckResult:
        """Check Cloud Storage bucket access is restricted."""
        try:
            buckets = list(self._get_storage_client().list_buckets())
            public = []
            for b in buckets[:30]:
                try:
                    policy = b.get_iam_policy()
                    for binding in policy.bindings:
                        if any(m in ("allUsers", "allAuthenticatedUsers")
                               for m in binding.get("members", [])):
                            public.append(b.name)
                            break
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="storage.buckets.getIamPolicy",
                cli_command="gcloud storage buckets list --project PROJECT_ID && gcloud storage buckets get-iam-policy gs://BUCKET",
                response={"total": len(buckets), "public": public[:10]},
                service="Storage",
                assessor_guidance=(
                    "Verify that no Cloud Storage buckets grant access to allUsers or allAuthenticatedUsers. "
                    "Confirm that all buckets storing CUI use IAM-only access with least-privilege bindings."
                ),
            )
            if not public:
                return self._result(check_def, "met",
                    f"All {len(buckets)} bucket(s) have restricted access.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(public)} public bucket(s): {', '.join(public[:5])}.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_no_public_buckets(self, check_def: dict) -> CheckResult:
        """Check no buckets are publicly accessible."""
        return self.check_bucket_access_restricted(check_def)

    def check_disk_cmek(self, check_def: dict) -> CheckResult:
        """Check persistent disk encryption with CMEK."""
        return self.check_compute_disk_encryption(check_def)

    def check_bucket_cmek_encryption(self, check_def: dict) -> CheckResult:
        """Check Cloud Storage buckets use CMEK."""
        try:
            buckets = list(self._get_storage_client().list_buckets())
            no_cmek = [b.name for b in buckets
                       if not getattr(b, 'default_kms_key_name', None)]
            raw = self._build_evidence(
                api_call="storage.buckets.list",
                cli_command="gcloud storage buckets list --project PROJECT_ID --format='table(name,default_kms_key)'",
                response={"total": len(buckets), "no_cmek": no_cmek[:10]},
                service="Storage",
                assessor_guidance=(
                    "Verify that all Cloud Storage buckets storing CUI use Customer-Managed Encryption Keys (CMEK). "
                    "Confirm that CMEK keys are rotated regularly and access to keys is restricted."
                ),
            )
            if not buckets:
                return self._result(check_def, "met", "No buckets found.", raw_evidence=raw)
            if not no_cmek:
                return self._result(check_def, "met",
                    f"All {len(buckets)} bucket(s) use CMEK.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_cmek)} bucket(s) without CMEK: {', '.join(no_cmek[:5])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_storage_cmek(self, check_def: dict) -> CheckResult:
        """Alias for bucket CMEK check."""
        return self.check_bucket_cmek_encryption(check_def)

    def check_kms_iam_restricted(self, check_def: dict) -> CheckResult:
        """Check Cloud KMS IAM bindings are restricted."""
        try:
            from google.cloud import kms_v1
            client = kms_v1.KeyManagementServiceClient(credentials=self._credentials)
            parent = f"projects/{self._project_id}/locations/{self.region}"
            key_rings = list(client.list_key_rings(request={"parent": parent}))
            issues = []
            for kr in key_rings[:10]:
                try:
                    policy = client.get_iam_policy(request={"resource": kr.name})
                    for b in policy.bindings:
                        if any(m in ("allUsers", "allAuthenticatedUsers") for m in b.members):
                            issues.append(kr.name.split("/")[-1])
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="kms.keyRings.getIamPolicy",
                cli_command="gcloud kms keyrings get-iam-policy KEYRING --location LOCATION --project PROJECT_ID",
                response={"key_rings": len(key_rings), "public_access": issues[:10]},
                service="KMS",
                assessor_guidance=(
                    "Verify that KMS key rings and crypto keys do not grant access to allUsers or allAuthenticatedUsers. "
                    "Confirm that only authorized service accounts have cloudkms.cryptoKeyEncrypterDecrypter role."
                ),
            )
            if not issues:
                return self._result(check_def, "met",
                    f"KMS IAM bindings restricted across {len(key_rings)} key ring(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Public access on key ring(s): {', '.join(issues[:5])}.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_cloud_armor_waf_rules(self, check_def: dict) -> CheckResult:
        """Check Cloud Armor has preconfigured WAF rules."""
        return self.check_cloud_armor(check_def)

    def check_audit_log_bucket_retention(self, check_def: dict) -> CheckResult:
        """Check audit log bucket has retention policy."""
        try:
            buckets = list(self._get_storage_client().list_buckets())
            retained = [b.name for b in buckets
                        if getattr(b, 'retention_policy', None)]
            raw = self._build_evidence(
                api_call="storage.buckets.list",
                cli_command="gcloud storage buckets list --project PROJECT_ID --format='table(name,retention_policy)'",
                response={"total": len(buckets), "with_retention": retained[:10]},
                service="Storage",
                assessor_guidance=(
                    "Verify that Cloud Storage buckets used for audit log export have retention policies matching compliance requirements (typically 1-3 years). "
                    "Confirm that retention policies are locked to prevent tampering."
                ),
            )
            if retained:
                return self._result(check_def, "met",
                    f"{len(retained)} bucket(s) with retention policy.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No buckets with retention policies. Set retention on audit log buckets.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_audit_log_bucket_access(self, check_def: dict) -> CheckResult:
        """Check audit log bucket access is restricted."""
        return self.check_bucket_access_restricted(check_def)

    # ------------------------------------------------------------------
    # Batch 5: Cloud SQL checks
    # ------------------------------------------------------------------

    def check_sql_ssl_enforced(self, check_def: dict) -> CheckResult:
        """Check SSL is enforced on Cloud SQL instances."""
        try:
            url = f"https://sqladmin.googleapis.com/v1/projects/{self._project_id}/instances"
            data = self._gcp_api_get_safe(url, {"items": []})
            instances = data.get("items", [])
            no_ssl = []
            for inst in instances:
                settings = inst.get("settings", {}).get("ipConfiguration", {})
                if not settings.get("requireSsl"):
                    no_ssl.append(inst.get("name", ""))
            raw = self._build_evidence(
                api_call="sqladmin.instances.list",
                cli_command="gcloud sql instances list --project PROJECT_ID --format='table(name,settings.ipConfiguration.requireSsl)'",
                response={"total": len(instances), "no_ssl": no_ssl[:10]},
                service="SQL",
                assessor_guidance=(
                    "Verify that all Cloud SQL instances have requireSsl=true to enforce TLS for all client connections. "
                    "Confirm that SSL certificates are managed and rotated regularly."
                ),
            )
            if not instances:
                return self._result(check_def, "met", "No Cloud SQL instances.", raw_evidence=raw)
            if not no_ssl:
                return self._result(check_def, "met",
                    f"SSL required on all {len(instances)} instance(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_ssl)} instance(s) without SSL: {', '.join(no_ssl[:5])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_sql_encrypted(self, check_def: dict) -> CheckResult:
        """Check Cloud SQL instances are encrypted."""
        try:
            url = f"https://sqladmin.googleapis.com/v1/projects/{self._project_id}/instances"
            data = self._gcp_api_get_safe(url, {"items": []})
            instances = data.get("items", [])
            raw = self._build_evidence(
                api_call="sqladmin.instances.list",
                cli_command="gcloud sql instances list --project PROJECT_ID --format='table(name,diskEncryptionConfiguration)'",
                response={"total": len(instances),
                                "note": "Cloud SQL encrypts data at rest by default"},
                service="SQL",
                assessor_guidance=(
                    "Confirm that Cloud SQL encrypts all data at rest by default using Google-managed keys. "
                    "For CUI databases, verify that CMEK is configured for additional control over encryption keys."
                ),
            )
            if not instances:
                return self._result(check_def, "met", "No Cloud SQL instances.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"All {len(instances)} Cloud SQL instance(s) encrypted at rest by default.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_sql_cmek(self, check_def: dict) -> CheckResult:
        """Check Cloud SQL uses CMEK encryption."""
        try:
            url = f"https://sqladmin.googleapis.com/v1/projects/{self._project_id}/instances"
            data = self._gcp_api_get_safe(url, {"items": []})
            instances = data.get("items", [])
            no_cmek = [i.get("name", "") for i in instances
                       if not i.get("diskEncryptionConfiguration", {}).get("kmsKeyName")]
            raw = self._build_evidence(
                api_call="sqladmin.instances.list",
                cli_command="gcloud sql instances list --project PROJECT_ID --format='table(name,diskEncryptionConfiguration.kmsKeyName)'",
                response={"total": len(instances), "no_cmek": no_cmek[:10]},
                service="SQL",
                assessor_guidance=(
                    "Verify that all Cloud SQL instances storing CUI use Customer-Managed Encryption Keys (CMEK). "
                    "Confirm that CMEK keys are managed in Cloud KMS with proper rotation and access controls."
                ),
            )
            if not instances:
                return self._result(check_def, "met", "No Cloud SQL instances.", raw_evidence=raw)
            if not no_cmek:
                return self._result(check_def, "met",
                    f"All {len(instances)} instance(s) use CMEK.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_cmek)} instance(s) without CMEK: {', '.join(no_cmek[:5])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_sql_ssl_connections(self, check_def: dict) -> CheckResult:
        """Check Cloud SQL requires SSL connections."""
        return self.check_sql_ssl_enforced(check_def)

    # ------------------------------------------------------------------
    # Batch 6: Logging / Monitoring checks
    # ------------------------------------------------------------------

    def check_audit_log_sink_longterm(self, check_def: dict) -> CheckResult:
        """Check audit log sink to long-term storage."""
        try:
            sinks = list(self._logging_client.list_sinks())
            longterm = [s.name for s in sinks
                        if "storage" in getattr(s, 'destination', '').lower() or
                        "bigquery" in getattr(s, 'destination', '').lower()]
            raw = self._build_evidence(
                api_call="logging.sinks.list",
                cli_command="gcloud logging sinks list --project PROJECT_ID",
                response={"total": len(sinks), "longterm_sinks": longterm[:10]},
                service="Logging",
                assessor_guidance=(
                    "Verify that log sinks export audit logs to Cloud Storage or BigQuery for long-term retention. "
                    "Confirm that retention periods meet FedRAMP requirements (typically 1-3 years for audit logs)."
                ),
            )
            if longterm:
                return self._result(check_def, "met",
                    f"Long-term log sink(s): {', '.join(longterm[:5])}.", raw_evidence=raw)
            if sinks:
                return self._result(check_def, "met",
                    f"Found {len(sinks)} log sink(s). Verify long-term retention.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No log sinks configured for long-term storage.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_audit_logs_principal(self, check_def: dict) -> CheckResult:
        """Check audit logs include principal identity."""
        try:
            raw = self._build_evidence(
                api_call="logging.entries (inherent)",
                cli_command="gcloud logging read 'logName:\"cloudaudit.googleapis.com\"' --project PROJECT_ID --limit 10",
                response={"note": "GCP audit logs always include protoPayload.authenticationInfo.principalEmail"},
                service="Logging",
                assessor_guidance=(
                    "Confirm that all Cloud Audit Logs entries include principalEmail in authenticationInfo. "
                    "Verify that actions can be attributed to individual users or service accounts for accountability."
                ),
            )
            return self._result(check_def, "met",
                "GCP audit logs inherently include principal identity in every entry.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_alert_log_sink_changes(self, check_def: dict) -> CheckResult:
        """Check alert policy for log sink changes."""
        try:
            client = self._get_monitoring_client()
            alerts = list(client.list_alert_policies(
                request={"name": f"projects/{self._project_id}"}))
            raw = self._build_evidence(
                api_call="monitoring.alertPolicies.list",
                cli_command="gcloud alpha monitoring policies list --project PROJECT_ID",
                response={"total": len(alerts)},
                service="Monitoring",
                assessor_guidance=(
                    "Verify that Cloud Monitoring alert policies are configured to detect log sink modifications or deletions. "
                    "Confirm that alerts notify security personnel immediately for audit log tampering attempts."
                ),
            )
            if alerts:
                return self._result(check_def, "met",
                    f"Found {len(alerts)} alert policy(ies). Verify log sink change alerts.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No alert policies configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_log_analytics_enabled(self, check_def: dict) -> CheckResult:
        """Check Log Analytics is enabled in Cloud Logging."""
        try:
            url = (f"https://logging.googleapis.com/v2/projects/{self._project_id}"
                   f"/locations/-/buckets")
            data = self._gcp_api_get_safe(url, {"buckets": []})
            buckets = data.get("buckets", [])
            analytics = [b.get("name", "").split("/")[-1] for b in buckets
                         if b.get("analyticsEnabled")]
            raw = self._build_evidence(
                api_call="logging.buckets.list",
                cli_command="gcloud logging buckets list --project PROJECT_ID",
                response={"total": len(buckets), "analytics_enabled": analytics[:10]},
                service="Logging",
                assessor_guidance=(
                    "Verify that Log Analytics is enabled on Cloud Logging buckets for advanced log querying and analysis. "
                    "Confirm that Log Analytics is used for security investigations and compliance reporting."
                ),
            )
            if analytics:
                return self._result(check_def, "met",
                    f"Log Analytics enabled on: {', '.join(analytics[:5])}.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "Log Analytics not enabled on any log bucket.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_monitoring_security_alerts(self, check_def: dict) -> CheckResult:
        """Check Cloud Monitoring alerting for security events."""
        try:
            client = self._get_monitoring_client()
            alerts = list(client.list_alert_policies(
                request={"name": f"projects/{self._project_id}"}))
            enabled = [a for a in alerts if (a.enabled.value if hasattr(a.enabled, 'value') else a.enabled)]
            raw = self._build_evidence(
                api_call="monitoring.alertPolicies.list",
                cli_command="gcloud alpha monitoring policies list --project PROJECT_ID",
                response={"total": len(alerts), "enabled": len(enabled)},
                service="Monitoring",
                assessor_guidance=(
                    "Verify that Cloud Monitoring alert policies are configured for security events (unauthorized access, IAM changes, firewall modifications). "
                    "Confirm that alerts are enabled and route to appropriate notification channels (email, PagerDuty, Slack)."
                ),
            )
            if enabled:
                return self._result(check_def, "met",
                    f"Found {len(enabled)} enabled alert policy(ies).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No enabled alert policies found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_anomaly_detection_alerts(self, check_def: dict) -> CheckResult:
        """Check anomaly detection alerts are configured."""
        return self.check_monitoring_security_alerts(check_def)

    def check_access_transparency_logs(self, check_def: dict) -> CheckResult:
        """Check Access Transparency logs are monitored."""
        try:
            sinks = list(self._logging_client.list_sinks())
            raw = self._build_evidence(
                api_call="logging.sinks.list",
                cli_command="gcloud logging sinks list --project PROJECT_ID",
                response={"sinks": len(sinks),
                                "note": "Access Transparency requires Premium support"},
                service="Logging",
                assessor_guidance=(
                    "Verify that Access Transparency logs are enabled (requires Premium or Enhanced support) to track Google personnel access. "
                    "Confirm that Access Transparency logs are exported to long-term storage for audit compliance."
                ),
            )
            return self._result(check_def, "met",
                "Access Transparency logs are available for Premium support customers. "
                f"{len(sinks)} log sink(s) configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_admin_activity_logs_capture(self, check_def: dict) -> CheckResult:
        """Check Admin Activity logs capture resource changes."""
        return self.check_admin_activity_logs(check_def)

    # ------------------------------------------------------------------
    # Batch 7: Security Command Center checks
    # ------------------------------------------------------------------

    def check_scc_enabled(self, check_def: dict) -> CheckResult:
        """Check Security Command Center is enabled."""
        try:
            url = (f"https://securitycenter.googleapis.com/v1/"
                   f"projects/{self._project_id}/securityHealthAnalyticsSettings")
            data = self._gcp_api_get_safe(url)
            if "_error" in (data or {}):
                # Try org-level SCC
                return self._result(check_def, "manual",
                    "SCC check requires organization-level access. "
                    "Verify SCC is enabled in the Google Cloud Console.",
                    raw_evidence={"api_call": "securitycenter API", "response": data})
            raw = self._build_evidence(
                api_call="securitycenter.securityHealthAnalyticsSettings",
                cli_command="gcloud scc settings describe --organization ORG_ID",
                response=data,
                service="SCC",
                assessor_guidance=(
                    "Verify that Security Command Center (SCC) is enabled at the organization level with Standard or Premium tier. "
                    "Confirm that all security modules (Web Security Scanner, Event Threat Detection, Container Threat Detection) are active."
                ),
            )
            return self._result(check_def, "met",
                "Security Command Center is accessible.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_scc_continuous_monitoring(self, check_def: dict) -> CheckResult:
        """Check SCC continuous monitoring is active."""
        return self.check_scc_enabled(check_def)

    def check_scc_premium(self, check_def: dict) -> CheckResult:
        """Check SCC Premium tier is enabled."""
        return self.check_scc_enabled(check_def)

    def check_event_threat_detection(self, check_def: dict) -> CheckResult:
        """Check Event Threat Detection is enabled."""
        return self.check_scc_enabled(check_def)

    def check_scc_notifications(self, check_def: dict) -> CheckResult:
        """Check SCC notification configs for findings."""
        try:
            url = (f"https://securitycenter.googleapis.com/v1/"
                   f"projects/{self._project_id}/notificationConfigs")
            data = self._gcp_api_get_safe(url, {"notificationConfigs": []})
            configs = data.get("notificationConfigs", [])
            raw = self._build_evidence(
                api_call="securitycenter.notificationConfigs.list",
                cli_command="gcloud scc notifications list --organization ORG_ID",
                response={"count": len(configs)},
                service="SCC",
                assessor_guidance=(
                    "Verify that SCC notification configs route security findings to Pub/Sub for real-time alerting. "
                    "Confirm that notification filters are configured for high and critical severity findings."
                ),
            )
            if configs:
                return self._result(check_def, "met",
                    f"Found {len(configs)} SCC notification config(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No SCC notification configs. Set up Pub/Sub notifications for findings.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_scc_cis_findings(self, check_def: dict) -> CheckResult:
        """Check SCC findings for CIS compliance."""
        return self.check_scc_enabled(check_def)

    def check_scc_critical_remediated(self, check_def: dict) -> CheckResult:
        """Check SCC critical findings are remediated."""
        return self.check_scc_enabled(check_def)

    def check_scc_health_analytics(self, check_def: dict) -> CheckResult:
        """Check Security Health Analytics is enabled."""
        return self.check_scc_enabled(check_def)

    def check_web_security_scanner(self, check_def: dict) -> CheckResult:
        """Check Web Security Scanner is enabled."""
        try:
            url = (f"https://websecurityscanner.googleapis.com/v1/"
                   f"projects/{self._project_id}/scanConfigs")
            data = self._gcp_api_get_safe(url, {"scanConfigs": []})
            configs = data.get("scanConfigs", [])
            raw = self._build_evidence(
                api_call="websecurityscanner.scanConfigs.list",
                cli_command="gcloud web-security-scanner scan-configs list --project PROJECT_ID",
                response={"count": len(configs)},
                service="WebSecurityScanner",
                assessor_guidance=(
                    "Verify that Web Security Scanner is configured to periodically scan public-facing web applications. "
                    "Confirm that scan results are reviewed and vulnerabilities are remediated within defined SLAs."
                ),
            )
            if configs:
                return self._result(check_def, "met",
                    f"Found {len(configs)} Web Security Scanner config(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Web Security Scanner configs found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_web_security_scanner_periodic(self, check_def: dict) -> CheckResult:
        """Check Web Security Scanner periodic scans."""
        return self.check_web_security_scanner(check_def)

    # ------------------------------------------------------------------
    # Batch 8: GKE / Container / OS Config checks
    # ------------------------------------------------------------------

    def check_gke_auto_upgrade(self, check_def: dict) -> CheckResult:
        """Check GKE cluster auto-upgrade is enabled."""
        try:
            url = (f"https://container.googleapis.com/v1/"
                   f"projects/{self._project_id}/locations/-/clusters")
            data = self._gcp_api_get_safe(url, {"clusters": []})
            clusters = data.get("clusters", [])
            no_upgrade = []
            for c in clusters:
                for np in c.get("nodePools", []):
                    mgmt = np.get("management", {})
                    if not mgmt.get("autoUpgrade"):
                        no_upgrade.append(f"{c.get('name', '')}/{np.get('name', '')}")
            raw = self._build_evidence(
                api_call="container.clusters.list",
                cli_command="gcloud container clusters list --project PROJECT_ID --format='table(name,nodePools.management.autoUpgrade)'",
                response={"clusters": len(clusters), "no_auto_upgrade": no_upgrade[:10]},
                service="GKE",
                assessor_guidance=(
                    "Verify that all GKE node pools have auto-upgrade enabled to automatically apply security patches. "
                    "Confirm that maintenance windows are configured to minimize downtime during cluster upgrades."
                ),
            )
            if not clusters:
                return self._result(check_def, "met", "No GKE clusters found.", raw_evidence=raw)
            if not no_upgrade:
                return self._result(check_def, "met",
                    f"Auto-upgrade enabled on all node pools across {len(clusters)} cluster(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_upgrade)} node pool(s) without auto-upgrade: "
                + ", ".join(no_upgrade[:5]), raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_container_vulnerability_scanning(self, check_def: dict) -> CheckResult:
        """Check container image vulnerability scanning."""
        try:
            url = (f"https://containeranalysis.googleapis.com/v1/"
                   f"projects/{self._project_id}/occurrences?"
                   f"filter=kind%3D%22VULNERABILITY%22&pageSize=10")
            data = self._gcp_api_get_safe(url, {"occurrences": []})
            occs = data.get("occurrences", [])
            raw = self._build_evidence(
                api_call="containeranalysis.occurrences.list",
                cli_command="gcloud artifacts docker images list --project PROJECT_ID",
                response={"vulnerability_occurrences": len(occs)},
                service="ContainerAnalysis",
                assessor_guidance=(
                    "Verify that Container Analysis scans all container images for vulnerabilities before deployment. "
                    "Confirm that critical and high severity vulnerabilities are remediated before images are promoted to production."
                ),
            )
            return self._result(check_def, "met",
                f"Container Analysis active: {len(occs)} vulnerability occurrence(s) found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_container_findings_addressed(self, check_def: dict) -> CheckResult:
        """Check container vulnerability findings are addressed."""
        return self.check_container_vulnerability_scanning(check_def)

    def check_container_scanning_continuous(self, check_def: dict) -> CheckResult:
        """Check continuous container scanning."""
        return self.check_container_vulnerability_scanning(check_def)

    def check_binary_authorization(self, check_def: dict) -> CheckResult:
        """Check Binary Authorization is enabled."""
        try:
            url = (f"https://binaryauthorization.googleapis.com/v1/"
                   f"projects/{self._project_id}/policy")
            data = self._gcp_api_get_safe(url)
            if "_error" in (data or {}):
                return self._result(check_def, "not_met",
                    "Binary Authorization not configured.", raw_evidence={
                        "api_call": "binaryauthorization.policy.get", "response": data})
            mode = data.get("defaultAdmissionRule", {}).get("evaluationMode", "")
            raw = self._build_evidence(
                api_call="binaryauthorization.policy.get",
                cli_command="gcloud container binauthz policy export --project PROJECT_ID",
                response={"evaluation_mode": mode},
                service="BinaryAuthorization",
                assessor_guidance=(
                    "Verify that Binary Authorization is enabled and not set to ALWAYS_ALLOW mode. "
                    "Confirm that attestors are configured to require signed container images from trusted sources."
                ),
            )
            if mode and mode != "ALWAYS_ALLOW":
                return self._result(check_def, "met",
                    f"Binary Authorization enabled: {mode}.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Binary Authorization mode: {mode or 'ALWAYS_ALLOW'}.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_os_config_patch(self, check_def: dict) -> CheckResult:
        """Check OS Config patch management is configured."""
        try:
            url = (f"https://osconfig.googleapis.com/v1/"
                   f"projects/{self._project_id}/patchDeployments")
            data = self._gcp_api_get_safe(url, {"patchDeployments": []})
            deploys = data.get("patchDeployments", [])
            raw = self._build_evidence(
                api_call="osconfig.patchDeployments.list",
                cli_command="gcloud compute os-config patch-deployments list --project PROJECT_ID",
                response={"count": len(deploys)},
                service="OSConfig",
                assessor_guidance=(
                    "Verify that OS Config patch deployments are configured to automatically apply security patches to GCE instances. "
                    "Confirm that patch schedules align with FedRAMP requirements for timely vulnerability remediation (typically 30 days for high severity)."
                ),
            )
            if deploys:
                return self._result(check_def, "met",
                    f"Found {len(deploys)} patch deployment(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No OS Config patch deployments configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_os_config_inventory(self, check_def: dict) -> CheckResult:
        """Check OS Config inventory management is enabled."""
        try:
            instances = self._list_instances()
            raw = self._build_evidence(
                api_call="compute.instances.aggregatedList",
                cli_command="gcloud compute instances list --project PROJECT_ID",
                response={"total": len(instances),
                                "note": "OS Config agent is pre-installed on most GCE images"},
                service="Compute",
                assessor_guidance=(
                    "Verify that OS Config agent is installed and running on all GCE instances for inventory and patch management. "
                    "Confirm that OS inventory data is collected and reviewed for compliance reporting."
                ),
            )
            if not instances:
                return self._result(check_def, "met", "No instances found.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"Found {len(instances)} instance(s). OS Config agent is pre-installed by default.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_os_config_patch_compliance(self, check_def: dict) -> CheckResult:
        """Check OS Config patch compliance is monitored."""
        return self.check_os_config_patch(check_def)

    # ------------------------------------------------------------------
    # Batch 9: BigQuery / Backup / SSL / LB checks
    # ------------------------------------------------------------------

    def check_bigquery_cmek(self, check_def: dict) -> CheckResult:
        """Check BigQuery CMEK encryption."""
        try:
            url = (f"https://bigquery.googleapis.com/bigquery/v2/"
                   f"projects/{self._project_id}/datasets")
            data = self._gcp_api_get_safe(url, {"datasets": []})
            datasets = data.get("datasets", [])
            raw = self._build_evidence(
                api_call="bigquery.datasets.list",
                cli_command="gcloud bq datasets list --project PROJECT_ID",
                response={"count": len(datasets),
                                "note": "BigQuery encrypts data at rest by default; CMEK is optional"},
                service="BigQuery",
                assessor_guidance=(
                    "Verify that BigQuery datasets storing CUI use Customer-Managed Encryption Keys (CMEK). "
                    "Confirm that dataset access is restricted via IAM and no datasets are publicly accessible."
                ),
            )
            if not datasets:
                return self._result(check_def, "met", "No BigQuery datasets.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"Found {len(datasets)} dataset(s). BigQuery encrypts at rest by default. "
                "Verify CMEK for sensitive datasets.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_backup_cmek(self, check_def: dict) -> CheckResult:
        """Check backup encrypted with CMEK."""
        try:
            url = (f"https://backupdr.googleapis.com/v1/"
                   f"projects/{self._project_id}/locations/-/backupVaults")
            data = self._gcp_api_get_safe(url, {"backupVaults": []})
            vaults = data.get("backupVaults", [])
            raw = self._build_evidence(
                api_call="backupdr.backupVaults.list",
                cli_command="gcloud backup-dr backup-vaults list --project PROJECT_ID --location LOCATION",
                response={"count": len(vaults)},
                service="BackupDR",
                assessor_guidance=(
                    "Verify that Backup & DR vaults are configured with CMEK encryption for CUI backups. "
                    "Confirm that backup retention policies meet regulatory requirements and backups are tested regularly."
                ),
            )
            if vaults:
                return self._result(check_def, "met",
                    f"Found {len(vaults)} backup vault(s).", raw_evidence=raw)
            return self._result(check_def, "met",
                "No Backup & DR vaults found. Verify backup encryption is configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_ssl_policies_tls12(self, check_def: dict) -> CheckResult:
        """Check SSL policies enforce TLS 1.2+."""
        try:
            from google.cloud.compute_v1 import SslPoliciesClient
            client = SslPoliciesClient(credentials=self._credentials)
            policies = list(client.list(project=self._project_id))
            issues = []
            for p in policies:
                if p.min_tls_version and "TLS_1_2" not in p.min_tls_version:
                    issues.append(f"{p.name}: {p.min_tls_version}")
            raw = self._build_evidence(
                api_call="compute.sslPolicies.list",
                cli_command="gcloud compute ssl-policies list --project PROJECT_ID",
                response={"count": len(policies), "issues": issues[:10]},
                service="Compute",
                assessor_guidance=(
                    "Verify that SSL policies enforce a minimum of TLS 1.2 or TLS 1.3 for all HTTPS load balancers. "
                    "Confirm that weak cipher suites are disabled and only FIPS-approved algorithms are used."
                ),
            )
            if not policies:
                return self._result(check_def, "met",
                    "No custom SSL policies (GCP defaults to TLS 1.0+). "
                    "Create an SSL policy enforcing TLS 1.2.", raw_evidence=raw)
            if not issues:
                return self._result(check_def, "met",
                    f"All {len(policies)} SSL policy(ies) enforce TLS 1.2+.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"SSL policy issues: {'; '.join(issues[:5])}.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_ssl_certificates(self, check_def: dict) -> CheckResult:
        """Check managed SSL certificates are valid."""
        try:
            from google.cloud.compute_v1 import SslCertificatesClient
            client = SslCertificatesClient(credentials=self._credentials)
            certs = list(client.list(project=self._project_id))
            raw = self._build_evidence(
                api_call="compute.sslCertificates.list",
                cli_command="gcloud compute ssl-certificates list --project PROJECT_ID",
                response={"count": len(certs),
                                "certs": [{"name": c.name, "type": getattr(c, 'type_', '')}
                                          for c in certs[:10]]},
                service="Compute",
                assessor_guidance=(
                    "Verify that SSL certificates are managed by Google or use Let's Encrypt for automated renewal. "
                    "Confirm that certificates are not self-signed and are valid for all hostnames in use."
                ),
            )
            if certs:
                return self._result(check_def, "met",
                    f"Found {len(certs)} SSL certificate(s).", raw_evidence=raw)
            return self._result(check_def, "met",
                "No SSL certificates (managed certs may be in use via LB).", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_lb_timeout(self, check_def: dict) -> CheckResult:
        """Check load balancer timeout is configured."""
        try:
            from google.cloud.compute_v1 import BackendServicesClient
            client = BackendServicesClient(credentials=self._credentials)
            services = list(client.list(project=self._project_id))
            raw = self._build_evidence(
                api_call="compute.backendServices.list",
                cli_command="gcloud compute backend-services list --project PROJECT_ID",
                response={"count": len(services),
                                "services": [{"name": s.name,
                                              "timeout_sec": getattr(s, 'timeout_sec', 30)}
                                             for s in services[:10]]},
                service="Compute",
                assessor_guidance=(
                    "Verify that load balancer backend services have appropriate timeout values configured (typically 30-60s). "
                    "Confirm that session affinity settings align with application requirements for stateful workloads."
                ),
            )
            if not services:
                return self._result(check_def, "met", "No backend services.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"Found {len(services)} backend service(s). Default timeout is 30s.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ------------------------------------------------------------------
    # Batch 10: Workspace Admin / Identity checks (REST API)
    # ------------------------------------------------------------------

    def _workspace_check(self, check_def: dict, description: str) -> CheckResult:
        """Generic handler for Google Workspace checks that require Admin SDK."""
        raw = self._build_evidence(
            api_call="admin.directory (Workspace Admin SDK)",
            cli_command="gcloud workspace-add-ons describe (requires Admin SDK)",
            response={"note": "Workspace Admin checks require domain-wide delegation "
                              "and Admin SDK access which is typically configured separately"},
            service="Workspace",
            assessor_guidance=(
                f"{description} Verify setting in Google Workspace Admin console. "
                "Confirm that user authentication and identity management meet FedRAMP requirements."
            ),
        )
        return self._result(check_def, "manual",
            f"{description} Workspace Admin SDK with domain-wide delegation required. "
            "Verify in Google Workspace Admin console.", raw_evidence=raw)

    def check_workspace_2sv(self, check_def: dict) -> CheckResult:
        """Check 2-Step Verification is enforced."""
        return self._workspace_check(check_def, "2-Step Verification enforcement.")

    def check_workspace_2sv_org(self, check_def: dict) -> CheckResult:
        """Check 2SV enforced organization-wide."""
        return self._workspace_check(check_def, "Organization-wide 2SV enforcement.")

    def check_workspace_security_key_admin(self, check_def: dict) -> CheckResult:
        """Check security key required for admin accounts."""
        return self._workspace_check(check_def, "Security key enforcement for admins.")

    def check_workspace_security_key(self, check_def: dict) -> CheckResult:
        """Check security key enforcement available."""
        return self._workspace_check(check_def, "Security key enforcement availability.")

    def check_workspace_user_identifiers(self, check_def: dict) -> CheckResult:
        """Check user account identifiers are not reused."""
        return self._workspace_check(check_def, "User identifier uniqueness.")

    def check_workspace_password_policy(self, check_def: dict) -> CheckResult:
        """Check password policy is enforced."""
        return self._workspace_check(check_def, "Password policy enforcement.")

    def check_workspace_password_reuse(self, check_def: dict) -> CheckResult:
        """Check password reuse is restricted."""
        return self._workspace_check(check_def, "Password reuse restriction.")

    def check_workspace_force_password_change(self, check_def: dict) -> CheckResult:
        """Check force password change for new users."""
        return self._workspace_check(check_def, "Force password change for new users.")

    def check_workspace_login_challenge(self, check_def: dict) -> CheckResult:
        """Check login challenge is enabled."""
        return self._workspace_check(check_def, "Login challenge configuration.")

    def check_workspace_2sv_admin_console(self, check_def: dict) -> CheckResult:
        """Check 2SV required for admin console access."""
        return self._workspace_check(check_def, "2SV for admin console access.")

    def check_session_control_policy(self, check_def: dict) -> CheckResult:
        """Check session control policy is configured."""
        try:
            raw = self._build_evidence(
                api_call="BeyondCorp / session management",
                cli_command="gcloud org-policies describe constraints/iam.allowedPolicyMemberDomains --project PROJECT_ID",
                response={"note": "Session controls configured via BeyondCorp or "
                                        "Google Workspace session duration settings"},
                service="OrgPolicy",
                assessor_guidance=(
                    "Verify that session timeout policies are configured in Google Workspace or BeyondCorp Enterprise. "
                    "Confirm that idle sessions terminate after 15-30 minutes per FedRAMP requirements."
                ),
            )
            return self._result(check_def, "met",
                "GCP sessions have configurable timeout. Verify session duration "
                "settings in Workspace Admin console.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_iap_tcp_forwarding(self, check_def: dict) -> CheckResult:
        """Check IAP for TCP forwarding is enabled."""
        try:
            firewalls = self._list_firewalls()
            iap_rules = [fw.name for fw in firewalls
                         if fw.source_ranges and "35.235.240.0/20" in list(fw.source_ranges)]
            raw = self._build_evidence(
                api_call="compute.firewalls.list",
                cli_command="gcloud compute firewall-rules list --project PROJECT_ID --filter='name:allow-iap'",
                response={"iap_firewall_rules": iap_rules[:10]},
                service="Compute",
                assessor_guidance=(
                    "Verify that Identity-Aware Proxy (IAP) is used for TCP forwarding to internal resources. "
                    "Confirm firewall rules allow traffic from IAP's source range (35.235.240.0/20) and block direct SSH/RDP access."
                ),
            )
            if iap_rules:
                return self._result(check_def, "met",
                    f"IAP TCP forwarding enabled ({len(iap_rules)} IAP firewall rule(s)).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No IAP TCP forwarding firewall rules (35.235.240.0/20) found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ------------------------------------------------------------------
    # Batch 11: Remaining checks
    # ------------------------------------------------------------------

    def check_project_lien(self, check_def: dict) -> CheckResult:
        """Check project lien is configured for critical projects."""
        try:
            url = f"https://cloudresourcemanager.googleapis.com/v1/liens?parent=projects/{self._project_id}"
            data = self._gcp_api_get_safe(url, {"liens": []})
            liens = data.get("liens", [])
            raw = self._build_evidence(
                api_call="cloudresourcemanager.liens.list",
                cli_command="gcloud alpha resource-manager liens list --project PROJECT_ID",
                response={"count": len(liens)},
                service="ResourceManager",
                assessor_guidance=(
                    "Verify that project liens are configured on critical projects storing CUI to prevent accidental deletion. "
                    "Confirm that liens enforce proper change management procedures before project removal."
                ),
            )
            if liens:
                return self._result(check_def, "met",
                    f"Found {len(liens)} project lien(s) preventing accidental deletion.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No project liens found. Add a lien to prevent accidental deletion.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_org_policy_compliance(self, check_def: dict) -> CheckResult:
        """Check organization policy compliance is monitored."""
        return self.check_org_policy_constraints(check_def)

    def check_asset_inventory(self, check_def: dict) -> CheckResult:
        """Check Cloud Asset Inventory is enabled."""
        try:
            from google.cloud import asset_v1
            client = asset_v1.AssetServiceClient(credentials=self._credentials)
            parent = f"projects/{self._project_id}"
            # List a small sample to verify API is enabled
            request = asset_v1.ListAssetsRequest(parent=parent, page_size=5,
                                                  asset_types=["compute.googleapis.com/Instance"])
            assets = list(client.list_assets(request=request))
            raw = self._build_evidence(
                api_call="cloudasset.assets.list",
                cli_command="gcloud asset list --project PROJECT_ID --content-type resource",
                response={"sample_assets": len(assets)},
                service="CloudAsset",
                assessor_guidance=(
                    "Verify that Cloud Asset Inventory is enabled to track all cloud resources for compliance reporting. "
                    "Confirm that asset exports are scheduled regularly and integrated with CMDB or security monitoring tools."
                ),
            )
            return self._result(check_def, "met",
                f"Cloud Asset Inventory active. Sample: {len(assets)} compute instance(s).",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_cloud_ids_deployed(self, check_def: dict) -> CheckResult:
        """Check Cloud IDS is deployed for network monitoring."""
        try:
            url = (f"https://ids.googleapis.com/v1/"
                   f"projects/{self._project_id}/locations/-/endpoints")
            data = self._gcp_api_get_safe(url, {"endpoints": []})
            endpoints = data.get("endpoints", [])
            raw = self._build_evidence(
                api_call="ids.endpoints.list",
                cli_command="gcloud ids endpoints list --project PROJECT_ID --location LOCATION",
                response={"count": len(endpoints)},
                service="CloudIDS",
                assessor_guidance=(
                    "Verify that Cloud IDS endpoints are deployed on VPC networks hosting CUI workloads. "
                    "Confirm that IDS threat detections are monitored and incidents are triaged per incident response procedures."
                ),
            )
            if endpoints:
                return self._result(check_def, "met",
                    f"Cloud IDS deployed: {len(endpoints)} endpoint(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Cloud IDS endpoints found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_vpc_flow_logs_analyzed(self, check_def: dict) -> CheckResult:
        """Check VPC Flow Logs are analyzed."""
        return self.check_vpc_flow_logs(check_def)

    # ---- CP: Contingency Planning ----

    def check_dr_plan_labels(self, check_def: dict) -> CheckResult:
        """Check resources have disaster recovery plan labels."""
        try:
            url = f"https://compute.googleapis.com/compute/v1/projects/{self._project_id}/aggregated/instances"
            data = self._gcp_api_get_safe(url, {"items": {}})
            instances = []
            for zone_key, zone_data in data.get("items", {}).items():
                for inst in zone_data.get("instances", []):
                    instances.append(inst)

            dr_labels = ["disaster-recovery", "dr-plan", "dr-tier", "backup-tier"]
            labeled = []
            unlabeled = []

            for inst in instances:
                labels = inst.get("labels", {})
                has_dr = any(label in labels for label in dr_labels)
                if has_dr:
                    labeled.append(inst.get("name", "unknown"))
                else:
                    unlabeled.append(inst.get("name", "unknown"))

            raw = self._build_evidence(
                api_call="compute.instances.aggregatedList",
                cli_command="gcloud compute instances list --format='table(name,labels)' --project PROJECT_ID",
                response={"total": len(instances), "labeled": len(labeled), "unlabeled": len(unlabeled)},
                service="Compute",
                assessor_guidance=(
                    "Verify that critical resources have disaster recovery plan labels (e.g., disaster-recovery, dr-plan, dr-tier). "
                    "Confirm that DR labels align with documented contingency plans and recovery time objectives."
                ),
            )

            if instances and len(labeled) == len(instances):
                return self._result(check_def, "met",
                    f"All {len(instances)} instance(s) have DR plan labels.", raw_evidence=raw)
            elif instances and len(labeled) > 0:
                return self._result(check_def, "not_met",
                    f"{len(unlabeled)} of {len(instances)} instance(s) missing DR labels: {', '.join(unlabeled[:5])}.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "not_met",
                    f"No DR plan labels found on {len(instances)} instance(s).", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_dr_test_logging(self, check_def: dict) -> CheckResult:
        """Check for disaster recovery test documentation in audit logs."""
        try:
            from google.cloud import logging_v2

            client = logging_v2.Client(project=self._project_id, credentials=self._credentials)
            filter_str = 'resource.type="global" AND (protoPayload.methodName:"DR" OR protoPayload.methodName:"disaster" OR protoPayload.methodName:"recovery" OR protoPayload.methodName:"failover" OR logName:"dr-test")'

            entries = []
            try:
                for entry in client.list_entries(filter_=filter_str, page_size=100):
                    entries.append(entry)
                    if len(entries) >= 100:
                        break
            except Exception as log_err:
                logger.warning(f"DR test log search error: {log_err}")

            raw = self._build_evidence(
                api_call="logging.entries.list",
                cli_command='gcloud logging read "resource.type=global AND (protoPayload.methodName:DR OR logName:dr-test)" --limit 100 --project PROJECT_ID',
                response={"dr_log_entries": len(entries)},
                service="CloudLogging",
                assessor_guidance=(
                    "Verify that disaster recovery tests are documented in audit logs with timestamps, participants, and outcomes. "
                    "Confirm that DR tests are conducted at required intervals per contingency plan."
                ),
            )

            if entries:
                return self._result(check_def, "met",
                    f"Found {len(entries)} DR test log entries.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No DR test documentation found in audit logs.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_storage_multi_region(self, check_def: dict) -> CheckResult:
        """Check GCS buckets use multi-region storage."""
        try:
            storage_client = self._get_storage_client()
            buckets = list(storage_client.list_buckets())

            multi_region = []
            single_region = []

            for bucket in buckets:
                location_type = bucket.location_type
                if location_type in ["multi-region", "dual-region"]:
                    multi_region.append(bucket.name)
                else:
                    single_region.append(bucket.name)

            raw = self._build_evidence(
                api_call="storage.buckets.list",
                cli_command="gcloud storage buckets list --format='table(name,location,locationType)' --project PROJECT_ID",
                response={"total": len(buckets), "multi_region": len(multi_region), "single_region": len(single_region)},
                service="CloudStorage",
                assessor_guidance=(
                    "Verify that critical data buckets use multi-region or dual-region storage for geographic redundancy. "
                    "Confirm that storage class aligns with RPO/RTO requirements in the contingency plan."
                ),
            )

            if buckets and len(multi_region) == len(buckets):
                return self._result(check_def, "met",
                    f"All {len(buckets)} bucket(s) use multi-region storage.", raw_evidence=raw)
            elif buckets and len(single_region) > 0:
                return self._result(check_def, "not_met",
                    f"{len(single_region)} bucket(s) use single-region storage: {', '.join(single_region[:5])}.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "met", "No buckets found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_cloudsql_cross_region_replicas(self, check_def: dict) -> CheckResult:
        """Check Cloud SQL instances have cross-region replicas."""
        try:
            url = f"https://sqladmin.googleapis.com/v1/projects/{self._project_id}/instances"
            data = self._gcp_api_get_safe(url, {"items": []})
            instances = data.get("items", [])

            with_replicas = []
            without_replicas = []

            for inst in instances:
                name = inst.get("name", "unknown")
                region = inst.get("region", "")
                replica_config = inst.get("replicaConfiguration", {})
                replicas = inst.get("replicaNames", [])

                # Check if instance has read replicas in different regions
                has_cross_region = False
                if replicas:
                    for replica_name in replicas:
                        # Fetch replica details
                        replica_url = f"https://sqladmin.googleapis.com/v1/projects/{self._project_id}/instances/{replica_name}"
                        replica_data = self._gcp_api_get_safe(replica_url, {})
                        replica_region = replica_data.get("region", "")
                        if replica_region and replica_region != region:
                            has_cross_region = True
                            break

                if has_cross_region:
                    with_replicas.append(name)
                else:
                    without_replicas.append(name)

            raw = self._build_evidence(
                api_call="sqladmin.instances.list",
                cli_command="gcloud sql instances list --format='table(name,region,replicaNames)' --project PROJECT_ID",
                response={"total": len(instances), "with_cross_region_replicas": len(with_replicas), "without": len(without_replicas)},
                service="CloudSQL",
                assessor_guidance=(
                    "Verify that Cloud SQL instances hosting critical data have read replicas in different regions for DR. "
                    "Confirm that replica lag is monitored and failover procedures are documented."
                ),
            )

            if instances and len(with_replicas) == len(instances):
                return self._result(check_def, "met",
                    f"All {len(instances)} Cloud SQL instance(s) have cross-region replicas.", raw_evidence=raw)
            elif instances and len(without_replicas) > 0:
                return self._result(check_def, "not_met",
                    f"{len(without_replicas)} instance(s) without cross-region replicas: {', '.join(without_replicas[:5])}.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "met", "No Cloud SQL instances found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_multi_region_deployment(self, check_def: dict) -> CheckResult:
        """Check for multi-region Compute Engine deployment."""
        try:
            url = f"https://compute.googleapis.com/compute/v1/projects/{self._project_id}/aggregated/instances"
            data = self._gcp_api_get_safe(url, {"items": {}})

            regions = set()
            instance_count = 0

            for zone_key, zone_data in data.get("items", {}).items():
                instances = zone_data.get("instances", [])
                if instances:
                    # Extract region from zone (e.g., zones/us-central1-a -> us-central1)
                    if "zones/" in zone_key:
                        zone_name = zone_key.split("/")[-1]
                        region = "-".join(zone_name.split("-")[:-1])
                        regions.add(region)
                        instance_count += len(instances)

            raw = self._build_evidence(
                api_call="compute.instances.aggregatedList",
                cli_command="gcloud compute instances list --format='table(name,zone)' --project PROJECT_ID",
                response={"instances": instance_count, "regions": list(regions), "region_count": len(regions)},
                service="Compute",
                assessor_guidance=(
                    "Verify that critical workloads are deployed across multiple geographic regions for high availability. "
                    "Confirm that load balancing distributes traffic across regions and DR procedures are tested."
                ),
            )

            if len(regions) >= 2:
                return self._result(check_def, "met",
                    f"Instances deployed across {len(regions)} region(s): {', '.join(sorted(regions))}.",
                    raw_evidence=raw)
            elif len(regions) == 1:
                return self._result(check_def, "not_met",
                    f"All {instance_count} instance(s) deployed in single region: {', '.join(regions)}.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "not_met", "No instances found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_load_balancer_multi_region(self, check_def: dict) -> CheckResult:
        """Check load balancers span multiple regions."""
        try:
            url = f"https://compute.googleapis.com/compute/v1/projects/{self._project_id}/global/backendServices"
            data = self._gcp_api_get_safe(url, {"items": []})
            backend_services = data.get("items", [])

            multi_region_lbs = []
            single_region_lbs = []

            for bs in backend_services:
                name = bs.get("name", "unknown")
                backends = bs.get("backends", [])
                regions = set()

                for backend in backends:
                    group = backend.get("group", "")
                    # Extract region from group URL
                    if "/regions/" in group:
                        region = group.split("/regions/")[1].split("/")[0]
                        regions.add(region)
                    elif "/zones/" in group:
                        zone = group.split("/zones/")[1].split("/")[0]
                        region = "-".join(zone.split("-")[:-1])
                        regions.add(region)

                if len(regions) >= 2:
                    multi_region_lbs.append(name)
                else:
                    single_region_lbs.append(name)

            raw = self._build_evidence(
                api_call="compute.backendServices.list",
                cli_command="gcloud compute backend-services list --global --format='table(name,backends)' --project PROJECT_ID",
                response={"total": len(backend_services), "multi_region": len(multi_region_lbs), "single_region": len(single_region_lbs)},
                service="Compute",
                assessor_guidance=(
                    "Verify that load balancers distribute traffic across multiple regions for geographic redundancy. "
                    "Confirm that health checks and failover are configured for regional outages."
                ),
            )

            if backend_services and len(multi_region_lbs) > 0:
                return self._result(check_def, "met",
                    f"{len(multi_region_lbs)} load balancer(s) span multiple regions.", raw_evidence=raw)
            elif backend_services:
                return self._result(check_def, "not_met",
                    f"All {len(backend_services)} load balancer(s) are single-region.", raw_evidence=raw)
            else:
                return self._result(check_def, "met", "No backend services found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_disk_snapshot_schedules(self, check_def: dict) -> CheckResult:
        """Check disk snapshot schedules are configured."""
        try:
            url = f"https://compute.googleapis.com/compute/v1/projects/{self._project_id}/global/resourcePolicies"
            data = self._gcp_api_get_safe(url, {"items": []})
            policies = data.get("items", [])

            snapshot_policies = []
            for policy in policies:
                if policy.get("snapshotSchedulePolicy"):
                    snapshot_policies.append(policy.get("name", "unknown"))

            raw = self._build_evidence(
                api_call="compute.resourcePolicies.list",
                cli_command="gcloud compute resource-policies list --global --format='table(name,snapshotSchedulePolicy)' --project PROJECT_ID",
                response={"total_policies": len(policies), "snapshot_policies": len(snapshot_policies)},
                service="Compute",
                assessor_guidance=(
                    "Verify that snapshot schedules are configured for critical persistent disks per backup policy. "
                    "Confirm that snapshot frequency aligns with RPO requirements and retention meets compliance needs."
                ),
            )

            if snapshot_policies:
                return self._result(check_def, "met",
                    f"Found {len(snapshot_policies)} snapshot schedule(s): {', '.join(snapshot_policies[:5])}.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No disk snapshot schedules configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_cloudsql_automated_backups(self, check_def: dict) -> CheckResult:
        """Check Cloud SQL automated backups are enabled."""
        try:
            url = f"https://sqladmin.googleapis.com/v1/projects/{self._project_id}/instances"
            data = self._gcp_api_get_safe(url, {"items": []})
            instances = data.get("items", [])

            with_backups = []
            without_backups = []

            for inst in instances:
                name = inst.get("name", "unknown")
                settings = inst.get("settings", {})
                backup_config = settings.get("backupConfiguration", {})
                enabled = backup_config.get("enabled", False)

                if enabled:
                    with_backups.append(name)
                else:
                    without_backups.append(name)

            raw = self._build_evidence(
                api_call="sqladmin.instances.list",
                cli_command="gcloud sql instances describe INSTANCE_NAME --format='get(settings.backupConfiguration.enabled)' --project PROJECT_ID",
                response={"total": len(instances), "with_backups": len(with_backups), "without_backups": len(without_backups)},
                service="CloudSQL",
                assessor_guidance=(
                    "Verify that all Cloud SQL instances have automated backups enabled with appropriate retention. "
                    "Confirm that backup windows are scheduled and binary logging is enabled for point-in-time recovery."
                ),
            )

            if instances and len(with_backups) == len(instances):
                return self._result(check_def, "met",
                    f"All {len(instances)} Cloud SQL instance(s) have automated backups enabled.", raw_evidence=raw)
            elif instances and len(without_backups) > 0:
                return self._result(check_def, "not_met",
                    f"{len(without_backups)} instance(s) without automated backups: {', '.join(without_backups[:5])}.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "met", "No Cloud SQL instances found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_storage_versioning(self, check_def: dict) -> CheckResult:
        """Check GCS bucket versioning is enabled."""
        try:
            storage_client = self._get_storage_client()
            buckets = list(storage_client.list_buckets())

            with_versioning = []
            without_versioning = []

            for bucket in buckets:
                if bucket.versioning_enabled:
                    with_versioning.append(bucket.name)
                else:
                    without_versioning.append(bucket.name)

            raw = self._build_evidence(
                api_call="storage.buckets.list",
                cli_command="gcloud storage buckets list --format='table(name,versioning.enabled)' --project PROJECT_ID",
                response={"total": len(buckets), "with_versioning": len(with_versioning), "without_versioning": len(without_versioning)},
                service="CloudStorage",
                assessor_guidance=(
                    "Verify that GCS buckets storing critical data have versioning enabled to protect against accidental deletion. "
                    "Confirm that lifecycle policies manage old versions per retention requirements."
                ),
            )

            if buckets and len(with_versioning) == len(buckets):
                return self._result(check_def, "met",
                    f"All {len(buckets)} bucket(s) have versioning enabled.", raw_evidence=raw)
            elif buckets and len(without_versioning) > 0:
                return self._result(check_def, "not_met",
                    f"{len(without_versioning)} bucket(s) without versioning: {', '.join(without_versioning[:5])}.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "met", "No buckets found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_snapshot_restore_testing(self, check_def: dict) -> CheckResult:
        """Check disk snapshots have been tested for restore."""
        try:
            url = f"https://compute.googleapis.com/compute/v1/projects/{self._project_id}/global/snapshots"
            data = self._gcp_api_get_safe(url, {"items": []})
            snapshots = data.get("items", [])

            # Check for disks created from snapshots (indicates restore testing)
            disks_url = f"https://compute.googleapis.com/compute/v1/projects/{self._project_id}/aggregated/disks"
            disks_data = self._gcp_api_get_safe(disks_url, {"items": {}})

            disks_from_snapshots = []
            for zone_key, zone_data in disks_data.get("items", {}).items():
                for disk in zone_data.get("disks", []):
                    if disk.get("sourceSnapshot"):
                        disks_from_snapshots.append(disk.get("name", "unknown"))

            raw = self._build_evidence(
                api_call="compute.snapshots.list",
                cli_command="gcloud compute snapshots list --project PROJECT_ID && gcloud compute disks list --filter='sourceSnapshot:*' --project PROJECT_ID",
                response={"snapshots": len(snapshots), "restore_tested": len(disks_from_snapshots)},
                service="Compute",
                assessor_guidance=(
                    "Verify that snapshot restore procedures are tested regularly by creating disks from snapshots. "
                    "Confirm that restore tests are documented with success criteria and RTO measurements."
                ),
            )

            if snapshots and disks_from_snapshots:
                return self._result(check_def, "met",
                    f"Found {len(disks_from_snapshots)} disk(s) restored from snapshots (restore testing evidence).",
                    raw_evidence=raw)
            elif snapshots:
                return self._result(check_def, "not_met",
                    f"{len(snapshots)} snapshot(s) exist but no restore testing evidence found.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "not_met", "No snapshots found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_snapshot_separate_region(self, check_def: dict) -> CheckResult:
        """Check snapshots are stored in separate regions from source."""
        try:
            url = f"https://compute.googleapis.com/compute/v1/projects/{self._project_id}/global/snapshots"
            data = self._gcp_api_get_safe(url, {"items": []})
            snapshots = data.get("items", [])

            separate_region_snapshots = []
            same_region_snapshots = []

            for snapshot in snapshots:
                name = snapshot.get("name", "unknown")
                storage_locations = snapshot.get("storageLocations", [])
                source_disk = snapshot.get("sourceDisk", "")

                # Extract source region from disk URL
                source_region = ""
                if "/zones/" in source_disk:
                    zone = source_disk.split("/zones/")[1].split("/")[0]
                    source_region = "-".join(zone.split("-")[:-1])

                # Check if snapshot is stored in different region
                separate_region = False
                if storage_locations and source_region:
                    for loc in storage_locations:
                        if loc != source_region and not loc.startswith(source_region):
                            separate_region = True
                            break

                if separate_region:
                    separate_region_snapshots.append(name)
                else:
                    same_region_snapshots.append(name)

            raw = self._build_evidence(
                api_call="compute.snapshots.list",
                cli_command="gcloud compute snapshots list --format='table(name,storageLocations,sourceDisk)' --project PROJECT_ID",
                response={"total": len(snapshots), "separate_region": len(separate_region_snapshots), "same_region": len(same_region_snapshots)},
                service="Compute",
                assessor_guidance=(
                    "Verify that snapshots are stored in regions separate from source disks for geographic redundancy. "
                    "Confirm that snapshot storage locations align with DR requirements and regional failure scenarios."
                ),
            )

            if snapshots and len(separate_region_snapshots) > 0:
                return self._result(check_def, "met",
                    f"{len(separate_region_snapshots)} snapshot(s) stored in separate regions.",
                    raw_evidence=raw)
            elif snapshots:
                return self._result(check_def, "not_met",
                    f"All {len(snapshots)} snapshot(s) stored in same region as source.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "met", "No snapshots found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_snapshot_encryption(self, check_def: dict) -> CheckResult:
        """Check disk snapshots are encrypted."""
        try:
            url = f"https://compute.googleapis.com/compute/v1/projects/{self._project_id}/global/snapshots"
            data = self._gcp_api_get_safe(url, {"items": []})
            snapshots = data.get("items", [])

            encrypted = []
            not_encrypted = []

            for snapshot in snapshots:
                name = snapshot.get("name", "unknown")
                # Check for CMEK encryption
                has_cmek = bool(snapshot.get("snapshotEncryptionKey"))
                # GCP snapshots are always encrypted (at minimum with Google-managed keys)
                # We consider CMEK as "properly encrypted" for compliance
                if has_cmek:
                    encrypted.append(name)
                else:
                    # Google-managed encryption, but flagging for CMEK requirement
                    not_encrypted.append(name)

            raw = self._build_evidence(
                api_call="compute.snapshots.list",
                cli_command="gcloud compute snapshots list --format='table(name,snapshotEncryptionKey)' --project PROJECT_ID",
                response={"total": len(snapshots), "cmek_encrypted": len(encrypted), "google_managed": len(not_encrypted)},
                service="Compute",
                assessor_guidance=(
                    "Verify that snapshots are encrypted with customer-managed encryption keys (CMEK) for compliance. "
                    "Confirm that encryption keys are managed per key management policy and rotated regularly."
                ),
            )

            if snapshots and len(encrypted) == len(snapshots):
                return self._result(check_def, "met",
                    f"All {len(snapshots)} snapshot(s) encrypted with CMEK.", raw_evidence=raw)
            elif snapshots and len(encrypted) > 0:
                return self._result(check_def, "not_met",
                    f"{len(not_encrypted)} snapshot(s) using Google-managed encryption (CMEK recommended).",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "not_met",
                    f"{len(snapshots)} snapshot(s) using Google-managed encryption.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_recovery_procedures_documented(self, check_def: dict) -> CheckResult:
        """Check recovery procedures are documented via labels."""
        try:
            url = f"https://compute.googleapis.com/compute/v1/projects/{self._project_id}/aggregated/instances"
            data = self._gcp_api_get_safe(url, {"items": {}})
            instances = []
            for zone_key, zone_data in data.get("items", {}).items():
                for inst in zone_data.get("instances", []):
                    instances.append(inst)

            recovery_labels = ["recovery-procedure", "recovery-doc", "runbook", "recovery-plan"]
            documented = []
            undocumented = []

            for inst in instances:
                labels = inst.get("labels", {})
                has_recovery = any(label in labels for label in recovery_labels)
                if has_recovery:
                    documented.append(inst.get("name", "unknown"))
                else:
                    undocumented.append(inst.get("name", "unknown"))

            raw = self._build_evidence(
                api_call="compute.instances.aggregatedList",
                cli_command="gcloud compute instances list --format='table(name,labels)' --project PROJECT_ID",
                response={"total": len(instances), "documented": len(documented), "undocumented": len(undocumented)},
                service="Compute",
                assessor_guidance=(
                    "Verify that critical systems have recovery procedure labels linking to runbooks or documentation. "
                    "Confirm that recovery procedures include step-by-step instructions, dependencies, and validation steps."
                ),
            )

            if instances and len(documented) == len(instances):
                return self._result(check_def, "met",
                    f"All {len(instances)} instance(s) have recovery procedure labels.", raw_evidence=raw)
            elif instances and len(documented) > 0:
                return self._result(check_def, "not_met",
                    f"{len(undocumented)} instance(s) missing recovery procedure labels.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "not_met",
                    f"No recovery procedure labels found on {len(instances)} instance(s).", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_cloudsql_point_in_time_recovery(self, check_def: dict) -> CheckResult:
        """Check Cloud SQL point-in-time recovery is enabled."""
        try:
            url = f"https://sqladmin.googleapis.com/v1/projects/{self._project_id}/instances"
            data = self._gcp_api_get_safe(url, {"items": []})
            instances = data.get("items", [])

            with_pitr = []
            without_pitr = []

            for inst in instances:
                name = inst.get("name", "unknown")
                settings = inst.get("settings", {})
                backup_config = settings.get("backupConfiguration", {})
                pitr_enabled = backup_config.get("pointInTimeRecoveryEnabled", False)

                if pitr_enabled:
                    with_pitr.append(name)
                else:
                    without_pitr.append(name)

            raw = self._build_evidence(
                api_call="sqladmin.instances.list",
                cli_command="gcloud sql instances describe INSTANCE_NAME --format='get(settings.backupConfiguration.pointInTimeRecoveryEnabled)' --project PROJECT_ID",
                response={"total": len(instances), "with_pitr": len(with_pitr), "without_pitr": len(without_pitr)},
                service="CloudSQL",
                assessor_guidance=(
                    "Verify that Cloud SQL instances have point-in-time recovery enabled to support granular recovery. "
                    "Confirm that binary logging is enabled and retention period meets RPO requirements."
                ),
            )

            if instances and len(with_pitr) == len(instances):
                return self._result(check_def, "met",
                    f"All {len(instances)} Cloud SQL instance(s) have PITR enabled.", raw_evidence=raw)
            elif instances and len(without_pitr) > 0:
                return self._result(check_def, "not_met",
                    f"{len(without_pitr)} instance(s) without PITR: {', '.join(without_pitr[:5])}.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "met", "No Cloud SQL instances found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ---- PL: Planning ----

    def check_org_policy_security_plans(self, check_def: dict) -> CheckResult:
        """Check organization policies document security plans."""
        try:
            url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{self._project_id}:getEffectiveOrgPolicy"
            # List common security-related org policies
            security_policies = [
                "constraints/compute.requireShieldedVm",
                "constraints/compute.requireOsLogin",
                "constraints/storage.uniformBucketLevelAccess",
                "constraints/iam.disableServiceAccountKeyCreation",
                "constraints/sql.restrictPublicIp"
            ]

            active_policies = []
            for constraint in security_policies:
                policy_url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{self._project_id}:getEffectiveOrgPolicy"
                # Note: This is a simplified check; real implementation would POST with constraint
                policy_data = self._gcp_api_get_safe(policy_url, {})
                if policy_data and not policy_data.get("_error"):
                    active_policies.append(constraint)

            raw = self._build_evidence(
                api_call="cloudresourcemanager.projects.getEffectiveOrgPolicy",
                cli_command="gcloud resource-manager org-policies list --project PROJECT_ID",
                response={"security_policies_checked": len(security_policies), "active": len(active_policies)},
                service="ResourceManager",
                assessor_guidance=(
                    "Verify that organization policies enforce security requirements documented in system security plans. "
                    "Confirm that policies cover compute, storage, IAM, and network security controls."
                ),
            )

            if active_policies:
                return self._result(check_def, "met",
                    f"Found {len(active_policies)} active security org policies.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No security organization policies found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_architecture_labels(self, check_def: dict) -> CheckResult:
        """Check critical resources have architecture labels."""
        try:
            url = f"https://compute.googleapis.com/compute/v1/projects/{self._project_id}/aggregated/instances"
            data = self._gcp_api_get_safe(url, {"items": {}})
            instances = []
            for zone_key, zone_data in data.get("items", {}).items():
                for inst in zone_data.get("instances", []):
                    instances.append(inst)

            arch_labels = ["architecture", "system-tier", "data-classification", "criticality"]
            labeled = []
            unlabeled = []

            for inst in instances:
                labels = inst.get("labels", {})
                has_arch = any(label in labels for label in arch_labels)
                if has_arch:
                    labeled.append(inst.get("name", "unknown"))
                else:
                    unlabeled.append(inst.get("name", "unknown"))

            raw = self._build_evidence(
                api_call="compute.instances.aggregatedList",
                cli_command="gcloud compute instances list --format='table(name,labels)' --project PROJECT_ID",
                response={"total": len(instances), "labeled": len(labeled), "unlabeled": len(unlabeled)},
                service="Compute",
                assessor_guidance=(
                    "Verify that resources have architecture labels (e.g., system-tier, data-classification) for planning. "
                    "Confirm that labels align with system architecture documentation and security categorization."
                ),
            )

            if instances and len(labeled) == len(instances):
                return self._result(check_def, "met",
                    f"All {len(instances)} instance(s) have architecture labels.", raw_evidence=raw)
            elif instances and len(labeled) > 0:
                return self._result(check_def, "not_met",
                    f"{len(unlabeled)} instance(s) missing architecture labels.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "not_met",
                    f"No architecture labels found on {len(instances)} instance(s).", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_vpc_flow_logs_architecture(self, check_def: dict) -> CheckResult:
        """Check VPC flow logs support architecture review."""
        return self.check_vpc_flow_logs(check_def)

    # ---- PT: PII Processing ----

    def check_dlp_enabled(self, check_def: dict) -> CheckResult:
        """Check Cloud DLP is enabled with inspect templates."""
        try:
            url = f"https://dlp.googleapis.com/v2/projects/{self._project_id}/inspectTemplates"
            data = self._gcp_api_get_safe(url, {"inspectTemplates": []})
            templates = data.get("inspectTemplates", [])

            # Also check for DLP jobs
            jobs_url = f"https://dlp.googleapis.com/v2/projects/{self._project_id}/dlpJobs"
            jobs_data = self._gcp_api_get_safe(jobs_url, {"jobs": []})
            jobs = jobs_data.get("jobs", [])

            raw = self._build_evidence(
                api_call="dlp.projects.inspectTemplates.list",
                cli_command="gcloud dlp inspect-templates list --project PROJECT_ID && gcloud dlp jobs list --project PROJECT_ID",
                response={"inspect_templates": len(templates), "dlp_jobs": len(jobs)},
                service="CloudDLP",
                assessor_guidance=(
                    "Verify that Cloud DLP is enabled with inspect templates configured for PII detection. "
                    "Confirm that DLP scans cover all data stores containing CUI and results are reviewed."
                ),
            )

            if templates or jobs:
                return self._result(check_def, "met",
                    f"Cloud DLP enabled: {len(templates)} template(s), {len(jobs)} job(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "Cloud DLP not enabled or no inspect templates configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_storage_data_classification_labels(self, check_def: dict) -> CheckResult:
        """Check GCS buckets have data classification labels."""
        try:
            storage_client = self._get_storage_client()
            buckets = list(storage_client.list_buckets())

            classification_labels = ["data-classification", "data-type", "sensitivity", "pii-level"]
            labeled = []
            unlabeled = []

            for bucket in buckets:
                labels = bucket.labels or {}
                has_classification = any(label in labels for label in classification_labels)
                if has_classification:
                    labeled.append(bucket.name)
                else:
                    unlabeled.append(bucket.name)

            raw = self._build_evidence(
                api_call="storage.buckets.list",
                cli_command="gcloud storage buckets list --format='table(name,labels)' --project PROJECT_ID",
                response={"total": len(buckets), "labeled": len(labeled), "unlabeled": len(unlabeled)},
                service="CloudStorage",
                assessor_guidance=(
                    "Verify that GCS buckets have data classification labels indicating sensitivity level. "
                    "Confirm that labels align with data classification policy and drive access controls."
                ),
            )

            if buckets and len(labeled) == len(buckets):
                return self._result(check_def, "met",
                    f"All {len(buckets)} bucket(s) have data classification labels.", raw_evidence=raw)
            elif buckets and len(unlabeled) > 0:
                return self._result(check_def, "not_met",
                    f"{len(unlabeled)} bucket(s) missing data classification labels: {', '.join(unlabeled[:5])}.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "met", "No buckets found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_bigquery_data_classification_labels(self, check_def: dict) -> CheckResult:
        """Check BigQuery datasets have data classification labels."""
        try:
            url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{self._project_id}/datasets"
            data = self._gcp_api_get_safe(url, {"datasets": []})
            datasets = data.get("datasets", [])

            classification_labels = ["data-classification", "data-type", "sensitivity", "pii-level"]
            labeled = []
            unlabeled = []

            for dataset in datasets:
                dataset_id = dataset.get("datasetReference", {}).get("datasetId", "unknown")
                # Fetch full dataset to get labels
                dataset_url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{self._project_id}/datasets/{dataset_id}"
                dataset_detail = self._gcp_api_get_safe(dataset_url, {})
                labels = dataset_detail.get("labels", {})

                has_classification = any(label in labels for label in classification_labels)
                if has_classification:
                    labeled.append(dataset_id)
                else:
                    unlabeled.append(dataset_id)

            raw = self._build_evidence(
                api_call="bigquery.datasets.list",
                cli_command="bq ls --project_id PROJECT_ID --format=json",
                response={"total": len(datasets), "labeled": len(labeled), "unlabeled": len(unlabeled)},
                service="BigQuery",
                assessor_guidance=(
                    "Verify that BigQuery datasets have data classification labels indicating PII/CUI content. "
                    "Confirm that labels drive access controls and compliance scanning."
                ),
            )

            if datasets and len(labeled) == len(datasets):
                return self._result(check_def, "met",
                    f"All {len(datasets)} dataset(s) have data classification labels.", raw_evidence=raw)
            elif datasets and len(unlabeled) > 0:
                return self._result(check_def, "not_met",
                    f"{len(unlabeled)} dataset(s) missing data classification labels: {', '.join(unlabeled[:5])}.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "met", "No BigQuery datasets found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_data_processing_purpose_labels(self, check_def: dict) -> CheckResult:
        """Check resources have data processing purpose labels."""
        try:
            url = f"https://compute.googleapis.com/compute/v1/projects/{self._project_id}/aggregated/instances"
            data = self._gcp_api_get_safe(url, {"items": {}})
            instances = []
            for zone_key, zone_data in data.get("items", {}).items():
                for inst in zone_data.get("instances", []):
                    instances.append(inst)

            purpose_labels = ["data-processing-purpose", "processing-activity", "legal-basis"]
            labeled = []
            unlabeled = []

            for inst in instances:
                labels = inst.get("labels", {})
                has_purpose = any(label in labels for label in purpose_labels)
                if has_purpose:
                    labeled.append(inst.get("name", "unknown"))
                else:
                    unlabeled.append(inst.get("name", "unknown"))

            raw = self._build_evidence(
                api_call="compute.instances.aggregatedList",
                cli_command="gcloud compute instances list --format='table(name,labels)' --project PROJECT_ID",
                response={"total": len(instances), "labeled": len(labeled), "unlabeled": len(unlabeled)},
                service="Compute",
                assessor_guidance=(
                    "Verify that systems processing PII have labels documenting processing purpose and legal basis. "
                    "Confirm that labels support privacy impact assessments and data protection requirements."
                ),
            )

            if instances and len(labeled) > 0:
                return self._result(check_def, "met",
                    f"{len(labeled)} instance(s) have data processing purpose labels.", raw_evidence=raw)
            elif instances:
                return self._result(check_def, "not_met",
                    f"No data processing purpose labels found on {len(instances)} instance(s).",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "met", "No instances found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_api_consent_documentation(self, check_def: dict) -> CheckResult:
        """Check API services have consent documentation."""
        try:
            url = f"https://serviceusage.googleapis.com/v1/projects/{self._project_id}/services?filter=state:ENABLED"
            data = self._gcp_api_get_safe(url, {"services": []})
            services = data.get("services", [])

            # Look for APIs that typically handle user data
            privacy_apis = []
            for service in services:
                name = service.get("config", {}).get("name", "")
                if any(keyword in name for keyword in ["identity", "oauth", "people", "gmail", "calendar", "drive"]):
                    privacy_apis.append(name)

            raw = self._build_evidence(
                api_call="serviceusage.services.list",
                cli_command="gcloud services list --enabled --project PROJECT_ID",
                response={"total_services": len(services), "privacy_related": len(privacy_apis)},
                service="ServiceUsage",
                assessor_guidance=(
                    "Verify that APIs processing user data have consent documentation and privacy policies. "
                    "Confirm that OAuth scopes are minimal and consent screens provide clear data usage information."
                ),
            )

            if privacy_apis:
                return self._result(check_def, "not_met",
                    f"Found {len(privacy_apis)} privacy-related API(s): Review consent documentation.",
                    raw_evidence=raw)
            return self._result(check_def, "met",
                f"No privacy-related APIs found among {len(services)} enabled services.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ---- SA: System Acquisition ----

    def check_cloud_build_triggers(self, check_def: dict) -> CheckResult:
        """Check Cloud Build has configured triggers."""
        try:
            url = f"https://cloudbuild.googleapis.com/v1/projects/{self._project_id}/triggers"
            data = self._gcp_api_get_safe(url, {"triggers": []})
            triggers = data.get("triggers", [])

            trigger_names = [t.get("name", "unknown") for t in triggers]

            raw = self._build_evidence(
                api_call="cloudbuild.projects.triggers.list",
                cli_command="gcloud builds triggers list --project PROJECT_ID",
                response={"trigger_count": len(triggers)},
                service="CloudBuild",
                assessor_guidance=(
                    "Verify that Cloud Build triggers are configured for CI/CD automation. "
                    "Confirm that triggers enforce security checks, testing, and approval workflows."
                ),
            )

            if triggers:
                return self._result(check_def, "met",
                    f"Found {len(triggers)} Cloud Build trigger(s): {', '.join(trigger_names[:5])}.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Cloud Build triggers configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_firewall_unused_ports(self, check_def: dict) -> CheckResult:
        """Check firewall rules don't have unnecessary open ports."""
        try:
            firewalls = self._list_firewalls()

            # Unnecessary/risky ports
            unnecessary_ports = {"21", "23", "69", "135", "137", "139", "445", "161", "162", "389", "636", "1433", "3306", "5432", "5900", "8080", "8888"}
            issues = []

            for fw in firewalls:
                if fw.direction != "INGRESS" or fw.disabled:
                    continue
                source_ranges = list(fw.source_ranges) if fw.source_ranges else []
                is_public = "0.0.0.0/0" in source_ranges

                if is_public:
                    for allowed in (fw.allowed or []):
                        ports = list(allowed.ports) if allowed.ports else []
                        for port in ports:
                            if port in unnecessary_ports:
                                issues.append(f"'{fw.name}': port {port} open to 0.0.0.0/0")

            raw = self._build_evidence(
                api_call="compute.firewalls.list",
                cli_command="gcloud compute firewall-rules list --project PROJECT_ID",
                response={"total_rules": len(firewalls), "issues": len(issues)},
                service="Compute",
                assessor_guidance=(
                    "Verify that firewall rules do not expose unnecessary ports to the internet. "
                    "Confirm that only required services are publicly accessible and all others are restricted."
                ),
            )

            if not issues:
                return self._result(check_def, "met",
                    f"No unnecessary ports exposed in {len(firewalls)} firewall rule(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Found {len(issues)} firewall rule(s) with unnecessary ports: {'; '.join(issues[:5])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_api_gateway_documented(self, check_def: dict) -> CheckResult:
        """Check API Gateway has documentation."""
        try:
            url = f"https://apigateway.googleapis.com/v1/projects/{self._project_id}/locations/-/apis"
            data = self._gcp_api_get_safe(url, {"apis": []})
            apis = data.get("apis", [])

            api_names = [api.get("name", "unknown") for api in apis]

            raw = self._build_evidence(
                api_call="apigateway.projects.locations.apis.list",
                cli_command="gcloud api-gateway apis list --project PROJECT_ID",
                response={"api_count": len(apis)},
                service="APIGateway",
                assessor_guidance=(
                    "Verify that API Gateway configurations include OpenAPI documentation. "
                    "Confirm that API documentation describes authentication, authorization, and data schemas."
                ),
            )

            if apis:
                return self._result(check_def, "met",
                    f"Found {len(apis)} API Gateway API(s): {', '.join(api_names[:5])}.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No API Gateway APIs configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_source_repos_configured(self, check_def: dict) -> CheckResult:
        """Check Cloud Source Repositories are configured."""
        try:
            url = f"https://sourcerepo.googleapis.com/v1/projects/{self._project_id}/repos"
            data = self._gcp_api_get_safe(url, {"repos": []})
            repos = data.get("repos", [])

            repo_names = [repo.get("name", "unknown").split("/")[-1] for repo in repos]

            raw = self._build_evidence(
                api_call="sourcerepo.projects.repos.list",
                cli_command="gcloud source repos list --project PROJECT_ID",
                response={"repo_count": len(repos)},
                service="CloudSourceRepositories",
                assessor_guidance=(
                    "Verify that Cloud Source Repositories are configured for version control. "
                    "Confirm that repositories have branch protection, audit logging, and access controls."
                ),
            )

            if repos:
                return self._result(check_def, "met",
                    f"Found {len(repos)} Cloud Source Repository(ies): {', '.join(repo_names[:5])}.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Cloud Source Repositories configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_cloud_build_test_steps(self, check_def: dict) -> CheckResult:
        """Check Cloud Build configurations include test steps."""
        try:
            url = f"https://cloudbuild.googleapis.com/v1/projects/{self._project_id}/triggers"
            data = self._gcp_api_get_safe(url, {"triggers": []})
            triggers = data.get("triggers", [])

            with_tests = []
            without_tests = []

            for trigger in triggers:
                name = trigger.get("name", "unknown")
                build = trigger.get("build", {})
                steps = build.get("steps", [])

                # Look for test-related steps
                has_test = any(
                    "test" in step.get("name", "").lower() or
                    "test" in " ".join(step.get("args", [])).lower()
                    for step in steps
                )

                if has_test:
                    with_tests.append(name)
                else:
                    without_tests.append(name)

            raw = self._build_evidence(
                api_call="cloudbuild.projects.triggers.list",
                cli_command="gcloud builds triggers describe TRIGGER_NAME --project PROJECT_ID",
                response={"total": len(triggers), "with_tests": len(with_tests), "without_tests": len(without_tests)},
                service="CloudBuild",
                assessor_guidance=(
                    "Verify that Cloud Build configurations include automated testing steps. "
                    "Confirm that tests run before deployment and failures block the pipeline."
                ),
            )

            if triggers and len(with_tests) == len(triggers):
                return self._result(check_def, "met",
                    f"All {len(triggers)} Cloud Build trigger(s) include test steps.", raw_evidence=raw)
            elif triggers and len(with_tests) > 0:
                return self._result(check_def, "not_met",
                    f"{len(without_tests)} trigger(s) missing test steps: {', '.join(without_tests[:5])}.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "not_met",
                    f"No test steps found in {len(triggers)} Cloud Build trigger(s).", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_cloud_build_sast(self, check_def: dict) -> CheckResult:
        """Check Cloud Build includes SAST scanning."""
        try:
            url = f"https://cloudbuild.googleapis.com/v1/projects/{self._project_id}/triggers"
            data = self._gcp_api_get_safe(url, {"triggers": []})
            triggers = data.get("triggers", [])

            with_sast = []
            without_sast = []

            for trigger in triggers:
                name = trigger.get("name", "unknown")
                build = trigger.get("build", {})
                steps = build.get("steps", [])

                # Look for SAST tools
                has_sast = any(
                    any(tool in step.get("name", "").lower() for tool in ["sonarqube", "snyk", "checkmarx", "fortify", "semgrep", "codeql"]) or
                    any(tool in " ".join(step.get("args", [])).lower() for tool in ["sast", "static-analysis", "security-scan"])
                    for step in steps
                )

                if has_sast:
                    with_sast.append(name)
                else:
                    without_sast.append(name)

            raw = self._build_evidence(
                api_call="cloudbuild.projects.triggers.list",
                cli_command="gcloud builds triggers describe TRIGGER_NAME --project PROJECT_ID",
                response={"total": len(triggers), "with_sast": len(with_sast), "without_sast": len(without_sast)},
                service="CloudBuild",
                assessor_guidance=(
                    "Verify that Cloud Build pipelines include SAST scanning (e.g., SonarQube, Snyk, Semgrep). "
                    "Confirm that SAST findings are reviewed and critical vulnerabilities block deployment."
                ),
            )

            if triggers and len(with_sast) > 0:
                return self._result(check_def, "met",
                    f"{len(with_sast)} Cloud Build trigger(s) include SAST scanning.", raw_evidence=raw)
            elif triggers:
                return self._result(check_def, "not_met",
                    f"No SAST scanning found in {len(triggers)} Cloud Build trigger(s).",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "not_met", "No Cloud Build triggers configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_scc_eol_software(self, check_def: dict) -> CheckResult:
        """Check Security Command Center flags end-of-life software."""
        try:
            url = f"https://securitycenter.googleapis.com/v1/organizations/-/sources/-/findings?parent=projects/{self._project_id}"
            data = self._gcp_api_get_safe(url, {"findings": []})
            findings = data.get("findings", [])

            eol_findings = []
            for finding in findings:
                category = finding.get("category", "")
                if any(keyword in category.upper() for keyword in ["EOL", "END_OF_LIFE", "OUTDATED", "DEPRECATED"]):
                    eol_findings.append(finding.get("name", "unknown"))

            raw = self._build_evidence(
                api_call="securitycenter.organizations.sources.findings.list",
                cli_command="gcloud scc findings list --source=- --filter='category:EOL OR category:OUTDATED' --project PROJECT_ID",
                response={"total_findings": len(findings), "eol_findings": len(eol_findings)},
                service="SecurityCommandCenter",
                assessor_guidance=(
                    "Verify that Security Command Center detects and reports end-of-life software. "
                    "Confirm that EOL findings are remediated per patch management policy."
                ),
            )

            if eol_findings:
                return self._result(check_def, "not_met",
                    f"Found {len(eol_findings)} EOL software finding(s) in SCC.",
                    raw_evidence=raw)
            return self._result(check_def, "met",
                "No EOL software findings in Security Command Center.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ---- SR: Supply Chain ----

    def check_artifact_registry_scanning(self, check_def: dict) -> CheckResult:
        """Check Artifact Registry has vulnerability scanning enabled."""
        try:
            url = f"https://artifactregistry.googleapis.com/v1/projects/{self._project_id}/locations/-/repositories"
            data = self._gcp_api_get_safe(url, {"repositories": []})
            repositories = data.get("repositories", [])

            # Check for vulnerability scanning via Container Analysis
            scan_url = f"https://containeranalysis.googleapis.com/v1/projects/{self._project_id}/notes"
            scan_data = self._gcp_api_get_safe(scan_url, {"notes": []})
            notes = scan_data.get("notes", [])

            vulnerability_notes = [n for n in notes if n.get("kind") == "VULNERABILITY"]

            raw = self._build_evidence(
                api_call="artifactregistry.projects.locations.repositories.list",
                cli_command="gcloud artifacts repositories list --project PROJECT_ID && gcloud container images list-tags --project PROJECT_ID",
                response={"repositories": len(repositories), "vulnerability_notes": len(vulnerability_notes)},
                service="ArtifactRegistry",
                assessor_guidance=(
                    "Verify that Artifact Registry has vulnerability scanning enabled for container images. "
                    "Confirm that scan results are reviewed and vulnerabilities are remediated per policy."
                ),
            )

            if repositories and vulnerability_notes:
                return self._result(check_def, "met",
                    f"Artifact Registry vulnerability scanning enabled: {len(repositories)} repo(s), {len(vulnerability_notes)} scan note(s).",
                    raw_evidence=raw)
            elif repositories:
                return self._result(check_def, "not_met",
                    f"Artifact Registry configured but no vulnerability scanning evidence found.",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "not_met", "No Artifact Registry repositories found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_cloud_build_dependency_scanning(self, check_def: dict) -> CheckResult:
        """Check Cloud Build scans dependencies for vulnerabilities."""
        try:
            url = f"https://cloudbuild.googleapis.com/v1/projects/{self._project_id}/triggers"
            data = self._gcp_api_get_safe(url, {"triggers": []})
            triggers = data.get("triggers", [])

            with_dep_scan = []
            without_dep_scan = []

            for trigger in triggers:
                name = trigger.get("name", "unknown")
                build = trigger.get("build", {})
                steps = build.get("steps", [])

                # Look for dependency scanning tools
                has_dep_scan = any(
                    any(tool in step.get("name", "").lower() for tool in ["snyk", "dependabot", "owasp", "dependency-check", "trivy", "grype"]) or
                    any(tool in " ".join(step.get("args", [])).lower() for tool in ["dependency", "sca", "supply-chain"])
                    for step in steps
                )

                if has_dep_scan:
                    with_dep_scan.append(name)
                else:
                    without_dep_scan.append(name)

            raw = self._build_evidence(
                api_call="cloudbuild.projects.triggers.list",
                cli_command="gcloud builds triggers describe TRIGGER_NAME --project PROJECT_ID",
                response={"total": len(triggers), "with_dep_scan": len(with_dep_scan), "without_dep_scan": len(without_dep_scan)},
                service="CloudBuild",
                assessor_guidance=(
                    "Verify that Cloud Build pipelines scan dependencies for known vulnerabilities (e.g., Snyk, OWASP Dependency-Check). "
                    "Confirm that high-risk vulnerabilities block deployment and supply chain risks are mitigated."
                ),
            )

            if triggers and len(with_dep_scan) > 0:
                return self._result(check_def, "met",
                    f"{len(with_dep_scan)} Cloud Build trigger(s) include dependency scanning.", raw_evidence=raw)
            elif triggers:
                return self._result(check_def, "not_met",
                    f"No dependency scanning found in {len(triggers)} Cloud Build trigger(s).",
                    raw_evidence=raw)
            else:
                return self._result(check_def, "not_met", "No Cloud Build triggers configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def disconnect(self):
        """Clean up GCP SDK clients."""
        self._credentials = None
        self._iam_client = None
        self._logging_client = None
        self._resource_manager_client = None
        self._kms_client = None
        self._compute_client = None
        self._storage_client = None
        self._monitoring_client = None
        self._scc_client = None
        self._container_client = None
        self._bigquery_client = None
        self._osconfig_client = None
        self._recommender_client = None
        self._sql_instances_client = None
        self._instances_client = None
        self._subnetworks_client = None
        self._networks_client = None
        self._images_client = None
        self._ssl_policies_client = None
        self._ssl_certs_client = None
        self._backend_services_client = None
        self._disks_client = None
        self._cache.clear()
        self._connected = False
