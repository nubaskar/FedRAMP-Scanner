"""
Scan orchestration engine — the main entry point for running compliance scans.

Called as a BackgroundTask from the scans API. Loads client credentials,
determines the appropriate cloud scanner, iterates through CMMC practice
checks, stores findings, and updates scan status.
"""
from __future__ import annotations

import concurrent.futures
import json
import logging
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.models.schemas import Client, Finding, Scan
from app.scanner.aws_scanner import AwsScanner
from app.scanner.azure_scanner import AzureScanner
from app.scanner.base import BaseScanner, CheckResult
from app.scanner.gcp_scanner import GcpScanner

logger = logging.getLogger(__name__)

# Per-check timeout — prevents any single Azure/GCP/AWS API call from
# blocking the entire scan.  If a check exceeds this, it is marked "error"
# and the engine moves on to the next check.
CHECK_TIMEOUT_SECONDS = 60

# Number of automated checks to run concurrently.  With prefetch caching most
# checks only do 1-2 small per-resource API calls, so we can safely run more.
PARALLEL_CHECKS = 8

# Path to check definition JSON files
CONFIG_DIR = Path(__file__).resolve().parent.parent.parent.parent / "config"
CHECKS_DIR = CONFIG_DIR / "checks"

# CMMC domain metadata
CMMC_DOMAINS = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PS": "Personnel Security",
    "PE": "Physical and Environmental Protection",
    "RA": "Risk Assessment",
    "CA": "Security Assessment",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

# NIST 800-171 practice families mapped to CMMC domains
NIST_FAMILIES = {
    "3.1":  {"domain": "AC",  "family": "Access Control"},
    "3.2":  {"domain": "AT",  "family": "Awareness and Training"},
    "3.3":  {"domain": "AU",  "family": "Audit and Accountability"},
    "3.4":  {"domain": "CM",  "family": "Configuration Management"},
    "3.5":  {"domain": "IA",  "family": "Identification and Authentication"},
    "3.6":  {"domain": "IR",  "family": "Incident Response"},
    "3.7":  {"domain": "MA",  "family": "Maintenance"},
    "3.8":  {"domain": "MP",  "family": "Media Protection"},
    "3.9":  {"domain": "PS",  "family": "Personnel Security"},
    "3.10": {"domain": "PE",  "family": "Physical and Environmental Protection"},
    "3.11": {"domain": "RA",  "family": "Risk Assessment"},
    "3.12": {"domain": "CA",  "family": "Security Assessment"},
    "3.13": {"domain": "SC",  "family": "System and Communications Protection"},
    "3.14": {"domain": "SI",  "family": "System and Information Integrity"},
}

# ---------------------------------------------------------------------------
# Mapping: config check_id → scanner method name
# Only check_ids with a real Python implementation are listed.  Config checks
# NOT in the map are treated as "automated but not yet implemented" → manual.
# ---------------------------------------------------------------------------
AWS_CHECK_METHODS: dict[str, str] = {
    # --- Existing 15 checks ---
    "ac-3.1.1-aws-001": "check_root_access_keys",
    "ac-3.1.1-aws-003": "check_password_policy",
    "ac-3.1.3-aws-001": "check_vpc_flow_logs",
    "au-3.3.1-aws-001": "check_cloudtrail_enabled",
    "au-3.3.1-aws-002": "check_cloudtrail_log_validation",
    "ia-3.5.3-aws-001": "check_mfa_enabled",
    "sc-3.13.10-aws-001": "check_kms_key_rotation",
    "sc-3.13.11-aws-002": "check_encryption_at_rest",
    "si-3.14.6-aws-001": "check_guardduty_enabled",
    "ac-3.1.14-aws-002": "check_security_groups",
    "sc-3.13.2-aws-001": "check_defense_in_depth",
    "ac-3.1.16-aws-001": "check_vpn_remote_access",
    "ac-3.1.18-aws-001": "check_mobile_device_control",
    "ac-3.1.19-aws-001": "check_ebs_default_encryption",
    "ac-3.1.21-aws-001": "check_s3_account_public_access_block",
    # --- Phase 1: IAM Checks (28) ---
    "ac-3.1.1-aws-002": "check_credential_report_review",
    "ac-3.1.2-aws-001": "check_least_privilege_policies",
    "ac-3.1.2-aws-002": "check_permission_boundaries",
    "ac-3.1.4-aws-001": "check_separation_of_duties_roles",
    "ac-3.1.4-aws-002": "check_deploy_approve_separation",
    "ac-3.1.5-aws-001": "check_no_inline_wildcard_policies",
    "ac-3.1.5-aws-003": "check_no_admin_access_users",
    "ac-3.1.6-aws-001": "check_admin_standard_role_separation",
    "ac-3.1.10-aws-001": "check_session_timeout",
    "ac-3.1.11-aws-001": "check_role_session_duration",
    "ac-3.1.22-aws-002": "check_no_public_ip_cui_instances",
    "ia-3.5.1-aws-001": "check_unique_iam_users",
    "ia-3.5.1-aws-002": "check_service_account_naming",
    "ia-3.5.1-aws-003": "check_instance_profiles",
    "ia-3.5.2-aws-001": "check_root_mfa",
    "ia-3.5.2-aws-002": "check_console_users_mfa",
    "ia-3.5.3-aws-002": "check_mfa_condition_policies",
    "ia-3.5.3-aws-003": "check_hardware_mfa_root",
    "ia-3.5.4-aws-001": "check_fido2_mfa_support",
    "ia-3.5.4-aws-002": "check_sts_token_duration",
    "ia-3.5.5-aws-001": "check_no_username_reuse",
    "ia-3.5.6-aws-001": "check_inactive_users",
    "ia-3.5.6-aws-002": "check_inactive_access_keys",
    "ia-3.5.7-aws-001": "check_password_complexity",
    "ia-3.5.8-aws-001": "check_password_reuse_prevention",
    "ia-3.5.10-aws-001": "check_tls_api_enforcement",
    "au-3.3.2-aws-002": "check_no_shared_accounts",
    "au-3.3.9-aws-001": "check_cloudtrail_access_restricted",
    # --- Phase 2: CloudTrail + S3 Deep Checks (12) ---
    "au-3.3.1-aws-003": "check_cloudtrail_log_retention",
    "au-3.3.1-aws-004": "check_cloudtrail_data_events",
    "au-3.3.2-aws-001": "check_cloudtrail_user_identity",
    "au-3.3.5-aws-002": "check_cloudtrail_cloudwatch_integration",
    "au-3.3.8-aws-001": "check_cloudtrail_bucket_logging",
    "au-3.3.8-aws-002": "check_cloudtrail_bucket_encryption",
    "au-3.3.8-aws-003": "check_cloudtrail_bucket_mfa_delete",
    "ac-3.1.3-aws-002": "check_s3_public_access_block",
    "ac-3.1.22-aws-001": "check_no_public_s3_buckets",
    "mp-3.8.2-aws-001": "check_s3_cui_bucket_policies",
    "mp-3.8.6-aws-001": "check_s3_bucket_encryption",
    "sc-3.13.16-aws-001": "check_s3_default_encryption",
    # --- Phase 3: EC2/VPC Network Checks (19) ---
    "ac-3.1.7-aws-001": "check_cloudtrail_management_events",
    "ac-3.1.12-aws-001": "check_vpn_monitoring",
    "ac-3.1.13-aws-001": "check_vpn_encryption",
    "ac-3.1.20-aws-001": "check_vpc_peering_reviewed",
    "ac-3.1.20-aws-002": "check_transit_gateway_reviewed",
    "cm-3.4.6-aws-001": "check_unused_security_groups",
    "cm-3.4.7-aws-001": "check_sg_restrict_unnecessary_ports",
    "mp-3.8.2-aws-002": "check_ebs_volumes_encrypted",
    "mp-3.8.2-aws-003": "check_ebs_default_encryption_regions",
    "sc-3.13.1-aws-002": "check_all_vpc_flow_logs",
    "sc-3.13.3-aws-001": "check_subnet_separation",
    "sc-3.13.4-aws-001": "check_ebs_snapshots_private",
    "sc-3.13.4-aws-002": "check_amis_private",
    "sc-3.13.5-aws-001": "check_public_private_subnet_isolation",
    "sc-3.13.5-aws-002": "check_nat_gateway_usage",
    "sc-3.13.6-aws-001": "check_default_sg_deny_all",
    "sc-3.13.6-aws-002": "check_nacl_deny_default",
    "sc-3.13.16-aws-004": "check_ebs_encryption_by_default",
    "sc-3.13.10-aws-002": "check_kms_key_policy_least_privilege",
    # --- Phase 4: SSM + Config + RDS + EFS + Backup (25) ---
    "ac-3.1.12-aws-002": "check_session_manager_logging",
    "ac-3.1.15-aws-001": "check_session_manager_usage",
    "cm-3.4.1-aws-001": "check_config_enabled",
    "cm-3.4.1-aws-002": "check_ssm_inventory",
    "cm-3.4.1-aws-003": "check_ami_baseline",
    "cm-3.4.2-aws-001": "check_config_cis_rules",
    "cm-3.4.3-aws-001": "check_config_history",
    "cm-3.4.3-aws-002": "check_cloudtrail_config_changes",
    "cm-3.4.5-aws-002": "check_deployment_roles_scoped",
    "cm-3.4.6-aws-002": "check_unused_iam_roles",
    "cm-3.4.8-aws-001": "check_application_control",
    "cm-3.4.9-aws-001": "check_software_inventory",
    "ia-3.5.10-aws-002": "check_rds_ssl_enforcement",
    "ma-3.7.1-aws-001": "check_patch_manager_configured",
    "ma-3.7.1-aws-002": "check_patch_compliance",
    "ma-3.7.1-aws-003": "check_rds_auto_upgrade",
    "mp-3.8.6-aws-002": "check_rds_encryption",
    "mp-3.8.6-aws-003": "check_efs_encryption",
    "mp-3.8.9-aws-001": "check_backup_vault_encryption",
    "mp-3.8.9-aws-002": "check_backup_vault_access_policy",
    "mp-3.8.9-aws-003": "check_s3_replication_encryption",
    "sc-3.13.16-aws-002": "check_rds_encryption_at_rest",
    "si-3.14.1-aws-001": "check_ssm_patch_deployed",
    "si-3.14.1-aws-002": "check_patch_compliance_sla",
    "si-3.14.1-aws-004": "check_rds_auto_minor_upgrade",
    # --- Phase 5: SecurityHub + GuardDuty + Inspector (15) ---
    "au-3.3.5-aws-001": "check_security_hub_enabled",
    "ca-3.12.3-aws-001": "check_security_hub_monitoring",
    "ca-3.12.3-aws-002": "check_config_rules_evaluating",
    "ca-3.12.3-aws-003": "check_guardduty_all_features",
    "cm-3.4.2-aws-002": "check_security_hub_cis",
    "ir-3.6.1-aws-001": "check_guardduty_all_regions",
    "ir-3.6.1-aws-002": "check_security_hub_findings",
    "ra-3.11.2-aws-001": "check_inspector_enabled",
    "ra-3.11.2-aws-003": "check_vulnerability_findings_age",
    "si-3.14.1-aws-003": "check_inspector_findings_addressed",
    "si-3.14.2-aws-001": "check_guardduty_malware_protection",
    "si-3.14.3-aws-001": "check_security_hub_notifications",
    "si-3.14.3-aws-002": "check_guardduty_alerting",
    "si-3.14.5-aws-001": "check_inspector_continuous_scan",
    "si-3.14.5-aws-002": "check_guardduty_ebs_scanning",
    # --- Phase 6: WAF + ELB + CloudFront + ACM + Route53 + NF (14) ---
    "ac-3.1.13-aws-002": "check_tls_on_load_balancers",
    "sc-3.13.1-aws-001": "check_waf_deployed",
    "sc-3.13.1-aws-003": "check_network_firewall",
    "sc-3.13.7-aws-001": "check_vpn_full_tunnel",
    "sc-3.13.8-aws-001": "check_alb_tls_policy",
    "sc-3.13.8-aws-002": "check_cloudfront_tls",
    "sc-3.13.8-aws-003": "check_s3_tls_policy",
    "sc-3.13.9-aws-001": "check_alb_idle_timeout",
    "sc-3.13.10-aws-003": "check_acm_certificates",
    "sc-3.13.11-aws-001": "check_fips_endpoints",
    "sc-3.13.13-aws-001": "check_waf_xss_sqli_rules",
    "sc-3.13.15-aws-001": "check_acm_cert_validity",
    "sc-3.13.15-aws-002": "check_dnssec_enabled",
    "si-3.14.6-aws-003": "check_network_firewall_ids_ips",
    # --- Phase 7: EventBridge + CW + SNS + DynamoDB + ECR + Logs (11) ---
    "au-3.3.4-aws-001": "check_cloudwatch_cloudtrail_alarm",
    "au-3.3.4-aws-002": "check_sns_audit_notifications",
    "au-3.3.6-aws-001": "check_cloudwatch_logs_insights",
    "ir-3.6.1-aws-003": "check_eventbridge_security_rules",
    "ra-3.11.2-aws-002": "check_ecr_image_scanning",
    "sc-3.13.16-aws-003": "check_dynamodb_encryption",
    "si-3.14.6-aws-002": "check_flow_logs_analysis",
    "si-3.14.7-aws-001": "check_guardduty_unauthorized_findings",
    "si-3.14.7-aws-002": "check_cloudwatch_anomaly_detection",
    "si-3.14.7-aws-003": "check_cloudtrail_insights",
    "si-3.14.4-aws-002": "check_guardduty_threat_intel",
    # --- Phase 8: Elevated-Permission Services (24) ---
    "ac-3.1.5-aws-002": "check_access_analyzer",
    "ac-3.1.7-aws-002": "check_scp_cloudtrail_protection",
    "ac-3.1.8-aws-001": "check_sso_lockout_policy",
    "ac-3.1.8-aws-002": "check_guardduty_brute_force",
    "ac-3.1.11-aws-002": "check_sso_session_timeout",
    "au-3.3.6-aws-002": "check_athena_cloudtrail_table",
    "au-3.3.9-aws-002": "check_scp_audit_protection",
    "cm-3.4.5-aws-001": "check_cicd_approval_gates",
    "cm-3.4.7-aws-002": "check_scp_service_restrictions",
    "ia-3.5.9-aws-001": "check_sso_force_password_change",
    "ir-3.6.1-aws-004": "check_ir_playbooks",
    "ma-3.7.5-aws-001": "check_session_manager_mfa",
    "ma-3.7.5-aws-002": "check_vpn_mfa_required",
    "sc-3.13.1-aws-004": "check_guardduty_vpc_monitoring",
    "sc-3.13.3-aws-002": "check_ssm_management_access",
    "sc-3.13.9-aws-002": "check_apigateway_timeout",
    "si-3.14.2-aws-002": "check_endpoint_protection",
    "si-3.14.2-aws-003": "check_s3_malware_scanning",
    "si-3.14.3-aws-003": "check_health_dashboard_alerts",
    "si-3.14.4-aws-001": "check_endpoint_protection_updates",
    "si-3.14.5-aws-003": "check_s3_object_scanning",
    "au-3.3.7-aws-001": "check_ntp_configured",
    "ra-3.11.3-aws-001": "check_patch_state_compliance",
    "ra-3.11.3-aws-002": "check_inspector_remediation_sla",
}

AZURE_CHECK_METHODS: dict[str, str] = {
    # --- Original 13 checks ---
    "ac-3.1.1-azure-001": "check_conditional_access",
    "ia-3.5.3-azure-001": "check_mfa_enabled",
    "ac-3.1.14-azure-001": "check_nsg_rules",
    "au-3.3.1-azure-001": "check_activity_log_alerts",
    "sc-3.13.11-azure-001": "check_storage_encryption",
    "sc-3.13.10-azure-001": "check_key_vault_config",
    "si-3.14.6-azure-001": "check_security_center_enabled",
    "sc-3.13.16-azure-003": "check_disk_encryption",
    "sc-3.13.2-azure-001": "check_defense_in_depth",
    "ac-3.1.16-azure-001": "check_vpn_remote_access",
    "ac-3.1.18-azure-001": "check_mobile_device_control",
    "ac-3.1.19-azure-001": "check_vm_disk_encryption",
    "ac-3.1.21-azure-001": "check_storage_public_access",
    # --- Batch 1: Network (18) ---
    "ac-3.1.3-azure-001": "check_nsg_flow_logs",
    "ac-3.1.3-azure-002": "check_azure_firewall",
    "ac-3.1.12-azure-001": "check_bastion_hosts",
    "ac-3.1.13-azure-001": "check_vpn_encryption",
    "ac-3.1.20-azure-001": "check_vnet_peering",
    "sc-3.13.1-azure-001": "check_azure_firewall",
    "sc-3.13.1-azure-002": "check_nsg_flow_logs_all",
    "sc-3.13.1-azure-003": "check_waf_policies",
    "sc-3.13.3-azure-001": "check_management_network_isolation",
    "sc-3.13.5-azure-001": "check_dmz_subnet",
    "sc-3.13.6-azure-001": "check_nsg_default_deny",
    "sc-3.13.6-azure-002": "check_azure_firewall_default_deny",
    "sc-3.13.7-azure-001": "check_vpn_forced_tunneling",
    "sc-3.13.9-azure-001": "check_appgw_idle_timeout",
    "cm-3.4.7-azure-001": "check_nsg_restrict_unnecessary_ports",
    "sc-3.13.8-azure-001": "check_webapp_min_tls",
    "si-3.14.1-azure-002": "check_defender_vulnerability_findings",
    "au-3.3.1-azure-002": "check_network_watcher",
    # --- Batch 2: Compute (8) ---
    "ia-3.5.1-azure-002": "check_managed_identities",
    "au-3.3.7-azure-001": "check_vm_time_sync",
    "mp-3.8.2-azure-002": "check_managed_disk_encryption",
    "ma-3.7.1-azure-002": "check_vm_patch_assessment",
    "si-3.14.1-azure-001": "check_vm_update_manager",
    "mp-3.8.6-azure-001": "check_storage_encryption",
    "ac-3.1.22-azure-001": "check_storage_no_public_blobs",
    "sc-3.13.11-azure-002": "check_disk_encryption",
    # --- Batch 3: Storage (6) ---
    "mp-3.8.2-azure-001": "check_storage_private_access",
    "sc-3.13.16-azure-001": "check_storage_cmk_encryption",
    "sc-3.13.8-azure-002": "check_storage_tls",
    "au-3.3.8-azure-002": "check_immutable_audit_storage",
    "sc-3.13.10-azure-002": "check_keyvault_access_least_privilege",
    "sc-3.13.16-azure-002": "check_sql_tde_cmk",
    # --- Batch 4: Auth / Resource (5) ---
    "ac-3.1.2-azure-001": "check_custom_rbac_least_privilege",
    "ac-3.1.4-azure-001": "check_separation_of_duties",
    "au-3.3.9-azure-001": "check_diagnostic_settings_restricted",
    "cm-3.4.5-azure-001": "check_resource_locks",
    "au-3.3.8-azure-001": "check_log_analytics_access_control",
    # --- Batch 5: Monitor (5) ---
    "ac-3.1.7-azure-001": "check_privilege_escalation_alerts",
    "au-3.3.1-azure-003": "check_resource_diagnostic_settings",
    "au-3.3.4-azure-001": "check_diagnostic_change_alerts",
    "cm-3.4.3-azure-001": "check_activity_log_captures_changes",
    "au-3.3.6-azure-001": "check_log_analytics_workspace",
    # --- Batch 6: Security Center (13) ---
    "ir-3.6.1-azure-001": "check_defender_plans_enabled",
    "ac-3.1.5-azure-002": "check_jit_vm_access",
    "cm-3.4.2-azure-002": "check_defender_secure_score",
    "cm-3.4.8-azure-001": "check_adaptive_app_controls",
    "ra-3.11.2-azure-001": "check_defender_vulnerability_findings",
    "ra-3.11.2-azure-002": "check_defender_for_containers",
    "ra-3.11.2-azure-003": "check_sql_vulnerability_assessment",
    "ra-3.11.3-azure-002": "check_defender_recommendations",
    "ca-3.12.3-azure-001": "check_defender_continuous_assessment",
    "ca-3.12.3-azure-002": "check_policy_compliance_state",
    "sc-3.13.11-azure-001": "check_storage_encryption",
    "ac-3.1.5-azure-001": "check_global_admin_count",
    "mp-3.8.9-azure-001": "check_recovery_vault_encryption",
    # --- Batch 7: New Management SDKs (19+) ---
    "mp-3.8.6-azure-002": "check_sql_tde",
    "ia-3.5.10-azure-001": "check_webapp_https_only",
    "cm-3.4.2-azure-001": "check_policy_assignments",
    "mp-3.8.9-azure-002": "check_recovery_vault_soft_delete",
    "cm-3.4.6-azure-001": "check_advisor_unused_resources",
    "cm-3.4.1-azure-001": "check_resource_graph_inventory",
    "ma-3.7.1-azure-001": "check_update_management",
    "cm-3.4.9-azure-001": "check_change_tracking",
    "ra-3.11.3-azure-001": "check_update_management_compliance",
    "au-3.3.5-azure-001": "check_sentinel_enabled",
    "ir-3.6.1-azure-002": "check_sentinel_deployed",
    "ir-3.6.1-azure-003": "check_sentinel_automation_rules",
    "cm-3.4.1-azure-002": "check_guest_configuration",
    # --- Batch 8: Graph API (25) ---
    "ac-3.1.1-azure-002": "check_guest_access_restricted",
    "ac-3.1.1-azure-003": "check_security_defaults",
    "ac-3.1.2-azure-002": "check_pim_enabled",
    "ac-3.1.6-azure-001": "check_admin_accounts_separate",
    "ac-3.1.8-azure-001": "check_smart_lockout",
    "ac-3.1.10-azure-001": "check_conditional_access_session_controls",
    "ac-3.1.11-azure-001": "check_token_lifetime_policy",
    "ac-3.1.15-azure-001": "check_paw_policy",
    "ia-3.5.1-azure-001": "check_unique_users",
    "ia-3.5.2-azure-001": "check_mfa_registration",
    "ia-3.5.2-azure-002": "check_legacy_auth_blocked",
    "ia-3.5.3-azure-002": "check_mfa_azure_management",
    "ia-3.5.4-azure-001": "check_fido2_enabled",
    "ia-3.5.5-azure-001": "check_deleted_users_soft_delete",
    "ia-3.5.6-azure-001": "check_inactive_users",
    "ia-3.5.7-azure-001": "check_password_protection",
    "ia-3.5.8-azure-001": "check_password_history",
    "ia-3.5.9-azure-001": "check_force_password_change",
    "au-3.3.2-azure-001": "check_sign_in_logs",
    "ma-3.7.5-azure-001": "check_mfa_bastion_access",
    "ia-3.5.3-azure-001": "check_mfa_conditional_access",
    # --- Additional checks found in config (16) ---
    "sc-3.13.4-azure-001": "check_shared_disks_restricted",
    "sc-3.13.13-azure-001": "check_waf_owasp_rules",
    "sc-3.13.15-azure-001": "check_app_service_certificates",
    "si-3.14.1-azure-003": "check_webapp_platform_version",
    "si-3.14.2-azure-001": "check_defender_for_endpoint",
    "si-3.14.2-azure-002": "check_antimalware_extension",
    "si-3.14.3-azure-001": "check_security_contacts",
    "si-3.14.3-azure-002": "check_service_health_alerts",
    "si-3.14.4-azure-001": "check_defender_signature_updates",
    "si-3.14.5-azure-001": "check_scheduled_vulnerability_scans",
    "si-3.14.5-azure-002": "check_realtime_protection",
    "si-3.14.6-azure-002": "check_azure_firewall_idps",
    "si-3.14.6-azure-003": "check_nsg_flow_log_analytics",
    "si-3.14.7-azure-001": "check_identity_protection_risk",
    "si-3.14.7-azure-002": "check_sentinel_ueba",
    "si-3.14.7-azure-003": "check_risky_users",
}

GCP_CHECK_METHODS: dict[str, str] = {
    # --- Original 13 checks ---
    "ac-3.1.1-gcp-001": "check_iam_bindings",
    "au-3.3.1-gcp-002": "check_audit_logging",
    "ac-3.1.14-gcp-001": "check_vpc_firewall_rules",
    "sc-3.13.10-gcp-001": "check_kms_key_rotation",
    "sc-3.13.11-gcp-001": "check_compute_disk_encryption",
    "sc-3.13.6-gcp-001": "check_cloud_armor",
    "au-3.3.1-gcp-003": "check_logging_enabled",
    "cm-3.4.2-gcp-001": "check_org_policy_constraints",
    "sc-3.13.2-gcp-001": "check_defense_in_depth",
    "ac-3.1.16-gcp-001": "check_vpn_remote_access",
    "ac-3.1.18-gcp-001": "check_mobile_device_control",
    "ac-3.1.19-gcp-001": "check_cmek_org_policy",
    "ac-3.1.21-gcp-001": "check_uniform_bucket_access",
    # --- IAM & Resource Manager ---
    "ac-3.1.1-gcp-002": "check_service_account_keys_rotated",
    "ac-3.1.1-gcp-003": "check_default_sa_not_used",
    "ac-3.1.2-gcp-001": "check_custom_iam_roles_scoped",
    "ac-3.1.2-gcp-002": "check_primitive_roles_not_assigned",
    "ac-3.1.4-gcp-001": "check_separation_of_duties",
    "ac-3.1.5-gcp-001": "check_owner_role_limited",
    "ac-3.1.5-gcp-002": "check_iam_recommender",
    "ac-3.1.6-gcp-001": "check_admin_user_separation",
    "ac-3.1.7-gcp-001": "check_admin_activity_logs",
    "ac-3.1.7-gcp-002": "check_iam_changes_alerts",
    "ac-3.1.8-gcp-001": "check_workspace_login_challenge",
    "ac-3.1.10-gcp-001": "check_session_control_policy",
    "ac-3.1.11-gcp-001": "check_oauth_token_expiration",
    "ac-3.1.12-gcp-001": "check_iap_tcp_forwarding",
    "ac-3.1.13-gcp-001": "check_vpn_ikev2_encryption",
    "ac-3.1.15-gcp-001": "check_os_login_enabled",
    "ac-3.1.20-gcp-001": "check_vpc_peering",
    "ac-3.1.22-gcp-001": "check_no_public_buckets",
    # --- VPC / Network ---
    "ac-3.1.3-gcp-001": "check_vpc_flow_logs",
    "ac-3.1.3-gcp-002": "check_firewall_least_privilege",
    # --- Audit & Accountability ---
    "au-3.3.1-gcp-001": "check_admin_activity_logs",
    "au-3.3.2-gcp-001": "check_audit_logs_principal",
    "au-3.3.4-gcp-001": "check_alert_log_sink_changes",
    "au-3.3.5-gcp-001": "check_scc_enabled",
    "au-3.3.6-gcp-001": "check_log_analytics_enabled",
    "au-3.3.7-gcp-001": "check_gce_ntp_sync",
    "au-3.3.8-gcp-001": "check_audit_log_bucket_retention",
    "au-3.3.8-gcp-002": "check_audit_log_bucket_access",
    "au-3.3.9-gcp-001": "check_logging_admin_restricted",
    # --- Security Assessment ---
    "ca-3.12.3-gcp-001": "check_scc_continuous_monitoring",
    "ca-3.12.3-gcp-002": "check_org_policy_compliance",
    # --- Configuration Management ---
    "cm-3.4.1-gcp-001": "check_asset_inventory",
    "cm-3.4.1-gcp-002": "check_os_config_inventory",
    "cm-3.4.2-gcp-002": "check_scc_cis_findings",
    "cm-3.4.3-gcp-001": "check_admin_activity_logs_capture",
    "cm-3.4.5-gcp-001": "check_project_lien",
    "cm-3.4.6-gcp-001": "check_unused_firewall_rules",
    "cm-3.4.7-gcp-001": "check_firewall_restrict_ports",
    "cm-3.4.8-gcp-001": "check_binary_authorization",
    "cm-3.4.9-gcp-001": "check_os_config_patch",
    # --- Identification & Authentication ---
    "ia-3.5.1-gcp-001": "check_all_users_identified",
    "ia-3.5.1-gcp-002": "check_service_accounts_identified",
    "ia-3.5.2-gcp-001": "check_workspace_2sv",
    "ia-3.5.3-gcp-001": "check_workspace_2sv_org",
    "ia-3.5.3-gcp-002": "check_workspace_security_key_admin",
    "ia-3.5.4-gcp-001": "check_workspace_security_key",
    "ia-3.5.5-gcp-001": "check_workspace_user_identifiers",
    "ia-3.5.6-gcp-001": "check_inactive_sa_keys",
    "ia-3.5.7-gcp-001": "check_workspace_password_policy",
    "ia-3.5.8-gcp-001": "check_workspace_password_reuse",
    "ia-3.5.9-gcp-001": "check_workspace_force_password_change",
    "ia-3.5.10-gcp-001": "check_sql_ssl_enforced",
    # --- Incident Response ---
    "ir-3.6.1-gcp-001": "check_scc_premium",
    "ir-3.6.1-gcp-002": "check_event_threat_detection",
    "ir-3.6.1-gcp-003": "check_scc_notifications",
    # --- Maintenance ---
    "ma-3.7.1-gcp-001": "check_os_config_patch",
    "ma-3.7.1-gcp-002": "check_container_vulnerability_scanning",
    "ma-3.7.5-gcp-001": "check_workspace_2sv_admin_console",
    # --- Media Protection ---
    "mp-3.8.2-gcp-001": "check_bucket_access_restricted",
    "mp-3.8.2-gcp-002": "check_disk_cmek",
    "mp-3.8.6-gcp-001": "check_bucket_cmek_encryption",
    "mp-3.8.6-gcp-002": "check_sql_encrypted",
    "mp-3.8.9-gcp-001": "check_backup_cmek",
    # --- Risk Assessment ---
    "ra-3.11.2-gcp-001": "check_web_security_scanner",
    "ra-3.11.2-gcp-002": "check_container_vulnerability_scanning",
    "ra-3.11.2-gcp-003": "check_scc_health_analytics",
    "ra-3.11.3-gcp-001": "check_os_config_patch_compliance",
    "ra-3.11.3-gcp-002": "check_scc_critical_remediated",
    # --- System & Communications Protection ---
    "sc-3.13.1-gcp-001": "check_cloud_armor_waf_rules",
    "sc-3.13.1-gcp-002": "check_vpc_flow_logs",
    "sc-3.13.1-gcp-003": "check_packet_mirroring_ids",
    "sc-3.13.3-gcp-001": "check_management_network_segmented",
    "sc-3.13.4-gcp-001": "check_images_not_public",
    "sc-3.13.5-gcp-001": "check_public_subnets_dedicated",
    "sc-3.13.6-gcp-002": "check_default_egress_reviewed",
    "sc-3.13.7-gcp-001": "check_vpn_full_tunnel",
    "sc-3.13.8-gcp-001": "check_ssl_policies_tls12",
    "sc-3.13.8-gcp-002": "check_sql_ssl_connections",
    "sc-3.13.9-gcp-001": "check_lb_timeout",
    "sc-3.13.10-gcp-002": "check_kms_iam_restricted",
    "sc-3.13.13-gcp-001": "check_cloud_armor_waf_rules",
    "sc-3.13.15-gcp-001": "check_ssl_certificates",
    "sc-3.13.16-gcp-001": "check_storage_cmek",
    "sc-3.13.16-gcp-002": "check_sql_cmek",
    "sc-3.13.16-gcp-003": "check_bigquery_cmek",
    # --- System & Information Integrity ---
    "si-3.14.1-gcp-001": "check_os_config_patch",
    "si-3.14.1-gcp-002": "check_gke_auto_upgrade",
    "si-3.14.1-gcp-003": "check_container_findings_addressed",
    "si-3.14.2-gcp-001": "check_endpoint_protection",
    "si-3.14.2-gcp-002": "check_malware_scanning_storage",
    "si-3.14.3-gcp-001": "check_scc_notifications",
    "si-3.14.3-gcp-002": "check_monitoring_security_alerts",
    "si-3.14.4-gcp-001": "check_endpoint_auto_update",
    "si-3.14.5-gcp-001": "check_container_scanning_continuous",
    "si-3.14.5-gcp-002": "check_web_security_scanner_periodic",
    "si-3.14.6-gcp-001": "check_cloud_ids_deployed",
    "si-3.14.6-gcp-002": "check_vpc_flow_logs_analyzed",
    "si-3.14.6-gcp-003": "check_event_threat_detection",
    "si-3.14.7-gcp-001": "check_event_threat_detection",
    "si-3.14.7-gcp-002": "check_anomaly_detection_alerts",
    "si-3.14.7-gcp-003": "check_access_transparency_logs",
}

PLATFORM_CHECK_METHODS: dict[str, dict[str, str]] = {
    "aws": AWS_CHECK_METHODS,
    "azure": AZURE_CHECK_METHODS,
    "gcp": GCP_CHECK_METHODS,
}


def get_scanner(environment: str, credentials: dict) -> BaseScanner:
    """
    Factory function — return the appropriate cloud scanner based on environment.

    Args:
        environment: One of aws_commercial, aws_govcloud, azure_commercial,
                     azure_government, gcp_commercial, gcp_assured_workloads.
        credentials: Cloud credential dictionary from the client record.

    Returns:
        An instance of AwsScanner, AzureScanner, or GcpScanner.

    Raises:
        ValueError: If the environment is not recognized.
    """
    env_config = _load_environment_config(environment)
    region = env_config.get("default_region", "")

    if environment.startswith("aws"):
        return AwsScanner(credentials=credentials, environment=environment, region=region)
    elif environment.startswith("azure"):
        return AzureScanner(credentials=credentials, environment=environment, region=region)
    elif environment.startswith("gcp"):
        return GcpScanner(credentials=credentials, environment=environment, region=region)
    else:
        raise ValueError(f"Unsupported environment: {environment}")


def _load_environment_config(environment: str) -> dict:
    """Load environment configuration from config/environments.json."""
    env_file = CONFIG_DIR / "environments.json"
    if not env_file.exists():
        logger.warning("environments.json not found at %s, using defaults", env_file)
        return {}
    with open(env_file, "r") as f:
        data = json.load(f)
    return data.get("environments", {}).get(environment, {})


def _load_checks(environment: str) -> list[dict]:
    """
    Load check definitions from config/checks/ directory.

    Reads ALL domain JSON files (ac.json, au.json, …) and extracts checks
    relevant to the current platform.  Each config check is converted to the
    flat dict format expected by ``run_scan()``.

    For manual-only practices the entry has ``check_type="manual"``.
    For automated checks with a real scanner method, ``method`` is set.
    For automated checks without a scanner method yet, ``method`` is None
    so ``run_scan()`` can flag them as "not yet implemented".

    Falls back to built-in checks if no config files are found.
    """
    if not CHECKS_DIR.exists():
        logger.warning("Checks directory not found at %s, using built-in checks", CHECKS_DIR)
        return _get_builtin_checks(environment)

    # Determine platform
    if environment.startswith("aws"):
        platform = "aws"
    elif environment.startswith("azure"):
        platform = "azure"
    elif environment.startswith("gcp"):
        platform = "gcp"
    else:
        platform = ""

    method_map = PLATFORM_CHECK_METHODS.get(platform, {})
    checks: list[dict] = []

    for check_file in sorted(CHECKS_DIR.glob("*.json")):
        try:
            with open(check_file, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Skipping bad config file %s: %s", check_file.name, exc)
            continue

        domain_code = data.get("domain", "")
        domain_name = data.get("name", "")
        practices = data.get("checks", {})

        for practice_id, practice_data in practices.items():
            # --- Manual-only practice ---
            if practice_data.get("manual_only"):
                guidance = practice_data.get("manual_guidance", "")
                evidence_reqs = practice_data.get("evidence_requests", [])
                evidence_text = guidance
                if evidence_reqs:
                    evidence_text += "\n\nEvidence requested:\n- " + "\n- ".join(evidence_reqs)

                checks.append({
                    "check_id": f"{domain_code.lower()}-{practice_id}-manual",
                    "practice_id": practice_id,
                    "check_name": f"{domain_name} — {practice_id} (Manual Review)",
                    "check_type": "manual",
                    "method": None,
                    "severity": "medium",
                    "remediation": guidance,
                    "evidence_text": evidence_text,
                })
                continue

            # --- Platform-specific automated checks ---
            platform_checks = practice_data.get(platform, [])
            for chk in platform_checks:
                check_id = chk.get("check_id", "")
                checks.append({
                    "check_id": check_id,
                    "practice_id": practice_id,
                    "check_name": chk.get("name", ""),
                    "check_type": "automated",
                    "method": method_map.get(check_id),  # None if not implemented
                    "severity": chk.get("severity", "medium"),
                    "remediation": chk.get("remediation", ""),
                    "service": chk.get("service", ""),
                    "api_call": chk.get("api_call", ""),
                    "expected": chk.get("expected", ""),
                    "supports_objectives": chk.get("supports_objectives", []),
                })

    if not checks:
        logger.info("No checks extracted from config, using built-in checks for %s", platform)
        return _get_builtin_checks(environment)

    logger.info(
        "Loaded %d checks from config for platform=%s (%d automated, %d manual)",
        len(checks),
        platform,
        sum(1 for c in checks if c["check_type"] == "automated"),
        sum(1 for c in checks if c["check_type"] == "manual"),
    )
    return checks


def _get_builtin_checks(environment: str) -> list[dict]:
    """
    Return built-in check definitions when config files are not present.

    Provides a comprehensive set of checks for each cloud platform covering
    key CMMC practices across all 14 domains.
    """
    if environment.startswith("aws"):
        return _get_aws_builtin_checks()
    elif environment.startswith("azure"):
        return _get_azure_builtin_checks()
    elif environment.startswith("gcp"):
        return _get_gcp_builtin_checks()
    return []


def _get_aws_builtin_checks() -> list[dict]:
    return [
        {
            "check_id": "ac-3.1.1-aws-001",
            "practice_id": "3.1.1",
            "check_name": "Limit system access to authorized users",
            "check_type": "automated",
            "method": "check_root_access_keys",
            "severity": "critical",
            "remediation": "Remove root account access keys and use IAM users with least privilege.",
        },
        {
            "check_id": "ac-3.1.1-aws-002",
            "practice_id": "3.1.1",
            "check_name": "IAM password policy strength",
            "check_type": "automated",
            "method": "check_password_policy",
            "severity": "high",
            "remediation": "Configure IAM password policy with minimum 14 characters, complexity requirements, and 90-day rotation.",
        },
        {
            "check_id": "ia-3.5.3-aws-001",
            "practice_id": "3.5.3",
            "check_name": "Multi-factor authentication for privileged accounts",
            "check_type": "automated",
            "method": "check_mfa_enabled",
            "severity": "critical",
            "remediation": "Enable MFA for all IAM users, especially those with administrative privileges.",
        },
        {
            "check_id": "au-3.3.1-aws-001",
            "practice_id": "3.3.1",
            "check_name": "CloudTrail audit logging enabled",
            "check_type": "automated",
            "method": "check_cloudtrail_enabled",
            "severity": "critical",
            "remediation": "Enable AWS CloudTrail in all regions with management event logging.",
        },
        {
            "check_id": "au-3.3.1-aws-002",
            "practice_id": "3.3.1",
            "check_name": "CloudTrail log file validation",
            "check_type": "automated",
            "method": "check_cloudtrail_log_validation",
            "severity": "high",
            "remediation": "Enable log file validation on all CloudTrail trails to detect tampering.",
        },
        {
            "check_id": "sc-3.13.11-aws-001",
            "practice_id": "3.13.11",
            "check_name": "Encryption at rest for storage services",
            "check_type": "automated",
            "method": "check_encryption_at_rest",
            "severity": "critical",
            "remediation": "Enable default encryption on all S3 buckets and EBS volumes using AES-256 or KMS.",
        },
        {
            "check_id": "au-3.3.1-aws-003",
            "practice_id": "3.3.1",
            "check_name": "VPC Flow Logs enabled",
            "check_type": "automated",
            "method": "check_vpc_flow_logs",
            "severity": "high",
            "remediation": "Enable VPC Flow Logs on all VPCs to capture network traffic metadata.",
        },
        {
            "check_id": "ac-3.1.5-aws-001",
            "practice_id": "3.1.5",
            "check_name": "Security groups restrict inbound access",
            "check_type": "automated",
            "method": "check_security_groups",
            "severity": "high",
            "remediation": "Remove overly permissive security group rules allowing 0.0.0.0/0 on sensitive ports.",
        },
        {
            "check_id": "sc-3.13.10-aws-001",
            "practice_id": "3.13.10",
            "check_name": "KMS key rotation enabled",
            "check_type": "automated",
            "method": "check_kms_key_rotation",
            "severity": "medium",
            "remediation": "Enable automatic annual rotation for all customer-managed KMS keys.",
        },
        {
            "check_id": "si-3.14.6-aws-001",
            "practice_id": "3.14.6",
            "check_name": "GuardDuty threat detection enabled",
            "check_type": "automated",
            "method": "check_guardduty_enabled",
            "severity": "high",
            "remediation": "Enable Amazon GuardDuty in all regions for continuous threat detection.",
        },
        {
            "check_id": "at-3.2.1-aws-001",
            "practice_id": "3.2.1",
            "check_name": "Security awareness training program",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Establish and maintain a security awareness training program for all system users.",
        },
        {
            "check_id": "ir-3.6.1-aws-001",
            "practice_id": "3.6.1",
            "check_name": "Incident response plan established",
            "check_type": "manual",
            "method": None,
            "severity": "high",
            "remediation": "Develop and implement an incident response plan that includes preparation, detection, containment, eradication, and recovery.",
        },
        {
            "check_id": "ma-3.7.1-aws-001",
            "practice_id": "3.7.1",
            "check_name": "System maintenance procedures",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Perform maintenance on organizational systems in a timely manner.",
        },
        {
            "check_id": "mp-3.8.1-aws-001",
            "practice_id": "3.8.1",
            "check_name": "Media protection policy",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Protect CUI on digital and non-digital media during transport and storage.",
        },
        {
            "check_id": "ps-3.9.1-aws-001",
            "practice_id": "3.9.1",
            "check_name": "Personnel screening procedures",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Screen individuals prior to authorizing access to systems containing CUI.",
        },
        {
            "check_id": "pe-3.10.1-aws-001",
            "practice_id": "3.10.1",
            "check_name": "Physical access controls",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Limit physical access to organizational systems, equipment, and operating environments.",
        },
        {
            "check_id": "ra-3.11.1-aws-001",
            "practice_id": "3.11.1",
            "check_name": "Risk assessment procedures",
            "check_type": "manual",
            "method": None,
            "severity": "high",
            "remediation": "Periodically assess the risk to organizational operations, assets, and individuals.",
        },
        {
            "check_id": "ca-3.12.1-aws-001",
            "practice_id": "3.12.1",
            "check_name": "Security assessment plan",
            "check_type": "manual",
            "method": None,
            "severity": "high",
            "remediation": "Periodically assess security controls to determine if they are effective.",
        },
        {
            "check_id": "cm-3.4.1-aws-001",
            "practice_id": "3.4.1",
            "check_name": "Configuration baseline documentation",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Establish and maintain baseline configurations and inventories of organizational systems.",
        },
    ]


def _get_azure_builtin_checks() -> list[dict]:
    return [
        {
            "check_id": "ac-3.1.1-azure-001",
            "practice_id": "3.1.1",
            "check_name": "Conditional access policies enforced",
            "check_type": "automated",
            "method": "check_conditional_access",
            "severity": "critical",
            "remediation": "Configure Azure AD Conditional Access policies to enforce MFA and restrict access by location and device compliance.",
        },
        {
            "check_id": "ia-3.5.3-azure-001",
            "practice_id": "3.5.3",
            "check_name": "MFA enabled for all users",
            "check_type": "automated",
            "method": "check_mfa_enabled",
            "severity": "critical",
            "remediation": "Enable Azure AD MFA for all users via Conditional Access or Security Defaults.",
        },
        {
            "check_id": "ac-3.1.5-azure-001",
            "practice_id": "3.1.5",
            "check_name": "NSG rules restrict inbound traffic",
            "check_type": "automated",
            "method": "check_nsg_rules",
            "severity": "high",
            "remediation": "Review and restrict Network Security Group rules to deny unrestricted inbound access on sensitive ports.",
        },
        {
            "check_id": "au-3.3.1-azure-001",
            "practice_id": "3.3.1",
            "check_name": "Activity log alerts configured",
            "check_type": "automated",
            "method": "check_activity_log_alerts",
            "severity": "high",
            "remediation": "Configure Activity Log alerts for critical operations (policy changes, role assignments, resource deletions).",
        },
        {
            "check_id": "sc-3.13.11-azure-001",
            "practice_id": "3.13.11",
            "check_name": "Storage account encryption enabled",
            "check_type": "automated",
            "method": "check_storage_encryption",
            "severity": "critical",
            "remediation": "Ensure all storage accounts use Microsoft-managed or customer-managed keys for encryption at rest.",
        },
        {
            "check_id": "sc-3.13.10-azure-001",
            "practice_id": "3.13.10",
            "check_name": "Key Vault configuration secure",
            "check_type": "automated",
            "method": "check_key_vault_config",
            "severity": "high",
            "remediation": "Enable soft delete and purge protection on all Key Vaults. Use RBAC for access control.",
        },
        {
            "check_id": "au-3.3.1-azure-002",
            "practice_id": "3.3.1",
            "check_name": "Network Watcher enabled",
            "check_type": "automated",
            "method": "check_network_watcher",
            "severity": "medium",
            "remediation": "Enable Network Watcher in all regions where resources are deployed.",
        },
        {
            "check_id": "si-3.14.6-azure-001",
            "practice_id": "3.14.6",
            "check_name": "Microsoft Defender for Cloud enabled",
            "check_type": "automated",
            "method": "check_security_center_enabled",
            "severity": "high",
            "remediation": "Enable Microsoft Defender for Cloud Standard tier on all subscriptions.",
        },
        {
            "check_id": "sc-3.13.11-azure-002",
            "practice_id": "3.13.11",
            "check_name": "Managed disk encryption enabled",
            "check_type": "automated",
            "method": "check_disk_encryption",
            "severity": "critical",
            "remediation": "Enable Azure Disk Encryption or server-side encryption with customer-managed keys for all managed disks.",
        },
        {
            "check_id": "at-3.2.1-azure-001",
            "practice_id": "3.2.1",
            "check_name": "Security awareness training program",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Establish and maintain a security awareness training program for all system users.",
        },
        {
            "check_id": "ir-3.6.1-azure-001",
            "practice_id": "3.6.1",
            "check_name": "Incident response plan established",
            "check_type": "manual",
            "method": None,
            "severity": "high",
            "remediation": "Develop and implement an incident response plan.",
        },
        {
            "check_id": "ma-3.7.1-azure-001",
            "practice_id": "3.7.1",
            "check_name": "System maintenance procedures",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Perform maintenance on organizational systems in a timely manner.",
        },
        {
            "check_id": "mp-3.8.1-azure-001",
            "practice_id": "3.8.1",
            "check_name": "Media protection policy",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Protect CUI on digital and non-digital media.",
        },
        {
            "check_id": "ps-3.9.1-azure-001",
            "practice_id": "3.9.1",
            "check_name": "Personnel screening procedures",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Screen individuals prior to authorizing access to systems containing CUI.",
        },
        {
            "check_id": "pe-3.10.1-azure-001",
            "practice_id": "3.10.1",
            "check_name": "Physical access controls",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Limit physical access to organizational systems.",
        },
        {
            "check_id": "ra-3.11.1-azure-001",
            "practice_id": "3.11.1",
            "check_name": "Risk assessment procedures",
            "check_type": "manual",
            "method": None,
            "severity": "high",
            "remediation": "Periodically assess the risk to organizational operations.",
        },
        {
            "check_id": "ca-3.12.1-azure-001",
            "practice_id": "3.12.1",
            "check_name": "Security assessment plan",
            "check_type": "manual",
            "method": None,
            "severity": "high",
            "remediation": "Periodically assess security controls.",
        },
        {
            "check_id": "cm-3.4.1-azure-001",
            "practice_id": "3.4.1",
            "check_name": "Configuration baseline documentation",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Establish and maintain baseline configurations.",
        },
    ]


def _get_gcp_builtin_checks() -> list[dict]:
    return [
        {
            "check_id": "ac-3.1.1-gcp-001",
            "practice_id": "3.1.1",
            "check_name": "IAM bindings follow least privilege",
            "check_type": "automated",
            "method": "check_iam_bindings",
            "severity": "critical",
            "remediation": "Review IAM bindings and remove overly broad roles (Editor, Owner) in favor of predefined or custom roles.",
        },
        {
            "check_id": "au-3.3.1-gcp-001",
            "practice_id": "3.3.1",
            "check_name": "Audit logging enabled for all services",
            "check_type": "automated",
            "method": "check_audit_logging",
            "severity": "critical",
            "remediation": "Enable Data Access audit logs for all services in the project IAM policy.",
        },
        {
            "check_id": "ac-3.1.5-gcp-001",
            "practice_id": "3.1.5",
            "check_name": "VPC firewall rules restrict inbound access",
            "check_type": "automated",
            "method": "check_vpc_firewall_rules",
            "severity": "high",
            "remediation": "Remove firewall rules allowing 0.0.0.0/0 ingress on sensitive ports (SSH, RDP, databases).",
        },
        {
            "check_id": "sc-3.13.10-gcp-001",
            "practice_id": "3.13.10",
            "check_name": "Cloud KMS key rotation configured",
            "check_type": "automated",
            "method": "check_kms_key_rotation",
            "severity": "medium",
            "remediation": "Configure automatic rotation with a period of 365 days or less for all Cloud KMS keys.",
        },
        {
            "check_id": "sc-3.13.11-gcp-001",
            "practice_id": "3.13.11",
            "check_name": "Compute disk encryption with CMEK",
            "check_type": "automated",
            "method": "check_compute_disk_encryption",
            "severity": "high",
            "remediation": "Use Customer-Managed Encryption Keys (CMEK) for all Compute Engine persistent disks.",
        },
        {
            "check_id": "sc-3.13.6-gcp-001",
            "practice_id": "3.13.6",
            "check_name": "Cloud Armor WAF policies configured",
            "check_type": "automated",
            "method": "check_cloud_armor",
            "severity": "medium",
            "remediation": "Configure Cloud Armor security policies on all external HTTP(S) load balancers.",
        },
        {
            "check_id": "au-3.3.1-gcp-002",
            "practice_id": "3.3.1",
            "check_name": "Cloud Logging enabled and exported",
            "check_type": "automated",
            "method": "check_logging_enabled",
            "severity": "high",
            "remediation": "Enable Cloud Logging and configure log sinks to export logs to Cloud Storage or BigQuery for long-term retention.",
        },
        {
            "check_id": "cm-3.4.2-gcp-001",
            "practice_id": "3.4.2",
            "check_name": "Organization Policy constraints enforced",
            "check_type": "automated",
            "method": "check_org_policy_constraints",
            "severity": "high",
            "remediation": "Enforce Organization Policy constraints including resource location restriction and uniform bucket-level access.",
        },
        {
            "check_id": "ia-3.5.3-gcp-001",
            "practice_id": "3.5.3",
            "check_name": "MFA enforced for all users",
            "check_type": "manual",
            "method": None,
            "severity": "critical",
            "remediation": "Enforce 2-Step Verification for all users in Google Workspace Admin console.",
        },
        {
            "check_id": "at-3.2.1-gcp-001",
            "practice_id": "3.2.1",
            "check_name": "Security awareness training program",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Establish and maintain a security awareness training program.",
        },
        {
            "check_id": "ir-3.6.1-gcp-001",
            "practice_id": "3.6.1",
            "check_name": "Incident response plan established",
            "check_type": "manual",
            "method": None,
            "severity": "high",
            "remediation": "Develop and implement an incident response plan.",
        },
        {
            "check_id": "ma-3.7.1-gcp-001",
            "practice_id": "3.7.1",
            "check_name": "System maintenance procedures",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Perform maintenance on organizational systems in a timely manner.",
        },
        {
            "check_id": "mp-3.8.1-gcp-001",
            "practice_id": "3.8.1",
            "check_name": "Media protection policy",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Protect CUI on digital and non-digital media.",
        },
        {
            "check_id": "ps-3.9.1-gcp-001",
            "practice_id": "3.9.1",
            "check_name": "Personnel screening procedures",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Screen individuals prior to authorizing access to systems containing CUI.",
        },
        {
            "check_id": "pe-3.10.1-gcp-001",
            "practice_id": "3.10.1",
            "check_name": "Physical access controls",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Limit physical access to organizational systems.",
        },
        {
            "check_id": "ra-3.11.1-gcp-001",
            "practice_id": "3.11.1",
            "check_name": "Risk assessment procedures",
            "check_type": "manual",
            "method": None,
            "severity": "high",
            "remediation": "Periodically assess the risk to organizational operations.",
        },
        {
            "check_id": "ca-3.12.1-gcp-001",
            "practice_id": "3.12.1",
            "check_name": "Security assessment plan",
            "check_type": "manual",
            "method": None,
            "severity": "high",
            "remediation": "Periodically assess security controls.",
        },
        {
            "check_id": "cm-3.4.1-gcp-001",
            "practice_id": "3.4.1",
            "check_name": "Configuration baseline documentation",
            "check_type": "manual",
            "method": None,
            "severity": "medium",
            "remediation": "Establish and maintain baseline configurations.",
        },
    ]


def _load_practice_names() -> dict[str, str]:
    """Load NIST practice requirement text from config/nist_practices.json."""
    practices_file = CONFIG_DIR / "nist_practices.json"
    if not practices_file.exists():
        return {}
    try:
        with open(practices_file, "r") as f:
            data = json.load(f)
        names: dict[str, str] = {}
        for _fam_id, fam_data in data.get("families", {}).items():
            for practice_id, p_data in fam_data.get("practices", {}).items():
                req = p_data.get("requirement", "")
                names[practice_id] = req
        return names
    except Exception:
        return {}


def _load_practice_objectives() -> dict[str, dict]:
    """
    Load NIST 800-171A assessment objectives from config/nist_practices.json.

    Returns a dict keyed by practice_id, each containing:
        objectives: dict of "[a]" -> {"text": ..., "automatable": ...}
    """
    practices_file = CONFIG_DIR / "nist_practices.json"
    if not practices_file.exists():
        return {}
    try:
        with open(practices_file, "r") as f:
            data = json.load(f)
        result: dict[str, dict] = {}
        for _fam_id, fam_data in data.get("families", {}).items():
            for practice_id, p_data in fam_data.get("practices", {}).items():
                result[practice_id] = {
                    "objectives": p_data.get("objectives", {}),
                }
        return result
    except Exception:
        logger.warning("Failed to load practice objectives", exc_info=True)
        return {}


def _load_documentation_requirements(environment: str) -> dict[str, list[dict]]:
    """
    Load documentation requirements from check config files.

    Returns a dict keyed by practice_id, each containing a list of
    {"id": "[a]", "text": "...", "evidence_needed": "..."} items.
    """
    if not CHECKS_DIR.exists():
        return {}

    result: dict[str, list[dict]] = {}
    for check_file in sorted(CHECKS_DIR.glob("*.json")):
        try:
            with open(check_file, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        for practice_id, practice_data in data.get("checks", {}).items():
            doc_reqs = practice_data.get("objectives_requiring_documentation", [])
            if doc_reqs:
                result[practice_id] = doc_reqs
    return result


def _compute_coverage(
    practice_id: str,
    check_results: list[CheckResult],
    check_defs: list[dict],
    practice_objectives: dict[str, dict],
    doc_requirements: dict[str, list[dict]],
) -> dict:
    """
    Compute assessment objective coverage for a single practice.

    Returns a dict with:
        total_objectives: int
        covered_objectives: int
        coverage_pct: float
        objective_details: list of {id, text, status, source}
    """
    obj_info = practice_objectives.get(practice_id, {})
    objectives = obj_info.get("objectives", {})
    doc_reqs = doc_requirements.get(practice_id, [])
    doc_req_ids = {d["id"] for d in doc_reqs}

    if not objectives:
        return {
            "total_objectives": 0,
            "covered_objectives": 0,
            "coverage_pct": 0.0,
            "objective_details": [],
        }

    # Gather all objectives covered by checks (from supports_objectives)
    covered_by_checks: dict[str, str] = {}  # obj_id -> best status
    for chk_def in check_defs:
        supported = chk_def.get("supports_objectives", [])
        check_id = chk_def.get("check_id", "")
        # Find corresponding result
        result_status = "not_tested"
        for r in check_results:
            if r.check_id == check_id:
                result_status = r.status
                break

        for obj_id in supported:
            if obj_id not in covered_by_checks:
                covered_by_checks[obj_id] = result_status
            else:
                # Prioritize: met > not_met > manual > error > not_tested
                current = covered_by_checks[obj_id]
                if result_status == "met":
                    covered_by_checks[obj_id] = "met"
                elif result_status == "not_met" and current not in ("met",):
                    covered_by_checks[obj_id] = "not_met"

    # Build objective details
    details = []
    covered_count = 0
    for obj_id in sorted(objectives.keys()):
        obj = objectives[obj_id]
        obj_text = obj["text"]
        automatable = obj["automatable"]

        if obj_id in covered_by_checks:
            status = covered_by_checks[obj_id]
            source = "automated_check"
            covered_count += 1
        elif obj_id in doc_req_ids:
            status = "documentation_required"
            source = "documentation"
            # Documentation requirements count as "covered" for coverage %
            # (they're acknowledged, just not automated)
            covered_count += 1
        elif automatable is False:
            status = "documentation_required"
            source = "not_automatable"
            covered_count += 1  # Acknowledged as non-automatable
        else:
            status = "not_tested"
            source = "gap"

        details.append({
            "id": obj_id,
            "text": obj_text,
            "status": status,
            "source": source,
            "automatable": automatable,
        })

    total = len(objectives)
    coverage_pct = round((covered_count / total * 100), 1) if total > 0 else 0.0

    return {
        "total_objectives": total,
        "covered_objectives": covered_count,
        "coverage_pct": coverage_pct,
        "objective_details": details,
    }


def _practice_to_family(practice_id: str) -> tuple[str, str]:
    """
    Map a NIST 800-171 practice ID to its CMMC domain and family name.

    Args:
        practice_id: e.g., "3.1.1"

    Returns:
        Tuple of (domain_code, family_name), e.g., ("AC", "Access Control")
    """
    parts = practice_id.split(".")
    if len(parts) >= 2:
        prefix = f"{parts[0]}.{parts[1]}"
        info = NIST_FAMILIES.get(prefix)
        if info:
            return info["domain"], info["family"]
    return "AC", "Access Control"  # fallback


def run_scan(scan_id: str, client_id: str, db_session: Optional[Session] = None):
    """
    Main scan execution function. Called as a background task.

    Steps:
        1. Load client from DB, get credentials and environment
        2. Load check definitions from config/checks/*.json (or built-in)
        3. Instantiate appropriate scanner (AWS/Azure/GCP)
        4. For each check:
           a. If automated: run cloud API check, collect evidence
           b. If manual: create finding with status="manual" and guidance
        5. Store findings in DB
        6. Update scan status to completed with summary counts
    """
    # Create a new session for background task execution
    db = db_session or SessionLocal()
    scan_start = time.time()
    try:
        # 1. Load client and scan
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return

        client = db.query(Client).filter(Client.id == client_id).first()
        if not client:
            scan.status = "failed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.summary = {"error": "Client not found"}
            db.commit()
            return

        # Update status to running
        scan.status = "running"
        db.commit()

        # 2. Load check definitions
        checks = _load_checks(client.environment)
        if not checks:
            scan.status = "failed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.summary = {"error": "No check definitions found"}
            db.commit()
            return

        # 3. Instantiate scanner
        credentials = client.credentials_config or {}
        scanner = get_scanner(client.environment, credentials)

        # 4. Attempt connection
        connected = False
        try:
            connected = scanner.connect()
            if connected and hasattr(scanner, "prefetch"):
                logger.info("Pre-fetching Azure resource data...")
                scanner.prefetch()
        except Exception as e:
            logger.warning("Scanner connection failed: %s. Running manual-only checks.", e)

        # 5. Execute checks — run all cloud checks, then aggregate per practice
        #
        # Checks are split into two groups:
        #   a) Instant checks (manual, no-method, no-connection) — processed
        #      synchronously because they don't make API calls.
        #   b) Automated checks — submitted to a thread-pool so multiple
        #      cloud API calls run concurrently.  The pool size is kept
        #      moderate (PARALLEL_CHECKS) to avoid Azure rate-limiting.

        practice_results: dict[str, list[CheckResult]] = {}

        instant_checks: list[tuple[dict, CheckResult]] = []
        automated_checks: list[dict] = []

        for check_def in checks:
            practice_id = check_def.get("practice_id", "")

            if check_def.get("check_type") == "manual":
                evidence = check_def.get(
                    "evidence_text",
                    "This practice requires manual verification by a CMMC assessor "
                    "and cannot be assessed through automated API scanning.",
                )
                instant_checks.append((check_def, CheckResult(
                    check_id=check_def["check_id"],
                    practice_id=practice_id,
                    check_name=check_def["check_name"],
                    status="manual",
                    severity=check_def.get("severity", "medium"),
                    evidence=evidence,
                    remediation=check_def.get("remediation", ""),
                )))
            elif not check_def.get("method"):
                svc = check_def.get("service", "N/A")
                api = check_def.get("api_call", "N/A")
                exp = check_def.get("expected", "N/A")
                instant_checks.append((check_def, CheckResult(
                    check_id=check_def["check_id"],
                    practice_id=practice_id,
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def.get("severity", "medium"),
                    evidence=(
                        f"Automated check not yet verified — scanner pending implementation. "
                        f"Service: {svc}. API: {api}. Expected: {exp}."
                    ),
                    remediation=check_def.get("remediation", ""),
                )))
            elif not connected:
                instant_checks.append((check_def, CheckResult(
                    check_id=check_def["check_id"],
                    practice_id=practice_id,
                    check_name=check_def["check_name"],
                    status="error",
                    severity=check_def.get("severity", "medium"),
                    evidence="Could not connect to cloud environment. Check credentials and network access.",
                    remediation=check_def.get("remediation", ""),
                )))
            else:
                automated_checks.append(check_def)

        # 5a. Record instant results
        for check_def, result in instant_checks:
            pid = check_def.get("practice_id", "")
            practice_results.setdefault(pid, []).append(result)

        # 5b. Run automated checks in parallel with enforced per-check timeout
        #
        # Each check is submitted to the main pool.  Inside _run_one the
        # actual scanner.run_check() call is wrapped in a *nested* single-
        # thread executor so we can enforce a hard timeout — if the check
        # takes longer than CHECK_TIMEOUT_SECONDS the inner future is
        # abandoned and the check is marked "error".
        def _run_one(chk: dict) -> tuple[dict, CheckResult]:
            pid = chk.get("practice_id", "")
            t0 = time.time()
            inner = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                fut = inner.submit(scanner.run_check, chk)
                r = fut.result(timeout=CHECK_TIMEOUT_SECONDS)
                inner.shutdown(wait=False)
                elapsed = time.time() - t0
                if elapsed > 5:
                    logger.warning("Slow check %s: %.1fs", chk["check_id"], elapsed)
                return chk, r
            except concurrent.futures.TimeoutError:
                inner.shutdown(wait=False)  # Don't block waiting for hung thread
                logger.warning(
                    "Check %s timed out after %ds", chk["check_id"], CHECK_TIMEOUT_SECONDS)
                return chk, CheckResult(
                    check_id=chk["check_id"],
                    practice_id=pid,
                    check_name=chk["check_name"],
                    status="error",
                    severity=chk.get("severity", "medium"),
                    evidence=(
                        f"Check timed out after {CHECK_TIMEOUT_SECONDS}s. "
                        "The cloud API may be slow or rate-limiting requests."
                    ),
                    remediation=chk.get("remediation", ""),
                )
            except Exception as exc:
                inner.shutdown(wait=False)
                logger.error("Check %s failed (%.1fs): %s", chk["check_id"], time.time() - t0, exc)
                return chk, CheckResult(
                    check_id=chk["check_id"],
                    practice_id=pid,
                    check_name=chk["check_name"],
                    status="error",
                    severity=chk.get("severity", "medium"),
                    evidence=f"Check execution failed: {str(exc)}",
                    remediation=chk.get("remediation", ""),
                )

        if automated_checks:
            checks_start = time.time()
            logger.info(
                "Running %d automated checks with %d parallel workers",
                len(automated_checks),
                PARALLEL_CHECKS,
            )
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=PARALLEL_CHECKS
            ) as pool:
                future_map = {
                    pool.submit(_run_one, chk): chk
                    for chk in automated_checks
                }
                for future in concurrent.futures.as_completed(future_map):
                    chk = future_map[future]
                    pid = chk.get("practice_id", "")
                    try:
                        _, result = future.result()
                    except Exception as exc:
                        logger.error("Check %s failed: %s", chk["check_id"], exc)
                        result = CheckResult(
                            check_id=chk["check_id"],
                            practice_id=pid,
                            check_name=chk["check_name"],
                            status="error",
                            severity=chk.get("severity", "medium"),
                            evidence=f"Check execution failed: {str(exc)}",
                            remediation=chk.get("remediation", ""),
                        )
                    practice_results.setdefault(pid, []).append(result)
            logger.info(
                "Automated checks completed in %.0fs", time.time() - checks_start
            )

        # 5b. Aggregate sub-checks into one Finding per practice (110 for L2)
        SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        status_counts = {"met": 0, "not_met": 0, "manual": 0, "error": 0}

        # Load practice names and objectives from nist_practices.json
        practice_names = _load_practice_names()
        practice_objectives = _load_practice_objectives()
        doc_requirements = _load_documentation_requirements(client.environment)

        # Build a lookup: practice_id -> list of check defs (for coverage scoring)
        practice_check_defs: dict[str, list[dict]] = {}
        for chk_def in checks:
            pid = chk_def.get("practice_id", "")
            practice_check_defs.setdefault(pid, []).append(chk_def)

        for practice_id, results in practice_results.items():
            domain, family = _practice_to_family(practice_id)

            # Separate verified results (actually ran) from pending (not implemented)
            # Pending sub-checks have status="not_met" with "pending implementation" evidence
            verified = []
            pending = []
            for r in results:
                if r.evidence and "pending implementation" in r.evidence:
                    pending.append(r)
                else:
                    verified.append(r)

            # Determine practice status from verified results only
            # Pending sub-checks are noted in evidence but don't affect status
            if verified:
                v_statuses = [r.status for r in verified]
                if "not_met" in v_statuses:
                    agg_status = "not_met"
                elif "error" in v_statuses:
                    agg_status = "error"
                elif "met" in v_statuses:
                    agg_status = "met"
                else:
                    agg_status = "manual"
            else:
                # No verified results — all sub-checks are pending implementation
                agg_status = "not_met"

            # Highest severity
            agg_severity = max(
                (r.severity for r in results),
                key=lambda s: SEVERITY_RANK.get(s, 0),
            )

            # Compute assessment objective coverage
            coverage = _compute_coverage(
                practice_id,
                results,
                practice_check_defs.get(practice_id, []),
                practice_objectives,
                doc_requirements,
            )

            # Combine evidence from all sub-checks
            evidence_parts = []
            remediation_parts = []
            for r in results:
                if r.evidence:
                    label = r.check_name or r.check_id
                    evidence_parts.append(f"[{label}] {r.evidence}")
                if r.remediation:
                    remediation_parts.append(r.remediation)

            # Add coverage summary to evidence
            if coverage["total_objectives"] > 0:
                cov_line = (
                    f"[Assessment Objective Coverage] "
                    f"{coverage['covered_objectives']}/{coverage['total_objectives']} "
                    f"({coverage['coverage_pct']}%)"
                )
                # List objectives with gaps
                gaps = [
                    d for d in coverage["objective_details"]
                    if d["status"] == "not_tested"
                ]
                doc_needed = [
                    d for d in coverage["objective_details"]
                    if d["status"] == "documentation_required"
                ]
                if gaps:
                    cov_line += "\n  Untested objectives: " + ", ".join(
                        f"{d['id']} {d['text'][:50]}" for d in gaps
                    )
                if doc_needed:
                    cov_line += "\n  Documentation required: " + ", ".join(
                        f"{d['id']}" for d in doc_needed
                    )
                evidence_parts.append(cov_line)

            agg_evidence = "\n\n".join(evidence_parts)
            # Deduplicate remediation lines
            seen_rems: set[str] = set()
            unique_rems: list[str] = []
            for rem in remediation_parts:
                if rem not in seen_rems:
                    seen_rems.add(rem)
                    unique_rems.append(rem)
            agg_remediation = "\n".join(unique_rems)

            # Practice-level check_id and name
            check_id = f"{domain.lower()}-{practice_id}"
            check_name = practice_names.get(practice_id, results[0].check_name)

            status_counts[agg_status] = status_counts.get(agg_status, 0) + 1

            finding = Finding(
                scan_id=scan_id,
                practice_id=practice_id,
                family=family,
                domain=domain,
                check_id=check_id,
                check_name=check_name,
                status=agg_status,
                severity=agg_severity,
                evidence=agg_evidence or None,
                remediation=agg_remediation or None,
                objective_coverage=coverage,
            )
            db.add(finding)

        # 6. Cleanup scanner connection
        try:
            scanner.disconnect()
        except Exception:
            pass

        # 7. Update scan summary and status
        total = sum(status_counts.values())
        compliance_pct = round((status_counts["met"] / total * 100), 1) if total > 0 else 0.0

        # Aggregate objective coverage across all findings
        all_total_objs = sum(
            len(practice_objectives.get(pid, {}).get("objectives", {}))
            for pid in practice_results
        )
        all_covered_objs = 0
        for pid, results in practice_results.items():
            cov = _compute_coverage(
                pid, results,
                practice_check_defs.get(pid, []),
                practice_objectives, doc_requirements,
            )
            all_covered_objs += cov["covered_objectives"]
        obj_coverage_pct = round((all_covered_objs / all_total_objs * 100), 1) if all_total_objs > 0 else 0.0

        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = {
            "total": total,
            "met": status_counts["met"],
            "not_met": status_counts["not_met"],
            "manual": status_counts["manual"],
            "error": status_counts["error"],
            "compliance_pct": compliance_pct,
            "total_objectives": all_total_objs,
            "covered_objectives": all_covered_objs,
            "objective_coverage_pct": obj_coverage_pct,
        }
        db.commit()
        elapsed = time.time() - scan_start
        logger.info(
            "Scan %s completed in %.0fs: %d findings (%d met, %d not_met, %d manual, %d error)",
            scan_id[:8],
            elapsed,
            total,
            status_counts["met"],
            status_counts["not_met"],
            status_counts["manual"],
            status_counts["error"],
        )

    except Exception as e:
        logger.error("Scan %s failed with exception: %s\n%s", scan_id, e, traceback.format_exc())
        try:
            db.rollback()  # Clear the broken transaction before retrying
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc)
                scan.summary = {"error": str(e)}
                db.commit()
        except Exception as inner_exc:
            logger.error("Failed to update scan status after error: %s", inner_exc)
    finally:
        if db_session is None:
            db.close()


def fetch_evidence(scan_id: str, practice_id: str, db: Session) -> list[dict]:
    """
    Re-run sub-checks for a single practice and return raw API evidence.

    Called on-demand from the evidence endpoint — connects to the client's
    cloud, re-runs only the checks for the requested practice, and captures
    raw API responses.
    """
    # 1. Load scan → get client
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError("Scan not found")

    client = db.query(Client).filter(Client.id == scan.client_id).first()
    if not client:
        raise ValueError("Client not found")

    # 2. Load check defs for this practice only
    all_checks = _load_checks(client.environment)
    practice_checks = [
        c for c in all_checks
        if c["practice_id"] == practice_id and c.get("method")
    ]

    if not practice_checks:
        return []

    # 3. Connect scanner (fresh session)
    scanner = get_scanner(client.environment, client.credentials_config or {})
    scanner.connect()

    # 4. Run each sub-check, collect raw evidence
    results = []
    try:
        for check_def in practice_checks:
            try:
                result = scanner.run_check(check_def)
                evidence_item = {
                    "check_id": check_def["check_id"],
                    "check_name": check_def.get("check_name", ""),
                    "api_call": result.raw_evidence.get("api_call", check_def.get("api_call", "")),
                    "service": check_def.get("service", ""),
                    "status": result.status,
                    "evidence_summary": result.evidence,
                    "raw_response": result.raw_evidence.get("response", {}),
                    "query_info": result.raw_evidence.get("query_info", {}),
                    "cli_command": result.raw_evidence.get("cli_command", ""),
                }
                if result.raw_evidence.get("assessor_guidance"):
                    evidence_item["assessor_guidance"] = result.raw_evidence["assessor_guidance"]
                if result.raw_evidence.get("corrective_actions"):
                    evidence_item["corrective_actions"] = result.raw_evidence["corrective_actions"]
                results.append(evidence_item)
            except Exception as exc:
                results.append({
                    "check_id": check_def["check_id"],
                    "check_name": check_def.get("check_name", ""),
                    "api_call": check_def.get("api_call", ""),
                    "service": check_def.get("service", ""),
                    "status": "error",
                    "evidence_summary": f"Check failed: {exc}",
                    "raw_response": {},
                })
    finally:
        try:
            scanner.disconnect()
        except Exception:
            pass

    return results
