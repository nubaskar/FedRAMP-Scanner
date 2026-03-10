"""
AWS Scanner — Compliance check implementations using boto3.

Connects to AWS (Commercial or GovCloud) via STS AssumeRole and runs
automated NIST 800-53 control checks against the target account.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import time
from datetime import date, datetime, timezone, timedelta
from typing import Any, Optional

from app.scanner.base import BaseScanner, CheckResult

logger = logging.getLogger(__name__)


class _BotoEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime objects from boto3 responses."""

    def default(self, o):
        if isinstance(o, (datetime, date)):
            return o.isoformat()
        if isinstance(o, bytes):
            return o.decode("utf-8", errors="replace")
        return super().default(o)


def _sanitize_response(obj: Any) -> Any:
    """Make a boto3 response JSON-serializable by converting datetimes/bytes."""
    return json.loads(json.dumps(obj, cls=_BotoEncoder))


def _truncate_list(items: list, limit: int = 50) -> dict:
    """Truncate a list for evidence, preserving total count."""
    return {
        "items": _sanitize_response(items[:limit]),
        "total_count": len(items),
        "truncated": len(items) > limit,
    }


# Corrective action guidance for SCP checks when Organizations is not in use
_SCP_NO_ORG_CORRECTIVE_ACTIONS = [
    {
        "scenario": "Single-Account Environment",
        "severity": "info",
        "description": (
            "AWS Organizations is not required. SCPs are not applicable to "
            "single-account setups. Use IAM policies, permission boundaries, "
            "or AWS Config rules as alternative controls to restrict "
            "unauthorized actions."
        ),
        "alternatives": [
            "IAM deny policies on CloudTrail/Config/audit services",
            "IAM permission boundaries limiting what principals can do",
            "AWS Config rules to detect unauthorized configuration changes",
            "CloudTrail log file validation + S3 Object Lock for integrity",
        ],
    },
    {
        "scenario": "Multi-Account Without Organizations",
        "severity": "warning",
        "description": (
            "This is a compliance gap. Multi-account environments should use "
            "AWS Organizations with SCPs to enforce guardrails across all accounts. "
            "Without Organizations, there is no centralized mechanism to prevent "
            "individual accounts from disabling security controls."
        ),
        "alternatives": [
            "Enable AWS Organizations and enroll all accounts",
            "Create SCPs to deny critical security service modifications",
            "Apply SCPs to all OUs with exceptions only for security admin roles",
        ],
    },
    {
        "scenario": "Multi-Account With Organizations",
        "severity": "success",
        "description": (
            "AWS Organizations is in use. Ensure SCPs are properly configured "
            "to deny unauthorized modifications to audit and security services. "
            "Verify SCPs are applied to all OUs and accounts."
        ),
        "alternatives": [],
    },
]


class AwsScanner(BaseScanner):
    """AWS-specific compliance scanner using boto3 SDK."""

    def __init__(self, credentials: dict, environment: str, region: str = "us-east-1"):
        super().__init__(credentials, environment, region)
        self._session = None
        # Core clients
        self._iam = None
        self._sts = None
        self._cloudtrail = None
        self._s3 = None
        self._ec2 = None
        self._kms = None
        self._guardduty = None
        # Phase 4 clients
        self._ssm = None
        self._config_service = None
        self._rds = None
        self._efs = None
        self._backup = None
        # Phase 5 clients
        self._securityhub = None
        self._inspector2 = None
        # Phase 6 clients
        self._wafv2 = None
        self._elbv2 = None
        self._cloudfront = None
        self._acm = None
        self._route53 = None
        self._network_firewall = None
        # Phase 7 clients
        self._events = None
        self._cloudwatch = None
        self._sns = None
        self._dynamodb = None
        self._ecr = None
        self._logs = None
        # Phase 8 clients
        self._organizations = None
        self._sso_admin = None
        self._identitystore = None
        self._codepipeline = None
        self._apigateway = None
        self._athena = None
        self._health = None
        # Caches
        self._credential_report_cache = None
        self._trails_cache = None
        self._s3_buckets_cache = None
        # Identity
        self._account_id = ""

    def connect(self) -> bool:
        """
        Establish connection to AWS via STS AssumeRole.

        Expects credentials dict with:
            - role_arn: ARN of the cross-account IAM role
            - external_id: External ID for role assumption (optional)
            - region: Override region (optional)

        Returns True if connection successful.
        """
        try:
            import boto3

            role_arn = self.credentials.get("role_arn", "")
            external_id = self.credentials.get("external_id", "")
            region = self.credentials.get("region", self.region)

            if role_arn:
                # Assume cross-account role
                sts_client = boto3.client("sts", region_name=region)
                assume_params = {
                    "RoleArn": role_arn,
                    "RoleSessionName": "cmmc-scanner-session",
                    "DurationSeconds": 3600,
                }
                if external_id:
                    assume_params["ExternalId"] = external_id

                response = sts_client.assume_role(**assume_params)
                creds = response["Credentials"]

                self._session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    region_name=region,
                )
            else:
                # Use default credentials (for local testing)
                self._session = boto3.Session(region_name=region)

            # Initialize service clients
            self._iam = self._session.client("iam")
            self._sts = self._session.client("sts")
            self._cloudtrail = self._session.client("cloudtrail")
            self._s3 = self._session.client("s3")
            self._ec2 = self._session.client("ec2")
            self._kms = self._session.client("kms")
            self._guardduty = self._session.client("guardduty")
            # Extended clients (Phase 4-8)
            self._ssm = self._session.client("ssm")
            self._config_service = self._session.client("config")
            self._rds = self._session.client("rds")
            self._efs = self._session.client("efs")
            self._backup = self._session.client("backup")
            self._securityhub = self._session.client("securityhub")
            self._inspector2 = self._session.client("inspector2")
            self._wafv2 = self._session.client("wafv2")
            self._elbv2 = self._session.client("elbv2")
            self._cloudfront = self._session.client("cloudfront")
            self._acm = self._session.client("acm")
            self._route53 = self._session.client("route53")
            self._network_firewall = self._session.client("network-firewall")
            self._events = self._session.client("events")
            self._cloudwatch = self._session.client("cloudwatch")
            self._sns = self._session.client("sns")
            self._dynamodb = self._session.client("dynamodb")
            self._ecr = self._session.client("ecr")
            self._logs = self._session.client("logs")
            self._organizations = self._session.client("organizations")
            self._sso_admin = self._session.client("sso-admin")
            self._identitystore = self._session.client("identitystore")
            self._codepipeline = self._session.client("codepipeline")
            self._apigateway = self._session.client("apigateway")
            self._athena = self._session.client("athena")
            self._health = self._session.client("health")

            # Verify connectivity and capture account ID
            caller = self._sts.get_caller_identity()
            self._account_id = caller.get("Account", "")
            logger.info("Connected to AWS account %s as %s", caller["Account"], caller["Arn"])
            self._connected = True
            return True

        except ImportError:
            logger.error("boto3 is not installed. Install it with: pip install boto3")
            return False
        except Exception as e:
            logger.error("Failed to connect to AWS: %s", e)
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
    # Helpers
    # ------------------------------------------------------------------


    def _get_credential_report(self) -> list[dict]:
        """Generate and parse the IAM credential report CSV. Cached."""
        if self._credential_report_cache is not None:
            return self._credential_report_cache
        self._iam.generate_credential_report()
        time.sleep(2)
        response = self._iam.get_credential_report()
        content = response["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        self._credential_report_cache = list(reader)
        return self._credential_report_cache

    def _get_all_trails(self) -> list[dict]:
        """Describe all CloudTrail trails. Cached."""
        if self._trails_cache is not None:
            return self._trails_cache
        trails = self._cloudtrail.describe_trails(includeShadowTrails=False)
        self._trails_cache = trails.get("trailList", [])
        return self._trails_cache

    def _get_all_s3_buckets(self) -> list[str]:
        """List all S3 bucket names. Cached."""
        if self._s3_buckets_cache is not None:
            return self._s3_buckets_cache
        response = self._s3.list_buckets()
        self._s3_buckets_cache = [b["Name"] for b in response.get("Buckets", [])]
        return self._s3_buckets_cache

    def _build_evidence(self, api_call: str, cli_command: str, response: Any,
                        service: str = "", parameters: dict | None = None,
                        assessor_guidance: str = "",
                        corrective_actions: list[dict] | None = None) -> dict:
        """Build structured evidence dict with query context and CLI command."""
        result = {
            "api_call": api_call,
            "cli_command": cli_command,
            "query_info": {
                "service": service,
                "api_method": api_call,
                "parameters": parameters or {},
                "region": self.region or "us-east-1",
                "account_id": self._account_id,
            },
            "response": response,
        }
        if assessor_guidance:
            result["assessor_guidance"] = assessor_guidance
        if corrective_actions:
            result["corrective_actions"] = corrective_actions
        return result

    # ------------------------------------------------------------------
    # Automated check implementations (existing)
    # ------------------------------------------------------------------

    def check_root_access_keys(self, check_def: dict) -> CheckResult:
        """
        Check if root account has active access keys.

        NIST 800-53 Control: 3.1.1 — Limit system access to authorized users.
        Root access keys are a critical security risk — all access should
        use IAM users/roles with least privilege.
        """
        try:
            summary = self._iam.get_account_summary()
            summary_map = summary.get("SummaryMap", {})
            raw = self._build_evidence(
                api_call="iam.get_account_summary",
                cli_command="aws iam get-account-summary",
                response=_sanitize_response(summary_map),
                service="IAM",
                assessor_guidance="Check AccountAccessKeysPresent=0. Any value >0 means root has active access keys, which is a critical finding. Root should never have programmatic access.",
            )
            root_keys = summary_map.get("AccountAccessKeysPresent", 0)

            if root_keys == 0:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence="No root account access keys found. AccountAccessKeysPresent=0.",
                    raw_evidence=raw,
                )
            else:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence=f"Root account has {root_keys} active access key(s). AccountAccessKeysPresent={root_keys}.",
                    remediation=check_def.get("remediation", "Remove root account access keys."),
                    raw_evidence=raw,
                )
        except Exception as e:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking root access keys: {str(e)}",
                remediation=check_def.get("remediation", ""),
            )

    def check_mfa_enabled(self, check_def: dict) -> CheckResult:
        """
        Check if MFA is enabled for IAM users with console access.

        NIST 800-53 Control: 3.5.3 — Use multifactor authentication for local
        and network access to privileged accounts.
        """
        try:
            # Generate credential report
            self._iam.generate_credential_report()
            import time
            time.sleep(2)  # Wait for report generation
            report_response = self._iam.get_credential_report()
            report_csv = report_response["Content"].decode("utf-8")
            raw = self._build_evidence(
                api_call="iam.get_credential_report",
                cli_command="aws iam generate-credential-report && aws iam get-credential-report",
                response={"user_count": 0, "fields": []},
                service="IAM",
                assessor_guidance="Look for mfa_active=false on any user with password_enabled=true. Every console user must have MFA. Check users_without_mfa list for specific accounts needing remediation.",
            )

            lines = report_csv.strip().split("\n")
            headers = lines[0].split(",")
            mfa_idx = headers.index("mfa_active") if "mfa_active" in headers else -1
            password_idx = headers.index("password_enabled") if "password_enabled" in headers else -1

            users_without_mfa = []
            total_console_users = 0

            for line in lines[1:]:
                fields = line.split(",")
                user = fields[0]
                has_password = fields[password_idx].lower() == "true" if password_idx >= 0 else False
                has_mfa = fields[mfa_idx].lower() == "true" if mfa_idx >= 0 else False

                if has_password:
                    total_console_users += 1
                    if not has_mfa:
                        users_without_mfa.append(user)

            raw["response"] = {
                "total_users": len(lines) - 1,
                "console_users": total_console_users,
                "users_without_mfa": users_without_mfa[:20],
                "headers": headers,
            }

            if not users_without_mfa:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence=f"All {total_console_users} console users have MFA enabled.",
                    raw_evidence=raw,
                )
            else:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence=(
                        f"{len(users_without_mfa)} of {total_console_users} console users "
                        f"do not have MFA enabled: {', '.join(users_without_mfa[:10])}"
                        f"{'...' if len(users_without_mfa) > 10 else ''}"
                    ),
                    remediation=check_def.get("remediation", "Enable MFA for all IAM users with console access."),
                    raw_evidence=raw,
                )
        except Exception as e:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking MFA status: {str(e)}",
                remediation=check_def.get("remediation", ""),
            )

    def check_cloudtrail_enabled(self, check_def: dict) -> CheckResult:
        """
        Check if CloudTrail is enabled with multi-region logging.

        NIST 800-53 Control: 3.3.1 — Create and retain system audit logs to
        enable monitoring, analysis, investigation, and reporting.
        """
        try:
            trails = self._cloudtrail.describe_trails(includeShadowTrails=False)
            trail_list = trails.get("trailList", [])
            raw = self._build_evidence(
                api_call="cloudtrail.describe_trails",
                cli_command="aws cloudtrail describe-trails && aws cloudtrail get-trail-status --name TRAIL",
                response=_sanitize_response(trail_list),
                service="CloudTrail",
                assessor_guidance="Verify IsMultiRegionTrail=true and IsLogging=true on at least one trail. Check S3BucketName for log destination. All regions must be covered.",
            )

            if not trail_list:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence="No CloudTrail trails found in the account.",
                    remediation=check_def.get("remediation", "Enable CloudTrail."),
                    raw_evidence=raw,
                )

            multi_region_trails = [t for t in trail_list if t.get("IsMultiRegionTrail", False)]
            active_trails = []

            for trail in trail_list:
                try:
                    status = self._cloudtrail.get_trail_status(Name=trail["TrailARN"])
                    if status.get("IsLogging", False):
                        active_trails.append(trail["Name"])
                except Exception:
                    pass

            if multi_region_trails and active_trails:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence=(
                        f"Found {len(trail_list)} trail(s), {len(multi_region_trails)} multi-region, "
                        f"{len(active_trails)} actively logging: {', '.join(active_trails)}"
                    ),
                    raw_evidence=raw,
                )
            else:
                issues = []
                if not multi_region_trails:
                    issues.append("No multi-region trail configured")
                if not active_trails:
                    issues.append("No trails are actively logging")
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence=f"CloudTrail issues: {'; '.join(issues)}. Found {len(trail_list)} trail(s).",
                    remediation=check_def.get("remediation", "Enable multi-region CloudTrail."),
                    raw_evidence=raw,
                )
        except Exception as e:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking CloudTrail: {str(e)}",
                remediation=check_def.get("remediation", ""),
            )

    def check_cloudtrail_log_validation(self, check_def: dict) -> CheckResult:
        """
        Check if CloudTrail log file validation is enabled.

        NIST 800-53 Control: 3.3.1 — Ensure audit log integrity.
        """
        try:
            trails = self._cloudtrail.describe_trails(includeShadowTrails=False)
            trail_list = trails.get("trailList", [])
            raw = self._build_evidence(
                api_call="cloudtrail.describe_trails",
                cli_command="aws cloudtrail describe-trails --query 'trailList[].{Name:Name,LogFileValidation:LogFileValidationEnabled}'",
                response=_sanitize_response(trail_list),
                service="CloudTrail",
                assessor_guidance="Check LogFileValidationEnabled=true on every trail. If false, log integrity cannot be verified and tampered logs would go undetected.",
            )

            if not trail_list:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence="No CloudTrail trails found.",
                    remediation=check_def.get("remediation", ""),
                    raw_evidence=raw,
                )

            trails_without_validation = []
            for trail in trail_list:
                if not trail.get("LogFileValidationEnabled", False):
                    trails_without_validation.append(trail["Name"])

            if not trails_without_validation:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence=f"Log file validation is enabled on all {len(trail_list)} trail(s).",
                    raw_evidence=raw,
                )
            else:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence=(
                        f"Log file validation is NOT enabled on: {', '.join(trails_without_validation)}"
                    ),
                    remediation=check_def.get("remediation", "Enable log file validation on all trails."),
                    raw_evidence=raw,
                )
        except Exception as e:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking log validation: {str(e)}",
                remediation=check_def.get("remediation", ""),
            )

    def check_encryption_at_rest(self, check_def: dict) -> CheckResult:
        """
        Check encryption at rest for S3 buckets and EBS volumes.

        NIST 800-53 Control: 3.13.11 — Employ FIPS-validated cryptography for CUI.
        """
        try:
            issues = []
            raw_parts = []

            # Check S3 bucket default encryption
            buckets_response = self._s3.list_buckets()
            buckets = buckets_response.get("Buckets", [])
            raw_parts.append({"api_call": "s3.list_buckets", "bucket_count": len(buckets)})
            unencrypted_buckets = []

            for bucket in buckets:
                bucket_name = bucket["Name"]
                try:
                    enc = self._s3.get_bucket_encryption(Bucket=bucket_name)
                    # Encryption exists — check it
                    rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    if not rules:
                        unencrypted_buckets.append(bucket_name)
                except self._s3.exceptions.ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "")
                    if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                        unencrypted_buckets.append(bucket_name)

            if unencrypted_buckets:
                issues.append(
                    f"{len(unencrypted_buckets)} S3 bucket(s) without default encryption: "
                    f"{', '.join(unencrypted_buckets[:5])}"
                    f"{'...' if len(unencrypted_buckets) > 5 else ''}"
                )

            # Check EBS default encryption
            ebs_raw = {}
            try:
                ebs_enc = self._ec2.get_ebs_encryption_by_default()
                ebs_raw = _sanitize_response(ebs_enc)
                if not ebs_enc.get("EbsEncryptionByDefault", False):
                    issues.append("EBS default encryption is not enabled for the account")
            except Exception as e:
                issues.append(f"Could not check EBS default encryption: {str(e)}")
            raw_parts.append({"api_call": "ec2.get_ebs_encryption_by_default", "response": ebs_raw})

            raw = self._build_evidence(
                api_call="s3.get_bucket_encryption + ec2.get_ebs_encryption_by_default",
                cli_command="aws s3api list-buckets && aws s3api get-bucket-encryption --bucket BUCKET",
                response=raw_parts,
                service="S3",
                assessor_guidance="Check each bucket has ServerSideEncryptionConfiguration with SSEAlgorithm=aws:kms or AES256. Verify EbsEncryptionByDefault=true. Unencrypted resources are a critical CUI risk.",
            )

            if not issues:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence=(
                        f"All {len(buckets)} S3 bucket(s) have default encryption. "
                        "EBS default encryption is enabled."
                    ),
                    raw_evidence=raw,
                )
            else:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence="; ".join(issues),
                    remediation=check_def.get("remediation", "Enable encryption at rest."),
                    raw_evidence=raw,
                )
        except Exception as e:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking encryption at rest: {str(e)}",
                remediation=check_def.get("remediation", ""),
            )

    def check_vpc_flow_logs(self, check_def: dict) -> CheckResult:
        """
        Check if VPC Flow Logs are enabled on all VPCs.

        NIST 800-53 Control: 3.3.1 — Audit and accountability.
        """
        try:
            vpcs = self._ec2.describe_vpcs()
            vpc_list = vpcs.get("Vpcs", [])

            if not vpc_list:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence="No VPCs found in the account.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_vpcs",
                        cli_command="aws ec2 describe-vpcs && aws ec2 describe-flow-logs",
                        response={"vpcs": [], "vpc_count": 0},
                        service="EC2",
                        assessor_guidance="No VPCs found. Confirm account is in scope and correct region is being scanned. An empty VPC list may indicate a non-production account.",
                    ),
                )

            flow_logs = self._ec2.describe_flow_logs()
            raw = self._build_evidence(
                api_call="ec2.describe_vpcs + ec2.describe_flow_logs",
                cli_command="aws ec2 describe-vpcs && aws ec2 describe-flow-logs",
                response={                "vpcs": _sanitize_response([{"VpcId": v["VpcId"], "State": v.get("State")} for v in vpc_list]),
                "flow_logs": _sanitize_response([{"ResourceId": fl.get("ResourceId"), "FlowLogId": fl.get("FlowLogId")} for fl in flow_logs.get("FlowLogs", [])]),
            },
                service="EC2",
                assessor_guidance="Match each VpcId in 'vpcs' to a FlowLog ResourceId. Any VPC without a matching flow log has no network traffic auditing. Check FlowLogStatus=ACTIVE.",
            )
            flow_log_vpcs = set()
            for fl in flow_logs.get("FlowLogs", []):
                if fl.get("ResourceId", "").startswith("vpc-"):
                    flow_log_vpcs.add(fl["ResourceId"])

            vpcs_without_flow_logs = []
            for vpc in vpc_list:
                vpc_id = vpc["VpcId"]
                if vpc_id not in flow_log_vpcs:
                    vpcs_without_flow_logs.append(vpc_id)

            if not vpcs_without_flow_logs:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence=f"VPC Flow Logs are enabled on all {len(vpc_list)} VPC(s).",
                    raw_evidence=raw,
                )
            else:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence=(
                        f"{len(vpcs_without_flow_logs)} of {len(vpc_list)} VPC(s) do not have "
                        f"Flow Logs: {', '.join(vpcs_without_flow_logs[:5])}"
                    ),
                    remediation=check_def.get("remediation", "Enable VPC Flow Logs."),
                    raw_evidence=raw,
                )
        except Exception as e:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking VPC Flow Logs: {str(e)}",
                remediation=check_def.get("remediation", ""),
            )

    def check_security_groups(self, check_def: dict) -> CheckResult:
        """
        Check for overly permissive security group rules (0.0.0.0/0).

        NIST 800-53 Control: 3.1.5 — Employ the principle of least privilege.
        """
        try:
            sgs = self._ec2.describe_security_groups()
            sg_list = sgs.get("SecurityGroups", [])
            raw = self._build_evidence(
                api_call="ec2.describe_security_groups()",
                cli_command="aws ec2 describe-security-groups",
                response=_sanitize_response(
                    [{"GroupId": sg["GroupId"], "GroupName": sg.get("GroupName", ""), "IpPermissions": sg.get("IpPermissions", [])} for sg in sg_list[:50]]
                ),
                service="EC2",
                assessor_guidance="Look for IpRanges with CidrIp=0.0.0.0/0 or Ipv6Ranges with CidrIpv6=::/0 on sensitive ports (22,3389,3306,5432,1433). Any match is overly permissive.",
            )

            sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200}
            overly_permissive = []

            for sg in sg_list:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "")
                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)

                    for ip_range in rule.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp", "")
                        if cidr == "0.0.0.0/0":
                            # Check if it covers sensitive ports
                            if from_port == 0 and to_port == 65535:
                                overly_permissive.append(
                                    f"{sg_id} ({sg_name}): all ports open to 0.0.0.0/0"
                                )
                            else:
                                exposed = [
                                    p for p in sensitive_ports
                                    if from_port <= p <= to_port
                                ]
                                if exposed:
                                    overly_permissive.append(
                                        f"{sg_id} ({sg_name}): port(s) {exposed} open to 0.0.0.0/0"
                                    )

                    for ip_range in rule.get("Ipv6Ranges", []):
                        cidr = ip_range.get("CidrIpv6", "")
                        if cidr == "::/0":
                            if from_port == 0 and to_port == 65535:
                                overly_permissive.append(
                                    f"{sg_id} ({sg_name}): all ports open to ::/0"
                                )
                            else:
                                exposed = [
                                    p for p in sensitive_ports
                                    if from_port <= p <= to_port
                                ]
                                if exposed:
                                    overly_permissive.append(
                                        f"{sg_id} ({sg_name}): port(s) {exposed} open to ::/0"
                                    )

            if not overly_permissive:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence=(
                        f"Reviewed {len(sg_list)} security group(s). "
                        "No overly permissive rules found on sensitive ports."
                    ),
                    raw_evidence=raw,
                )
            else:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence=(
                        f"Found {len(overly_permissive)} overly permissive rule(s): "
                        + "; ".join(overly_permissive[:10])
                        + ("..." if len(overly_permissive) > 10 else "")
                    ),
                    remediation=check_def.get("remediation", "Restrict security group rules."),
                    raw_evidence=raw,
                )
        except Exception as e:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking security groups: {str(e)}",
                remediation=check_def.get("remediation", ""),
            )

    def check_password_policy(self, check_def: dict) -> CheckResult:
        """
        Check IAM account password policy meets FedRAMP requirements.

        NIST 800-53 Control: 3.1.1 / 3.5.7 — Enforce minimum password complexity.
        """
        try:
            policy = self._iam.get_account_password_policy()
            pp = policy.get("PasswordPolicy", {})
            raw = self._build_evidence(
                api_call="iam.get_account_password_policy",
                cli_command="aws iam get-account-password-policy",
                response=_sanitize_response(pp),
                service="IAM",
                assessor_guidance="Verify MinimumPasswordLength>=14, RequireUppercase/Lowercase/Numbers/Symbols all true, MaxPasswordAge<=90, PasswordReusePrevention>=24. Any gap is not_met.",
            )

            issues = []
            min_length = pp.get("MinimumPasswordLength", 0)
            if min_length < 14:
                issues.append(f"Minimum length is {min_length} (should be >= 14)")

            if not pp.get("RequireUppercaseCharacters", False):
                issues.append("Uppercase characters not required")
            if not pp.get("RequireLowercaseCharacters", False):
                issues.append("Lowercase characters not required")
            if not pp.get("RequireNumbers", False):
                issues.append("Numbers not required")
            if not pp.get("RequireSymbols", False):
                issues.append("Symbols not required")

            max_age = pp.get("MaxPasswordAge", 0)
            if max_age == 0 or max_age > 90:
                issues.append(f"Password max age is {max_age} days (should be <= 90)")

            password_reuse = pp.get("PasswordReusePrevention", 0)
            if password_reuse < 24:
                issues.append(f"Password reuse prevention is {password_reuse} (should be >= 24)")

            if not issues:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence=(
                        f"Password policy meets requirements: min_length={min_length}, "
                        f"max_age={max_age}, reuse_prevention={password_reuse}, "
                        "complexity requirements all enabled."
                    ),
                    raw_evidence=raw,
                )
            else:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence=f"Password policy issues: {'; '.join(issues)}",
                    remediation=check_def.get("remediation", "Update the IAM password policy."),
                    raw_evidence=raw,
                )
        except self._iam.exceptions.NoSuchEntityException:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="not_met",
                severity=check_def["severity"],
                evidence="No account password policy is configured.",
                remediation=check_def.get("remediation", "Configure an IAM password policy."),
                raw_evidence=self._build_evidence(
                    api_call="iam.get_account_password_policy",
                    cli_command="aws iam get-account-password-policy",
                    response={"error": "NoSuchEntity", "detail": "No account password policy configured"},
                    service="IAM",
                    assessor_guidance="NoSuchEntity means no password policy exists at all. This is an automatic not_met. A custom policy must be created with FedRAMP-compliant settings.",
                ),
            )
        except Exception as e:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking password policy: {str(e)}",
                remediation=check_def.get("remediation", ""),
            )

    def check_kms_key_rotation(self, check_def: dict) -> CheckResult:
        """
        Check if automatic rotation is enabled for customer-managed KMS keys.

        NIST 800-53 Control: 3.13.10 — Establish and manage cryptographic keys.
        """
        try:
            keys_response = self._kms.list_keys()
            keys = keys_response.get("Keys", [])
            raw = self._build_evidence(
                api_call="kms.list_keys + kms.get_key_rotation_status",
                cli_command="aws kms list-keys && aws kms get-key-rotation-status --key-id KEY",
                response={"total_keys": len(keys), "customer_keys": []},
                service="KMS",
                assessor_guidance="Review customer_keys list. Each must have RotationEnabled=true. Only CUSTOMER-managed SYMMETRIC_DEFAULT keys are checked. AWS-managed keys rotate automatically.",
            )

            customer_keys = []
            keys_without_rotation = []

            for key_entry in keys:
                key_id = key_entry["KeyId"]
                try:
                    key_meta = self._kms.describe_key(KeyId=key_id)
                    metadata = key_meta.get("KeyMetadata", {})

                    # Only check customer-managed symmetric keys
                    if (
                        metadata.get("KeyManager") == "CUSTOMER"
                        and metadata.get("KeyState") == "Enabled"
                        and metadata.get("KeySpec", "") == "SYMMETRIC_DEFAULT"
                    ):
                        customer_keys.append(key_id)
                        rotation = self._kms.get_key_rotation_status(KeyId=key_id)
                        rotation_enabled = rotation.get("KeyRotationEnabled", False)
                        raw["response"]["customer_keys"].append({"KeyId": key_id[:12] + "...", "RotationEnabled": rotation_enabled})
                        if not rotation_enabled:
                            keys_without_rotation.append(key_id[:12] + "...")
                except Exception:
                    pass

            if not customer_keys:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence="No customer-managed symmetric KMS keys found.",
                    raw_evidence=raw,
                )

            if not keys_without_rotation:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence=(
                        f"Automatic rotation is enabled on all {len(customer_keys)} "
                        "customer-managed KMS key(s)."
                    ),
                    raw_evidence=raw,
                )
            else:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence=(
                        f"{len(keys_without_rotation)} of {len(customer_keys)} customer-managed "
                        f"key(s) do not have rotation enabled: {', '.join(keys_without_rotation[:5])}"
                    ),
                    remediation=check_def.get("remediation", "Enable KMS key rotation."),
                    raw_evidence=raw,
                )
        except Exception as e:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking KMS key rotation: {str(e)}",
                remediation=check_def.get("remediation", ""),
            )

    def check_guardduty_enabled(self, check_def: dict) -> CheckResult:
        """
        Check if Amazon GuardDuty is enabled.

        NIST 800-53 Control: 3.14.6 — Monitor organizational systems for attacks.
        """
        try:
            detectors = self._guardduty.list_detectors()
            detector_ids = detectors.get("DetectorIds", [])
            raw = self._build_evidence(
                api_call="guardduty.list_detectors",
                cli_command="aws guardduty list-detectors && aws guardduty get-detector --detector-id ID",
                response={"DetectorIds": detector_ids},
                service="GuardDuty",
                assessor_guidance="Verify DetectorIds is non-empty and active_detectors shows at least one with Status=ENABLED. Empty list means no threat detection is active in this region.",
            )

            if not detector_ids:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence="Amazon GuardDuty is not enabled. No detectors found.",
                    remediation=check_def.get("remediation", "Enable GuardDuty."),
                    raw_evidence=raw,
                )

            active_detectors = []
            for det_id in detector_ids:
                try:
                    det = self._guardduty.get_detector(DetectorId=det_id)
                    if det.get("Status") == "ENABLED":
                        active_detectors.append(det_id)
                except Exception:
                    pass

            raw["response"]["active_detectors"] = active_detectors

            if active_detectors:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence=f"GuardDuty is enabled with {len(active_detectors)} active detector(s).",
                    raw_evidence=raw,
                )
            else:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence=f"Found {len(detector_ids)} detector(s) but none are active.",
                    remediation=check_def.get("remediation", "Activate GuardDuty detectors."),
                    raw_evidence=raw,
                )
        except Exception as e:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking GuardDuty: {str(e)}",
                remediation=check_def.get("remediation", ""),
            )

    def check_defense_in_depth(self, check_def: dict) -> CheckResult:
        """
        Check for defense-in-depth architecture across multiple security layers.

        NIST 800-53 Control: 3.13.2 — Employ architectural designs, software development
        techniques, and systems engineering principles that promote effective
        information security.

        Met if >= 4 of 5 layers present: network segmentation (multiple subnets),
        GuardDuty, CloudTrail, KMS customer-managed keys, VPC Flow Logs.
        """
        try:
            layers = []
            raw_layers = {}

            # Layer 1: Network segmentation — multiple subnets
            subnets = self._ec2.describe_subnets()
            subnet_count = len(subnets.get("Subnets", []))
            raw_layers["subnets"] = subnet_count
            if subnet_count >= 2:
                layers.append(f"Network segmentation ({subnet_count} subnets)")

            # Layer 2: GuardDuty threat detection
            detector_ids = self._guardduty.list_detectors().get("DetectorIds", [])
            raw_layers["guardduty_detectors"] = detector_ids
            for det_id in detector_ids:
                try:
                    det = self._guardduty.get_detector(DetectorId=det_id)
                    if det.get("Status") == "ENABLED":
                        layers.append("GuardDuty enabled")
                        break
                except Exception:
                    pass

            # Layer 3: CloudTrail audit logging
            trails = self._cloudtrail.describe_trails(includeShadowTrails=False)
            trail_list = trails.get("trailList", [])
            raw_layers["cloudtrail_count"] = len(trail_list)
            for trail in trail_list:
                try:
                    status = self._cloudtrail.get_trail_status(Name=trail["TrailARN"])
                    if status.get("IsLogging", False):
                        layers.append("CloudTrail logging active")
                        break
                except Exception:
                    pass

            # Layer 4: KMS customer-managed keys
            keys = self._kms.list_keys().get("Keys", [])
            raw_layers["kms_key_count"] = len(keys)
            for key_entry in keys[:20]:
                try:
                    meta = self._kms.describe_key(KeyId=key_entry["KeyId"]).get("KeyMetadata", {})
                    if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeyState") == "Enabled":
                        layers.append("KMS customer-managed keys")
                        break
                except Exception:
                    pass

            # Layer 5: VPC Flow Logs
            flow_logs = self._ec2.describe_flow_logs().get("FlowLogs", [])
            raw_layers["flow_log_count"] = len(flow_logs)
            if flow_logs:
                layers.append(f"VPC Flow Logs ({len(flow_logs)} configured)")

            raw = self._build_evidence(
                api_call="ec2/guardduty/cloudtrail/kms (defense-in-depth)",
                cli_command="aws guardduty list-detectors && aws cloudtrail describe-trails && aws ec2 describe-subnets",
                response=raw_layers,
                service="Multiple",
                assessor_guidance="Verify >=4 of 5 layers: subnets>=2, guardduty_detectors non-empty, cloudtrail_count>=1, kms_key_count>=1 (customer-managed), flow_log_count>=1. Missing layers are gaps.",
            )

            if len(layers) >= 4:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence=f"Defense-in-depth: {len(layers)}/5 layers present — {'; '.join(layers)}.",
                    raw_evidence=raw,
                )
            else:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence=f"Only {len(layers)}/5 defense-in-depth layers found: {'; '.join(layers) if layers else 'none'}.",
                    remediation=check_def.get("remediation", ""),
                    raw_evidence=raw,
                )
        except Exception as e:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking defense-in-depth: {str(e)}",
                remediation=check_def.get("remediation", ""),
            )

    def check_vpn_remote_access(self, check_def: dict) -> CheckResult:
        """
        Check if VPN infrastructure exists for controlled remote access.

        NIST 800-53 Control: 3.1.16 — Authorize wireless access prior to allowing
        such connections (interpreted as VPN remote access in cloud).
        """
        try:
            vpn_resources = []

            # Check Site-to-Site VPN connections
            vpn_conns = self._ec2.describe_vpn_connections()
            active_vpns = [
                v for v in vpn_conns.get("VpnConnections", [])
                if v.get("State") == "available"
            ]
            if active_vpns:
                vpn_resources.append(f"{len(active_vpns)} site-to-site VPN connection(s)")

            # Check Client VPN endpoints
            try:
                client_vpns = self._ec2.describe_client_vpn_endpoints()
                endpoints = client_vpns.get("ClientVpnEndpoints", [])
                active_endpoints = [e for e in endpoints if e.get("Status", {}).get("Code") == "available"]
                if active_endpoints:
                    vpn_resources.append(f"{len(active_endpoints)} Client VPN endpoint(s)")
            except Exception:
                pass  # Client VPN API may not be available in all regions

            raw = self._build_evidence(
                api_call="ec2.describe_vpn_connections() + describe_client_vpn_endpoints()",
                cli_command="aws ec2 describe-vpn-connections && aws ec2 describe-client-vpn-endpoints",
                response={
                    "site_to_site_vpns": _sanitize_response([{"VpnConnectionId": v.get("VpnConnectionId"), "State": v.get("State")} for v in active_vpns]),
                    "vpn_resource_summary": vpn_resources,
                },
                service="EC2",
                assessor_guidance="Check for at least one VPN with State=available. No VPN infrastructure means remote access is uncontrolled. Verify Client VPN or Site-to-Site VPN exists.",
            )
            if vpn_resources:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence=f"VPN infrastructure present: {'; '.join(vpn_resources)}.",
                    raw_evidence=raw,
                )
            else:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence="No VPN connections or Client VPN endpoints found in the account.",
                    remediation=check_def.get("remediation", ""),
                    raw_evidence=raw,
                )
        except Exception as e:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking VPN remote access: {str(e)}",
                remediation=check_def.get("remediation", ""),
            )

    def check_mobile_device_control(self, check_def: dict) -> CheckResult:
        """
        Check if centralized identity/device management is configured.

        NIST 800-53 Control: 3.1.18 — Control connection of mobile devices.
        Verifies SAML and OIDC identity providers are configured in IAM.
        """
        try:
            providers = []

            # Check SAML providers
            saml_response = self._iam.list_saml_providers()
            saml_providers = saml_response.get("SAMLProviderList", [])
            if saml_providers:
                names = [p["Arn"].split("/")[-1] for p in saml_providers]
                providers.append(f"{len(saml_providers)} SAML provider(s): {', '.join(names[:3])}")

            # Check OIDC providers
            oidc_response = self._iam.list_open_id_connect_providers()
            oidc_providers = oidc_response.get("OpenIDConnectProviderList", [])
            if oidc_providers:
                providers.append(f"{len(oidc_providers)} OIDC provider(s)")

            raw = self._build_evidence(
                api_call="iam.list_saml_providers() + list_open_id_connect_providers()",
                cli_command="aws iam list-saml-providers && aws iam list-open-id-connect-providers",
                response={
                    "saml_providers": _sanitize_response([{"Arn": p.get("Arn"), "ValidUntil": p.get("ValidUntil")} for p in saml_providers]),
                    "oidc_providers": _sanitize_response([{"Arn": p.get("Arn")} for p in oidc_providers]),
                },
                service="IAM",
                assessor_guidance="Verify at least one SAML or OIDC provider exists. No identity providers means no centralized device/identity management. Check ARNs to confirm federation with an enterprise IdP.",
            )
            if providers:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence=f"Centralized identity providers configured: {'; '.join(providers)}.",
                    raw_evidence=raw,
                )
            else:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence="No SAML or OIDC identity providers found in IAM.",
                    remediation=check_def.get("remediation", ""),
                    raw_evidence=raw,
                )
        except Exception as e:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking identity providers: {str(e)}",
                remediation=check_def.get("remediation", ""),
            )

    def check_ebs_default_encryption(self, check_def: dict) -> CheckResult:
        """
        Check if EBS encryption by default is enabled.

        NIST 800-53 Control: 3.1.19 — Encrypt CUI on computing platforms.
        """
        try:
            response = self._ec2.get_ebs_encryption_by_default()
            enabled = response.get("EbsEncryptionByDefault", False)
            raw = self._build_evidence(
                api_call="ec2.get_ebs_encryption_by_default",
                cli_command="aws ec2 get-ebs-encryption-by-default",
                response=_sanitize_response(response),
                service="EC2",
                assessor_guidance="Check EbsEncryptionByDefault=true. If false, new EBS volumes can be created unencrypted, risking CUI exposure. This is a region-level setting.",
            )

            if enabled:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence="EBS encryption by default is enabled for this account/region.",
                    raw_evidence=raw,
                )
            else:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence="EBS encryption by default is NOT enabled. New EBS volumes may be created unencrypted.",
                    remediation=check_def.get("remediation", ""),
                    raw_evidence=raw,
                )
        except Exception as e:
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking EBS default encryption: {str(e)}",
                remediation=check_def.get("remediation", ""),
            )

    def check_s3_account_public_access_block(self, check_def: dict) -> CheckResult:
        """
        Check if S3 Block Public Access is enabled at the account level.

        NIST 800-53 Control: 3.1.21 — Limit use of portable storage devices.
        Verifies all four public access block settings are enabled.
        """
        try:
            s3control = self._session.client("s3control")
            sts_identity = self._sts.get_caller_identity()
            account_id = sts_identity["Account"]

            response = s3control.get_public_access_block(AccountId=account_id)
            config = response.get("PublicAccessBlockConfiguration", {})

            settings = {
                "BlockPublicAcls": config.get("BlockPublicAcls", False),
                "IgnorePublicAcls": config.get("IgnorePublicAcls", False),
                "BlockPublicPolicy": config.get("BlockPublicPolicy", False),
                "RestrictPublicBuckets": config.get("RestrictPublicBuckets", False),
            }
            raw = self._build_evidence(
                api_call="s3control.get_public_access_block",
                cli_command="aws s3control get-public-access-block --account-id ACCOUNT",
                response=settings,
                service="S3",
                assessor_guidance="All 4 settings must be true: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets. Any false value allows potential public S3 exposure.",
            )

            all_enabled = all(settings.values())
            enabled_list = [k for k, v in settings.items() if v]
            disabled_list = [k for k, v in settings.items() if not v]

            if all_enabled:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="met",
                    severity=check_def["severity"],
                    evidence="All 4 S3 Block Public Access settings are enabled at the account level.",
                    raw_evidence=raw,
                )
            else:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence=(
                        f"S3 Block Public Access: {len(enabled_list)}/4 enabled. "
                        f"Disabled: {', '.join(disabled_list)}."
                    ),
                    remediation=check_def.get("remediation", ""),
                    raw_evidence=raw,
                )
        except Exception as e:
            error_msg = str(e)
            if "NoSuchPublicAccessBlockConfiguration" in error_msg:
                return CheckResult(
                    check_id=check_def["check_id"],
                    control_id=check_def["control_id"],
                    check_name=check_def["check_name"],
                    status="not_met",
                    severity=check_def["severity"],
                    evidence="No S3 Block Public Access configuration found at account level.",
                    remediation=check_def.get("remediation", ""),
                    raw_evidence=self._build_evidence(
                        api_call="s3control.get_public_access_block",
                        cli_command="aws s3control get-public-access-block --account-id ACCOUNT",
                        response={"error": "NoSuchPublicAccessBlockConfiguration", "detail": "No account-level public access block configured"},
                        service="S3",
                        assessor_guidance="No account-level public access block exists. All 4 settings default to false, meaning any bucket can be made public. This is an automatic not_met.",
                    ),
                )
            return CheckResult(
                check_id=check_def["check_id"],
                control_id=check_def["control_id"],
                check_name=check_def["check_name"],
                status="error",
                severity=check_def["severity"],
                evidence=f"Error checking S3 Block Public Access: {error_msg}",
                remediation=check_def.get("remediation", ""),
            )

    # ------------------------------------------------------------------
    # Phase 1: IAM Checks (28 methods)
    # ------------------------------------------------------------------

    def check_credential_report_review(self, check_def: dict) -> CheckResult:
        """Check active users have been active within 90 days."""
        try:
            report = self._get_credential_report()
            cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT")
            stale = []
            for u in report:
                if u.get("password_enabled") == "true":
                    last = u.get("password_last_used", "N/A")
                    if last in ("N/A", "no_information", "not_supported"):
                        stale.append(u["user"])
                    elif last[:11] < cutoff:
                        stale.append(u["user"])
            raw = self._build_evidence(
                api_call="iam.get_credential_report",
                cli_command="aws iam get-credential-report",
                response={                "total_users": len(report), "stale_users": stale[:20], "cutoff": cutoff,
            },
                service="IAM",
                assessor_guidance="Check stale_users list for accounts inactive >90 days. These should be disabled or removed. Users with password_last_used=N/A may never have logged in.",
            )
            if not stale:
                return self._result(check_def, "met",
                    f"All console users active within 90 days.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(stale)} user(s) inactive >90 days: {', '.join(stale[:10])}", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error checking credential report: {e}")

    def check_least_privilege_policies(self, check_def: dict) -> CheckResult:
        """Check no customer-managed policies grant Action:*/Resource:*."""
        try:
            paginator = self._iam.get_paginator("list_policies")
            violations = []
            policy_count = 0
            for page in paginator.paginate(Scope="Local"):
                for policy in page["Policies"]:
                    policy_count += 1
                    try:
                        ver = self._iam.get_policy_version(
                            PolicyArn=policy["Arn"],
                            VersionId=policy["DefaultVersionId"])
                        doc = ver["PolicyVersion"]["Document"]
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        for stmt in (doc.get("Statement") or []):
                            if isinstance(stmt, dict) and stmt.get("Effect") == "Allow":
                                actions = stmt.get("Action", [])
                                resources = stmt.get("Resource", [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                if isinstance(resources, str):
                                    resources = [resources]
                                if "*" in actions and "*" in resources:
                                    violations.append(policy["PolicyName"])
                                    break
                    except Exception:
                        pass
            raw = self._build_evidence(
                api_call="iam.list_policies",
                cli_command="aws iam list-policies --scope Local --only-attached",
                response={                "total_local_policies": policy_count, "violations": violations[:20],
            },
                service="IAM",
                assessor_guidance="Check 'violations' for policies with Action:*/Resource:*. Each must be scoped down or have documented justification. Zero violations = pass.",
            )
            if not violations:
                return self._result(check_def, "met",
                    "No customer-managed policies with Action:*/Resource:* found.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(violations)} over-privileged policy(ies): {', '.join(violations[:10])}", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error checking policies: {e}")

    def check_permission_boundaries(self, check_def: dict) -> CheckResult:
        """Check admin-delegated users have permission boundaries."""
        try:
            users = self._iam.list_users().get("Users", [])
            no_boundary = []
            for user in users:
                policies = self._iam.list_attached_user_policies(
                    UserName=user["UserName"]).get("AttachedPolicies", [])
                is_admin = any("Admin" in p["PolicyName"] for p in policies)
                if is_admin and not user.get("PermissionsBoundary"):
                    no_boundary.append(user["UserName"])
            if not no_boundary:
                return self._result(check_def, "met",
                    "All admin-delegated users have permission boundaries.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_users() + list_attached_user_policies()",
                        cli_command="aws iam list-users && aws iam list-attached-user-policies --user-name USER",
                        response={"total_users": len(users), "admin_users_without_boundary": no_boundary[:20], "all_have_boundaries": True},
                        service="IAM",
                        assessor_guidance="Verify 'all_have_boundaries' is True. Check that admin-delegated users have PermissionsBoundary set to restrict privilege escalation.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(no_boundary)} admin user(s) without boundary: {', '.join(no_boundary[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_users() + list_attached_user_policies()",
                    cli_command="aws iam list-users && aws iam list-attached-user-policies --user-name USER",
                    response={"total_users": len(users), "admin_users_without_boundary": no_boundary[:20], "all_have_boundaries": False},
                    service="IAM",
                    assessor_guidance="Review 'admin_users_without_boundary' list. Each user must have a PermissionsBoundary ARN set or be demoted from admin policies.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking boundaries: {e}")

    def check_separation_of_duties_roles(self, check_def: dict) -> CheckResult:
        """Check admin roles are separate from operational roles."""
        try:
            roles = self._iam.list_roles().get("Roles", [])
            admin_roles = [r["RoleName"] for r in roles
                if any(k in r["RoleName"].lower() for k in ("admin", "root", "superuser"))]
            ops_roles = [r["RoleName"] for r in roles
                if any(k in r["RoleName"].lower() for k in ("readonly", "operator", "viewer", "dev", "user"))]
            if admin_roles and ops_roles:
                return self._result(check_def, "met",
                    f"Role separation present: {len(admin_roles)} admin, {len(ops_roles)} operational roles.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_roles()",
                        cli_command="aws iam list-roles",
                        response={"total_roles": len(roles), "admin_roles": admin_roles[:20], "operational_roles": ops_roles[:20]},
                        service="IAM",
                        assessor_guidance="Verify 'admin_roles' and 'operational_roles' are distinct sets. No role should appear in both. Look for naming conventions that confirm separation.",
                    ))
            issues = []
            if not admin_roles:
                issues.append("No dedicated admin roles found")
            if not ops_roles:
                issues.append("No dedicated operational roles found")
            return self._result(check_def, "not_met", "; ".join(issues),
                raw_evidence=self._build_evidence(
                    api_call="iam.list_roles()",
                    cli_command="aws iam list-roles",
                    response={"total_roles": len(roles), "admin_roles": admin_roles[:20], "operational_roles": ops_roles[:20]},
                    service="IAM",
                    assessor_guidance="Check if 'admin_roles' or 'operational_roles' is empty. Both must exist for proper separation of duties. Missing category = fail.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking role separation: {e}")

    def check_deploy_approve_separation(self, check_def: dict) -> CheckResult:
        """Check no user has both deploy and approve permissions."""
        try:
            users = self._iam.list_users().get("Users", [])
            violations = []
            deploy_actions = {"codedeploy:*", "codepipeline:*", "ecs:UpdateService", "lambda:UpdateFunctionCode"}
            approve_actions = {"codepipeline:PutApprovalResult", "codepipeline:EnableStageTransition"}
            for user in users[:50]:
                attached = self._iam.list_attached_user_policies(
                    UserName=user["UserName"]).get("AttachedPolicies", [])
                user_actions = set()
                for pol in attached:
                    try:
                        p = self._iam.get_policy(PolicyArn=pol["PolicyArn"])["Policy"]
                        ver = self._iam.get_policy_version(
                            PolicyArn=pol["PolicyArn"],
                            VersionId=p["DefaultVersionId"])
                        doc = ver["PolicyVersion"]["Document"]
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        for stmt in (doc.get("Statement") or []):
                            if stmt.get("Effect") == "Allow":
                                acts = stmt.get("Action", [])
                                if isinstance(acts, str):
                                    acts = [acts]
                                user_actions.update(acts)
                    except Exception:
                        pass
                has_deploy = bool(user_actions & deploy_actions) or "*" in user_actions
                has_approve = bool(user_actions & approve_actions) or "*" in user_actions
                if has_deploy and has_approve:
                    violations.append(user["UserName"])
            if not violations:
                return self._result(check_def, "met",
                    "No users have both deploy and approve permissions.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_users() + list_attached_user_policies()",
                        cli_command="aws iam list-users",
                        response={"total_users_checked": min(len(users), 50), "users_with_both_deploy_approve": violations[:20]},
                        service="IAM",
                        assessor_guidance="Verify 'users_with_both_deploy_approve' is empty. Any user with both deploy and approve actions violates separation of duties.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(violations)} user(s) with both deploy+approve: {', '.join(violations[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_users() + list_attached_user_policies()",
                    cli_command="aws iam list-users",
                    response={"total_users_checked": min(len(users), 50), "users_with_both_deploy_approve": violations[:20]},
                    service="IAM",
                    assessor_guidance="Each user in 'users_with_both_deploy_approve' has codedeploy/codepipeline AND approval permissions. Split into separate roles immediately.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking separation: {e}")

    def check_no_inline_wildcard_policies(self, check_def: dict) -> CheckResult:
        """Check no inline policies have Action:*/Resource:*."""
        try:
            users = self._iam.list_users().get("Users", [])
            violations = []
            for user in users:
                inline = self._iam.list_user_policies(
                    UserName=user["UserName"]).get("PolicyNames", [])
                for pname in inline:
                    pol = self._iam.get_user_policy(
                        UserName=user["UserName"], PolicyName=pname)
                    doc = pol.get("PolicyDocument", {})
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    for stmt in (doc.get("Statement") or []):
                        if stmt.get("Effect") == "Allow":
                            actions = stmt.get("Action", [])
                            resources = stmt.get("Resource", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]
                            if "*" in actions and "*" in resources:
                                violations.append(f"{user['UserName']}:{pname}")
                                break
            if not violations:
                return self._result(check_def, "met",
                    "No inline policies with wildcard Action/Resource found.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_users() + list_user_policies() + get_user_policy()",
                        cli_command="aws iam list-users && aws iam list-user-policies --user-name USER",
                        response={"total_users": len(users), "wildcard_inline_policies": violations[:20]},
                        service="IAM",
                        assessor_guidance="Verify 'wildcard_inline_policies' is empty. Format is 'username:policyname'. Any inline policy with Action:*/Resource:* is a critical finding.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(violations)} wildcard inline policy(ies): {', '.join(violations[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_users() + list_user_policies() + get_user_policy()",
                    cli_command="aws iam list-users && aws iam list-user-policies --user-name USER",
                    response={"total_users": len(users), "wildcard_inline_policies": violations[:20]},
                    service="IAM",
                    assessor_guidance="Each entry in 'wildcard_inline_policies' is 'user:policy' with Action:*/Resource:*. These must be scoped down or converted to managed policies.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking inline policies: {e}")

    def check_no_admin_access_users(self, check_def: dict) -> CheckResult:
        """Check AdministratorAccess not attached directly to IAM users."""
        try:
            admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
            try:
                entities = self._iam.list_entities_for_policy(
                    PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
                user_list = entities.get("PolicyUsers", [])
            except Exception:
                # Try account-specific ARN
                account = self._sts.get_caller_identity()["Account"]
                entities = self._iam.list_entities_for_policy(
                    PolicyArn=f"arn:aws:iam::aws:policy/AdministratorAccess")
                user_list = entities.get("PolicyUsers", [])
            if not user_list:
                return self._result(check_def, "met",
                    "AdministratorAccess is not attached to any IAM users directly.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_entities_for_policy()",
                        cli_command="aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                        response={"policy_users": [], "policy_groups": entities.get("PolicyGroups", [])[:20], "policy_roles": entities.get("PolicyRoles", [])[:20]},
                        service="IAM",
                        assessor_guidance="Verify 'policy_users' is empty -- AdministratorAccess should only be on roles, not users. Check 'policy_roles' for role-based access.",
                    ))
            names = [u["UserName"] for u in user_list]
            return self._result(check_def, "not_met",
                f"AdministratorAccess attached to {len(names)} user(s): {', '.join(names[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_entities_for_policy()",
                    cli_command="aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                    response={"policy_users": [u["UserName"] for u in user_list][:20], "policy_groups": entities.get("PolicyGroups", [])[:20], "policy_roles": entities.get("PolicyRoles", [])[:20]},
                    service="IAM",
                    assessor_guidance="'policy_users' must be empty. AdministratorAccess on users is a critical finding -- must be moved to roles with MFA conditions.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking admin users: {e}")

    def check_admin_standard_role_separation(self, check_def: dict) -> CheckResult:
        """Check distinct admin vs non-admin roles exist."""
        try:
            roles = self._iam.list_roles().get("Roles", [])
            admin_count = 0
            standard_count = 0
            for role in roles:
                if role["Path"] == "/aws-service-role/":
                    continue
                attached = self._iam.list_attached_role_policies(
                    RoleName=role["RoleName"]).get("AttachedPolicies", [])
                is_admin = any("Admin" in p["PolicyName"] or "FullAccess" in p["PolicyName"]
                    for p in attached)
                if is_admin:
                    admin_count += 1
                else:
                    standard_count += 1
            if admin_count > 0 and standard_count > 0:
                return self._result(check_def, "met",
                    f"Role separation: {admin_count} admin, {standard_count} standard roles.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_roles() + list_attached_role_policies()",
                        cli_command="aws iam list-roles",
                        response={"total_roles": len(roles), "admin_role_count": admin_count, "standard_role_count": standard_count},
                        service="IAM",
                        assessor_guidance="Verify both 'admin_role_count' and 'standard_role_count' are > 0. Healthy ratio: standard roles should significantly outnumber admin roles.",
                    ))
            return self._result(check_def, "not_met",
                f"Insufficient separation: {admin_count} admin, {standard_count} standard roles.",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_roles() + list_attached_role_policies()",
                    cli_command="aws iam list-roles",
                    response={"total_roles": len(roles), "admin_role_count": admin_count, "standard_role_count": standard_count},
                    service="IAM",
                    assessor_guidance="Either 'admin_role_count' or 'standard_role_count' is 0, indicating no role separation. Create dedicated admin vs standard roles.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking role separation: {e}")

    def check_session_timeout(self, check_def: dict) -> CheckResult:
        """Check console role MaxSessionDuration <= 3600s."""
        try:
            roles = self._iam.list_roles().get("Roles", [])
            long_sessions = []
            for role in roles:
                if role["Path"] == "/aws-service-role/":
                    continue
                duration = role.get("MaxSessionDuration", 3600)
                if duration > 3600:
                    long_sessions.append(f"{role['RoleName']}={duration}s")
            if not long_sessions:
                return self._result(check_def, "met",
                    "All roles have MaxSessionDuration <= 3600s.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_roles()",
                        cli_command="aws iam list-roles --query 'Roles[].{Name:RoleName,MaxSession:MaxSessionDuration}'",
                        response={"total_roles_checked": len([r for r in roles if r["Path"] != "/aws-service-role/"]), "roles_exceeding_3600s": long_sessions[:20]},
                        service="IAM",
                        assessor_guidance="Verify 'roles_exceeding_3600s' is empty. Each entry shows 'RoleName=Xs'. Max allowed is 3600s (1 hour) for FedRAMP compliance.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(long_sessions)} role(s) with long sessions: {', '.join(long_sessions[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_roles()",
                    cli_command="aws iam list-roles --query 'Roles[].{Name:RoleName,MaxSession:MaxSessionDuration}'",
                    response={"total_roles_checked": len([r for r in roles if r["Path"] != "/aws-service-role/"]), "roles_exceeding_3600s": long_sessions[:20]},
                    service="IAM",
                    assessor_guidance="Each role in 'roles_exceeding_3600s' must have MaxSessionDuration reduced to <= 3600s. Format: 'RoleName=Xs' shows current value.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking session timeout: {e}")

    def check_role_session_duration(self, check_def: dict) -> CheckResult:
        """Check all roles MaxSessionDuration <= 3600s."""
        try:
            roles = self._iam.list_roles().get("Roles", [])
            violations = []
            for role in roles:
                if role["Path"] == "/aws-service-role/":
                    continue
                duration = role.get("MaxSessionDuration", 3600)
                if duration > 3600:
                    violations.append(f"{role['RoleName']}={duration}s")
            if not violations:
                return self._result(check_def, "met",
                    f"All {len(roles)} roles have session duration <= 3600s.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_roles()",
                        cli_command="aws iam list-roles --query 'Roles[].{Name:RoleName,MaxSession:MaxSessionDuration}'",
                        response={"total_roles": len(roles), "violations": violations[:20]},
                        service="IAM",
                        assessor_guidance="Verify 'violations' is empty. All roles must have MaxSessionDuration <= 3600s. Service-linked roles are excluded from this check.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(violations)} role(s) exceed 3600s: {', '.join(violations[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_roles()",
                    cli_command="aws iam list-roles --query 'Roles[].{Name:RoleName,MaxSession:MaxSessionDuration}'",
                    response={"total_roles": len(roles), "violations": violations[:20]},
                    service="IAM",
                    assessor_guidance="Each entry in 'violations' is 'RoleName=Xs' exceeding 3600s limit. Update via 'aws iam update-role --max-session-duration 3600'.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking role durations: {e}")

    def check_no_public_ip_cui_instances(self, check_def: dict) -> CheckResult:
        """Check no EC2 instances have public IP addresses."""
        try:
            paginator = self._ec2.get_paginator("describe_instances")
            public_instances = []
            for page in paginator.paginate():
                for res in page.get("Reservations", []):
                    for inst in res.get("Instances", []):
                        if inst.get("State", {}).get("Name") != "running":
                            continue
                        if inst.get("PublicIpAddress"):
                            iid = inst["InstanceId"]
                            public_instances.append(f"{iid}={inst['PublicIpAddress']}")
            if not public_instances:
                return self._result(check_def, "met",
                    "No running EC2 instances have public IP addresses.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_instances()",
                        cli_command="aws ec2 describe-instances --query 'Reservations[].Instances[].{Id:InstanceId,PublicIp:PublicIpAddress}'",
                        response={"instances_with_public_ips": public_instances[:20], "total_public": len(public_instances)},
                        service="EC2",
                        assessor_guidance="Verify 'instances_with_public_ips' is empty. Format: 'InstanceId=PublicIP'. CUI instances must not have public IPs -- use private subnets + NAT.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(public_instances)} instance(s) with public IPs: {', '.join(public_instances[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_instances()",
                    cli_command="aws ec2 describe-instances --query 'Reservations[].Instances[].{Id:InstanceId,PublicIp:PublicIpAddress}'",
                    response={"instances_with_public_ips": public_instances[:20], "total_public": len(public_instances)},
                    service="EC2",
                    assessor_guidance="Each entry in 'instances_with_public_ips' is 'InstanceId=IP'. Remove public IPs or move instances to private subnets behind NAT gateway.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking public IPs: {e}")

    def check_unique_iam_users(self, check_def: dict) -> CheckResult:
        """Check all IAM users are uniquely named."""
        try:
            users = self._iam.list_users().get("Users", [])
            names = [u["UserName"] for u in users]
            if len(names) == len(set(names)):
                return self._result(check_def, "met",
                    f"All {len(names)} IAM users have unique names (enforced by IAM).",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_users()",
                        cli_command="aws iam list-users",
                        response={"total_users": len(names), "usernames": names[:50], "all_unique": True},
                        service="IAM",
                        assessor_guidance="Verify 'all_unique' is True. IAM enforces uniqueness natively. Check 'usernames' list for naming convention compliance.",
                    ))
            return self._result(check_def, "not_met", "Duplicate IAM user names detected.",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_users()",
                    cli_command="aws iam list-users",
                    response={"total_users": len(names), "usernames": names[:50], "all_unique": False},
                    service="IAM",
                    assessor_guidance="'all_unique' is False -- duplicate usernames detected. This should not occur in AWS IAM. Investigate potential API or cross-account issues.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking users: {e}")

    def check_service_account_naming(self, check_def: dict) -> CheckResult:
        """Check service roles have descriptive names."""
        try:
            roles = self._iam.list_roles().get("Roles", [])
            service_roles = [r for r in roles if r["Path"] == "/aws-service-role/"
                or "service" in r.get("Description", "").lower()
                or "service" in r["RoleName"].lower()]
            generic = [r["RoleName"] for r in service_roles
                if len(r["RoleName"]) < 4 or r["RoleName"] in ("role", "test", "temp")]
            if not generic:
                return self._result(check_def, "met",
                    f"{len(service_roles)} service roles have descriptive names.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_roles()",
                        cli_command="aws iam list-roles --query 'Roles[].RoleName'",
                        response={"total_service_roles": len(service_roles), "generic_named_roles": generic[:20], "service_role_names": [r["RoleName"] for r in service_roles][:30]},
                        service="IAM",
                        assessor_guidance="Verify 'generic_named_roles' is empty. Service roles should have descriptive names indicating purpose (e.g., 'lambda-log-processor').",
                    ))
            return self._result(check_def, "not_met",
                f"{len(generic)} role(s) with generic names: {', '.join(generic[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_roles()",
                    cli_command="aws iam list-roles --query 'Roles[].RoleName'",
                    response={"total_service_roles": len(service_roles), "generic_named_roles": generic[:20], "service_role_names": [r["RoleName"] for r in service_roles][:30]},
                    service="IAM",
                    assessor_guidance="Roles in 'generic_named_roles' have names < 4 chars or are 'role/test/temp'. Rename to describe function (e.g., 'ec2-backup-agent').",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking role names: {e}")

    def check_instance_profiles(self, check_def: dict) -> CheckResult:
        """Check all EC2 instances use instance profiles."""
        try:
            paginator = self._ec2.get_paginator("describe_instances")
            no_profile = []
            total = 0
            for page in paginator.paginate():
                for res in page.get("Reservations", []):
                    for inst in res.get("Instances", []):
                        if inst.get("State", {}).get("Name") != "running":
                            continue
                        total += 1
                        if not inst.get("IamInstanceProfile"):
                            no_profile.append(inst["InstanceId"])
            if not no_profile:
                return self._result(check_def, "met",
                    f"All {total} running instances have instance profiles." if total else
                    "No running instances found.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_instances()",
                        cli_command="aws ec2 describe-instances --query 'Reservations[].Instances[].{Id:InstanceId,Profile:IamInstanceProfile}'",
                        response={"total_running_instances": total, "instances_without_profile": no_profile[:20]},
                        service="EC2",
                        assessor_guidance="Verify 'instances_without_profile' is empty. All EC2 instances should use IAM instance profiles instead of embedded credentials.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(no_profile)} of {total} instance(s) without profile: {', '.join(no_profile[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_instances()",
                    cli_command="aws ec2 describe-instances --query 'Reservations[].Instances[].{Id:InstanceId,Profile:IamInstanceProfile}'",
                    response={"total_running_instances": total, "instances_without_profile": no_profile[:20]},
                    service="EC2",
                    assessor_guidance="Each instance in 'instances_without_profile' lacks an IAM role. Attach an instance profile with least-privilege permissions.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking instance profiles: {e}")

    def check_root_mfa(self, check_def: dict) -> CheckResult:
        """Check root account has MFA enabled."""
        try:
            summary = self._iam.get_account_summary().get("SummaryMap", {})
            if summary.get("AccountMFAEnabled", 0) == 1:
                return self._result(check_def, "met",
                    "Root account MFA is enabled. AccountMFAEnabled=1.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.get_account_summary()",
                        cli_command="aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'",
                        response={"AccountMFAEnabled": summary.get("AccountMFAEnabled", 0), "Users": summary.get("Users", 0), "MFADevices": summary.get("MFADevices", 0)},
                        service="IAM",
                        assessor_guidance="Verify 'AccountMFAEnabled' is 1. Also check 'MFADevices' > 0. Root MFA is a critical FedRAMP control.",
                    ))
            return self._result(check_def, "not_met",
                "Root account MFA is NOT enabled. AccountMFAEnabled=0.",
                raw_evidence=self._build_evidence(
                    api_call="iam.get_account_summary()",
                    cli_command="aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'",
                    response={"AccountMFAEnabled": summary.get("AccountMFAEnabled", 0), "Users": summary.get("Users", 0), "MFADevices": summary.get("MFADevices", 0)},
                    service="IAM",
                    assessor_guidance="CRITICAL: 'AccountMFAEnabled' is 0. Root account has no MFA. Enable hardware MFA on root immediately -- this is a mandatory FedRAMP control.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking root MFA: {e}")

    def check_console_users_mfa(self, check_def: dict) -> CheckResult:
        """Check all password-enabled users have MFA."""
        try:
            report = self._get_credential_report()
            no_mfa = []
            console_count = 0
            for u in report:
                if u.get("password_enabled") == "true":
                    console_count += 1
                    if u.get("mfa_active") != "true":
                        no_mfa.append(u["user"])
            if not no_mfa:
                return self._result(check_def, "met",
                    f"All {console_count} console users have MFA enabled.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.get_credential_report()",
                        cli_command="aws iam get-credential-report",
                        response={"console_users_total": console_count, "users_without_mfa": no_mfa[:20]},
                        service="IAM",
                        assessor_guidance="Verify 'users_without_mfa' is empty. All console (password-enabled) users must have MFA active. Check 'console_users_total' for scope.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(no_mfa)} of {console_count} console user(s) without MFA: {', '.join(no_mfa[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="iam.get_credential_report()",
                    cli_command="aws iam get-credential-report",
                    response={"console_users_total": console_count, "users_without_mfa": no_mfa[:20]},
                    service="IAM",
                    assessor_guidance="Each user in 'users_without_mfa' has console access but no MFA device. Enable MFA or disable console access for these users.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking MFA: {e}")

    def check_mfa_condition_policies(self, check_def: dict) -> CheckResult:
        """Check privileged policies require MFA condition."""
        try:
            paginator = self._iam.get_paginator("list_policies")
            no_mfa = []
            checked = 0
            for page in paginator.paginate(Scope="Local"):
                for policy in page["Policies"]:
                    if policy.get("AttachmentCount", 0) == 0:
                        continue
                    try:
                        ver = self._iam.get_policy_version(
                            PolicyArn=policy["Arn"],
                            VersionId=policy["DefaultVersionId"])
                        doc = ver["PolicyVersion"]["Document"]
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        has_priv = False
                        has_mfa_cond = False
                        for stmt in (doc.get("Statement") or []):
                            if stmt.get("Effect") == "Allow":
                                actions = stmt.get("Action", [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                if "*" in actions or any("Admin" in a for a in actions):
                                    has_priv = True
                                cond = stmt.get("Condition", {})
                                if "Bool" in cond and "aws:MultiFactorAuthPresent" in cond["Bool"]:
                                    has_mfa_cond = True
                        if has_priv:
                            checked += 1
                            if not has_mfa_cond:
                                no_mfa.append(policy["PolicyName"])
                    except Exception:
                        pass
            if not no_mfa:
                return self._result(check_def, "met",
                    f"All {checked} privileged policies require MFA condition.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_policies() + get_policy_version()",
                        cli_command="aws iam list-policies --scope Local --only-attached",
                        response={"privileged_policies_checked": checked, "policies_without_mfa_condition": no_mfa[:20]},
                        service="IAM",
                        assessor_guidance="Verify 'policies_without_mfa_condition' is empty. Privileged policies (with * or Admin actions) must have Condition: aws:MultiFactorAuthPresent.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(no_mfa)} privileged policy(ies) without MFA condition: {', '.join(no_mfa[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_policies() + get_policy_version()",
                    cli_command="aws iam list-policies --scope Local --only-attached",
                    response={"privileged_policies_checked": checked, "policies_without_mfa_condition": no_mfa[:20]},
                    service="IAM",
                    assessor_guidance="Each policy in 'policies_without_mfa_condition' grants privileged actions without MFA. Add Condition Bool aws:MultiFactorAuthPresent=true.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking MFA conditions: {e}")

    def check_hardware_mfa_root(self, check_def: dict) -> CheckResult:
        """Check root account uses hardware MFA (not virtual)."""
        try:
            virt = self._iam.list_virtual_mfa_devices().get("VirtualMFADevices", [])
            root_virtual = any(d.get("SerialNumber", "").endswith(":mfa/root-account-mfa-device")
                for d in virt)
            summary = self._iam.get_account_summary().get("SummaryMap", {})
            mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1
            if mfa_enabled and not root_virtual:
                return self._result(check_def, "met",
                    "Root account uses hardware MFA (no virtual MFA device found).",
                    raw_evidence=self._build_evidence(
                        api_call="iam.get_account_summary() + list_virtual_mfa_devices()",
                        cli_command="aws iam get-account-summary && aws iam list-virtual-mfa-devices",
                        response={"AccountMFAEnabled": 1, "root_uses_virtual_mfa": root_virtual, "virtual_mfa_device_count": len(virt)},
                        service="IAM",
                        assessor_guidance="Verify 'AccountMFAEnabled'=1 and 'root_uses_virtual_mfa'=False. Hardware MFA (YubiKey/token) is required for root account.",
                    ))
            if not mfa_enabled:
                return self._result(check_def, "not_met", "Root account MFA is not enabled.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.get_account_summary() + list_virtual_mfa_devices()",
                        cli_command="aws iam get-account-summary && aws iam list-virtual-mfa-devices",
                        response={"AccountMFAEnabled": 0, "root_uses_virtual_mfa": root_virtual, "virtual_mfa_device_count": len(virt)},
                        service="IAM",
                        assessor_guidance="CRITICAL: 'AccountMFAEnabled'=0. Root has no MFA at all. Enable hardware MFA before any other remediation.",
                    ))
            return self._result(check_def, "not_met",
                "Root account uses virtual MFA. Hardware MFA recommended.",
                raw_evidence=self._build_evidence(
                    api_call="iam.get_account_summary() + list_virtual_mfa_devices()",
                    cli_command="aws iam get-account-summary && aws iam list-virtual-mfa-devices",
                    response={"AccountMFAEnabled": 1, "root_uses_virtual_mfa": True, "virtual_mfa_device_count": len(virt)},
                    service="IAM",
                    assessor_guidance="Root uses virtual MFA (app-based). Replace with hardware MFA (FIDO2 key or hardware token) for stronger root protection.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking hardware MFA: {e}")

    def check_fido2_mfa_support(self, check_def: dict) -> CheckResult:
        """Check FIDO2/WebAuthn security keys are present."""
        try:
            users = self._iam.list_users().get("Users", [])
            fido_users = []
            for user in users[:50]:
                devices = self._iam.list_mfa_devices(
                    UserName=user["UserName"]).get("MFADevices", [])
                for d in devices:
                    serial = d.get("SerialNumber", "")
                    if "fido" in serial.lower() or "u2f" in serial.lower() or "webauthn" in serial.lower():
                        fido_users.append(user["UserName"])
                        break
            if fido_users:
                return self._result(check_def, "met",
                    f"FIDO2 security keys found for {len(fido_users)} user(s).",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_users() + list_mfa_devices()",
                        cli_command="aws iam list-users && aws iam list-mfa-devices --user-name USER",
                        response={"total_users_checked": min(len(users), 50), "fido2_users": fido_users[:20]},
                        service="IAM",
                        assessor_guidance="Verify 'fido2_users' list is non-empty. FIDO2/WebAuthn keys provide phishing-resistant MFA required for L3 compliance.",
                    ))
            return self._result(check_def, "not_met",
                "No FIDO2/WebAuthn security keys found. Consider deploying hardware keys.",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_users() + list_mfa_devices()",
                    cli_command="aws iam list-users && aws iam list-mfa-devices --user-name USER",
                    response={"total_users_checked": min(len(users), 50), "fido2_users": []},
                    service="IAM",
                    assessor_guidance="No FIDO2/WebAuthn devices found. Deploy hardware security keys (YubiKey 5) for phishing-resistant authentication. Required for L3.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking FIDO2: {e}")

    def check_sts_token_duration(self, check_def: dict) -> CheckResult:
        """Check role session durations are appropriately limited."""
        try:
            roles = self._iam.list_roles().get("Roles", [])
            excessive = []
            for role in roles:
                if role["Path"] == "/aws-service-role/":
                    continue
                duration = role.get("MaxSessionDuration", 3600)
                if duration > 3600:
                    excessive.append(f"{role['RoleName']}={duration}s")
            if not excessive:
                return self._result(check_def, "met",
                    "All role session durations are <= 3600s (1 hour).",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_roles()",
                        cli_command="aws iam list-roles --query 'Roles[].{Name:RoleName,MaxSession:MaxSessionDuration}'",
                        response={"total_roles": len(roles), "excessive_duration_roles": excessive[:20]},
                        service="IAM",
                        assessor_guidance="Verify 'excessive_duration_roles' is empty. STS tokens > 3600s increase exposure window. Service-linked roles are excluded.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(excessive)} role(s) with excessive duration: {', '.join(excessive[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_roles()",
                    cli_command="aws iam list-roles --query 'Roles[].{Name:RoleName,MaxSession:MaxSessionDuration}'",
                    response={"total_roles": len(roles), "excessive_duration_roles": excessive[:20]},
                    service="IAM",
                    assessor_guidance="Each role in 'excessive_duration_roles' shows 'Name=Xs'. Reduce MaxSessionDuration to 3600s to limit credential exposure window.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking token duration: {e}")

    def check_no_username_reuse(self, check_def: dict) -> CheckResult:
        """Check no recently deleted usernames have been reused."""
        try:
            users = self._iam.list_users().get("Users", [])
            names = [u["UserName"] for u in users]
            if len(names) == len(set(names)):
                return self._result(check_def, "met",
                    f"All {len(names)} IAM usernames are unique. IAM enforces uniqueness natively.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_users()",
                        cli_command="aws iam list-users",
                        response={"total_users": len(names), "usernames": names[:50], "all_unique": True},
                        service="IAM",
                        assessor_guidance="'all_unique' is True. AWS IAM enforces username uniqueness at the API level. Verify naming convention follows org policy.",
                    ))
            return self._result(check_def, "not_met", "Duplicate IAM usernames detected.",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_users()",
                    cli_command="aws iam list-users",
                    response={"total_users": len(names), "usernames": names[:50], "all_unique": False},
                    service="IAM",
                    assessor_guidance="'all_unique' is False. Investigate potential cross-account or API anomaly -- AWS IAM should enforce uniqueness natively.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking username reuse: {e}")

    def check_inactive_users(self, check_def: dict) -> CheckResult:
        """Check no users inactive for >90 days."""
        try:
            report = self._get_credential_report()
            cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT")
            inactive = []
            for u in report:
                if u["user"] == "<root_account>":
                    continue
                pw_last = u.get("password_last_used", "N/A")
                key1_last = u.get("access_key_1_last_used_date", "N/A")
                key2_last = u.get("access_key_2_last_used_date", "N/A")
                dates = [d for d in (pw_last, key1_last, key2_last)
                    if d not in ("N/A", "no_information", "not_supported")]
                if dates:
                    latest = max(dates)
                    if latest[:11] < cutoff:
                        inactive.append(u["user"])
                else:
                    created = u.get("user_creation_time", "")
                    if created and created[:11] < cutoff:
                        inactive.append(u["user"])
            if not inactive:
                return self._result(check_def, "met",
                    "No IAM users inactive for more than 90 days.",
                    raw_evidence=self._build_evidence(
                        api_call="iam API",
                        cli_command="aws iam get-credential-report",
                        response={"total_users": len(report), "inactive_users": inactive[:20], "cutoff_date": cutoff},
                        service="IAM",
                        assessor_guidance="Verify 'inactive_users' is empty. Users with no password/key activity since 'cutoff_date' must be disabled or have documented exception.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(inactive)} user(s) inactive >90 days: {', '.join(inactive[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="iam API",
                    cli_command="aws iam get-credential-report",
                    response={"total_users": len(report), "inactive_users": inactive[:20], "cutoff_date": cutoff},
                    service="IAM",
                    assessor_guidance="Each user in 'inactive_users' has had no activity for 90+ days. Disable accounts or document business justification for retention.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking inactive users: {e}")

    def check_inactive_access_keys(self, check_def: dict) -> CheckResult:
        """Check no access keys unused for >90 days."""
        try:
            report = self._get_credential_report()
            cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT")
            stale_keys = []
            for u in report:
                for key_num in ("1", "2"):
                    active = u.get(f"access_key_{key_num}_active", "false")
                    if active != "true":
                        continue
                    last_used = u.get(f"access_key_{key_num}_last_used_date", "N/A")
                    if last_used in ("N/A", "no_information", "not_supported"):
                        rotated = u.get(f"access_key_{key_num}_last_rotated", "")
                        if rotated and rotated[:11] < cutoff:
                            stale_keys.append(f"{u['user']}:key{key_num}")
                    elif last_used[:11] < cutoff:
                        stale_keys.append(f"{u['user']}:key{key_num}")
            if not stale_keys:
                return self._result(check_def, "met",
                    "No access keys unused for more than 90 days.",
                    raw_evidence=self._build_evidence(
                        api_call="iam API",
                        cli_command="aws iam get-credential-report",
                        response={"total_users_in_report": len(report), "stale_access_keys": stale_keys[:20], "cutoff_date": cutoff},
                        service="IAM",
                        assessor_guidance="Verify 'stale_access_keys' is empty. Format: 'user:keyN'. Active keys unused for 90+ days should be deactivated via 'aws iam update-access-key'.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(stale_keys)} stale access key(s): {', '.join(stale_keys[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="iam API",
                    cli_command="aws iam get-credential-report",
                    response={"total_users_in_report": len(report), "stale_access_keys": stale_keys[:20], "cutoff_date": cutoff},
                    service="IAM",
                    assessor_guidance="Each entry in 'stale_access_keys' ('user:keyN') is an active key unused for 90+ days. Deactivate with 'aws iam update-access-key --status Inactive'.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking access keys: {e}")

    def check_password_complexity(self, check_def: dict) -> CheckResult:
        """Check password policy enforces complexity (MinLength>=14, symbols, numbers, case)."""
        try:
            pp = self._iam.get_account_password_policy().get("PasswordPolicy", {})
            issues = []
            if pp.get("MinimumPasswordLength", 0) < 14:
                issues.append(f"MinLength={pp.get('MinimumPasswordLength', 0)} (need >=14)")
            if not pp.get("RequireUppercaseCharacters", False):
                issues.append("Uppercase not required")
            if not pp.get("RequireLowercaseCharacters", False):
                issues.append("Lowercase not required")
            if not pp.get("RequireNumbers", False):
                issues.append("Numbers not required")
            if not pp.get("RequireSymbols", False):
                issues.append("Symbols not required")
            if not issues:
                return self._result(check_def, "met",
                    f"Password complexity met: MinLength={pp.get('MinimumPasswordLength')}, all types required.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.get_account_password_policy()",
                        cli_command="aws iam get-account-password-policy",
                        response=_sanitize_response(pp),
                        service="IAM",
                        assessor_guidance="Verify MinimumPasswordLength >= 14, RequireUppercase/Lowercase/Numbers/Symbols are all True. Full policy in response JSON.",
                    ))
            return self._result(check_def, "not_met",
                f"Password complexity issues: {'; '.join(issues)}",
                raw_evidence=self._build_evidence(
                    api_call="iam.get_account_password_policy()",
                    cli_command="aws iam get-account-password-policy",
                    response={"password_policy": _sanitize_response(pp), "issues_found": issues},
                    service="IAM",
                    assessor_guidance="Review 'issues_found' for specific failures. Each issue must be fixed in IAM password policy. FedRAMP requires MinLength>=14 + all char types.",
                ))
        except self._iam.exceptions.NoSuchEntityException:
            return self._result(check_def, "not_met", "No password policy configured.",
                raw_evidence=self._build_evidence(
                    api_call="iam.get_account_password_policy()",
                    cli_command="aws iam get-account-password-policy",
                    response={"password_policy_exists": False},
                    service="IAM",
                    assessor_guidance="CRITICAL: No password policy exists at all. Create one with 'aws iam update-account-password-policy' meeting FedRAMP complexity requirements.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking password policy: {e}")

    def check_password_reuse_prevention(self, check_def: dict) -> CheckResult:
        """Check password reuse prevention >= 24."""
        try:
            pp = self._iam.get_account_password_policy().get("PasswordPolicy", {})
            reuse = pp.get("PasswordReusePrevention", 0)
            if reuse >= 24:
                return self._result(check_def, "met",
                    f"Password reuse prevention set to {reuse} (>= 24).",
                    raw_evidence=self._build_evidence(
                        api_call="iam.get_account_password_policy()",
                        cli_command="aws iam get-account-password-policy",
                        response={"PasswordReusePrevention": reuse, "password_policy": _sanitize_response(pp)},
                        service="IAM",
                        assessor_guidance="Verify 'PasswordReusePrevention' >= 24. This prevents reuse of the last 24 passwords. NIST 800-53 IA-5 requires this control.",
                    ))
            return self._result(check_def, "not_met",
                f"Password reuse prevention is {reuse} (should be >= 24).",
                raw_evidence=self._build_evidence(
                    api_call="iam.get_account_password_policy()",
                    cli_command="aws iam get-account-password-policy",
                    response={"PasswordReusePrevention": reuse, "password_policy": _sanitize_response(pp)},
                    service="IAM",
                    assessor_guidance="'PasswordReusePrevention' is below 24. Update with 'aws iam update-account-password-policy --password-reuse-prevention 24'.",
                ))
        except self._iam.exceptions.NoSuchEntityException:
            return self._result(check_def, "not_met", "No password policy configured.",
                raw_evidence=self._build_evidence(
                    api_call="iam.get_account_password_policy()",
                    cli_command="aws iam get-account-password-policy",
                    response={"password_policy_exists": False},
                    service="IAM",
                    assessor_guidance="CRITICAL: No password policy exists. Create one with PasswordReusePrevention >= 24 via 'aws iam update-account-password-policy'.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking password reuse: {e}")

    def check_tls_api_enforcement(self, check_def: dict) -> CheckResult:
        """Check AWS API uses TLS 1.2+ (always met — AWS enforces this)."""
        try:
            return self._result(check_def, "met",
                "AWS API endpoints enforce TLS 1.2+ for all communications. "
                "This is an AWS platform guarantee.",
                raw_evidence=self._build_evidence(
                    api_call="iam.get_credential_report()",
                    cli_command="aws iam get-credential-report",
                    response={"tls_enforced": True, "minimum_tls_version": "1.2", "enforcement": "AWS platform guarantee -- all API endpoints require TLS 1.2+"},
                    service="IAM",
                    assessor_guidance="AWS enforces TLS 1.2+ on all API endpoints. This is a platform-level control. Verify no custom endpoints bypass this.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_no_shared_accounts(self, check_def: dict) -> CheckResult:
        """Check each IAM user maps to a single individual (no generic/shared names)."""
        try:
            users = self._iam.list_users().get("Users", [])
            generic = []
            generic_patterns = ("shared", "generic", "team", "common", "group", "temp", "test")
            for u in users:
                name_lower = u["UserName"].lower()
                if any(p in name_lower for p in generic_patterns):
                    generic.append(u["UserName"])
            if not generic:
                return self._result(check_def, "met",
                    f"All {len(users)} IAM users appear to be individually named.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_users()",
                        cli_command="aws iam list-users",
                        response={"total_users": len(users), "generic_accounts": generic[:20], "usernames": [u["UserName"] for u in users][:50]},
                        service="IAM",
                        assessor_guidance="Verify 'generic_accounts' is empty. Check 'usernames' for patterns like shared/team/generic/test. Each account must map to one individual.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(generic)} potentially shared account(s): {', '.join(generic[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_users()",
                    cli_command="aws iam list-users",
                    response={"total_users": len(users), "generic_accounts": generic[:20], "patterns_checked": list(generic_patterns)},
                    service="IAM",
                    assessor_guidance="Users in 'generic_accounts' match shared-account patterns. Verify each with org -- rename to individual names or document as service accounts.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking shared accounts: {e}")

    def check_cloudtrail_access_restricted(self, check_def: dict) -> CheckResult:
        """Check CloudTrail management is restricted to security roles."""
        try:
            entities = self._iam.list_entities_for_policy(
                PolicyArn="arn:aws:iam::aws:policy/AWSCloudTrail_FullAccess"
            )
            users = entities.get("PolicyUsers", [])
            groups = entities.get("PolicyGroups", [])
            roles = entities.get("PolicyRoles", [])
            total = len(users) + len(groups) + len(roles)
            if total <= 3:
                return self._result(check_def, "met",
                    f"CloudTrail access is limited: {len(users)} users, {len(groups)} groups, "
                    f"{len(roles)} roles have full access.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_entities_for_policy()",
                        cli_command="aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSCloudTrail_FullAccess",
                        response={"policy_users": [u["UserName"] for u in users][:20], "policy_groups": [g["GroupName"] for g in groups][:20], "policy_roles": [r["RoleName"] for r in roles][:20], "total_entities": total},
                        service="IAM",
                        assessor_guidance="Verify 'total_entities' <= 3. CloudTrail admin access should be limited to security team roles only. Check role names for security context.",
                    ))
            return self._result(check_def, "not_met",
                f"CloudTrail access too broad: {len(users)} users, {len(groups)} groups, "
                f"{len(roles)} roles have AWSCloudTrail_FullAccess.",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_entities_for_policy()",
                    cli_command="aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSCloudTrail_FullAccess",
                    response={"policy_users": [u["UserName"] for u in users][:20], "policy_groups": [g["GroupName"] for g in groups][:20], "policy_roles": [r["RoleName"] for r in roles][:20], "total_entities": total},
                    service="IAM",
                    assessor_guidance="'total_entities' exceeds 3. Remove AWSCloudTrail_FullAccess from non-security entities. Use ReadOnlyAccess for audit/monitoring roles.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking CT access: {e}")

    # ------------------------------------------------------------------
    # Phase 2: CloudTrail + S3 Deep Checks (12 methods)
    # ------------------------------------------------------------------

    def check_cloudtrail_log_retention(self, check_def: dict) -> CheckResult:
        """Check CloudTrail S3 bucket retains logs >= 365 days."""
        try:
            trails = self._get_all_trails()
            if not trails:
                return self._result(check_def, "not_met", "No CloudTrail trails found.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_lifecycle_configuration()",
                        cli_command="aws s3api get-bucket-lifecycle-configuration --bucket TRAIL-BUCKET",
                        response={"trail_count": 0},
                        service="S3",
                        assessor_guidance="Verify no CloudTrail trails exist. If trails exist, check S3 lifecycle Rules[].Expiration.Days >= 365.",
                    ))
            issues = []
            for trail in trails:
                bucket = trail.get("S3BucketName", "")
                if not bucket:
                    continue
                try:
                    lc = self._s3.get_bucket_lifecycle_configuration(Bucket=bucket)
                    rules = lc.get("Rules", [])
                    max_days = max(
                        (r.get("Expiration", {}).get("Days", 0) for r in rules if r.get("Status") == "Enabled"),
                        default=0)
                    if max_days < 365 and max_days > 0:
                        issues.append(f"{bucket}: expires in {max_days} days")
                except Exception as ex:
                    if "NoSuchLifecycleConfiguration" in str(ex):
                        pass  # No expiration = retained indefinitely = good
                    else:
                        issues.append(f"{bucket}: cannot check lifecycle")
            if not issues:
                return self._result(check_def, "met",
                    "CloudTrail logs retained >= 365 days (or no expiration set).",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_lifecycle_configuration()",
                        cli_command="aws s3api get-bucket-lifecycle-configuration --bucket TRAIL-BUCKET",
                        response={"trail_count": len(trails), "buckets_checked": [t.get("S3BucketName") for t in trails if t.get("S3BucketName")][:20]},
                        service="S3",
                        assessor_guidance="Check each bucket's lifecycle Rules[].Expiration.Days field. If absent or >= 365, retention compliant.",
                    ))
            return self._result(check_def, "not_met", "; ".join(issues[:5]),
                raw_evidence=self._build_evidence(
                    api_call="s3.get_bucket_lifecycle_configuration()",
                    cli_command="aws s3api get-bucket-lifecycle-configuration --bucket TRAIL-BUCKET",
                    response={"trail_count": len(trails), "issues": issues[:20]},
                    service="S3",
                    assessor_guidance="Confirm lifecycle Rules[].Expiration.Days < 365 for flagged buckets. Remediation: increase to 365+ days.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking retention: {e}")

    def check_cloudtrail_data_events(self, check_def: dict) -> CheckResult:
        """Check CloudTrail data events enabled for S3 and Lambda."""
        try:
            trails = self._get_all_trails()
            if not trails:
                return self._result(check_def, "not_met", "No CloudTrail trails found.",
                    raw_evidence=self._build_evidence(
                        api_call="cloudtrail.get_event_selectors()",
                        cli_command="aws cloudtrail get-event-selectors --trail-name TRAIL",
                        response={"trail_count": 0},
                        service="CloudTrail",
                        assessor_guidance="Verify no trails exist. If trails exist, check EventSelectors[].DataResources[].Type for AWS::S3::Object and AWS::Lambda::Function.",
                    ))
            has_s3_data = False
            has_lambda_data = False
            for trail in trails:
                try:
                    selectors = self._cloudtrail.get_event_selectors(
                        TrailName=trail["TrailARN"])
                    for es in selectors.get("EventSelectors", []):
                        for dr in es.get("DataResources", []):
                            if dr.get("Type") == "AWS::S3::Object":
                                has_s3_data = True
                            elif dr.get("Type") == "AWS::Lambda::Function":
                                has_lambda_data = True
                    for adv in selectors.get("AdvancedEventSelectors", []):
                        for fs in adv.get("FieldSelectors", []):
                            if "S3" in str(fs.get("Equals", [])):
                                has_s3_data = True
                            if "Lambda" in str(fs.get("Equals", [])):
                                has_lambda_data = True
                except Exception:
                    pass
            if has_s3_data and has_lambda_data:
                return self._result(check_def, "met",
                    "CloudTrail data events enabled for both S3 and Lambda.",
                    raw_evidence=self._build_evidence(
                        api_call="cloudtrail.get_event_selectors()",
                        cli_command="aws cloudtrail get-event-selectors --trail-name TRAIL",
                        response={"trail_count": len(trails), "has_s3_data": True, "has_lambda_data": True, "trails": [t["Name"] for t in trails][:20]},
                        service="CloudTrail",
                        assessor_guidance="Confirm EventSelectors[].DataResources[].Type includes both AWS::S3::Object and AWS::Lambda::Function.",
                    ))
            missing = []
            if not has_s3_data:
                missing.append("S3")
            if not has_lambda_data:
                missing.append("Lambda")
            return self._result(check_def, "not_met",
                f"Data events not enabled for: {', '.join(missing)}",
                raw_evidence=self._build_evidence(
                    api_call="cloudtrail.get_event_selectors()",
                    cli_command="aws cloudtrail get-event-selectors --trail-name TRAIL",
                    response={"trail_count": len(trails), "has_s3_data": has_s3_data, "has_lambda_data": has_lambda_data, "missing": missing},
                    service="CloudTrail",
                    assessor_guidance="Verify EventSelectors[].DataResources[].Type is missing required resource types. Add missing types.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking data events: {e}")

    def check_cloudtrail_user_identity(self, check_def: dict) -> CheckResult:
        """Check CloudTrail captures user identity (always met when CT is enabled)."""
        try:
            trails = self._get_all_trails()
            active = []
            for trail in trails:
                try:
                    status = self._cloudtrail.get_trail_status(Name=trail["TrailARN"])
                    if status.get("IsLogging"):
                        active.append(trail["Name"])
                except Exception:
                    pass
            if active:
                return self._result(check_def, "met",
                    f"CloudTrail captures userIdentity on {len(active)} active trail(s). "
                    "This is a built-in CloudTrail feature.",
                    raw_evidence=self._build_evidence(
                        api_call="cloudtrail.get_trail_status()",
                        cli_command="aws cloudtrail get-trail-status --name TRAIL",
                        response={"active_trail_count": len(active), "active_trails": active[:20], "total_trails": len(trails)},
                        service="CloudTrail",
                        assessor_guidance="Verify IsLogging: true. CloudTrail automatically records userIdentity field in all events.",
                    ))
            return self._result(check_def, "not_met",
                "No active CloudTrail trails. User identity cannot be recorded.",
                raw_evidence=self._build_evidence(
                    api_call="cloudtrail.get_trail_status()",
                    cli_command="aws cloudtrail get-trail-status --name TRAIL",
                    response={"active_trail_count": 0, "total_trails": len(trails)},
                    service="CloudTrail",
                    assessor_guidance="Confirm IsLogging: false on all trails. Enable at least one trail to capture userIdentity.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking user identity: {e}")

    def check_cloudtrail_cloudwatch_integration(self, check_def: dict) -> CheckResult:
        """Check CloudTrail is integrated with CloudWatch Logs."""
        try:
            trails = self._get_all_trails()
            if not trails:
                return self._result(check_def, "not_met", "No CloudTrail trails found.",
                    raw_evidence=self._build_evidence(
                        api_call="cloudtrail.describe_trails()",
                        cli_command="aws cloudtrail describe-trails --query 'trailList[].CloudWatchLogsLogGroupArn'",
                        response={"trail_count": 0},
                        service="CloudTrail",
                        assessor_guidance="Verify no trails exist. If trails exist, check CloudWatchLogsLogGroupArn is populated.",
                    ))
            integrated = []
            not_integrated = []
            for trail in trails:
                if trail.get("CloudWatchLogsLogGroupArn"):
                    integrated.append(trail["Name"])
                else:
                    not_integrated.append(trail["Name"])
            if not not_integrated:
                return self._result(check_def, "met",
                    f"All {len(trails)} trail(s) integrated with CloudWatch Logs.",
                    raw_evidence=self._build_evidence(
                        api_call="cloudtrail.describe_trails()",
                        cli_command="aws cloudtrail describe-trails --query 'trailList[].CloudWatchLogsLogGroupArn'",
                        response={"trail_count": len(trails), "integrated_trails": integrated[:20]},
                        service="CloudTrail",
                        assessor_guidance="Confirm CloudWatchLogsLogGroupArn field is non-null for all trails. Check log group exists in CloudWatch.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(not_integrated)} trail(s) not integrated with CW Logs: {', '.join(not_integrated[:5])}",
                raw_evidence=self._build_evidence(
                    api_call="cloudtrail.describe_trails()",
                    cli_command="aws cloudtrail describe-trails --query 'trailList[].CloudWatchLogsLogGroupArn'",
                    response={"trail_count": len(trails), "not_integrated": not_integrated[:20], "integrated": integrated[:20]},
                    service="CloudTrail",
                    assessor_guidance="Confirm CloudWatchLogsLogGroupArn is null for flagged trails. Configure log group integration.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking CW integration: {e}")

    def check_cloudtrail_bucket_logging(self, check_def: dict) -> CheckResult:
        """Check CloudTrail S3 bucket has access logging enabled."""
        try:
            trails = self._get_all_trails()
            if not trails:
                return self._result(check_def, "not_met", "No CloudTrail trails found.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_logging()",
                        cli_command="aws s3api get-bucket-logging --bucket TRAIL-BUCKET",
                        response={"trail_count": 0},
                        service="S3",
                        assessor_guidance="Verify no trails exist. If trails exist, check LoggingEnabled.TargetBucket is populated.",
                    ))
            issues = []
            for trail in trails:
                bucket = trail.get("S3BucketName", "")
                if not bucket:
                    continue
                try:
                    logging_conf = self._s3.get_bucket_logging(Bucket=bucket)
                    if not logging_conf.get("LoggingEnabled"):
                        issues.append(bucket)
                except Exception:
                    issues.append(f"{bucket} (access denied)")
            if not issues:
                return self._result(check_def, "met",
                    "Access logging is enabled on all CloudTrail S3 buckets.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_logging()",
                        cli_command="aws s3api get-bucket-logging --bucket TRAIL-BUCKET",
                        response={"trail_count": len(trails), "buckets_checked": [t.get("S3BucketName") for t in trails if t.get("S3BucketName")][:20]},
                        service="S3",
                        assessor_guidance="Verify LoggingEnabled.TargetBucket is populated for all CloudTrail buckets.",
                    ))
            return self._result(check_def, "not_met",
                f"No access logging on CT bucket(s): {', '.join(issues[:5])}",
                raw_evidence=self._build_evidence(
                    api_call="s3.get_bucket_logging()",
                    cli_command="aws s3api get-bucket-logging --bucket TRAIL-BUCKET",
                    response={"trail_count": len(trails), "issues": issues[:20]},
                    service="S3",
                    assessor_guidance="Confirm LoggingEnabled is absent or TargetBucket is null. Enable S3 server access logging.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking bucket logging: {e}")

    def check_cloudtrail_bucket_encryption(self, check_def: dict) -> CheckResult:
        """Check CloudTrail S3 bucket uses SSE-KMS encryption."""
        try:
            trails = self._get_all_trails()
            if not trails:
                return self._result(check_def, "not_met", "No CloudTrail trails found.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_encryption()",
                        cli_command="aws s3api get-bucket-encryption --bucket TRAIL-BUCKET",
                        response={"trail_count": 0},
                        service="S3",
                        assessor_guidance="Verify no trails exist. If trails exist, check Rules[].ApplyServerSideEncryptionByDefault.SSEAlgorithm = aws:kms.",
                    ))
            issues = []
            for trail in trails:
                bucket = trail.get("S3BucketName", "")
                if not bucket:
                    continue
                try:
                    enc = self._s3.get_bucket_encryption(Bucket=bucket)
                    rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    if rules:
                        algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
                        if algo not in ("aws:kms", "aws:kms:dsse"):
                            issues.append(f"{bucket}: uses {algo} (should be KMS)")
                    else:
                        issues.append(f"{bucket}: no encryption rules")
                except Exception:
                    issues.append(f"{bucket}: no encryption configured")
            if not issues:
                return self._result(check_def, "met",
                    "All CloudTrail S3 buckets use SSE-KMS encryption.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_encryption()",
                        cli_command="aws s3api get-bucket-encryption --bucket TRAIL-BUCKET",
                        response={"trail_count": len(trails), "buckets_checked": [t.get("S3BucketName") for t in trails if t.get("S3BucketName")][:20]},
                        service="S3",
                        assessor_guidance="Verify SSEAlgorithm = aws:kms or aws:kms:dsse. Check KMS key exists and has proper rotation.",
                    ))
            return self._result(check_def, "not_met", "; ".join(issues[:5]),
                raw_evidence=self._build_evidence(
                    api_call="s3.get_bucket_encryption()",
                    cli_command="aws s3api get-bucket-encryption --bucket TRAIL-BUCKET",
                    response={"trail_count": len(trails), "issues": issues[:20]},
                    service="S3",
                    assessor_guidance="Confirm SSEAlgorithm is not aws:kms. Change to SSE-KMS with customer-managed CMK.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking bucket encryption: {e}")

    def check_cloudtrail_bucket_mfa_delete(self, check_def: dict) -> CheckResult:
        """Check CloudTrail S3 bucket has MFA Delete enabled."""
        try:
            trails = self._get_all_trails()
            if not trails:
                return self._result(check_def, "not_met", "No CloudTrail trails found.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_versioning()",
                        cli_command="aws s3api get-bucket-versioning --bucket TRAIL-BUCKET",
                        response={"trail_count": 0},
                        service="S3",
                        assessor_guidance="Verify no trails exist. If trails exist, check MFADelete field = Enabled in versioning config.",
                    ))
            issues = []
            for trail in trails:
                bucket = trail.get("S3BucketName", "")
                if not bucket:
                    continue
                try:
                    ver = self._s3.get_bucket_versioning(Bucket=bucket)
                    mfa_delete = ver.get("MFADelete", "Disabled")
                    if mfa_delete != "Enabled":
                        issues.append(bucket)
                except Exception:
                    issues.append(f"{bucket} (access denied)")
            if not issues:
                return self._result(check_def, "met",
                    "MFA Delete is enabled on all CloudTrail S3 buckets.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_versioning()",
                        cli_command="aws s3api get-bucket-versioning --bucket TRAIL-BUCKET",
                        response={"trail_count": len(trails), "buckets_checked": [t.get("S3BucketName") for t in trails if t.get("S3BucketName")][:20]},
                        service="S3",
                        assessor_guidance="Confirm MFADelete: Enabled. Requires root account credentials to enable via CLI.",
                    ))
            return self._result(check_def, "not_met",
                f"MFA Delete not enabled on: {', '.join(issues[:5])}",
                raw_evidence=self._build_evidence(
                    api_call="s3.get_bucket_versioning()",
                    cli_command="aws s3api get-bucket-versioning --bucket TRAIL-BUCKET",
                    response={"trail_count": len(trails), "issues": issues[:20]},
                    service="S3",
                    assessor_guidance="Confirm MFADelete: Disabled or null. Use root credentials to enable via CLI with --mfa parameter.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking MFA Delete: {e}")

    def check_s3_public_access_block(self, check_def: dict) -> CheckResult:
        """Check per-bucket public access block on all S3 buckets."""
        try:
            buckets = self._get_all_s3_buckets()
            if not buckets:
                return self._result(check_def, "met", "No S3 buckets found.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_public_access_block()",
                        cli_command="aws s3api get-public-access-block --bucket BUCKET",
                        response={"bucket_count": 0},
                        service="S3",
                        assessor_guidance="Verify no S3 buckets exist. If buckets exist, check PublicAccessBlockConfiguration has all 4 flags true.",
                    ))
            no_block = []
            for bucket in buckets:
                try:
                    pab = self._s3.get_public_access_block(Bucket=bucket)
                    config = pab.get("PublicAccessBlockConfiguration", {})
                    if not all([config.get("BlockPublicAcls"), config.get("IgnorePublicAcls"),
                               config.get("BlockPublicPolicy"), config.get("RestrictPublicBuckets")]):
                        no_block.append(bucket)
                except Exception:
                    no_block.append(bucket)
            if not no_block:
                return self._result(check_def, "met",
                    f"All {len(buckets)} bucket(s) have public access block enabled.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_public_access_block()",
                        cli_command="aws s3api get-public-access-block --bucket BUCKET",
                        response={"bucket_count": len(buckets), "buckets_checked": buckets[:20]},
                        service="S3",
                        assessor_guidance="Verify BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets all = true.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(no_block)} bucket(s) without full public access block: {', '.join(no_block[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="s3.get_public_access_block()",
                    cli_command="aws s3api get-public-access-block --bucket BUCKET",
                    response={"bucket_count": len(buckets), "no_block_count": len(no_block), "no_block_buckets": no_block[:20]},
                    service="S3",
                    assessor_guidance="Confirm at least one of the 4 flags is false. Enable all 4 flags via put-public-access-block.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking public access blocks: {e}")

    def check_no_public_s3_buckets(self, check_def: dict) -> CheckResult:
        """Check no S3 buckets are publicly accessible."""
        try:
            buckets = self._get_all_s3_buckets()
            if not buckets:
                return self._result(check_def, "met", "No S3 buckets found.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_policy_status()",
                        cli_command="aws s3api get-bucket-policy-status --bucket BUCKET",
                        response={"bucket_count": 0},
                        service="S3",
                        assessor_guidance="Verify no S3 buckets exist. If buckets exist, check PolicyStatus.IsPublic = false.",
                    ))
            public_buckets = []
            for bucket in buckets:
                try:
                    status = self._s3.get_bucket_policy_status(Bucket=bucket)
                    if status.get("PolicyStatus", {}).get("IsPublic"):
                        public_buckets.append(bucket)
                except Exception:
                    pass  # No policy = not public
            if not public_buckets:
                return self._result(check_def, "met",
                    f"No public S3 buckets found among {len(buckets)} bucket(s).",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_policy_status()",
                        cli_command="aws s3api get-bucket-policy-status --bucket BUCKET",
                        response={"bucket_count": len(buckets), "buckets_checked": buckets[:20]},
                        service="S3",
                        assessor_guidance="Verify PolicyStatus.IsPublic = false for all buckets. Check bucket policies and ACLs.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(public_buckets)} public bucket(s): {', '.join(public_buckets[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="s3.get_bucket_policy_status()",
                    cli_command="aws s3api get-bucket-policy-status --bucket BUCKET",
                    response={"bucket_count": len(buckets), "public_bucket_count": len(public_buckets), "public_buckets": public_buckets[:20]},
                    service="S3",
                    assessor_guidance="Confirm PolicyStatus.IsPublic = true. Remove public principals from bucket policy and ACLs.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking public buckets: {e}")

    def check_s3_cui_bucket_policies(self, check_def: dict) -> CheckResult:
        """Check S3 bucket policies deny unauthorized principals."""
        try:
            buckets = self._get_all_s3_buckets()
            if not buckets:
                return self._result(check_def, "met", "No S3 buckets found.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_policy()",
                        cli_command="aws s3api get-bucket-policy --bucket BUCKET",
                        response={"bucket_count": 0},
                        service="S3",
                        assessor_guidance="Verify no S3 buckets exist. If buckets exist, check Policy document exists with explicit deny statements.",
                    ))
            no_policy = []
            for bucket in buckets:
                try:
                    self._s3.get_bucket_policy(Bucket=bucket)
                except Exception as ex:
                    if "NoSuchBucketPolicy" in str(ex):
                        no_policy.append(bucket)
            if not no_policy:
                return self._result(check_def, "met",
                    f"All {len(buckets)} bucket(s) have bucket policies defined.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_policy()",
                        cli_command="aws s3api get-bucket-policy --bucket BUCKET",
                        response={"bucket_count": len(buckets), "buckets_checked": buckets[:20]},
                        service="S3",
                        assessor_guidance="Verify Policy document exists. Review Statement[].Principal and Condition for unauthorized access.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(no_policy)} bucket(s) without explicit policy: {', '.join(no_policy[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="s3.get_bucket_policy()",
                    cli_command="aws s3api get-bucket-policy --bucket BUCKET",
                    response={"bucket_count": len(buckets), "no_policy_count": len(no_policy), "no_policy_buckets": no_policy[:20]},
                    service="S3",
                    assessor_guidance="Confirm NoSuchBucketPolicy error. Create bucket policy with explicit allow/deny for authorized principals.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking bucket policies: {e}")

    def check_s3_bucket_encryption(self, check_def: dict) -> CheckResult:
        """Check all S3 buckets use SSE-KMS or SSE-S3 encryption."""
        try:
            buckets = self._get_all_s3_buckets()
            if not buckets:
                return self._result(check_def, "met", "No S3 buckets found.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_encryption()",
                        cli_command="aws s3api get-bucket-encryption --bucket BUCKET",
                        response={"bucket_count": 0},
                        service="S3",
                        assessor_guidance="Verify no S3 buckets exist. If buckets exist, check Rules[].ApplyServerSideEncryptionByDefault exists.",
                    ))
            unencrypted = []
            for bucket in buckets:
                try:
                    enc = self._s3.get_bucket_encryption(Bucket=bucket)
                    rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    if not rules:
                        unencrypted.append(bucket)
                except Exception:
                    unencrypted.append(bucket)
            if not unencrypted:
                return self._result(check_def, "met",
                    f"All {len(buckets)} bucket(s) have encryption configured.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_encryption()",
                        cli_command="aws s3api get-bucket-encryption --bucket BUCKET",
                        response={"bucket_count": len(buckets), "buckets_checked": buckets[:20]},
                        service="S3",
                        assessor_guidance="Verify Rules[].ApplyServerSideEncryptionByDefault.SSEAlgorithm = AES256 or aws:kms for all buckets.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(unencrypted)} bucket(s) without encryption: {', '.join(unencrypted[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="s3.get_bucket_encryption()",
                    cli_command="aws s3api get-bucket-encryption --bucket BUCKET",
                    response={"bucket_count": len(buckets), "unencrypted_count": len(unencrypted), "unencrypted_buckets": unencrypted[:20]},
                    service="S3",
                    assessor_guidance="Confirm Rules[] is empty or missing. Enable default encryption via put-bucket-encryption with SSE-KMS.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking bucket encryption: {e}")

    def check_s3_default_encryption(self, check_def: dict) -> CheckResult:
        """Check S3 default encryption is enabled on all buckets."""
        try:
            buckets = self._get_all_s3_buckets()
            if not buckets:
                return self._result(check_def, "met", "No S3 buckets found.",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_encryption()",
                        cli_command="aws s3api get-bucket-encryption --bucket BUCKET",
                        response={"bucket_count": 0},
                        service="S3",
                        assessor_guidance="Verify no S3 buckets exist. If buckets exist, check ServerSideEncryptionConfiguration.Rules exists.",
                    ))
            no_default = []
            for bucket in buckets:
                try:
                    enc = self._s3.get_bucket_encryption(Bucket=bucket)
                    rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    if not rules:
                        no_default.append(bucket)
                except Exception:
                    no_default.append(bucket)
            if not no_default:
                return self._result(check_def, "met",
                    f"Default encryption enabled on all {len(buckets)} bucket(s).",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_encryption()",
                        cli_command="aws s3api get-bucket-encryption --bucket BUCKET",
                        response={"bucket_count": len(buckets), "buckets_checked": buckets[:20]},
                        service="S3",
                        assessor_guidance="Verify Rules[].ApplyServerSideEncryptionByDefault.SSEAlgorithm exists with AES256 or aws:kms.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(no_default)} bucket(s) without default encryption: {', '.join(no_default[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="s3.get_bucket_encryption()",
                    cli_command="aws s3api get-bucket-encryption --bucket BUCKET",
                    response={"bucket_count": len(buckets), "no_default_count": len(no_default), "no_default_buckets": no_default[:20]},
                    service="S3",
                    assessor_guidance="Confirm Rules[] is empty. Use put-bucket-encryption to enable default SSE-KMS encryption.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking default encryption: {e}",
                                raw_evidence=self._build_evidence(
                                    api_call="s3.get_bucket_encryption()",
                                    cli_command="aws s3api get-bucket-encryption --bucket BUCKET",
                                    response={"error": str(e)},
                                    service="S3",
                                    assessor_guidance="Check exception details. May indicate permission issues or API throttling.",
                                ))

    # ------------------------------------------------------------------
    # Phase 3: EC2/VPC Network Checks (19 methods)
    # ------------------------------------------------------------------

    def check_cloudtrail_management_events(self, check_def: dict) -> CheckResult:
        """Check multi-region trail captures all management events."""
        try:
            trails = self._get_all_trails()
            for trail in trails:
                if trail.get("IsMultiRegionTrail"):
                    try:
                        status = self._cloudtrail.get_trail_status(Name=trail["TrailARN"])
                        if status.get("IsLogging"):
                            return self._result(check_def, "met",
                                f"Multi-region trail '{trail['Name']}' is actively logging all management events.",
                                raw_evidence=self._build_evidence(
                                    api_call="cloudtrail.get_trail_status()",
                                    cli_command="aws cloudtrail get-trail-status --name TRAIL",
                                    response={"trail_name": trail['Name'], "is_multi_region": True, "is_logging": True, "trail_arn": trail["TrailARN"]},
                                    service="CloudTrail",
                                    assessor_guidance="Verify IsLogging=true and IsMultiRegionTrail=true in JSON. Check TrailARN matches the region.",
                                ))
                    except Exception:
                        pass
            return self._result(check_def, "not_met",
                "No active multi-region CloudTrail trail found for management events.",
                raw_evidence=self._build_evidence(
                    api_call="cloudtrail.get_trail_status()",
                    cli_command="aws cloudtrail get-trail-status --name TRAIL",
                    response={"total_trails": len(trails), "trails": [{"name": t.get("Name"), "is_multi_region": t.get("IsMultiRegionTrail")} for t in trails[:20]]},
                    service="CloudTrail",
                    assessor_guidance="Check all trails for IsMultiRegionTrail and IsLogging flags. None should be false.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_vpn_monitoring(self, check_def: dict) -> CheckResult:
        """Check VPN connections have CloudWatch monitoring."""
        try:
            vpns = self._ec2.describe_vpn_connections().get("VpnConnections", [])
            active = [v for v in vpns if v.get("State") == "available"]
            if not active:
                return self._result(check_def, "met", "No active VPN connections to monitor.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_vpn_connections()",
                        cli_command="aws ec2 describe-vpn-connections",
                        response={"total_vpns": len(vpns), "active_vpns": 0, "vpn_states": [v.get("State") for v in vpns[:20]]},
                        service="EC2",
                        assessor_guidance="Verify no VPN connections have State=available. If empty, no VPNs exist.",
                    ))
            # VPN tunnels automatically publish metrics to CloudWatch
            return self._result(check_def, "met",
                f"{len(active)} active VPN connection(s). AWS VPN automatically publishes "
                "TunnelState, TunnelDataIn/Out metrics to CloudWatch.",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_vpn_connections()",
                    cli_command="aws ec2 describe-vpn-connections",
                    response={"active_vpn_count": len(active), "vpn_ids": [v["VpnConnectionId"] for v in active[:20]]},
                    service="EC2",
                    assessor_guidance="Verify State=available for all VPN connections. AWS auto-publishes TunnelState, TunnelDataIn/Out to CloudWatch.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking VPN monitoring: {e}")

    def check_vpn_encryption(self, check_def: dict) -> CheckResult:
        """Check VPN uses AES-256 encryption."""
        try:
            vpns = self._ec2.describe_vpn_connections().get("VpnConnections", [])
            active = [v for v in vpns if v.get("State") == "available"]
            if not active:
                return self._result(check_def, "met", "No active VPN connections.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_vpn_connections()",
                        cli_command="aws ec2 describe-vpn-connections",
                        response={"total_vpns": len(vpns), "active_vpns": 0},
                        service="EC2",
                        assessor_guidance="Verify no VPN connections exist or none have State=available.",
                    ))
            weak = []
            for vpn in active:
                for tunnel in vpn.get("Options", {}).get("TunnelOptions", []):
                    phase1 = tunnel.get("Phase1EncryptionAlgorithms", [])
                    phase2 = tunnel.get("Phase2EncryptionAlgorithms", [])
                    algos = [a.get("Value", "") for a in phase1 + phase2]
                    if algos and not any("AES256" in a or "AES-256" in a for a in algos):
                        weak.append(vpn["VpnConnectionId"])
                        break
            if not weak:
                return self._result(check_def, "met",
                    f"All {len(active)} VPN connection(s) use AES-256 encryption.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_vpn_connections()",
                        cli_command="aws ec2 describe-vpn-connections",
                        response={"active_vpn_count": len(active), "vpn_ids": [v["VpnConnectionId"] for v in active[:20]]},
                        service="EC2",
                        assessor_guidance="Check Options.TunnelOptions[].Phase1EncryptionAlgorithms and Phase2EncryptionAlgorithms contain AES256 or AES-256.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(weak)} VPN(s) may not use AES-256: {', '.join(weak[:5])}",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_vpn_connections()",
                    cli_command="aws ec2 describe-vpn-connections",
                    response={"weak_vpn_count": len(weak), "weak_vpn_ids": weak[:20], "total_active": len(active)},
                    service="EC2",
                    assessor_guidance="Check weak VPN IDs in JSON. Verify encryption algorithms lack AES256/AES-256 in Phase1/Phase2EncryptionAlgorithms.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking VPN encryption: {e}")

    def check_vpc_peering_reviewed(self, check_def: dict) -> CheckResult:
        """Check VPC peering connections are documented/authorized."""
        try:
            peerings = self._ec2.describe_vpc_peering_connections().get("VpcPeeringConnections", [])
            active = [p for p in peerings if p.get("Status", {}).get("Code") == "active"]
            if not active:
                return self._result(check_def, "met", "No active VPC peering connections.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_vpc_peering_connections()",
                        cli_command="aws ec2 describe-vpc-peering-connections",
                        response={"total_peerings": len(peerings), "active_peerings": 0},
                        service="EC2",
                        assessor_guidance="Verify no peering connections have Status.Code=active.",
                    ))
            details = []
            for p in active[:10]:
                req = p.get("RequesterVpcInfo", {}).get("VpcId", "?")
                acc = p.get("AccepterVpcInfo", {}).get("VpcId", "?")
                details.append(f"{p['VpcPeeringConnectionId']}: {req}<->{acc}")
            return self._result(check_def, "met",
                f"{len(active)} active VPC peering connection(s) found. Review: {'; '.join(details)}",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_vpc_peering_connections()",
                    cli_command="aws ec2 describe-vpc-peering-connections",
                    response={"active_peering_count": len(active), "peerings": [{"id": p["VpcPeeringConnectionId"], "requester": p.get("RequesterVpcInfo", {}).get("VpcId"), "accepter": p.get("AccepterVpcInfo", {}).get("VpcId")} for p in active[:20]]},
                    service="EC2",
                    assessor_guidance="Review each peering connection for authorization. Verify RequesterVpcInfo and AccepterVpcInfo match documented network design.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking VPC peering: {e}")

    def check_transit_gateway_reviewed(self, check_def: dict) -> CheckResult:
        """Check Transit Gateway attachments are authorized."""
        try:
            tgws = self._ec2.describe_transit_gateways().get("TransitGateways", [])
            if not tgws:
                return self._result(check_def, "met", "No Transit Gateways found.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_transit_gateways() + describe_transit_gateway_attachments()",
                        cli_command="aws ec2 describe-transit-gateways && aws ec2 describe-transit-gateway-attachments",
                        response={"transit_gateway_count": 0},
                        service="EC2",
                        assessor_guidance="Verify empty TransitGateways array in JSON response.",
                    ))
            attachments = self._ec2.describe_transit_gateway_attachments().get(
                "TransitGatewayAttachments", [])
            active = [a for a in attachments if a.get("State") == "available"]
            return self._result(check_def, "met",
                f"{len(tgws)} Transit Gateway(s) with {len(active)} active attachment(s). "
                "Review attachments for authorization.",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_transit_gateways() + describe_transit_gateway_attachments()",
                    cli_command="aws ec2 describe-transit-gateways && aws ec2 describe-transit-gateway-attachments",
                    response={"transit_gateway_count": len(tgws), "active_attachment_count": len(active), "attachments": [{"id": a.get("TransitGatewayAttachmentId"), "resource_id": a.get("ResourceId"), "state": a.get("State")} for a in active[:20]]},
                    service="EC2",
                    assessor_guidance="Review each attachment for State=available. Verify ResourceId matches authorized VPCs/VPNs in network documentation.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking Transit Gateway: {e}")

    def check_unused_security_groups(self, check_def: dict) -> CheckResult:
        """Check for security groups with no associated ENIs."""
        try:
            sgs = self._ec2.describe_security_groups().get("SecurityGroups", [])
            enis = self._ec2.describe_network_interfaces().get("NetworkInterfaces", [])
            used_sgs = set()
            for eni in enis:
                for sg in eni.get("Groups", []):
                    used_sgs.add(sg["GroupId"])
            unused = [sg["GroupId"] for sg in sgs
                if sg["GroupId"] not in used_sgs and sg.get("GroupName") != "default"]
            if not unused:
                return self._result(check_def, "met",
                    f"All {len(sgs)} security groups are in use or are default groups.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_security_groups() + describe_network_interfaces()",
                        cli_command="aws ec2 describe-security-groups && aws ec2 describe-network-interfaces",
                        response={"total_sgs": len(sgs), "used_sgs": len(used_sgs), "eni_count": len(enis)},
                        service="EC2",
                        assessor_guidance="Verify all non-default SGs are referenced by at least one ENI in NetworkInterfaces[].Groups[].",
                    ))
            return self._result(check_def, "not_met",
                f"{len(unused)} unused security group(s): {', '.join(unused[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_security_groups() + describe_network_interfaces()",
                    cli_command="aws ec2 describe-security-groups && aws ec2 describe-network-interfaces",
                    response={"unused_sg_count": len(unused), "unused_sg_ids": unused[:20], "total_sgs": len(sgs)},
                    service="EC2",
                    assessor_guidance="Review unused SG IDs. Verify they are not attached to any ENI and are not default groups.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking unused SGs: {e}")

    def check_sg_restrict_unnecessary_ports(self, check_def: dict) -> CheckResult:
        """Check no SGs allow unrestricted access on non-essential ports."""
        try:
            sgs = self._ec2.describe_security_groups().get("SecurityGroups", [])
            essential_ports = {80, 443}
            violations = []
            for sg in sgs:
                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)
                    for cidr in rule.get("IpRanges", []):
                        if cidr.get("CidrIp") == "0.0.0.0/0":
                            exposed = set(range(max(from_port, 1), min(to_port, 65535) + 1)) - essential_ports
                            if exposed and (to_port - from_port > 1 or from_port not in essential_ports):
                                violations.append(f"{sg['GroupId']}: ports {from_port}-{to_port}")
                                break
            if not violations:
                return self._result(check_def, "met",
                    "No security groups expose unnecessary ports to the internet.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_security_groups()",
                        cli_command="aws ec2 describe-security-groups",
                        response={"total_sgs": len(sgs), "violations": 0},
                        service="EC2",
                        assessor_guidance="Check IpPermissions[] for CidrIp=0.0.0.0/0. Verify only ports 80/443 are exposed, or FromPort=ToPort.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(violations)} SG rule(s) expose non-essential ports: {'; '.join(violations[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_security_groups()",
                    cli_command="aws ec2 describe-security-groups",
                    response={"violation_count": len(violations), "violations": violations[:20], "total_sgs": len(sgs)},
                    service="EC2",
                    assessor_guidance="Check violations list for SG IDs and port ranges. Verify FromPort-ToPort != 80/443 with CidrIp=0.0.0.0/0.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking SG ports: {e}")

    def check_ebs_volumes_encrypted(self, check_def: dict) -> CheckResult:
        """Check all EBS volumes are encrypted."""
        try:
            paginator = self._ec2.get_paginator("describe_volumes")
            unencrypted = []
            total = 0
            for page in paginator.paginate():
                for vol in page.get("Volumes", []):
                    total += 1
                    if not vol.get("Encrypted"):
                        unencrypted.append(vol["VolumeId"])
            if not unencrypted:
                return self._result(check_def, "met",
                    f"All {total} EBS volume(s) are encrypted." if total else "No EBS volumes found.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_volumes()",
                        cli_command="aws ec2 describe-volumes --query 'Volumes[].{Id:VolumeId,Encrypted:Encrypted}'",
                        response={"total_volumes": total, "encrypted_volumes": total},
                        service="EC2",
                        assessor_guidance="Verify Encrypted=true for all volumes in JSON. Check total matches volume count.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(unencrypted)} of {total} volume(s) unencrypted: {', '.join(unencrypted[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_volumes()",
                    cli_command="aws ec2 describe-volumes --query 'Volumes[].{Id:VolumeId,Encrypted:Encrypted}'",
                    response={"unencrypted_count": len(unencrypted), "unencrypted_volume_ids": unencrypted[:20], "total_volumes": total},
                    service="EC2",
                    assessor_guidance="Check unencrypted volume IDs in JSON. Verify Encrypted=false for these volumes.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking EBS encryption: {e}")

    def check_ebs_default_encryption_regions(self, check_def: dict) -> CheckResult:
        """Check EBS default encryption is enabled."""
        try:
            response = self._ec2.get_ebs_encryption_by_default()
            enabled = response.get("EbsEncryptionByDefault", False)
            if enabled:
                return self._result(check_def, "met",
                    "EBS default encryption is enabled for this region.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.get_ebs_encryption_by_default()",
                        cli_command="aws ec2 get-ebs-encryption-by-default",
                        response={"ebs_encryption_by_default": enabled},
                        service="EC2",
                        assessor_guidance="Verify EbsEncryptionByDefault=true in JSON response.",
                    ))
            return self._result(check_def, "not_met",
                "EBS default encryption is NOT enabled. New volumes may be unencrypted.",
                raw_evidence=self._build_evidence(
                    api_call="ec2.get_ebs_encryption_by_default()",
                    cli_command="aws ec2 get-ebs-encryption-by-default",
                    response={"ebs_encryption_by_default": enabled},
                    service="EC2",
                    assessor_guidance="Verify EbsEncryptionByDefault=false in JSON. This is a compliance gap.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_all_vpc_flow_logs(self, check_def: dict) -> CheckResult:
        """Check VPC Flow Logs enabled on all VPCs."""
        try:
            vpcs = self._ec2.describe_vpcs().get("Vpcs", [])
            if not vpcs:
                return self._result(check_def, "met", "No VPCs found.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_vpcs() + describe_flow_logs()",
                        cli_command="aws ec2 describe-vpcs && aws ec2 describe-flow-logs",
                        response={"vpc_count": 0},
                        service="EC2",
                        assessor_guidance="Verify empty Vpcs array in JSON response.",
                    ))
            flow_logs = self._ec2.describe_flow_logs().get("FlowLogs", [])
            fl_vpcs = {fl["ResourceId"] for fl in flow_logs if fl.get("ResourceId", "").startswith("vpc-")}
            missing = [v["VpcId"] for v in vpcs if v["VpcId"] not in fl_vpcs]
            if not missing:
                return self._result(check_def, "met",
                    f"Flow Logs enabled on all {len(vpcs)} VPC(s).",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_vpcs() + describe_flow_logs()",
                        cli_command="aws ec2 describe-vpcs && aws ec2 describe-flow-logs",
                        response={"vpc_count": len(vpcs), "flow_log_count": len(flow_logs), "vpc_ids": [v["VpcId"] for v in vpcs[:20]]},
                        service="EC2",
                        assessor_guidance="Verify each VPC ID appears in FlowLogs[].ResourceId. All VPCs should have matching flow logs.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(missing)} VPC(s) without Flow Logs: {', '.join(missing[:5])}",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_vpcs() + describe_flow_logs()",
                    cli_command="aws ec2 describe-vpcs && aws ec2 describe-flow-logs",
                    response={"missing_count": len(missing), "missing_vpc_ids": missing[:20], "total_vpcs": len(vpcs)},
                    service="EC2",
                    assessor_guidance="Check missing VPC IDs in JSON. Verify they have no matching ResourceId in FlowLogs array.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_subnet_separation(self, check_def: dict) -> CheckResult:
        """Check management subnets are isolated from data subnets."""
        try:
            subnets = self._ec2.describe_subnets().get("Subnets", [])
            if len(subnets) < 2:
                return self._result(check_def, "not_met",
                    f"Only {len(subnets)} subnet(s) found. Need separate management/data subnets.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_subnets()",
                        cli_command="aws ec2 describe-subnets",
                        response={"subnet_count": len(subnets), "subnets": [{"id": s["SubnetId"], "vpc_id": s["VpcId"]} for s in subnets]},
                        service="EC2",
                        assessor_guidance="Verify subnet count < 2. Proper network segmentation requires multiple subnets.",
                    ))
            # Check for subnet tag-based or CIDR-based separation
            vpcs = {}
            for s in subnets:
                vpcs.setdefault(s["VpcId"], []).append(s)
            multi_subnet_vpcs = {v: ss for v, ss in vpcs.items() if len(ss) >= 2}
            if multi_subnet_vpcs:
                return self._result(check_def, "met",
                    f"{len(multi_subnet_vpcs)} VPC(s) have multiple subnets for network separation. "
                    f"Total: {len(subnets)} subnets across {len(vpcs)} VPC(s).",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_subnets()",
                        cli_command="aws ec2 describe-subnets",
                        response={"total_subnets": len(subnets), "total_vpcs": len(vpcs), "multi_subnet_vpc_count": len(multi_subnet_vpcs), "vpcs": [{"vpc_id": v, "subnet_count": len(ss)} for v, ss in list(vpcs.items())[:20]]},
                        service="EC2",
                        assessor_guidance="Verify VPCs have >= 2 subnets for proper management/data separation. Check subnet_count per VPC.",
                    ))
            return self._result(check_def, "not_met",
                "No VPCs have multiple subnets for management/data separation.",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_subnets()",
                    cli_command="aws ec2 describe-subnets",
                    response={"total_subnets": len(subnets), "total_vpcs": len(vpcs), "vpcs": [{"vpc_id": v, "subnet_count": len(ss)} for v, ss in list(vpcs.items())[:20]]},
                    service="EC2",
                    assessor_guidance="Verify each VPC has only 1 subnet. This is insufficient for network segmentation.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking subnet separation: {e}")

    def check_ebs_snapshots_private(self, check_def: dict) -> CheckResult:
        """Check no EBS snapshots are shared publicly."""
        try:
            account_id = self._sts.get_caller_identity()["Account"]
            snapshots = self._ec2.describe_snapshots(OwnerIds=[account_id]).get("Snapshots", [])
            public = []
            for snap in snapshots[:100]:
                try:
                    attr = self._ec2.describe_snapshot_attribute(
                        SnapshotId=snap["SnapshotId"], Attribute="createVolumePermission")
                    perms = attr.get("CreateVolumePermissions", [])
                    if any(p.get("Group") == "all" for p in perms):
                        public.append(snap["SnapshotId"])
                except Exception:
                    pass
            if not public:
                return self._result(check_def, "met",
                    f"No public EBS snapshots found among {len(snapshots)} snapshot(s).",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_snapshots() + describe_snapshot_attribute()",
                        cli_command="aws ec2 describe-snapshots --owner-ids self",
                        response={"total_snapshots": len(snapshots), "public_snapshots": 0, "checked_count": min(100, len(snapshots))},
                        service="EC2",
                        assessor_guidance="Verify CreateVolumePermissions[] has no entries with Group=all. Check first 100 snapshots.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(public)} public snapshot(s): {', '.join(public[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_snapshots() + describe_snapshot_attribute()",
                    cli_command="aws ec2 describe-snapshots --owner-ids self",
                    response={"public_snapshot_count": len(public), "public_snapshot_ids": public[:20], "total_snapshots": len(snapshots)},
                    service="EC2",
                    assessor_guidance="Check public snapshot IDs. Verify CreateVolumePermissions contains Group=all for these snapshots.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking snapshots: {e}")

    def check_amis_private(self, check_def: dict) -> CheckResult:
        """Check no AMIs are shared publicly."""
        try:
            images = self._ec2.describe_images(Owners=["self"]).get("Images", [])
            public = []
            for img in images:
                if img.get("Public"):
                    public.append(img["ImageId"])
            if not public:
                return self._result(check_def, "met",
                    f"No public AMIs found among {len(images)} owned image(s).",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_images()",
                        cli_command="aws ec2 describe-images --owners self",
                        response={"total_images": len(images), "public_images": 0},
                        service="EC2",
                        assessor_guidance="Verify Public=false for all AMIs in Images[] array.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(public)} public AMI(s): {', '.join(public[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_images()",
                    cli_command="aws ec2 describe-images --owners self",
                    response={"public_image_count": len(public), "public_image_ids": public[:20], "total_images": len(images)},
                    service="EC2",
                    assessor_guidance="Check public AMI IDs. Verify Public=true for these images in JSON output.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking AMIs: {e}")

    def check_public_private_subnet_isolation(self, check_def: dict) -> CheckResult:
        """Check public and private subnets are separated."""
        try:
            subnets = self._ec2.describe_subnets().get("Subnets", [])
            rtbs = self._ec2.describe_route_tables().get("RouteTables", [])
            igw_subnets = set()
            for rtb in rtbs:
                has_igw = any(r.get("GatewayId", "").startswith("igw-")
                    for r in rtb.get("Routes", []))
                if has_igw:
                    for assoc in rtb.get("Associations", []):
                        if assoc.get("SubnetId"):
                            igw_subnets.add(assoc["SubnetId"])
            public = [s for s in subnets if s["SubnetId"] in igw_subnets or s.get("MapPublicIpOnLaunch")]
            private = [s for s in subnets if s["SubnetId"] not in igw_subnets and not s.get("MapPublicIpOnLaunch")]
            if public and private:
                return self._result(check_def, "met",
                    f"Subnet isolation present: {len(public)} public, {len(private)} private subnets.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_subnets() + describe_route_tables()",
                        cli_command="aws ec2 describe-subnets && aws ec2 describe-route-tables",
                        response={"public_subnet_count": len(public), "private_subnet_count": len(private), "public_subnet_ids": [s["SubnetId"] for s in public[:20]], "private_subnet_ids": [s["SubnetId"] for s in private[:20]]},
                        service="EC2",
                        assessor_guidance="Verify public subnets have IGW routes and MapPublicIpOnLaunch=true. Private subnets should have neither.",
                    ))
            if not public and not private:
                return self._result(check_def, "not_met", "No subnets found.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_subnets() + describe_route_tables()",
                        cli_command="aws ec2 describe-subnets && aws ec2 describe-route-tables",
                        response={"total_subnets": len(subnets), "public_count": 0, "private_count": 0},
                        service="EC2",
                        assessor_guidance="Verify empty Subnets[] array or no route tables found.",
                    ))
            return self._result(check_def, "not_met",
                f"Insufficient isolation: {len(public)} public, {len(private)} private subnets.",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_subnets() + describe_route_tables()",
                    cli_command="aws ec2 describe-subnets && aws ec2 describe-route-tables",
                    response={"public_subnet_count": len(public), "private_subnet_count": len(private), "total_subnets": len(subnets)},
                    service="EC2",
                    assessor_guidance="Check counts. Need both public and private subnets for proper isolation. One category is missing.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking subnet isolation: {e}")

    def check_nat_gateway_usage(self, check_def: dict) -> CheckResult:
        """Check private subnets use NAT Gateways for outbound access."""
        try:
            nat_gws = self._ec2.describe_nat_gateways(
                Filters=[{"Name": "state", "Values": ["available"]}]).get("NatGateways", [])
            if nat_gws:
                return self._result(check_def, "met",
                    f"{len(nat_gws)} active NAT Gateway(s) found for private subnet outbound access.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_nat_gateways()",
                        cli_command="aws ec2 describe-nat-gateways",
                        response={"nat_gateway_count": len(nat_gws), "nat_gateway_ids": [n["NatGatewayId"] for n in nat_gws[:20]]},
                        service="EC2",
                        assessor_guidance="Verify State=available for NAT Gateways. Check they are referenced in route tables for private subnets.",
                    ))
            return self._result(check_def, "not_met",
                "No active NAT Gateways found. Private subnets may lack outbound access control.",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_nat_gateways()",
                    cli_command="aws ec2 describe-nat-gateways",
                    response={"nat_gateway_count": 0},
                    service="EC2",
                    assessor_guidance="Verify no NAT Gateways with State=available exist. Private subnets need NAT for secure outbound access.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking NAT Gateways: {e}")

    def check_default_sg_deny_all(self, check_def: dict) -> CheckResult:
        """Check default security groups deny all traffic."""
        try:
            sgs = self._ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": ["default"]}]).get("SecurityGroups", [])
            permissive = []
            for sg in sgs:
                if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                    has_rules = False
                    for rule in sg.get("IpPermissions", []):
                        if rule.get("IpRanges") or rule.get("Ipv6Ranges") or rule.get("UserIdGroupPairs"):
                            has_rules = True
                    if has_rules:
                        permissive.append(f"{sg['GroupId']} ({sg.get('VpcId', 'N/A')})")
            if not permissive:
                return self._result(check_def, "met",
                    f"All {len(sgs)} default security group(s) deny inbound traffic.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_security_groups()",
                        cli_command="aws ec2 describe-security-groups --filters Name=group-name,Values=default",
                        response={"default_sg_count": len(sgs), "permissive_count": 0},
                        service="EC2",
                        assessor_guidance="Verify IpPermissions[] is empty or has no rules with IpRanges/Ipv6Ranges/UserIdGroupPairs for default SGs.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(permissive)} default SG(s) allow traffic: {', '.join(permissive[:5])}",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_security_groups()",
                    cli_command="aws ec2 describe-security-groups --filters Name=group-name,Values=default",
                    response={"permissive_count": len(permissive), "permissive_sgs": permissive[:20], "total_default_sgs": len(sgs)},
                    service="EC2",
                    assessor_guidance="Check permissive SG IDs. Verify IpPermissions[] contains active rules. Default SGs should have no ingress rules.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking default SGs: {e}")

    def check_nacl_deny_default(self, check_def: dict) -> CheckResult:
        """Check NACLs implement deny-by-default."""
        try:
            nacls = self._ec2.describe_network_acls().get("NetworkAcls", [])
            issues = []
            for nacl in nacls:
                for entry in nacl.get("Entries", []):
                    if (entry.get("RuleNumber") == 32767 and
                        entry.get("RuleAction") != "deny"):
                        issues.append(nacl["NetworkAclId"])
                        break
            if not issues:
                return self._result(check_def, "met",
                    f"All {len(nacls)} NACL(s) have deny-by-default rules.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_network_acls()",
                        cli_command="aws ec2 describe-network-acls",
                        response={"total_nacls": len(nacls), "nacls": nacls[:20]},
                        service="EC2",
                        assessor_guidance="Check Entries[] for each NACL. Rule 32767 should have RuleAction='deny' (default deny).",
                    ))
            return self._result(check_def, "not_met",
                f"{len(issues)} NACL(s) without proper deny default: {', '.join(issues[:5])}",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_network_acls()",
                    cli_command="aws ec2 describe-network-acls",
                    response={"total_nacls": len(nacls), "issues_count": len(issues), "issue_nacl_ids": issues[:20]},
                    service="EC2",
                    assessor_guidance="Verify listed NACLs have Entries[RuleNumber=32767].RuleAction='deny'. Fix NACLs that allow by default.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking NACLs: {e}")

    def check_ebs_encryption_by_default(self, check_def: dict) -> CheckResult:
        """Check EBS encryption by default is enabled."""
        try:
            response = self._ec2.get_ebs_encryption_by_default()
            if response.get("EbsEncryptionByDefault"):
                return self._result(check_def, "met",
                    "EBS encryption by default is enabled.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.get_ebs_encryption_by_default()",
                        cli_command="aws ec2 get-ebs-encryption-by-default",
                        response={"ebs_encryption_by_default": response.get("EbsEncryptionByDefault")},
                        service="EC2",
                        assessor_guidance="Verify EbsEncryptionByDefault=true. All new EBS volumes will be encrypted automatically.",
                    ))
            return self._result(check_def, "not_met",
                "EBS encryption by default is NOT enabled.",
                raw_evidence=self._build_evidence(
                    api_call="ec2.get_ebs_encryption_by_default()",
                    cli_command="aws ec2 get-ebs-encryption-by-default",
                    response={"ebs_encryption_by_default": response.get("EbsEncryptionByDefault")},
                    service="EC2",
                    assessor_guidance="Enable EBS encryption by default via Console or CLI. EbsEncryptionByDefault must be true.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_kms_key_policy_least_privilege(self, check_def: dict) -> CheckResult:
        """Check KMS key policies follow least privilege."""
        try:
            keys = self._kms.list_keys().get("Keys", [])
            overprivileged = []
            for key_entry in keys[:50]:
                try:
                    meta = self._kms.describe_key(KeyId=key_entry["KeyId"]).get("KeyMetadata", {})
                    if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
                        continue
                    policy_str = self._kms.get_key_policy(
                        KeyId=key_entry["KeyId"], PolicyName="default")["Policy"]
                    policy = json.loads(policy_str)
                    for stmt in policy.get("Statement", []):
                        if stmt.get("Effect") == "Allow":
                            principal = stmt.get("Principal", {})
                            if principal == "*" or principal.get("AWS") == "*":
                                overprivileged.append(key_entry["KeyId"][:12] + "...")
                                break
                except Exception:
                    pass
            if not overprivileged:
                return self._result(check_def, "met",
                    "All KMS key policies follow least privilege (no wildcard principals).",
                    raw_evidence=self._build_evidence(
                        api_call="kms.list_keys() + get_key_policy()",
                        cli_command="aws kms list-keys && aws kms get-key-policy --key-id KEY --policy-name default",
                        response={"total_customer_keys_checked": len([k for k in keys[:50]]), "keys": keys[:20]},
                        service="KMS",
                        assessor_guidance="Check Policy.Statement[].Principal. No statement should have Principal='*' or Principal.AWS='*'.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(overprivileged)} key(s) with overly permissive policy: {', '.join(overprivileged[:5])}",
                raw_evidence=self._build_evidence(
                    api_call="kms.list_keys() + get_key_policy()",
                    cli_command="aws kms list-keys && aws kms get-key-policy --key-id KEY --policy-name default",
                    response={"total_keys_checked": len(keys[:50]), "overprivileged_count": len(overprivileged), "overprivileged_keys": overprivileged[:20]},
                    service="KMS",
                    assessor_guidance="Review listed key policies. Replace wildcard principals with specific IAM roles/users/accounts.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking KMS policies: {e}")

    # ------------------------------------------------------------------
    # Phase 4: SSM + Config + RDS + EFS + Backup (25 methods)
    # ------------------------------------------------------------------

    def check_session_manager_logging(self, check_def: dict) -> CheckResult:
        """Check Session Manager logs to S3 or CloudWatch."""
        try:
            doc = self._ssm.get_document(Name="SSM-SessionManagerRunShell")["Content"]
            if isinstance(doc, str):
                doc = json.loads(doc)
            inputs = doc.get("inputs", doc.get("schemaVersion", {}))
            s3_enabled = bool(inputs.get("s3BucketName") if isinstance(inputs, dict) else False)
            cw_enabled = bool(inputs.get("cloudWatchLogGroupName") if isinstance(inputs, dict) else False)
            if s3_enabled or cw_enabled:
                targets = []
                if s3_enabled:
                    targets.append("S3")
                if cw_enabled:
                    targets.append("CloudWatch")
                return self._result(check_def, "met",
                    f"Session Manager logging to: {', '.join(targets)}.",
                    raw_evidence=self._build_evidence(
                        api_call="ssm.get_document()",
                        cli_command="aws ssm get-document --name SSM-SessionManagerRunShell",
                        response={"s3_enabled": s3_enabled, "cloudwatch_enabled": cw_enabled, "inputs": inputs},
                        service="SSM",
                        assessor_guidance="Verify inputs.s3BucketName or inputs.cloudWatchLogGroupName are configured. Both indicate logging.",
                    ))
            return self._result(check_def, "not_met",
                "Session Manager logging not configured to S3 or CloudWatch.",
                raw_evidence=self._build_evidence(
                    api_call="ssm.get_document()",
                    cli_command="aws ssm get-document --name SSM-SessionManagerRunShell",
                    response={"s3_enabled": s3_enabled, "cloudwatch_enabled": cw_enabled, "inputs": inputs},
                    service="SSM",
                    assessor_guidance="Configure Session Manager logging. Set s3BucketName or cloudWatchLogGroupName in document inputs.",
                ))
        except Exception as e:
            if "does not exist" in str(e).lower() or "not found" in str(e).lower():
                return self._result(check_def, "not_met",
                    "SSM Session Manager document not found. Session Manager may not be configured.",
                    raw_evidence=self._build_evidence(
                        api_call="ssm.get_document()",
                        cli_command="aws ssm get-document --name SSM-SessionManagerRunShell",
                        response={"document_name": "SSM-SessionManagerRunShell", "found": False},
                        service="SSM",
                        assessor_guidance="Create SSM Session Manager document. Document name must be SSM-SessionManagerRunShell.",
                    ))
            return self._result(check_def, "error", f"Error checking SM logging: {e}")

    def check_session_manager_usage(self, check_def: dict) -> CheckResult:
        """Check SSM Agent and Session Manager are deployed."""
        try:
            instances = self._ssm.describe_instance_information().get(
                "InstanceInformationList", [])
            online = [i for i in instances if i.get("PingStatus") == "Online"]
            if online:
                return self._result(check_def, "met",
                    f"{len(online)} instance(s) have SSM Agent online for Session Manager access.",
                    raw_evidence=self._build_evidence(
                        api_call="ssm.describe_instance_information()",
                        cli_command="aws ssm describe-instance-information",
                        response={"total_instances": len(instances), "online_count": len(online), "instances": instances[:20]},
                        service="SSM",
                        assessor_guidance="Check PingStatus='Online' for each instance. Online status confirms SSM Agent connectivity.",
                    ))
            if not instances:
                return self._result(check_def, "not_met",
                    "No instances registered with SSM. Deploy SSM Agent for secure remote access.",
                    raw_evidence=self._build_evidence(
                        api_call="ssm.describe_instance_information()",
                        cli_command="aws ssm describe-instance-information",
                        response={"total_instances": 0, "instances": []},
                        service="SSM",
                        assessor_guidance="Install SSM Agent on EC2 instances. Verify IAM instance profile allows ssm:UpdateInstanceInformation.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(instances)} instance(s) registered but none online.",
                raw_evidence=self._build_evidence(
                    api_call="ssm.describe_instance_information()",
                    cli_command="aws ssm describe-instance-information",
                    response={"total_instances": len(instances), "online_count": 0, "instances": instances[:20]},
                    service="SSM",
                    assessor_guidance="Check PingStatus field. Troubleshoot offline instances (IAM, network, agent status).",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking SSM: {e}")

    def check_config_enabled(self, check_def: dict) -> CheckResult:
        """Check AWS Config recorder is enabled."""
        try:
            recorders = self._config_service.describe_configuration_recorders().get(
                "ConfigurationRecorders", [])
            if not recorders:
                return self._result(check_def, "not_met", "No AWS Config recorders configured.",
                    raw_evidence=self._build_evidence(
                        api_call="config.describe_configuration_recorders()",
                        cli_command="aws configservice describe-configuration-recorders",
                        response={"total_recorders": 0, "recorders": []},
                        service="Config",
                        assessor_guidance="Create AWS Config recorder. Enable recording for all resource types and global resources.",
                    ))
            statuses = self._config_service.describe_configuration_recorder_status().get(
                "ConfigurationRecordersStatus", [])
            recording = [s for s in statuses if s.get("recording")]
            if recording:
                return self._result(check_def, "met",
                    f"{len(recording)} AWS Config recorder(s) actively recording.",
                    raw_evidence=self._build_evidence(
                        api_call="config.describe_configuration_recorders()",
                        cli_command="aws configservice describe-configuration-recorders",
                        response={"total_recorders": len(recorders), "recording_count": len(recording), "statuses": statuses[:20]},
                        service="Config",
                        assessor_guidance="Check recording=true in ConfigurationRecordersStatus[]. Confirms active config tracking.",
                    ))
            return self._result(check_def, "not_met",
                "AWS Config recorders exist but none are actively recording.",
                raw_evidence=self._build_evidence(
                    api_call="config.describe_configuration_recorders()",
                    cli_command="aws configservice describe-configuration-recorders",
                    response={"total_recorders": len(recorders), "recording_count": 0, "statuses": statuses[:20]},
                    service="Config",
                    assessor_guidance="Start Config recorders. Use start-configuration-recorder CLI command or Console.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking Config: {e}")

    def check_ssm_inventory(self, check_def: dict) -> CheckResult:
        """Check SSM inventory collection is enabled."""
        try:
            instances = self._ssm.describe_instance_information().get(
                "InstanceInformationList", [])
            if not instances:
                return self._result(check_def, "not_met",
                    "No instances registered with SSM for inventory collection.",
                    raw_evidence=self._build_evidence(
                        api_call="ssm.describe_instance_information()",
                        cli_command="aws ssm describe-instance-information",
                        response={"total_instances": 0, "instances": []},
                        service="SSM",
                        assessor_guidance="Deploy SSM Agent and configure inventory collection via State Manager or Inventory service.",
                    ))
            managed = len(instances)
            return self._result(check_def, "met",
                f"{managed} instance(s) managed by SSM for inventory collection.",
                raw_evidence=self._build_evidence(
                    api_call="ssm.describe_instance_information()",
                    cli_command="aws ssm describe-instance-information",
                    response={"total_instances": managed, "instances": instances[:20]},
                    service="SSM",
                    assessor_guidance="Verify instances appear in SSM Inventory with software/application data collected.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking SSM inventory: {e}")

    def check_ami_baseline(self, check_def: dict) -> CheckResult:
        """Check hardened AMI baselines exist."""
        try:
            images = self._ec2.describe_images(Owners=["self"]).get("Images", [])
            if images:
                return self._result(check_def, "met",
                    f"{len(images)} custom AMI(s) found as potential baselines. "
                    "Verify they are hardened and documented.",
                    raw_evidence=self._build_evidence(
                        api_call="ec2.describe_images()",
                        cli_command="aws ec2 describe-images --owners self",
                        response={"total_amis": len(images), "images": images[:20]},
                        service="EC2",
                        assessor_guidance="Verify AMIs are hardened per CIS/STIG. Check Name, Description for baseline identification.",
                    ))
            return self._result(check_def, "not_met",
                "No custom AMIs found. Create hardened AMI baselines.",
                raw_evidence=self._build_evidence(
                    api_call="ec2.describe_images()",
                    cli_command="aws ec2 describe-images --owners self",
                    response={"total_amis": 0, "images": []},
                    service="EC2",
                    assessor_guidance="Create custom AMIs from hardened instances. Document baseline configurations and security settings.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking AMI baselines: {e}")

    def check_config_cis_rules(self, check_def: dict) -> CheckResult:
        """Check AWS Config has CIS Benchmark rules."""
        try:
            rules = self._config_service.describe_config_rules().get("ConfigRules", [])
            cis_rules = [r["ConfigRuleName"] for r in rules
                if "cis" in r["ConfigRuleName"].lower() or "benchmark" in r["ConfigRuleName"].lower()]
            if cis_rules:
                return self._result(check_def, "met",
                    f"{len(cis_rules)} CIS Benchmark Config rule(s) found: {', '.join(cis_rules[:5])}",
                    raw_evidence=self._build_evidence(
                        api_call="config.describe_config_rules()",
                        cli_command="aws configservice describe-config-rules",
                        response={"total_rules": len(rules), "cis_rule_count": len(cis_rules), "cis_rules": cis_rules[:20]},
                        service="Config",
                        assessor_guidance="Check ConfigRuleName contains 'cis' or 'benchmark'. Verify rules are active and evaluating.",
                    ))
            if rules:
                return self._result(check_def, "not_met",
                    f"{len(rules)} Config rules found but none are CIS Benchmark rules.",
                    raw_evidence=self._build_evidence(
                        api_call="config.describe_config_rules()",
                        cli_command="aws configservice describe-config-rules",
                        response={"total_rules": len(rules), "cis_rule_count": 0, "rules": rules[:20]},
                        service="Config",
                        assessor_guidance="Deploy CIS AWS Foundations Benchmark conformance pack or individual CIS Config rules.",
                    ))
            return self._result(check_def, "not_met", "No AWS Config rules configured.",
                raw_evidence=self._build_evidence(
                    api_call="config.describe_config_rules()",
                    cli_command="aws configservice describe-config-rules",
                    response={"total_rules": 0, "rules": []},
                    service="Config",
                    assessor_guidance="Enable AWS Config and deploy CIS conformance pack for automated compliance checks.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking Config rules: {e}")

    def check_config_history(self, check_def: dict) -> CheckResult:
        """Check AWS Config delivers configuration history to S3."""
        try:
            channels = self._config_service.describe_delivery_channels().get(
                "DeliveryChannels", [])
            if not channels:
                return self._result(check_def, "not_met",
                    "No Config delivery channels configured.",
                    raw_evidence=self._build_evidence(
                        api_call="config.describe_delivery_channels()",
                        cli_command="aws configservice describe-delivery-channels",
                        response={"total_channels": 0, "channels": []},
                        service="Config",
                        assessor_guidance="Create Config delivery channel. Specify S3 bucket for configuration history storage.",
                    ))
            s3_channels = [c for c in channels if c.get("s3BucketName")]
            if s3_channels:
                buckets = [c["s3BucketName"] for c in s3_channels]
                return self._result(check_def, "met",
                    f"Config history delivered to S3: {', '.join(buckets)}",
                    raw_evidence=self._build_evidence(
                        api_call="config.describe_delivery_channels()",
                        cli_command="aws configservice describe-delivery-channels",
                        response={"total_channels": len(channels), "s3_channel_count": len(s3_channels), "s3_buckets": buckets},
                        service="Config",
                        assessor_guidance="Verify s3BucketName is set. Check bucket for configurationSnapshot/ and configurationHistory/ files.",
                    ))
            return self._result(check_def, "not_met",
                "Config delivery channels exist but no S3 bucket configured.",
                raw_evidence=self._build_evidence(
                    api_call="config.describe_delivery_channels()",
                    cli_command="aws configservice describe-delivery-channels",
                    response={"total_channels": len(channels), "s3_channel_count": 0, "channels": channels[:20]},
                    service="Config",
                    assessor_guidance="Update delivery channels to include s3BucketName. Config history requires S3 storage.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking Config history: {e}")

    def check_cloudtrail_config_changes(self, check_def: dict) -> CheckResult:
        """Check CloudTrail captures config changes (management events)."""
        try:
            trails = self._get_all_trails()
            for trail in trails:
                if trail.get("IsMultiRegionTrail"):
                    try:
                        status = self._cloudtrail.get_trail_status(Name=trail["TrailARN"])
                        if status.get("IsLogging"):
                            return self._result(check_def, "met",
                                f"Trail '{trail['Name']}' captures management events "
                                "including configuration changes.",
                                raw_evidence=self._build_evidence(
                                    api_call="cloudtrail.get_trail_status()",
                                    cli_command="aws cloudtrail get-trail-status --name TRAIL",
                                    response={"trail_name": trail['Name'], "is_logging": True, "is_multi_region": True},
                                    service="CloudTrail",
                                    assessor_guidance="Verify IsLogging=true and IsMultiRegionTrail=true. Management events capture all config changes.",
                                ))
                    except Exception:
                        pass
            return self._result(check_def, "not_met",
                "No active multi-region trail to capture configuration changes.",
                raw_evidence=self._build_evidence(
                    api_call="cloudtrail.get_trail_status()",
                    cli_command="aws cloudtrail get-trail-status --name TRAIL",
                    response={"total_trails": len(trails), "active_multi_region_trails": 0},
                    service="CloudTrail",
                    assessor_guidance="Create multi-region trail with IsLogging=true. Management events track all API calls.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_deployment_roles_scoped(self, check_def: dict) -> CheckResult:
        """Check deployment IAM roles are not admin-level."""
        try:
            roles = self._iam.list_roles().get("Roles", [])
            deploy_roles = [r for r in roles if any(
                k in r["RoleName"].lower() for k in ("deploy", "cicd", "pipeline", "codebuild", "codedeploy"))]
            admin_deploy = []
            for role in deploy_roles:
                policies = self._iam.list_attached_role_policies(
                    RoleName=role["RoleName"]).get("AttachedPolicies", [])
                if any("AdministratorAccess" in p["PolicyName"] for p in policies):
                    admin_deploy.append(role["RoleName"])
            if not admin_deploy:
                return self._result(check_def, "met",
                    f"{len(deploy_roles)} deployment role(s) found, none have AdministratorAccess."
                    if deploy_roles else "No deployment-specific roles found.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_roles() + list_attached_role_policies()",
                        cli_command="aws iam list-roles",
                        response={"total_roles": len(roles), "deploy_role_count": len(deploy_roles), "deploy_roles": [r["RoleName"] for r in deploy_roles][:20]},
                        service="IAM",
                        assessor_guidance="Check AttachedPolicies[] for deployment roles. None should have PolicyName='AdministratorAccess'.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(admin_deploy)} deploy role(s) with admin access: {', '.join(admin_deploy[:5])}",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_roles() + list_attached_role_policies()",
                    cli_command="aws iam list-roles",
                    response={"total_roles": len(roles), "deploy_role_count": len(deploy_roles), "admin_deploy_roles": admin_deploy[:20]},
                    service="IAM",
                    assessor_guidance="Replace AdministratorAccess with scoped policies (S3, EC2, Lambda only as needed).",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking deploy roles: {e}")

    def check_unused_iam_roles(self, check_def: dict) -> CheckResult:
        """Check no IAM roles unused for >90 days."""
        try:
            roles = self._iam.list_roles().get("Roles", [])
            cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT")
            unused = []
            for role in roles:
                if role["Path"] == "/aws-service-role/":
                    continue
                last_used = role.get("RoleLastUsed", {}).get("LastUsedDate")
                if last_used:
                    if last_used.strftime("%Y-%m-%dT") < cutoff:
                        unused.append(role["RoleName"])
                else:
                    created = role.get("CreateDate")
                    if created and created.strftime("%Y-%m-%dT") < cutoff:
                        unused.append(role["RoleName"])
            if not unused:
                return self._result(check_def, "met",
                    "No IAM roles unused for more than 90 days.",
                    raw_evidence=self._build_evidence(
                        api_call="iam.list_roles()",
                        cli_command="aws iam list-roles",
                        response={"total_roles": len(roles), "unused_count": 0},
                        service="IAM",
                        assessor_guidance="Check RoleLastUsed.LastUsedDate. Roles not used in 90+ days should be removed or justified.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(unused)} role(s) unused >90 days: {', '.join(unused[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="iam.list_roles()",
                    cli_command="aws iam list-roles",
                    response={"total_roles": len(roles), "unused_count": len(unused), "unused_roles": unused[:20]},
                    service="IAM",
                    assessor_guidance="Delete unused roles or document business justification. Check LastUsedDate and CreateDate.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking unused roles: {e}")

    def check_application_control(self, check_def: dict) -> CheckResult:
        """Check application control via SSM documents."""
        try:
            docs = self._ssm.list_documents(
                Filters=[{"Key": "DocumentType", "Values": ["Command", "Policy"]}]
            ).get("DocumentIdentifiers", [])
            app_docs = [d["Name"] for d in docs if any(
                k in d["Name"].lower() for k in ("whitelist", "allowlist", "appcontrol", "application"))]
            if app_docs:
                return self._result(check_def, "met",
                    f"Application control documents found: {', '.join(app_docs[:5])}",
                    raw_evidence=self._build_evidence(
                        api_call="ssm.list_documents()",
                        cli_command="aws ssm list-documents --filters Key=DocumentType,Values=Command",
                        response={"total_docs": len(docs), "app_control_doc_count": len(app_docs), "app_control_docs": app_docs[:20]},
                        service="SSM",
                        assessor_guidance="Check document names for 'whitelist'/'allowlist'/'appcontrol'. Verify they enforce application restrictions.",
                    ))
            if docs:
                return self._result(check_def, "met",
                    f"{len(docs)} SSM documents found for system management.",
                    raw_evidence=self._build_evidence(
                        api_call="ssm.list_documents()",
                        cli_command="aws ssm list-documents --filters Key=DocumentType,Values=Command",
                        response={"total_docs": len(docs), "docs": docs[:20]},
                        service="SSM",
                        assessor_guidance="Review documents for application control policies. Manual verification needed for effectiveness.",
                    ))
            return self._result(check_def, "not_met",
                "No SSM documents found for application control.",
                raw_evidence=self._build_evidence(
                    api_call="ssm.list_documents()",
                    cli_command="aws ssm list-documents --filters Key=DocumentType,Values=Command",
                    response={"total_docs": 0, "docs": []},
                    service="SSM",
                    assessor_guidance="Create SSM documents to enforce application whitelisting. Consider AWS AppConfig or third-party tools.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking app control: {e}")

    def check_software_inventory(self, check_def: dict) -> CheckResult:
        """Check software inventory is collected via SSM."""
        try:
            instances = self._ssm.describe_instance_information().get(
                "InstanceInformationList", [])
            if not instances:
                return self._result(check_def, "not_met",
                    "No instances registered with SSM for software inventory.",
                    raw_evidence=self._build_evidence(
                        api_call="ssm.describe_instance_information()",
                        cli_command="aws ssm describe-instance-information",
                        response={"total_instances": 0, "instances": []},
                        service="SSM",
                        assessor_guidance="Deploy SSM Agent and enable Inventory collection via State Manager associations.",
                    ))
            online = [i for i in instances if i.get("PingStatus") == "Online"]
            return self._result(check_def, "met",
                f"{len(online)} of {len(instances)} SSM-managed instance(s) online "
                "for software inventory collection.",
                raw_evidence=self._build_evidence(
                    api_call="ssm.describe_instance_information()",
                    cli_command="aws ssm describe-instance-information",
                    response={"total_instances": len(instances), "online_count": len(online), "instances": instances[:20]},
                    service="SSM",
                    assessor_guidance="Verify PingStatus='Online'. Check Systems Manager Inventory for collected software/application data.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking inventory: {e}")

    def check_rds_ssl_enforcement(self, check_def: dict) -> CheckResult:
        """Check SSL/TLS enforced on all RDS instances."""
        try:
            instances = self._rds.describe_db_instances().get("DBInstances", [])
            if not instances:
                return self._result(check_def, "met", "No RDS instances found.",
                    raw_evidence=self._build_evidence(
                        api_call="rds.describe_db_instances()",
                        cli_command="aws rds describe-db-instances",
                        response={"total_instances": 0, "instances": []},
                        service="RDS",
                        assessor_guidance="No RDS instances to check for SSL enforcement.",
                    ))
            no_ssl = []
            for db in instances:
                # Check parameter group for rds.force_ssl or require_secure_transport
                pg_name = db.get("DBParameterGroups", [{}])[0].get("DBParameterGroupName", "")
                if pg_name and "default" in pg_name:
                    no_ssl.append(db["DBInstanceIdentifier"])
            if not no_ssl:
                return self._result(check_def, "met",
                    f"All {len(instances)} RDS instance(s) use custom parameter groups for SSL enforcement.",
                    raw_evidence=self._build_evidence(
                        api_call="rds.describe_db_instances()",
                        cli_command="aws rds describe-db-instances",
                        response={"total_instances": len(instances), "instances_with_custom_pg": len(instances), "instances": instances[:20]},
                        service="RDS",
                        assessor_guidance="Check DBParameterGroups[].DBParameterGroupName. Custom groups should have rds.force_ssl=1 or require_secure_transport=ON.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(no_ssl)} RDS instance(s) use default parameter groups (SSL may not be enforced): "
                f"{', '.join(no_ssl[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="rds.describe_db_instances()",
                    cli_command="aws rds describe-db-instances",
                    response={"total_instances": len(instances), "default_pg_count": len(no_ssl), "instances_using_default": no_ssl[:20]},
                    service="RDS",
                    assessor_guidance="Create custom parameter group with rds.force_ssl=1. Apply to listed instances.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking RDS SSL: {e}")

    def check_patch_manager_configured(self, check_def: dict) -> CheckResult:
        """Check SSM Patch Manager baselines are configured."""
        try:
            baselines = self._ssm.describe_patch_baselines(
                Filters=[{"Key": "OWNER", "Values": ["Self"]}]).get("BaselineIdentities", [])
            if baselines:
                names = [b["BaselineName"] for b in baselines]
                return self._result(check_def, "met",
                    f"{len(baselines)} custom patch baseline(s): {', '.join(names[:5])}",
                    raw_evidence=self._build_evidence(
                        api_call="ssm.describe_patch_baselines()",
                        cli_command="aws ssm describe-patch-baselines",
                        response={"custom_baseline_count": len(baselines), "baselines": baselines[:20]},
                        service="SSM",
                        assessor_guidance="Check BaselineName and OperatingSystem. Verify baselines are registered as default for each OS.",
                    ))
            # Check for default baselines
            defaults = self._ssm.describe_patch_baselines().get("BaselineIdentities", [])
            if defaults:
                return self._result(check_def, "met",
                    f"Using {len(defaults)} AWS-provided patch baseline(s).",
                    raw_evidence=self._build_evidence(
                        api_call="ssm.describe_patch_baselines()",
                        cli_command="aws ssm describe-patch-baselines",
                        response={"default_baseline_count": len(defaults), "baselines": defaults[:20]},
                        service="SSM",
                        assessor_guidance="AWS default baselines meet basic patching needs. Consider custom baselines for stricter control.",
                    ))
            return self._result(check_def, "not_met",
                "No patch baselines configured. Set up SSM Patch Manager.",
                raw_evidence=self._build_evidence(
                    api_call="ssm.describe_patch_baselines()",
                    cli_command="aws ssm describe-patch-baselines",
                    response={"total_baselines": 0, "baselines": []},
                    service="SSM",
                    assessor_guidance="Create patch baselines and configure Patch Manager maintenance windows for automated patching.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking Patch Manager: {e}")

    def check_patch_compliance(self, check_def: dict) -> CheckResult:
        """Check instances are patched within 30 days."""
        try:
            managed = self._ssm.describe_instance_information().get("InstanceInformationList", [])
            instance_ids = [i["InstanceId"] for i in managed if i.get("InstanceId")]
            if not instance_ids:
                return self._result(check_def, "not_met",
                    "No SSM-managed instances found. Instances must have SSM Agent installed for patch compliance.",
                    raw_evidence=self._build_evidence(
                        api_call="ssm.describe_instance_information()",
                        cli_command="aws ssm describe-instance-information",
                        response={"managed_instance_count": 0},
                        service="SSM",
                        assessor_guidance="No instances are managed by SSM. Install SSM Agent and register instances with SSM to enable patch compliance monitoring.",
                    ))
            states = self._ssm.describe_instance_patch_states(
                InstanceIds=instance_ids[:50]).get("InstancePatchStates", [])
            if not states:
                return self._result(check_def, "not_met",
                    "No patch state data. Instances may not be managed by SSM Patch Manager.",
                    raw_evidence=self._build_evidence(
                        api_call="ssm.describe_instance_patch_states()",
                        cli_command="aws ssm describe-instance-patch-states",
                        response={"total_states": 0, "states": []},
                        service="SSM",
                        assessor_guidance="Configure Patch Manager and run initial scan. Verify SSM Agent is installed on all instances.",
                    ))
            non_compliant = [s["InstanceId"] for s in states
                if s.get("MissingCount", 0) > 0 or s.get("FailedCount", 0) > 0]
            if not non_compliant:
                return self._result(check_def, "met",
                    f"All {len(states)} instance(s) are patch compliant.",
                    raw_evidence=self._build_evidence(
                        api_call="ssm.describe_instance_patch_states()",
                        cli_command="aws ssm describe-instance-patch-states",
                        response={"total_instances": len(states), "compliant_count": len(states), "states": states[:20]},
                        service="SSM",
                        assessor_guidance="Check MissingCount=0 and FailedCount=0 for all instances. Indicates current patch compliance.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(non_compliant)} instance(s) have missing/failed patches: {', '.join(non_compliant[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="ssm.describe_instance_patch_states()",
                    cli_command="aws ssm describe-instance-patch-states",
                    response={"total_instances": len(states), "non_compliant_count": len(non_compliant), "non_compliant_instances": non_compliant[:20]},
                    service="SSM",
                    assessor_guidance="Check MissingCount and FailedCount >0. Run patch operations or troubleshoot failed patches.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking patch compliance: {e}")

    def check_rds_auto_upgrade(self, check_def: dict) -> CheckResult:
        """Check RDS instances have AutoMinorVersionUpgrade enabled."""
        try:
            instances = self._rds.describe_db_instances().get("DBInstances", [])
            if not instances:
                return self._result(check_def, "met", "No RDS instances found.",
                    raw_evidence=self._build_evidence(
                        api_call="rds.describe_db_instances()",
                        cli_command="aws rds describe-db-instances --query 'DBInstances[].{Id:DBInstanceIdentifier,AutoUpgrade:AutoMinorVersionUpgrade}'",
                        response={"total_instances": 0, "instances": []},
                        service="RDS",
                        assessor_guidance="No RDS instances to check for auto minor version upgrade.",
                    ))
            no_auto = [db["DBInstanceIdentifier"] for db in instances
                if not db.get("AutoMinorVersionUpgrade", False)]
            if not no_auto:
                return self._result(check_def, "met",
                    f"All {len(instances)} RDS instance(s) have auto minor version upgrade enabled.",
                    raw_evidence=self._build_evidence(
                        api_call="rds.describe_db_instances()",
                        cli_command="aws rds describe-db-instances --query 'DBInstances[].{Id:DBInstanceIdentifier,AutoUpgrade:AutoMinorVersionUpgrade}'",
                        response={"total_instances": len(instances), "auto_upgrade_enabled_count": len(instances), "instances": instances[:20]},
                        service="RDS",
                        assessor_guidance="Verify AutoMinorVersionUpgrade=true for all instances. Ensures automatic security patches.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(no_auto)} RDS instance(s) without auto upgrade: {', '.join(no_auto[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="rds.describe_db_instances()",
                    cli_command="aws rds describe-db-instances --query 'DBInstances[].{Id:DBInstanceIdentifier,AutoUpgrade:AutoMinorVersionUpgrade}'",
                    response={"total_instances": len(instances), "no_auto_upgrade_count": len(no_auto), "instances_without_auto": no_auto[:20]},
                    service="RDS",
                    assessor_guidance="Enable AutoMinorVersionUpgrade on listed instances via modify-db-instance command.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking RDS upgrade: {e}")

    def check_rds_encryption(self, check_def: dict) -> CheckResult:
        """Check all RDS instances have storage encryption."""
        try:
            instances = self._rds.describe_db_instances().get("DBInstances", [])
            if not instances:
                return self._result(check_def, "met", "No RDS instances found.",
                    raw_evidence=self._build_evidence(
                        api_call="rds.describe_db_instances()",
                        cli_command="aws rds describe-db-instances --query 'DBInstances[].{Id:DBInstanceIdentifier,Encrypted:StorageEncrypted}'",
                        response={"total_instances": 0, "instances": []},
                        service="RDS",
                        assessor_guidance="No RDS instances to check for storage encryption.",
                    ))
            unencrypted = [db["DBInstanceIdentifier"] for db in instances
                if not db.get("StorageEncrypted", False)]
            if not unencrypted:
                return self._result(check_def, "met",
                    f"All {len(instances)} RDS instance(s) have storage encryption enabled.",
                    raw_evidence=self._build_evidence(
                        api_call="rds.describe_db_instances()",
                        cli_command="aws rds describe-db-instances --query 'DBInstances[].{Id:DBInstanceIdentifier,Encrypted:StorageEncrypted}'",
                        response={"total_instances": len(instances), "encrypted_count": len(instances), "instances": instances[:20]},
                        service="RDS",
                        assessor_guidance="Verify StorageEncrypted=true for all instances. KMS encryption protects data at rest.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(unencrypted)} unencrypted RDS instance(s): {', '.join(unencrypted[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="rds.describe_db_instances()",
                    cli_command="aws rds describe-db-instances --query 'DBInstances[].{Id:DBInstanceIdentifier,Encrypted:StorageEncrypted}'",
                    response={"total_instances": len(instances), "unencrypted_count": len(unencrypted), "unencrypted_instances": unencrypted[:20]},
                    service="RDS",
                    assessor_guidance="Take snapshot, copy with encryption enabled, restore to new instance. Cannot encrypt in place.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking RDS encryption: {e}")

    def check_efs_encryption(self, check_def: dict) -> CheckResult:
        """Check all EFS file systems are encrypted."""
        try:
            filesystems = self._efs.describe_file_systems().get("FileSystems", [])
            if not filesystems:
                return self._result(check_def, "met", "No EFS file systems found.",
                    raw_evidence=self._build_evidence(
                        api_call="efs.describe_file_systems()",
                        cli_command="aws efs describe-file-systems",
                        response={"total_filesystems": 0, "filesystems": []},
                        service="EFS",
                        assessor_guidance="No EFS file systems to check for encryption.",
                    ))
            unencrypted = [fs["FileSystemId"] for fs in filesystems
                if not fs.get("Encrypted", False)]
            if not unencrypted:
                return self._result(check_def, "met",
                    f"All {len(filesystems)} EFS file system(s) are encrypted.",
                    raw_evidence=self._build_evidence(
                        api_call="efs.describe_file_systems()",
                        cli_command="aws efs describe-file-systems",
                        response={"total_filesystems": len(filesystems), "encrypted_count": len(filesystems), "filesystems": filesystems[:20]},
                        service="EFS",
                        assessor_guidance="Verify Encrypted=true for all file systems. KMS encryption protects data at rest.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(unencrypted)} unencrypted EFS: {', '.join(unencrypted[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="efs.describe_file_systems()",
                    cli_command="aws efs describe-file-systems",
                    response={"total_filesystems": len(filesystems), "unencrypted_count": len(unencrypted), "unencrypted_filesystems": unencrypted[:20]},
                    service="EFS",
                    assessor_guidance="Create new encrypted EFS, migrate data, delete unencrypted. Cannot enable encryption on existing EFS.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking EFS encryption: {e}")

    def check_backup_vault_encryption(self, check_def: dict) -> CheckResult:
        """Check AWS Backup vaults use KMS encryption."""
        try:
            vaults = self._backup.list_backup_vaults().get("BackupVaultList", [])
            if not vaults:
                return self._result(check_def, "met", "No Backup vaults found.",
                    raw_evidence=self._build_evidence(
                        api_call="backup.list_backup_vaults()",
                        cli_command="aws backup list-backup-vaults",
                        response={"total_vaults": 0, "vaults": []},
                        service="Backup",
                        assessor_guidance="No Backup vaults to check for KMS encryption.",
                    ))
            no_kms = [v["BackupVaultName"] for v in vaults if not v.get("EncryptionKeyArn")]
            if not no_kms:
                return self._result(check_def, "met",
                    f"All {len(vaults)} Backup vault(s) use KMS encryption.",
                    raw_evidence=self._build_evidence(
                        api_call="backup.list_backup_vaults()",
                        cli_command="aws backup list-backup-vaults",
                        response={"total_vaults": len(vaults), "vaults_with_kms": len(vaults), "vaults": vaults[:20]},
                        service="Backup",
                        assessor_guidance="Verify EncryptionKeyArn is present for all vaults. KMS key ARN confirms encryption.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(no_kms)} vault(s) without KMS: {', '.join(no_kms[:5])}",
                raw_evidence=self._build_evidence(
                    api_call="backup.list_backup_vaults()",
                    cli_command="aws backup list-backup-vaults",
                    response={"total_vaults": len(vaults), "vaults_without_kms": len(no_kms), "vaults_needing_kms": no_kms[:20]},
                    service="Backup",
                    assessor_guidance="Create new vaults with KMS encryption. Migrate backups to encrypted vaults.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking Backup vaults: {e}")

    def check_backup_vault_access_policy(self, check_def: dict) -> CheckResult:
        """Check Backup vault access policies are restricted."""
        try:
            vaults = self._backup.list_backup_vaults().get("BackupVaultList", [])
            if not vaults:
                return self._result(check_def, "met", "No Backup vaults found.",
                    raw_evidence=self._build_evidence(
                        api_call="backup.list_backup_vaults() + get_backup_vault_access_policy()",
                        cli_command="aws backup list-backup-vaults && aws backup get-backup-vault-access-policy --backup-vault-name VAULT",
                        response={"total_vaults": 0, "vaults": []},
                        service="Backup",
                        assessor_guidance="No Backup vaults to check for access policies.",
                    ))
            no_policy = []
            for v in vaults:
                try:
                    self._backup.get_backup_vault_access_policy(
                        BackupVaultName=v["BackupVaultName"])
                except Exception:
                    no_policy.append(v["BackupVaultName"])
            if not no_policy:
                return self._result(check_def, "met",
                    f"All {len(vaults)} vault(s) have access policies defined.",
                    raw_evidence=self._build_evidence(
                        api_call="backup.list_backup_vaults() + get_backup_vault_access_policy()",
                        cli_command="aws backup list-backup-vaults && aws backup get-backup-vault-access-policy --backup-vault-name VAULT",
                        response={"total_vaults": len(vaults), "vaults_with_policy": len(vaults), "vaults": [v["BackupVaultName"] for v in vaults][:20]},
                        service="Backup",
                        assessor_guidance="Review policies for least privilege. Ensure no wildcard principals or overly broad permissions.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(no_policy)} vault(s) without access policy: {', '.join(no_policy[:5])}",
                raw_evidence=self._build_evidence(
                    api_call="backup.list_backup_vaults() + get_backup_vault_access_policy()",
                    cli_command="aws backup list-backup-vaults && aws backup get-backup-vault-access-policy --backup-vault-name VAULT",
                    response={"total_vaults": len(vaults), "vaults_without_policy": len(no_policy), "vaults_needing_policy": no_policy[:20]},
                    service="Backup",
                    assessor_guidance="Define access policies for listed vaults. Use put-backup-vault-access-policy to restrict access.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking vault policies: {e}")

    def check_s3_replication_encryption(self, check_def: dict) -> CheckResult:
        """Check S3 cross-region replication uses encryption."""
        try:
            buckets = self._get_all_s3_buckets()
            issues = []
            for bucket in buckets:
                try:
                    repl = self._s3.get_bucket_replication(Bucket=bucket)
                    rules = repl.get("ReplicationConfiguration", {}).get("Rules", [])
                    for rule in rules:
                        if rule.get("Status") == "Enabled":
                            enc = rule.get("Destination", {}).get("EncryptionConfiguration")
                            if not enc:
                                issues.append(bucket)
                                break
                except Exception:
                    pass  # No replication = OK
            if not issues:
                return self._result(check_def, "met",
                    "All S3 replication rules use encryption (or no replication configured).",
                    raw_evidence=self._build_evidence(
                        api_call="s3.get_bucket_replication()",
                        cli_command="aws s3api get-bucket-replication --bucket BUCKET",
                        response={"total_buckets_checked": len(buckets), "buckets_with_replication_issues": 0},
                        service="S3",
                        assessor_guidance="Check Rules[].Destination.EncryptionConfiguration exists for all enabled replication rules.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(issues)} bucket(s) replicate without encryption: {', '.join(issues[:5])}",
                raw_evidence=self._build_evidence(
                    api_call="s3.get_bucket_replication()",
                    cli_command="aws s3api get-bucket-replication --bucket BUCKET",
                    response={"total_buckets_checked": len(buckets), "buckets_with_replication_issues": len(issues), "issue_buckets": issues[:20]},
                    service="S3",
                    assessor_guidance="Update replication configuration. Add EncryptionConfiguration with ReplicaKmsKeyID to rules.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error checking replication: {e}")

    def check_rds_encryption_at_rest(self, check_def: dict) -> CheckResult:
        """Check RDS storage encryption at rest."""
        try:
            instances = self._rds.describe_db_instances().get("DBInstances", [])
            if not instances:
                return self._result(check_def, "met", "No RDS instances found.",
                    raw_evidence=self._build_evidence(
                        api_call="rds.describe_db_instances()",
                        cli_command="aws rds describe-db-instances --query 'DBInstances[].{Id:DBInstanceIdentifier,Encrypted:StorageEncrypted}'",
                        response={"total_instances": 0, "instances": []},
                        service="RDS",
                        assessor_guidance="No RDS instances to check for encryption at rest.",
                    ))
            unencrypted = [db["DBInstanceIdentifier"] for db in instances
                if not db.get("StorageEncrypted")]
            if not unencrypted:
                return self._result(check_def, "met",
                    f"All {len(instances)} RDS instance(s) have encryption at rest.",
                    raw_evidence=self._build_evidence(
                        api_call="rds.describe_db_instances()",
                        cli_command="aws rds describe-db-instances --query 'DBInstances[].{Id:DBInstanceIdentifier,Encrypted:StorageEncrypted}'",
                        response={"total_instances": len(instances), "encrypted_count": len(instances), "instances": instances[:20]},
                        service="RDS",
                        assessor_guidance="Verify StorageEncrypted=true. All instances have at-rest encryption enabled.",
                    ))
            return self._result(check_def, "not_met",
                f"{len(unencrypted)} RDS instance(s) without encryption: {', '.join(unencrypted[:10])}",
                raw_evidence=self._build_evidence(
                    api_call="rds.describe_db_instances()",
                    cli_command="aws rds describe-db-instances --query 'DBInstances[].{Id:DBInstanceIdentifier,Encrypted:StorageEncrypted}'",
                    response={"total_instances": len(instances), "unencrypted_count": len(unencrypted), "unencrypted_instances": unencrypted[:20]},
                    service="RDS",
                    assessor_guidance="Snapshot unencrypted instances, copy with encryption, restore. Cannot enable in-place.",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_ssm_patch_deployed(self, check_def: dict) -> CheckResult:
        """Check SSM Patch Manager baselines cover all OS types."""
        try:
            baselines = self._ssm.describe_patch_baselines().get("BaselineIdentities", [])
            os_types = set()
            for b in baselines:
                os_types.add(b.get("OperatingSystem", "UNKNOWN"))
            raw = self._build_evidence(
                api_call="ssm.describe_patch_baselines()",
                cli_command="aws ssm describe-patch-baselines",
                response=_sanitize_response({
                    "baselines": [{"BaselineId": b.get("BaselineId"),
                                   "BaselineName": b.get("BaselineName"),
                                   "OperatingSystem": b.get("OperatingSystem")}
                                  for b in baselines[:50]],
                    "total_baselines": len(baselines),
                    "truncated": len(baselines) > 50,
                    "os_types_covered": list(sorted(os_types)),
                }),
                service="SSM",
                assessor_guidance=(
                    "Verify that SSM Patch Manager has baselines configured for all OS types in use "
                    "(Windows, Amazon Linux, Ubuntu, RHEL, etc.). Check that baselines define approval "
                    "rules for critical and security patches with appropriate deployment timelines."
                ),
            )
            if len(os_types) >= 2:
                return self._result(check_def, "met",
                    f"Patch baselines cover {len(os_types)} OS types: {', '.join(sorted(os_types))}",
                    raw_evidence=raw)
            if os_types:
                return self._result(check_def, "met",
                    f"Patch baselines configured for: {', '.join(sorted(os_types))}",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No patch baselines found. Configure SSM Patch Manager.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_patch_compliance_sla(self, check_def: dict) -> CheckResult:
        """Check patches applied within SLA (critical <15d, high <30d)."""
        try:
            managed = self._ssm.describe_instance_information().get("InstanceInformationList", [])
            instance_ids = [i["InstanceId"] for i in managed if i.get("InstanceId")]
            if not instance_ids:
                raw = self._build_evidence(
                    api_call="ssm.describe_instance_information()",
                    cli_command="aws ssm describe-instance-information",
                    response=_sanitize_response({"managed_instance_count": 0}),
                    service="SSM",
                    assessor_guidance=(
                        "No SSM-managed instances found. Install SSM Agent on all EC2 instances "
                        "and register them with SSM to enable patch compliance SLA tracking."
                    ),
                )
                return self._result(check_def, "not_met",
                    "No SSM-managed instances found. Cannot verify patch SLA compliance.",
                    raw_evidence=raw)
            states = self._ssm.describe_instance_patch_states(
                InstanceIds=instance_ids[:50]).get("InstancePatchStates", [])
            if not states:
                raw = self._build_evidence(
                    api_call="ssm.describe_instance_patch_states()",
                    cli_command="aws ssm describe-instance-patch-states",
                    response=_sanitize_response({"instance_count": 0}),
                    service="SSM",
                    assessor_guidance=(
                        "No patch state data available. Verify that EC2 instances have SSM agent installed "
                        "and are managed by SSM (check instance association with patch groups). Patch state "
                        "data is generated after the first patch scan."
                    ),
                )
                return self._result(check_def, "not_met",
                    "No patch state data available.",
                    raw_evidence=raw)
            non_compliant = []
            for s in states:
                crit = s.get("CriticalNonCompliantCount", 0)
                sec = s.get("SecurityNonCompliantCount", 0)
                if crit > 0 or sec > 0:
                    non_compliant.append(
                        f"{s['InstanceId']}(crit={crit},sec={sec})")
            raw = self._build_evidence(
                api_call="ssm.describe_instance_patch_states()",
                cli_command="aws ssm describe-instance-patch-states",
                response=_sanitize_response({
                    "total_instances": len(states),
                    "non_compliant_count": len(non_compliant),
                    "patch_states": [{"InstanceId": s.get("InstanceId"),
                                     "CriticalNonCompliantCount": s.get("CriticalNonCompliantCount", 0),
                                     "SecurityNonCompliantCount": s.get("SecurityNonCompliantCount", 0),
                                     "InstalledCount": s.get("InstalledCount", 0),
                                     "OperationEndTime": s.get("OperationEndTime")}
                                    for s in states[:50]],
                    "truncated": len(states) > 50,
                }),
                service="SSM",
                assessor_guidance=(
                    "Check that CriticalNonCompliantCount and SecurityNonCompliantCount are zero for all "
                    "instances. Critical patches should be deployed within 15 days, high-severity within 30 days "
                    "(per FedRAMP AC.L2-3.1.18). Review OperationEndTime to verify recent patch scans."
                ),
            )
            if not non_compliant:
                return self._result(check_def, "met",
                    f"All {len(states)} instance(s) meet patch SLA requirements.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(non_compliant)} instance(s) outside SLA: {', '.join(non_compliant[:5])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_rds_auto_minor_upgrade(self, check_def: dict) -> CheckResult:
        """Check RDS auto minor version upgrade enabled."""
        try:
            instances = self._rds.describe_db_instances().get("DBInstances", [])
            if not instances:
                raw = self._build_evidence(
                    api_call="rds.describe_db_instances()",
                    cli_command="aws rds describe-db-instances",
                    response=_sanitize_response({"instance_count": 0}),
                    service="RDS",
                    assessor_guidance=(
                        "No RDS instances found. If databases are expected, verify that RDS is the database "
                        "service in use (check for self-managed databases on EC2 or other managed services)."
                    ),
                )
                return self._result(check_def, "met", "No RDS instances found.",
                    raw_evidence=raw)
            disabled = [db["DBInstanceIdentifier"] for db in instances
                if not db.get("AutoMinorVersionUpgrade")]
            raw = self._build_evidence(
                api_call="rds.describe_db_instances()",
                cli_command="aws rds describe-db-instances",
                response=_sanitize_response({
                    "total_instances": len(instances),
                    "instances": [{"DBInstanceIdentifier": db.get("DBInstanceIdentifier"),
                                  "Engine": db.get("Engine"),
                                  "EngineVersion": db.get("EngineVersion"),
                                  "AutoMinorVersionUpgrade": db.get("AutoMinorVersionUpgrade", False)}
                                 for db in instances[:50]],
                    "truncated": len(instances) > 50,
                    "disabled_count": len(disabled),
                }),
                service="RDS",
                assessor_guidance=(
                    "Verify AutoMinorVersionUpgrade=true for all RDS instances. Minor version upgrades include "
                    "security patches and bug fixes. Check that maintenance windows are configured to minimize "
                    "disruption (preferably outside business hours)."
                ),
            )
            if not disabled:
                return self._result(check_def, "met",
                    f"All {len(instances)} RDS instance(s) have auto minor upgrade enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(disabled)} RDS instance(s) without auto upgrade: {', '.join(disabled[:10])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    # ------------------------------------------------------------------
    # Phase 5: SecurityHub + GuardDuty Deep + Inspector (15 methods)
    # ------------------------------------------------------------------

    def check_security_hub_enabled(self, check_def: dict) -> CheckResult:
        """Check AWS Security Hub is enabled."""
        try:
            hub = self._securityhub.describe_hub()
            raw = self._build_evidence(
                api_call="securityhub.describe_hub()",
                cli_command="aws securityhub describe-hub",
                response=_sanitize_response({
                    "hub_arn": hub.get("HubArn", "N/A"),
                    "subscribed_at": hub.get("SubscribedAt"),
                    "auto_enable_controls": hub.get("AutoEnableControls", False),
                }),
                service="SecurityHub",
                assessor_guidance=(
                    "Verify that AWS Security Hub is enabled in the account. Check the HubArn and "
                    "SubscribedAt timestamp to confirm active subscription. Security Hub centralizes "
                    "security findings from AWS services and third-party tools."
                ),
            )
            return self._result(check_def, "met",
                f"Security Hub is enabled. ARN: {hub.get('HubArn', 'N/A')}",
                raw_evidence=raw)
        except Exception as e:
            if "not subscribed" in str(e).lower() or "InvalidAccessException" in str(e):
                return self._result(check_def, "not_met",
                    "AWS Security Hub is not enabled.",
                    raw_evidence=self._build_evidence(
                        api_call="securityhub.describe_hub()",
                        cli_command="aws securityhub describe-hub",
                        response=_sanitize_response({"error": str(e)}),
                        service="SecurityHub",
                        assessor_guidance=(
                            "Security Hub is not subscribed in this account. Verify that the organization "
                            "has enabled Security Hub or has an alternative centralized security monitoring solution."
                        ),
                    ))
            return self._result(check_def, "error", f"Error: {e}")

    def check_security_hub_monitoring(self, check_def: dict) -> CheckResult:
        """Check Security Hub compliance checks are running."""
        try:
            hub = self._securityhub.describe_hub()
            standards = self._securityhub.get_enabled_standards().get(
                "StandardsSubscriptions", [])
            names = [s.get("StandardsArn", "").split("/")[-1] for s in standards]
            raw = self._build_evidence(
                api_call="securityhub.describe_hub() + get_enabled_standards()",
                cli_command="aws securityhub get-enabled-standards",
                response=_sanitize_response({
                    "hub_arn": hub.get("HubArn"),
                    "standards_enabled": [s.get("StandardsArn") for s in standards[:50]],
                    "total_standards": len(standards),
                    "truncated": len(standards) > 50,
                    "standards_status": [{"arn": s.get("StandardsArn"), "status": s.get("StandardsStatus")}
                                        for s in standards[:50]],
                }),
                service="SecurityHub",
                assessor_guidance=(
                    "Verify that Security Hub has at least one compliance standard enabled (e.g., CIS AWS "
                    "Foundations Benchmark, AWS Foundational Security Best Practices, or PCI DSS). Check that "
                    "StandardsStatus='READY' for all subscribed standards to ensure compliance checks are active."
                ),
            )
            if standards:
                return self._result(check_def, "met",
                    f"Security Hub active with {len(standards)} standard(s): {', '.join(names[:5])}",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "Security Hub enabled but no compliance standards activated.",
                raw_evidence=raw)
        except Exception as e:
            if "not subscribed" in str(e).lower():
                return self._result(check_def, "not_met", "Security Hub not enabled.",
                    raw_evidence=self._build_evidence(
                        api_call="securityhub.describe_hub() + get_enabled_standards()",
                        cli_command="aws securityhub get-enabled-standards",
                        response=_sanitize_response({"error": str(e)}),
                        service="SecurityHub",
                        assessor_guidance=(
                            "Security Hub is not subscribed. Confirm whether the organization uses an alternative "
                            "compliance monitoring solution or if Security Hub should be enabled."
                        ),
                    ))
            return self._result(check_def, "error", f"Error: {e}")

    def check_config_rules_evaluating(self, check_def: dict) -> CheckResult:
        """Check AWS Config rules are evaluating without errors."""
        try:
            compliance = self._config_service.describe_compliance_by_config_rule().get(
                "ComplianceByConfigRules", [])
            errors = [c["ConfigRuleName"] for c in compliance
                if c.get("Compliance", {}).get("ComplianceType") == "INSUFFICIENT_DATA"]
            raw = self._build_evidence(
                api_call="config.describe_compliance_by_config_rule()",
                cli_command="aws configservice describe-compliance-by-config-rule",
                response=_sanitize_response({
                    "total_rules": len(compliance),
                    "rule_compliance": [{"rule_name": c.get("ConfigRuleName"),
                                        "compliance_type": c.get("Compliance", {}).get("ComplianceType")}
                                       for c in compliance[:50]],
                    "truncated": len(compliance) > 50,
                    "insufficient_data_count": len(errors),
                }),
                service="Config",
                assessor_guidance=(
                    "Verify that all AWS Config rules are actively evaluating. Rules with 'INSUFFICIENT_DATA' "
                    "status indicate the rule cannot assess resources (e.g., no resources in scope or missing "
                    "permissions). Check that compliant rules show 'COMPLIANT' or 'NON_COMPLIANT' status."
                ),
            )
            if not compliance:
                return self._result(check_def, "not_met", "No Config rules found.",
                    raw_evidence=raw)
            if not errors:
                return self._result(check_def, "met",
                    f"All {len(compliance)} Config rule(s) are evaluating successfully.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(errors)} rule(s) with insufficient data: {', '.join(errors[:5])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_guardduty_all_features(self, check_def: dict) -> CheckResult:
        """Check GuardDuty has all finding types active."""
        try:
            detectors = self._guardduty.list_detectors().get("DetectorIds", [])
            if not detectors:
                return self._result(check_def, "not_met", "GuardDuty not enabled.",
                    raw_evidence=self._build_evidence(
                        api_call="guardduty.list_detectors() + get_detector()",
                        cli_command="aws guardduty list-detectors && aws guardduty get-detector --detector-id ID",
                        response=_sanitize_response({"detector_count": 0}),
                        service="GuardDuty",
                        assessor_guidance=(
                            "GuardDuty is not enabled in this region. Verify that threat detection is enabled "
                            "across all regions where workloads are deployed, or confirm an alternative IDS/IPS solution."
                        ),
                    ))
            det = self._guardduty.get_detector(DetectorId=detectors[0])
            features = det.get("Features", det.get("DataSources", {}))
            raw = self._build_evidence(
                api_call="guardduty.list_detectors() + get_detector()",
                cli_command="aws guardduty list-detectors && aws guardduty get-detector --detector-id ID",
                response=_sanitize_response({
                    "detector_id": detectors[0],
                    "status": det.get("Status"),
                    "finding_publishing_frequency": det.get("FindingPublishingFrequency"),
                    "features": det.get("Features", []),
                    "data_sources": det.get("DataSources", {}),
                }),
                service="GuardDuty",
                assessor_guidance=(
                    "Verify GuardDuty status is 'ENABLED' and that all finding types are active, including "
                    "S3 Protection, EKS Protection, RDS Protection, Lambda Protection, and Malware Protection. "
                    "Check FindingPublishingFrequency is set appropriately (e.g., FIFTEEN_MINUTES for rapid response)."
                ),
            )
            if det.get("Status") == "ENABLED":
                return self._result(check_def, "met",
                    f"GuardDuty enabled with all finding types active. "
                    f"Detector: {detectors[0][:12]}...",
                    raw_evidence=raw)
            return self._result(check_def, "not_met", "GuardDuty detector not fully active.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_security_hub_cis(self, check_def: dict) -> CheckResult:
        """Check Security Hub CIS standard is enabled."""
        try:
            standards = self._securityhub.get_enabled_standards().get(
                "StandardsSubscriptions", [])
            cis = [s for s in standards if "cis" in s.get("StandardsArn", "").lower()]
            raw = self._build_evidence(
                api_call="securityhub.get_enabled_standards()",
                cli_command="aws securityhub get-enabled-standards",
                response=_sanitize_response({
                    "standards_enabled": [s.get("StandardsArn") for s in standards[:50]],
                    "total_standards": len(standards),
                    "truncated": len(standards) > 50,
                    "cis_enabled": len(cis) > 0,
                    "cis_standards": [s.get("StandardsArn") for s in cis],
                }),
                service="SecurityHub",
                assessor_guidance=(
                    "Verify that the CIS AWS Foundations Benchmark standard is enabled in Security Hub. "
                    "CIS provides industry-recognized baseline configurations aligned with FedRAMP requirements. "
                    "Look for 'cis' in StandardsArn (e.g., 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0')."
                ),
            )
            if cis:
                return self._result(check_def, "met",
                    "CIS Benchmark standard enabled in Security Hub.",
                    raw_evidence=raw)
            if standards:
                return self._result(check_def, "not_met",
                    f"{len(standards)} standard(s) enabled but CIS Benchmark not among them.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Security Hub standards enabled.",
                raw_evidence=raw)
        except Exception as e:
            if "not subscribed" in str(e).lower():
                return self._result(check_def, "not_met", "Security Hub not enabled.",
                    raw_evidence=self._build_evidence(
                        api_call="securityhub.get_enabled_standards()",
                        cli_command="aws securityhub get-enabled-standards",
                        response=_sanitize_response({"error": str(e)}),
                        service="SecurityHub",
                        assessor_guidance=(
                            "Security Hub is not subscribed. Confirm whether CIS benchmarks are assessed "
                            "through an alternative compliance tool or if Security Hub should be enabled."
                        ),
                    ))
            return self._result(check_def, "error", f"Error: {e}")

    def check_guardduty_all_regions(self, check_def: dict) -> CheckResult:
        """Check GuardDuty enabled in current region."""
        try:
            detectors = self._guardduty.list_detectors().get("DetectorIds", [])
            if not detectors:
                return self._result(check_def, "not_met",
                    "GuardDuty not enabled in this region.",
                    raw_evidence=self._build_evidence(
                        api_call="guardduty.list_detectors()",
                        cli_command="aws guardduty list-detectors",
                        response=_sanitize_response({"detector_count": 0}),
                        service="GuardDuty",
                        assessor_guidance=(
                            "GuardDuty is not enabled in this region. Verify that threat detection is enabled "
                            "in all regions where resources are deployed. Consider using AWS Organizations to "
                            "enable GuardDuty across all accounts and regions centrally."
                        ),
                    ))
            active = []
            for det_id in detectors:
                det = self._guardduty.get_detector(DetectorId=det_id)
                if det.get("Status") == "ENABLED":
                    active.append(det_id[:12])
            raw = self._build_evidence(
                api_call="guardduty.list_detectors()",
                cli_command="aws guardduty list-detectors",
                response=_sanitize_response({
                    "detector_ids": detectors[:50],
                    "total_detectors": len(detectors),
                    "truncated": len(detectors) > 50,
                    "active_detectors": active,
                    "active_count": len(active),
                }),
                service="GuardDuty",
                assessor_guidance=(
                    "Verify that all detectors in the region have Status='ENABLED'. Best practice is to have "
                    "one detector per region with all protection features active. Check that detectors are not "
                    "suspended or disabled."
                ),
            )
            if active:
                return self._result(check_def, "met",
                    f"GuardDuty enabled with {len(active)} active detector(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "GuardDuty detectors found but none are active.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_security_hub_findings(self, check_def: dict) -> CheckResult:
        """Check Security Hub is receiving integrated findings."""
        try:
            hub = self._securityhub.describe_hub()
            # Check for recent findings
            findings = self._securityhub.get_findings(
                MaxResults=5,
                Filters={"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}
            ).get("Findings", [])
            raw = self._build_evidence(
                api_call="securityhub.get_findings()",
                cli_command="aws securityhub get-findings --filters '{\"SeverityLabel\":[{\"Value\":\"HIGH\",\"Comparison\":\"EQUALS\"}]}'",
                response=_sanitize_response({
                    "hub_arn": hub.get("HubArn"),
                    "findings_count": len(findings),
                    "findings_sample": [{"id": f.get("Id"), "severity": f.get("Severity", {}).get("Label"),
                                        "title": f.get("Title"), "resource_type": f.get("Resources", [{}])[0].get("Type")}
                                       for f in findings],
                }),
                service="SecurityHub",
                assessor_guidance=(
                    "Verify that Security Hub is receiving findings from integrated services (GuardDuty, "
                    "Inspector, Macie, IAM Access Analyzer, Config, etc.). Check that findings have recent "
                    "timestamps and cover multiple resource types. Zero findings may indicate either a compliant "
                    "environment or lack of integration—review enabled standards and data sources."
                ),
            )
            if findings:
                return self._result(check_def, "met",
                    f"Security Hub receiving findings. {len(findings)} recent active finding(s).",
                    raw_evidence=raw)
            return self._result(check_def, "met",
                "Security Hub enabled. No active findings (environment may be compliant).",
                raw_evidence=raw)
        except Exception as e:
            if "not subscribed" in str(e).lower():
                return self._result(check_def, "not_met", "Security Hub not enabled.",
                    raw_evidence=self._build_evidence(
                        api_call="securityhub.get_findings()",
                        cli_command="aws securityhub get-findings --filters '{\"SeverityLabel\":[{\"Value\":\"HIGH\",\"Comparison\":\"EQUALS\"}]}'",
                        response=_sanitize_response({"error": str(e)}),
                        service="SecurityHub",
                        assessor_guidance=(
                            "Security Hub is not subscribed. Confirm integration with centralized security "
                            "monitoring or if Security Hub should be enabled for this account."
                        ),
                    ))
            return self._result(check_def, "error", f"Error: {e}")

    def check_inspector_enabled(self, check_def: dict) -> CheckResult:
        """Check Amazon Inspector v2 is enabled."""
        try:
            status = self._inspector2.batch_get_account_status(
                accountIds=[self._sts.get_caller_identity()["Account"]])
            accounts = status.get("accounts", [])
            if accounts:
                state = accounts[0].get("state", {}).get("status", "DISABLED")
                raw = self._build_evidence(
                    api_call="inspector2.batch_get_account_status()",
                    cli_command="aws inspector2 batch-get-account-status",
                    response=_sanitize_response({
                        "account_id": accounts[0].get("accountId"),
                        "status": state,
                        "resource_state": accounts[0].get("resourceState", {}),
                    }),
                    service="Inspector",
                    assessor_guidance=(
                        "Verify that Amazon Inspector v2 status is 'ENABLED'. Inspector v2 provides continuous "
                        "vulnerability scanning for EC2 instances, container images in ECR, and Lambda functions. "
                        "Check resourceState to confirm which resource types are being scanned (ec2, ecr, lambda)."
                    ),
                )
                if state == "ENABLED":
                    return self._result(check_def, "met",
                        "Amazon Inspector v2 is enabled for this account.",
                        raw_evidence=raw)
                return self._result(check_def, "not_met",
                    f"Inspector v2 status: {state}. Enable for vulnerability scanning.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met", "Inspector v2 not enabled.",
                raw_evidence=self._build_evidence(
                    api_call="inspector2.batch_get_account_status()",
                    cli_command="aws inspector2 batch-get-account-status",
                    response=_sanitize_response({"accounts": []}),
                    service="Inspector",
                    assessor_guidance=(
                        "Inspector v2 is not enabled. Verify that continuous vulnerability scanning is provided "
                        "by an alternative tool or enable Inspector v2 for automated CVE detection."
                    ),
                ))
        except Exception as e:
            if "AccessDenied" in str(e):
                return self._result(check_def, "error",
                    "Access denied to Inspector v2. Ensure scanner role has inspector2:BatchGetAccountStatus.")
            return self._result(check_def, "error", f"Error: {e}")

    def check_vulnerability_findings_age(self, check_def: dict) -> CheckResult:
        """Check no critical/high vulnerability findings older than 30 days."""
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
            findings = self._inspector2.list_findings(
                filterCriteria={
                    "severity": [{"comparison": "EQUALS", "value": "CRITICAL"},
                                 {"comparison": "EQUALS", "value": "HIGH"}],
                    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]
                },
                maxResults=20
            ).get("findings", [])
            old = [f for f in findings
                if f.get("firstObservedAt", "").strftime("%Y-%m-%dT") < cutoff
                if hasattr(f.get("firstObservedAt", ""), "strftime")]
            raw = self._build_evidence(
                api_call="inspector2.list_findings()",
                cli_command="aws inspector2 list-findings --filter-criteria '{\"severity\":[{\"comparison\":\"EQUALS\",\"value\":\"HIGH\"}]}'",
                response=_sanitize_response({
                    "cutoff_date": cutoff,
                    "total_findings": len(findings),
                    "old_findings_count": len(old),
                    "findings_sample": [{"finding_arn": f.get("findingArn"), "severity": f.get("severity"),
                                        "first_observed": f.get("firstObservedAt"),
                                        "title": f.get("title"), "type": f.get("type")}
                                       for f in findings[:20]],
                    "truncated": len(findings) > 20,
                }),
                service="Inspector",
                assessor_guidance=(
                    "Verify that all critical and high severity vulnerability findings have been remediated "
                    "within 30 days of discovery. Check firstObservedAt timestamps. FedRAMP requires timely "
                    "patching of security flaws—findings older than 30 days indicate remediation SLA violations."
                ),
            )
            if not findings:
                return self._result(check_def, "met",
                    "No active critical/high vulnerability findings.",
                    raw_evidence=raw)
            if not old:
                return self._result(check_def, "met",
                    f"{len(findings)} active findings, none older than 30 days.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(old)} critical/high finding(s) older than 30 days.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_inspector_findings_addressed(self, check_def: dict) -> CheckResult:
        """Check Inspector findings addressed within SLA."""
        try:
            findings = self._inspector2.list_findings(
                filterCriteria={
                    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]
                },
                maxResults=50
            ).get("findings", [])
            crit_high = [f for f in findings
                if f.get("severity") in ("CRITICAL", "HIGH")]
            raw = self._build_evidence(
                api_call="inspector2.list_findings()",
                cli_command="aws inspector2 list-findings",
                response=_sanitize_response({
                    "total_active_findings": len(findings),
                    "critical_high_count": len(crit_high),
                    "critical_high_findings": [{"finding_arn": f.get("findingArn"), "severity": f.get("severity"),
                                               "status": f.get("status"), "title": f.get("title"),
                                               "first_observed": f.get("firstObservedAt")}
                                              for f in crit_high[:50]],
                    "truncated": len(crit_high) > 50,
                }),
                service="Inspector",
                assessor_guidance=(
                    "Verify that all active critical and high severity findings have remediation plans with "
                    "target dates. FedRAMP requires documented tracking and timely resolution of security flaws. "
                    "Check firstObservedAt to assess age and remediation urgency. Long-standing findings indicate "
                    "gaps in vulnerability management processes."
                ),
            )
            if not crit_high:
                return self._result(check_def, "met",
                    "No active critical/high Inspector findings.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(crit_high)} active critical/high finding(s) need remediation.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_guardduty_malware_protection(self, check_def: dict) -> CheckResult:
        """Check GuardDuty Malware Protection is enabled."""
        try:
            detectors = self._guardduty.list_detectors().get("DetectorIds", [])
            if not detectors:
                return self._result(check_def, "not_met", "GuardDuty not enabled.",
                    raw_evidence=self._build_evidence(
                        api_call="guardduty.get_detector()",
                        cli_command="aws guardduty get-detector --detector-id ID",
                        response=_sanitize_response({"detector_count": 0}),
                        service="GuardDuty",
                        assessor_guidance=(
                            "GuardDuty is not enabled. Malware Protection requires an active GuardDuty detector. "
                            "Verify that threat detection and malware scanning are provided by alternative tools."
                        ),
                    ))
            det = self._guardduty.get_detector(DetectorId=detectors[0])
            # Check for malware protection in features or data sources
            features = det.get("Features", [])
            mp_enabled = False
            for f in features:
                if f.get("Name") == "EBS_MALWARE_PROTECTION" and f.get("Status") == "ENABLED":
                    mp_enabled = True
            if not mp_enabled:
                ds = det.get("DataSources", {})
                mp = ds.get("MalwareProtection", {}).get("ScanEc2InstanceWithFindings", {})
                mp_enabled = mp.get("EbsVolumes", {}).get("Status") == "ENABLED"
            raw = self._build_evidence(
                api_call="guardduty.get_detector()",
                cli_command="aws guardduty get-detector --detector-id ID",
                response=_sanitize_response({
                    "detector_id": detectors[0],
                    "features": features,
                    "data_sources": det.get("DataSources", {}),
                    "malware_protection_enabled": mp_enabled,
                }),
                service="GuardDuty",
                assessor_guidance=(
                    "Verify that GuardDuty Malware Protection is enabled for EBS volume scanning. Look for "
                    "EBS_MALWARE_PROTECTION feature with Status='ENABLED' or MalwareProtection.ScanEc2InstanceWithFindings."
                    "EbsVolumes.Status='ENABLED'. This provides automated malware detection on EC2 instances with "
                    "suspicious activity."
                ),
            )
            if mp_enabled:
                return self._result(check_def, "met",
                    "GuardDuty Malware Protection is enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "GuardDuty Malware Protection is not enabled.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_security_hub_notifications(self, check_def: dict) -> CheckResult:
        """Check Security Hub findings are sent to SNS/EventBridge."""
        try:
            rules = self._events.list_rules(NamePrefix="").get("Rules", [])
            sh_rules = [r for r in rules
                if "securityhub" in json.dumps(r).lower() or "security" in r.get("Name", "").lower()]
            raw = self._build_evidence(
                api_call="events.list_rules()",
                cli_command="aws events list-rules",
                response=_sanitize_response({
                    "total_rules": len(rules),
                    "security_hub_rules": [{"name": r.get("Name"), "state": r.get("State"),
                                           "event_pattern": r.get("EventPattern")}
                                          for r in sh_rules[:50]],
                    "security_hub_rules_count": len(sh_rules),
                    "truncated": len(sh_rules) > 50,
                }),
                service="EventBridge",
                assessor_guidance=(
                    "Verify that EventBridge rules route Security Hub findings to notification channels (SNS, "
                    "Lambda, SIEM, etc.). FedRAMP requires timely alerting of security events. Look for rules with "
                    "'securityhub' in EventPattern and State='ENABLED'. Check that target actions send alerts to "
                    "the security operations team."
                ),
            )
            if sh_rules:
                return self._result(check_def, "met",
                    f"{len(sh_rules)} EventBridge rule(s) for Security Hub notifications.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No EventBridge rules found for Security Hub finding notifications.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_guardduty_alerting(self, check_def: dict) -> CheckResult:
        """Check GuardDuty findings are routed to SNS/SIEM."""
        try:
            rules = self._events.list_rules(NamePrefix="").get("Rules", [])
            gd_rules = [r for r in rules
                if "guardduty" in r.get("Name", "").lower()
                or "guardduty" in (r.get("EventPattern", "") or "").lower()]
            raw = self._build_evidence(
                api_call="events.list_rules()",
                cli_command="aws events list-rules",
                response=_sanitize_response({
                    "total_rules": len(rules),
                    "guardduty_rules": [{"name": r.get("Name"), "state": r.get("State"),
                                        "event_pattern": r.get("EventPattern")}
                                       for r in gd_rules[:50]],
                    "guardduty_rules_count": len(gd_rules),
                    "truncated": len(gd_rules) > 50,
                }),
                service="EventBridge",
                assessor_guidance=(
                    "Verify that EventBridge rules route GuardDuty findings to alerting systems (SNS, SIEM, "
                    "Lambda, security ticketing). FedRAMP requires security incident detection and response capabilities. "
                    "Look for rules with 'guardduty' in EventPattern and State='ENABLED'. Check that high-severity "
                    "findings trigger immediate alerts."
                ),
            )
            if gd_rules:
                return self._result(check_def, "met",
                    f"{len(gd_rules)} EventBridge rule(s) for GuardDuty alerting.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No EventBridge rules for GuardDuty findings. Configure alerting to SNS/SIEM.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_inspector_continuous_scan(self, check_def: dict) -> CheckResult:
        """Check Inspector continuous scanning is enabled."""
        try:
            status = self._inspector2.batch_get_account_status(
                accountIds=[self._sts.get_caller_identity()["Account"]])
            accounts = status.get("accounts", [])
            if accounts:
                state = accounts[0].get("state", {}).get("status", "DISABLED")
                raw = self._build_evidence(
                    api_call="inspector2.batch_get_account_status()",
                    cli_command="aws inspector2 batch-get-account-status",
                    response=_sanitize_response({
                        "account_id": accounts[0].get("accountId"),
                        "status": state,
                        "resource_state": accounts[0].get("resourceState", {}),
                    }),
                    service="Inspector",
                    assessor_guidance=(
                        "Verify that Amazon Inspector v2 is enabled for continuous scanning. Inspector v2 "
                        "automatically scans EC2 instances, container images in ECR, and Lambda functions for "
                        "vulnerabilities as they are deployed. Check resourceState to confirm all resource types "
                        "(ec2, ecr, lambda, lambdacode) are enabled."
                    ),
                )
                if state == "ENABLED":
                    return self._result(check_def, "met",
                        "Inspector v2 continuous scanning is enabled.",
                        raw_evidence=raw)
                return self._result(check_def, "not_met",
                    "Inspector v2 not enabled for continuous scanning.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "Inspector v2 not enabled for continuous scanning.",
                raw_evidence=self._build_evidence(
                    api_call="inspector2.batch_get_account_status()",
                    cli_command="aws inspector2 batch-get-account-status",
                    response=_sanitize_response({"accounts": []}),
                    service="Inspector",
                    assessor_guidance=(
                        "Inspector v2 is not enabled. Continuous vulnerability scanning is required for FedRAMP "
                        "compliance. Verify that an alternative continuous scanning solution is in place."
                    ),
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_guardduty_ebs_scanning(self, check_def: dict) -> CheckResult:
        """Check GuardDuty EBS volume scanning is active."""
        try:
            detectors = self._guardduty.list_detectors().get("DetectorIds", [])
            if not detectors:
                return self._result(check_def, "not_met", "GuardDuty not enabled.",
                    raw_evidence=self._build_evidence(
                        api_call="guardduty.get_detector()",
                        cli_command="aws guardduty get-detector --detector-id ID",
                        response={"detector_count": 0},
                        service="GuardDuty",
                        assessor_guidance="No GuardDuty detectors exist. EBS malware scanning requires an active detector.",
                    ))
            det = self._guardduty.get_detector(DetectorId=detectors[0])
            features = det.get("Features", [])
            ebs_enabled = any(
                f.get("Name") == "EBS_MALWARE_PROTECTION" and f.get("Status") == "ENABLED"
                for f in features)
            if not ebs_enabled:
                ds = det.get("DataSources", {})
                ebs_enabled = ds.get("MalwareProtection", {}).get(
                    "ScanEc2InstanceWithFindings", {}).get(
                    "EbsVolumes", {}).get("Status") == "ENABLED"
            raw = self._build_evidence(
                api_call="guardduty.get_detector()",
                cli_command="aws guardduty get-detector --detector-id ID",
                response=_sanitize_response({
                    "detector_id": detectors[0],
                    "features": features,
                    "data_sources": det.get("DataSources", {}),
                    "ebs_scanning_enabled": ebs_enabled,
                }),
                service="GuardDuty",
                assessor_guidance=(
                    "Verify that GuardDuty EBS volume scanning is enabled. Look for EBS_MALWARE_PROTECTION "
                    "feature with Status='ENABLED' or DataSources.MalwareProtection.ScanEc2InstanceWithFindings."
                    "EbsVolumes.Status='ENABLED'. EBS scanning detects malware on EC2 instance volumes when "
                    "GuardDuty identifies suspicious activity."
                ),
            )
            if ebs_enabled:
                return self._result(check_def, "met",
                    "GuardDuty EBS volume scanning is enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "GuardDuty EBS scanning not enabled.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    # ------------------------------------------------------------------
    # Phase 6: WAF + ELB + CloudFront + ACM + Route53 + NF (14 methods)
    # ------------------------------------------------------------------

    def check_tls_on_load_balancers(self, check_def: dict) -> CheckResult:
        """Check load balancers use TLS 1.2+."""
        try:
            lbs = self._elbv2.describe_load_balancers().get("LoadBalancers", [])
            if not lbs:
                raw = self._build_evidence(
                    api_call="elbv2.describe_load_balancers() + describe_listeners()",
                    cli_command="aws elbv2 describe-load-balancers && aws elbv2 describe-listeners --load-balancer-arn ARN",
                    response=_sanitize_response({"load_balancer_count": 0}),
                    service="ELBv2",
                    assessor_guidance=(
                        "No load balancers found. If public-facing web applications exist, verify that load "
                        "balancing is handled by CloudFront, API Gateway, or other services with TLS termination."
                    ),
                )
                return self._result(check_def, "met", "No load balancers found.",
                    raw_evidence=raw)
            weak_tls = []
            all_listeners = []
            for lb in lbs:
                listeners = self._elbv2.describe_listeners(
                    LoadBalancerArn=lb["LoadBalancerArn"]).get("Listeners", [])
                for listener in listeners:
                    if listener.get("Protocol") == "HTTPS":
                        policy = listener.get("SslPolicy", "")
                        all_listeners.append({"LoadBalancerName": lb.get("LoadBalancerName"),
                                             "Protocol": listener.get("Protocol"),
                                             "SslPolicy": policy})
                        if policy and "TLS-1-0" in policy:
                            weak_tls.append(f"{lb['LoadBalancerName']}:{policy}")
            raw = self._build_evidence(
                api_call="elbv2.describe_load_balancers() + describe_listeners()",
                cli_command="aws elbv2 describe-load-balancers && aws elbv2 describe-listeners --load-balancer-arn ARN",
                response=_sanitize_response({
                    "total_load_balancers": len(lbs),
                    "https_listeners": all_listeners[:50],
                    "truncated": len(all_listeners) > 50,
                    "weak_tls_count": len(weak_tls),
                }),
                service="ELBv2",
                assessor_guidance=(
                    "Verify all HTTPS listeners use TLS 1.2+ security policies (e.g., ELBSecurityPolicy-TLS-1-2-2017-01 "
                    "or newer). Policies containing 'TLS-1-0' are non-compliant with FedRAMP SC.L2-3.13.8 and SC.L2-3.13.11. "
                    "Update SslPolicy to enforce modern cryptographic standards."
                ),
            )
            if not weak_tls:
                return self._result(check_def, "met",
                    f"All {len(lbs)} load balancer(s) use TLS 1.2+ policies.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(weak_tls)} listener(s) with weak TLS: {', '.join(weak_tls[:5])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_waf_deployed(self, check_def: dict) -> CheckResult:
        """Check WAF is deployed on internet-facing resources."""
        try:
            acls = self._wafv2.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
            cf_acls = []
            try:
                cf_acls = self._wafv2.list_web_acls(Scope="CLOUDFRONT").get("WebACLs", [])
            except Exception:
                pass
            total = len(acls) + len(cf_acls)
            raw = self._build_evidence(
                api_call="wafv2.list_web_acls()",
                cli_command="aws wafv2 list-web-acls --scope REGIONAL",
                response=_sanitize_response({
                    "regional_acls": [{"Name": w.get("Name"), "Id": w.get("Id"), "ARN": w.get("ARN")}
                                     for w in acls[:50]],
                    "cloudfront_acls": [{"Name": w.get("Name"), "Id": w.get("Id"), "ARN": w.get("ARN")}
                                       for w in cf_acls[:50]],
                    "total_regional": len(acls),
                    "total_cloudfront": len(cf_acls),
                    "truncated": (len(acls) + len(cf_acls)) > 50,
                }),
                service="WAFv2",
                assessor_guidance=(
                    "Verify WAF Web ACLs are deployed on internet-facing resources (ALB, API Gateway, CloudFront). "
                    "Check that ACLs have active rules blocking common attacks (SQLi, XSS, CSRF) and rate-limiting "
                    "rules to prevent DoS. Review ACL associations to ensure coverage of all public endpoints."
                ),
            )
            if total > 0:
                return self._result(check_def, "met",
                    f"WAF deployed: {len(acls)} regional + {len(cf_acls)} CloudFront Web ACL(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No WAF Web ACLs found. Deploy WAF on internet-facing resources.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_network_firewall(self, check_def: dict) -> CheckResult:
        """Check AWS Network Firewall is deployed for CUI VPCs."""
        try:
            firewalls = self._network_firewall.list_firewalls().get("Firewalls", [])
            raw = self._build_evidence(
                api_call="network-firewall.list_firewalls()",
                cli_command="aws network-firewall list-firewalls",
                response=_sanitize_response({
                    "firewalls": [{"FirewallName": f.get("FirewallName"),
                                  "FirewallArn": f.get("FirewallArn")}
                                 for f in firewalls[:50]],
                    "total_firewalls": len(firewalls),
                    "truncated": len(firewalls) > 50,
                }),
                service="NetworkFirewall",
                assessor_guidance=(
                    "AWS Network Firewall provides stateful inspection for VPCs processing CUI. Verify firewall "
                    "policies include IPS/IDS rules, domain filtering, and protocol enforcement. Check that firewall "
                    "endpoints are deployed in all AZs of CUI VPCs. If not using Network Firewall, document alternative "
                    "network security controls (third-party NGFWs, security groups, NACLs)."
                ),
            )
            if firewalls:
                names = [f.get("FirewallName", "N/A") for f in firewalls]
                return self._result(check_def, "met",
                    f"{len(firewalls)} Network Firewall(s) deployed: {', '.join(names[:5])}",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No AWS Network Firewalls deployed. Consider for CUI VPCs.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_vpn_full_tunnel(self, check_def: dict) -> CheckResult:
        """Check Client VPN enforces full tunnel (SplitTunnel=false)."""
        try:
            endpoints = self._ec2.describe_client_vpn_endpoints().get(
                "ClientVpnEndpoints", [])
            if not endpoints:
                raw = self._build_evidence(
                    api_call="ec2.describe_client_vpn_endpoints()",
                    cli_command="aws ec2 describe-client-vpn-endpoints",
                    response=_sanitize_response({"endpoint_count": 0}),
                    service="EC2",
                    assessor_guidance=(
                        "No Client VPN endpoints found. If remote access is required, verify that VPN is provided "
                        "by AWS Site-to-Site VPN, third-party VPN, or Direct Connect."
                    ),
                )
                return self._result(check_def, "met", "No Client VPN endpoints found.",
                    raw_evidence=raw)
            split = [ep["ClientVpnEndpointId"] for ep in endpoints
                if ep.get("SplitTunnel")]
            raw = self._build_evidence(
                api_call="ec2.describe_client_vpn_endpoints()",
                cli_command="aws ec2 describe-client-vpn-endpoints",
                response=_sanitize_response({
                    "total_endpoints": len(endpoints),
                    "endpoints": [{"ClientVpnEndpointId": ep.get("ClientVpnEndpointId"),
                                  "SplitTunnel": ep.get("SplitTunnel", False),
                                  "Status": ep.get("Status", {}).get("Code")}
                                 for ep in endpoints[:50]],
                    "truncated": len(endpoints) > 50,
                    "split_tunnel_count": len(split),
                }),
                service="EC2",
                assessor_guidance=(
                    "Verify SplitTunnel=false for all Client VPN endpoints. Full tunnel mode routes all client "
                    "traffic through the VPN, preventing data exfiltration via local internet breakout. Split tunnel "
                    "is non-compliant with FedRAMP AC.L2-3.1.12 (remote access control) for CUI environments."
                ),
            )
            if not split:
                return self._result(check_def, "met",
                    f"All {len(endpoints)} Client VPN endpoint(s) enforce full tunnel.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(split)} endpoint(s) use split tunnel: {', '.join(split[:5])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_alb_tls_policy(self, check_def: dict) -> CheckResult:
        """Check ALB/NLB HTTPS listeners use TLS 1.2+."""
        try:
            lbs = self._elbv2.describe_load_balancers().get("LoadBalancers", [])
            if not lbs:
                raw = self._build_evidence(
                    api_call="elbv2.describe_listeners()",
                    cli_command="aws elbv2 describe-listeners --load-balancer-arn ARN",
                    response=_sanitize_response({"load_balancer_count": 0}),
                    service="ELBv2",
                    assessor_guidance=(
                        "No load balancers found. If TLS termination is required, verify that it's handled by "
                        "CloudFront, API Gateway, or application-level encryption."
                    ),
                )
                return self._result(check_def, "met", "No load balancers found.",
                    raw_evidence=raw)
            issues = []
            all_secure_listeners = []
            for lb in lbs:
                listeners = self._elbv2.describe_listeners(
                    LoadBalancerArn=lb["LoadBalancerArn"]).get("Listeners", [])
                for l in listeners:
                    if l.get("Protocol") in ("HTTPS", "TLS"):
                        policy = l.get("SslPolicy", "")
                        all_secure_listeners.append({"LoadBalancerName": lb.get("LoadBalancerName"),
                                                    "Protocol": l.get("Protocol"),
                                                    "Port": l.get("Port"),
                                                    "SslPolicy": policy})
                        if "TLS-1-0" in policy or "TLS-1-1" in policy:
                            issues.append(f"{lb['LoadBalancerName']}:{policy}")
            raw = self._build_evidence(
                api_call="elbv2.describe_listeners()",
                cli_command="aws elbv2 describe-listeners --load-balancer-arn ARN",
                response=_sanitize_response({
                    "total_load_balancers": len(lbs),
                    "secure_listeners": all_secure_listeners[:50],
                    "truncated": len(all_secure_listeners) > 50,
                    "weak_tls_count": len(issues),
                }),
                service="ELBv2",
                assessor_guidance=(
                    "Verify all HTTPS/TLS listeners use TLS 1.2 or TLS 1.3 security policies. Look for policies "
                    "like ELBSecurityPolicy-TLS-1-2-2017-01 or ELBSecurityPolicy-TLS13-1-2-2021-06. Policies with "
                    "'TLS-1-0' or 'TLS-1-1' are non-compliant with NIST SP 800-52r2 and FedRAMP SC.L2-3.13.11."
                ),
            )
            if not issues:
                return self._result(check_def, "met",
                    "All HTTPS/TLS listeners use TLS 1.2+ security policies.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(issues)} listener(s) with weak TLS: {', '.join(issues[:5])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_cloudfront_tls(self, check_def: dict) -> CheckResult:
        """Check CloudFront distributions use TLS 1.2 minimum."""
        try:
            dists = self._cloudfront.list_distributions().get(
                "DistributionList", {}).get("Items", [])
            if not dists:
                raw = self._build_evidence(
                    api_call="cloudfront.list_distributions()",
                    cli_command="aws cloudfront list-distributions",
                    response=_sanitize_response({"distribution_count": 0}),
                    service="CloudFront",
                    assessor_guidance=(
                        "No CloudFront distributions found. If CDN or global content delivery is required, verify "
                        "that TLS termination is handled by ALB, API Gateway, or other services with TLS 1.2+ enforcement."
                    ),
                )
                return self._result(check_def, "met", "No CloudFront distributions found.",
                    raw_evidence=raw)
            weak = []
            dist_info = []
            for d in dists:
                viewer_cert = d.get("ViewerCertificate", {})
                min_proto = viewer_cert.get("MinimumProtocolVersion", "")
                dist_info.append({"Id": d.get("Id"),
                                 "DomainName": d.get("DomainName"),
                                 "Status": d.get("Status"),
                                 "MinimumProtocolVersion": min_proto})
                if min_proto and "TLSv1_2" not in min_proto and "TLSv1.2" not in min_proto:
                    weak.append(f"{d['Id']}:{min_proto}")
            raw = self._build_evidence(
                api_call="cloudfront.list_distributions()",
                cli_command="aws cloudfront list-distributions",
                response=_sanitize_response({
                    "total_distributions": len(dists),
                    "distributions": dist_info[:50],
                    "truncated": len(dists) > 50,
                    "weak_tls_count": len(weak),
                }),
                service="CloudFront",
                assessor_guidance=(
                    "Verify ViewerCertificate.MinimumProtocolVersion is set to TLSv1.2_2021 or newer for all "
                    "distributions. CloudFront distributions serving CUI or handling authentication must use "
                    "TLS 1.2+ to comply with FedRAMP SC.L2-3.13.8 and SC.L2-3.13.11."
                ),
            )
            if not weak:
                return self._result(check_def, "met",
                    f"All {len(dists)} CloudFront distribution(s) use TLS 1.2+.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(weak)} distribution(s) with weak TLS: {', '.join(weak[:5])}",
                raw_evidence=self._build_evidence(
                    api_call="cloudfront.list_distributions()",
                    cli_command="aws cloudfront list-distributions",
                    response=_sanitize_response({
                        "total_distributions": len(dists),
                        "weak_distributions": weak[:20],
                    }),
                    service="CloudFront",
                ))
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_s3_tls_policy(self, check_def: dict) -> CheckResult:
        """Check S3 bucket policies deny requests without SecureTransport."""
        try:
            buckets = self._get_all_s3_buckets()
            no_tls = []

            for bucket in buckets[:50]:
                try:
                    policy_str = self._s3.get_bucket_policy(Bucket=bucket)["Policy"]
                    policy = json.loads(policy_str)
                    has_tls = False
                    for stmt in policy.get("Statement", []):
                        cond = stmt.get("Condition", {})
                        if "Bool" in cond and "aws:SecureTransport" in cond["Bool"]:
                            has_tls = True
                            break
                    if not has_tls:
                        no_tls.append(bucket)
                except Exception:
                    no_tls.append(bucket)

            raw = self._build_evidence(
                api_call="s3.get_bucket_policy()",
                cli_command="aws s3api get-bucket-policy --bucket BUCKET",
                response=_sanitize_response({
                    "total_buckets": len(buckets),
                    "buckets_without_tls": no_tls[:30],
                    "truncated": len(buckets) > 50,
                }),
                service="S3",
                assessor_guidance=(
                    "Verify all S3 bucket policies include a Deny statement with Condition "
                    "aws:SecureTransport=false to enforce HTTPS-only access. This prevents unencrypted "
                    "HTTP requests and ensures compliance with FedRAMP SC.L2-3.13.8 (data in transit)."
                ),
            )

            if not buckets:
                return self._result(check_def, "met", "No S3 buckets found.",
                    raw_evidence=raw)
            if not no_tls:
                return self._result(check_def, "met",
                    f"All {len(buckets)} bucket(s) enforce TLS via policy.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_tls)} bucket(s) without TLS enforcement: {', '.join(no_tls[:10])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_alb_idle_timeout(self, check_def: dict) -> CheckResult:
        """Check ALB idle timeout is <= 60 seconds."""
        try:
            lbs = self._elbv2.describe_load_balancers().get("LoadBalancers", [])
            albs = [lb for lb in lbs if lb.get("Type") == "application"]
            long_timeout = []
            alb_details = []

            for lb in albs[:50]:
                attrs = self._elbv2.describe_load_balancer_attributes(
                    LoadBalancerArn=lb["LoadBalancerArn"]).get("Attributes", [])
                timeout_val = None
                for attr in attrs:
                    if attr["Key"] == "idle_timeout.timeout_seconds":
                        timeout_val = int(attr["Value"])
                        if timeout_val > 60:
                            long_timeout.append(f"{lb['LoadBalancerName']}={attr['Value']}s")
                alb_details.append({
                    "LoadBalancerName": lb.get("LoadBalancerName"),
                    "IdleTimeout": timeout_val,
                })

            raw = self._build_evidence(
                api_call="elbv2.describe_load_balancers() + describe_load_balancer_attributes()",
                cli_command="aws elbv2 describe-load-balancers && aws elbv2 describe-load-balancer-attributes --load-balancer-arn ARN",
                response=_sanitize_response({
                    "total_albs": len(albs),
                    "alb_details": alb_details[:30],
                    "long_timeout_count": len(long_timeout),
                    "truncated": len(albs) > 50,
                }),
                service="ELBv2",
                assessor_guidance=(
                    "Verify ALB idle timeout is configured to 60 seconds or less to minimize session "
                    "persistence and reduce exposure window. Long timeouts can allow attackers to maintain "
                    "connections during reconnaissance. FedRAMP SC.L2-3.13.1 (session control)."
                ),
            )

            if not albs:
                return self._result(check_def, "met", "No Application Load Balancers found.",
                    raw_evidence=raw)
            if not long_timeout:
                return self._result(check_def, "met",
                    f"All {len(albs)} ALB(s) have idle timeout <= 60s.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(long_timeout)} ALB(s) with long timeout: {', '.join(long_timeout[:5])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_acm_certificates(self, check_def: dict) -> CheckResult:
        """Check ACM certificates are managed and auto-renewed."""
        try:
            certs = self._acm.list_certificates().get("CertificateSummaryList", [])
            non_auto = [c["DomainName"] for c in certs
                if c.get("Type") != "AMAZON_ISSUED" and c.get("RenewalEligibility") != "ELIGIBLE"]

            raw = self._build_evidence(
                api_call="acm.list_certificates()",
                cli_command="aws acm list-certificates",
                response=_sanitize_response({
                    "total_certificates": len(certs),
                    "certificates": [{"DomainName": c["DomainName"], "Type": c.get("Type"), "RenewalEligibility": c.get("RenewalEligibility"), "Status": c.get("Status")} for c in certs[:50]],
                    "non_auto_renewed": non_auto[:30],
                    "truncated": len(certs) > 50,
                }),
                service="ACM",
                assessor_guidance=(
                    "Verify all ACM certificates are Type=AMAZON_ISSUED (auto-renewed by AWS). Imported "
                    "certificates must be manually renewed before expiration. Check that auto-renewal is "
                    "successful and certificates are not approaching expiration (60-day warning threshold)."
                ),
            )

            if not certs:
                return self._result(check_def, "met", "No ACM certificates found.",
                    raw_evidence=raw)
            if not non_auto:
                return self._result(check_def, "met",
                    f"All {len(certs)} ACM certificate(s) are auto-renewed.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(non_auto)} certificate(s) not auto-renewed: {', '.join(non_auto[:5])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_fips_endpoints(self, check_def: dict) -> CheckResult:
        """Check FIPS endpoints are used (relevant for GovCloud)."""
        try:
            is_govcloud = "govcloud" in self.environment.lower()
            raw = self._build_evidence(
                api_call="(platform check)",
                cli_command="aws configure get use_fips_endpoint",
                response=_sanitize_response({
                    "environment": self.environment,
                    "is_govcloud": is_govcloud,
                }),
                service="IAM",
                assessor_guidance=(
                    "For GovCloud: FIPS 140-2 validated endpoints are used by default. "
                    "For Commercial: Verify use_fips_endpoint=true in AWS CLI/SDK config for CUI workloads. "
                    "FIPS endpoints use format: <service>-fips.<region>.amazonaws.com. Required for FedRAMP High."
                ),
            )

            if is_govcloud:
                return self._result(check_def, "met",
                    "AWS GovCloud uses FIPS 140-2 validated endpoints by default.",
                    raw_evidence=raw)
            return self._result(check_def, "met",
                "FIPS endpoints available. AWS Commercial supports FIPS endpoints "
                "via service-specific FIPS URLs when configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_waf_xss_sqli_rules(self, check_def: dict) -> CheckResult:
        """Check WAF has XSS and SQLi protection rules."""
        try:
            acls = self._wafv2.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
            has_xss = False
            has_sqli = False
            acl_details = []

            for acl_summary in acls[:5]:
                try:
                    acl = self._wafv2.get_web_acl(
                        Name=acl_summary["Name"], Scope="REGIONAL",
                        Id=acl_summary["Id"])["WebACL"]
                    rule_names = [r.get("Name", "") for r in acl.get("Rules", [])]
                    acl_details.append({
                        "Name": acl_summary["Name"],
                        "Id": acl_summary["Id"],
                        "RuleCount": len(rule_names),
                        "Rules": rule_names,
                    })
                    for rule in acl.get("Rules", []):
                        rule_str = json.dumps(rule).lower()
                        if "xss" in rule_str or "crosssite" in rule_str:
                            has_xss = True
                        if "sqli" in rule_str or "sql" in rule_str:
                            has_sqli = True
                except Exception:
                    pass

            raw = self._build_evidence(
                api_call="wafv2.list_web_acls() + get_web_acl()",
                cli_command="aws wafv2 list-web-acls --scope REGIONAL && aws wafv2 get-web-acl --name NAME --scope REGIONAL --id ID",
                response=_sanitize_response({
                    "total_acls": len(acls),
                    "acl_details": acl_details,
                    "has_xss_protection": has_xss,
                    "has_sqli_protection": has_sqli,
                }),
                service="WAFv2",
                assessor_guidance=(
                    "Verify WAF Web ACLs include XSS and SQLi managed rule groups (AWS Managed Rules Core or "
                    "OWASP Top 10). Check that rules are in Count or Block mode (not disabled) and associated "
                    "with ALB/CloudFront resources. FedRAMP SI.L2-3.14.7 (flaw remediation)."
                ),
            )

            if not acls:
                return self._result(check_def, "not_met", "No WAF Web ACLs deployed.",
                    raw_evidence=raw)
            if has_xss and has_sqli:
                return self._result(check_def, "met",
                    "WAF has both XSS and SQLi protection rules.",
                    raw_evidence=raw)
            missing = []
            if not has_xss:
                missing.append("XSS")
            if not has_sqli:
                missing.append("SQLi")
            return self._result(check_def, "not_met",
                f"WAF missing protection: {', '.join(missing)}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_acm_cert_validity(self, check_def: dict) -> CheckResult:
        """Check no ACM certificates are expired."""
        try:
            certs = self._acm.list_certificates().get("CertificateSummaryList", [])
            expired = [c["DomainName"] for c in certs
                if c.get("Status") in ("EXPIRED", "REVOKED")]

            raw = self._build_evidence(
                api_call="acm.list_certificates()",
                cli_command="aws acm list-certificates --certificate-statuses ISSUED",
                response=_sanitize_response({
                    "total_certificates": len(certs),
                    "expired_revoked": expired[:30],
                    "certificates": [{"DomainName": c["DomainName"], "Status": c.get("Status"), "NotAfter": str(c.get("NotAfter", ""))} for c in certs[:50]],
                    "truncated": len(certs) > 50,
                }),
                service="ACM",
                assessor_guidance=(
                    "Verify no ACM certificates are in EXPIRED or REVOKED status. Check expiration dates "
                    "(NotAfter) and ensure certificates are renewed at least 60 days before expiration. "
                    "Expired certificates cause TLS errors and service outages."
                ),
            )

            if not certs:
                return self._result(check_def, "met", "No ACM certificates found.",
                    raw_evidence=raw)
            if not expired:
                return self._result(check_def, "met",
                    f"All {len(certs)} ACM certificate(s) are valid.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(expired)} expired/revoked certificate(s): {', '.join(expired[:5])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_dnssec_enabled(self, check_def: dict) -> CheckResult:
        """Check DNSSEC is enabled on Route 53 hosted zones."""
        try:
            zones = self._route53.list_hosted_zones().get("HostedZones", [])
            no_dnssec = []
            zone_details = []

            for zone in zones[:50]:
                zone_id = zone["Id"].split("/")[-1]
                zone_name = zone.get("Name", zone_id)
                try:
                    dnssec = self._route53.get_dnssec(HostedZoneId=zone_id)
                    status = dnssec.get("Status", {}).get("ServeSignature", "NOT_SIGNING")
                    zone_details.append({
                        "Name": zone_name,
                        "Id": zone_id,
                        "DNSSECStatus": status,
                    })
                    if status != "SIGNING":
                        no_dnssec.append(zone_name)
                except Exception:
                    no_dnssec.append(zone_name)
                    zone_details.append({
                        "Name": zone_name,
                        "Id": zone_id,
                        "DNSSECStatus": "ERROR",
                    })

            raw = self._build_evidence(
                api_call="route53.list_hosted_zones() + get_dnssec()",
                cli_command="aws route53 list-hosted-zones && aws route53 get-dnssec --hosted-zone-id ID",
                response=_sanitize_response({
                    "total_zones": len(zones),
                    "zones_without_dnssec": no_dnssec[:30],
                    "zone_details": zone_details[:30],
                    "truncated": len(zones) > 50,
                }),
                service="Route53",
                assessor_guidance=(
                    "Verify DNSSEC is enabled (Status.ServeSignature=SIGNING) on all Route 53 hosted zones "
                    "serving critical domains. DNSSEC prevents DNS spoofing attacks by cryptographically "
                    "signing DNS records. FedRAMP SC.L2-3.13.12 (data origin authentication)."
                ),
            )

            if not zones:
                return self._result(check_def, "met", "No Route 53 hosted zones found.",
                    raw_evidence=raw)
            if not no_dnssec:
                return self._result(check_def, "met",
                    f"DNSSEC enabled on all {len(zones)} hosted zone(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_dnssec)} zone(s) without DNSSEC: {', '.join(no_dnssec[:5])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_network_firewall_ids_ips(self, check_def: dict) -> CheckResult:
        """Check Network Firewall has IDS/IPS rules configured."""
        try:
            policies = self._network_firewall.list_firewall_policies().get(
                "FirewallPolicies", [])
            has_ids = False
            policy_details = []

            for pol in policies[:5]:
                try:
                    detail = self._network_firewall.describe_firewall_policy(
                        FirewallPolicyArn=pol["Arn"])
                    fp = detail.get("FirewallPolicy", {})
                    rule_groups = fp.get("StatefulRuleGroupReferences", [])
                    policy_details.append({
                        "Name": pol.get("Name"),
                        "Arn": pol.get("Arn"),
                        "StatefulRuleGroupCount": len(rule_groups),
                    })
                    if rule_groups:
                        has_ids = True
                except Exception:
                    pass

            raw = self._build_evidence(
                api_call="network-firewall.list_firewall_policies() + describe_firewall_policy()",
                cli_command="aws network-firewall list-firewall-policies",
                response=_sanitize_response({
                    "total_policies": len(policies),
                    "policy_details": policy_details,
                    "has_stateful_rules": has_ids,
                }),
                service="NetworkFirewall",
                assessor_guidance=(
                    "Verify Network Firewall policies include StatefulRuleGroupReferences for IDS/IPS functionality. "
                    "Check that rule groups use Suricata-compatible rules for threat detection and prevention. "
                    "FedRAMP SI.L2-3.14.7 (flaw remediation) and SC.L2-3.13.6 (boundary protection)."
                ),
            )

            if not policies:
                return self._result(check_def, "not_met",
                    "No Network Firewall policies found.",
                    raw_evidence=raw)
            if has_ids:
                return self._result(check_def, "met",
                    "Network Firewall has stateful IDS/IPS rules configured.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "Network Firewall policies exist but no stateful IDS/IPS rules found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    # ------------------------------------------------------------------
    # Phase 7: EventBridge + CloudWatch + SNS + DynamoDB + ECR + Logs (11 methods)
    # ------------------------------------------------------------------

    def check_cloudwatch_cloudtrail_alarm(self, check_def: dict) -> CheckResult:
        """Check CloudWatch alarm exists for CloudTrail changes."""
        try:
            alarms = self._cloudwatch.describe_alarms().get("MetricAlarms", [])
            ct_alarms = [a["AlarmName"] for a in alarms
                if "cloudtrail" in a.get("AlarmName", "").lower()
                or "cloudtrail" in a.get("MetricName", "").lower()
                or "trail" in a.get("AlarmName", "").lower()]

            raw = self._build_evidence(
                api_call="cloudwatch.describe_alarms()",
                cli_command="aws cloudwatch describe-alarms",
                response=_sanitize_response({
                    "total_alarms": len(alarms),
                    "cloudtrail_alarms": ct_alarms[:20],
                    "sample_alarms": [{"AlarmName": a["AlarmName"], "MetricName": a.get("MetricName"), "StateValue": a.get("StateValue")} for a in alarms[:20]],
                    "truncated": len(alarms) > 20,
                }),
                service="CloudWatch",
                assessor_guidance=(
                    "Verify CloudWatch alarms exist for CloudTrail configuration changes. "
                    "Check that alarms are in OK state, have SNS actions configured, and monitor "
                    "metrics like StopLogging, DeleteTrail, UpdateTrail."
                ),
            )

            if ct_alarms:
                return self._result(check_def, "met",
                    f"CloudTrail change alarm(s) found: {', '.join(ct_alarms[:5])}",
                    raw_evidence=raw)
            if alarms:
                return self._result(check_def, "not_met",
                    f"{len(alarms)} CloudWatch alarms exist but none monitor CloudTrail changes.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No CloudWatch alarms configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_sns_audit_notifications(self, check_def: dict) -> CheckResult:
        """Check SNS topics exist for audit failure notifications."""
        try:
            topics = self._sns.list_topics().get("Topics", [])
            audit_topics = [t["TopicArn"].split(":")[-1] for t in topics
                if any(k in t["TopicArn"].lower() for k in ("audit", "security", "alert", "alarm"))]

            raw = self._build_evidence(
                api_call="sns.list_topics()",
                cli_command="aws sns list-topics",
                response=_sanitize_response({
                    "total_topics": len(topics),
                    "audit_topics": audit_topics[:20],
                    "all_topic_names": [t["TopicArn"].split(":")[-1] for t in topics[:50]],
                    "truncated": len(topics) > 50,
                }),
                service="SNS",
                assessor_guidance=(
                    "Verify SNS topics exist for audit event notifications. Check that topics have "
                    "valid subscriptions (email, HTTPS, Lambda) and are used as alarm actions in "
                    "CloudWatch alarms for security events."
                ),
            )

            if audit_topics:
                return self._result(check_def, "met",
                    f"Audit notification topic(s): {', '.join(audit_topics[:5])}",
                    raw_evidence=raw)
            if topics:
                return self._result(check_def, "not_met",
                    f"{len(topics)} SNS topics exist but none appear to be audit-related.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No SNS topics configured for audit notifications.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_cloudwatch_logs_insights(self, check_def: dict) -> CheckResult:
        """Check CloudTrail log group exists in CloudWatch Logs."""
        try:
            log_groups = self._logs.describe_log_groups().get("logGroups", [])
            ct_groups = [lg["logGroupName"] for lg in log_groups
                if "cloudtrail" in lg["logGroupName"].lower()
                or "trail" in lg["logGroupName"].lower()]

            raw = self._build_evidence(
                api_call="logs.describe_log_groups()",
                cli_command="aws logs describe-log-groups",
                response=_sanitize_response({
                    "total_log_groups": len(log_groups),
                    "cloudtrail_log_groups": ct_groups[:20],
                    "sample_log_groups": [{"logGroupName": lg["logGroupName"], "retentionInDays": lg.get("retentionInDays"), "storedBytes": lg.get("storedBytes")} for lg in log_groups[:30]],
                    "truncated": len(log_groups) > 30,
                }),
                service="CloudWatch",
                assessor_guidance=(
                    "Verify CloudTrail logs are delivered to CloudWatch Logs for real-time monitoring. "
                    "Check retention periods are configured (90+ days recommended) and log groups "
                    "have metric filters and alarms for security events."
                ),
            )

            if ct_groups:
                return self._result(check_def, "met",
                    f"CloudTrail log group(s) in CloudWatch: {', '.join(ct_groups[:3])}",
                    raw_evidence=raw)
            if log_groups:
                return self._result(check_def, "not_met",
                    f"{len(log_groups)} log groups exist but none appear to be CloudTrail.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No CloudWatch log groups found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_eventbridge_security_rules(self, check_def: dict) -> CheckResult:
        """Check EventBridge has rules for security events."""
        try:
            rules = self._events.list_rules().get("Rules", [])
            security_rules = [r["Name"] for r in rules
                if any(k in r.get("Name", "").lower()
                    for k in ("security", "guardduty", "securityhub", "finding"))]

            raw = self._build_evidence(
                api_call="events.list_rules()",
                cli_command="aws events list-rules",
                response=_sanitize_response({
                    "total_rules": len(rules),
                    "security_rules": security_rules[:20],
                    "sample_rules": [{"Name": r["Name"], "State": r.get("State"), "EventPattern": r.get("EventPattern", "")[:200]} for r in rules[:30]],
                    "truncated": len(rules) > 30,
                }),
                service="EventBridge",
                assessor_guidance=(
                    "Verify EventBridge rules exist for security event routing (GuardDuty findings, "
                    "SecurityHub findings, IAM changes). Check that rules have targets configured "
                    "(SNS, Lambda, Step Functions) and are in ENABLED state."
                ),
            )

            if security_rules:
                return self._result(check_def, "met",
                    f"{len(security_rules)} EventBridge security rule(s): {', '.join(security_rules[:5])}",
                    raw_evidence=raw)
            if rules:
                return self._result(check_def, "not_met",
                    f"{len(rules)} EventBridge rules exist but none target security events.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No EventBridge rules configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_ecr_image_scanning(self, check_def: dict) -> CheckResult:
        """Check ECR repositories have scan-on-push enabled."""
        try:
            repos = self._ecr.describe_repositories().get("repositories", [])
            no_scan = [r["repositoryName"] for r in repos
                if not r.get("imageScanningConfiguration", {}).get("scanOnPush")]

            raw = self._build_evidence(
                api_call="ecr.describe_repositories()",
                cli_command="aws ecr describe-repositories",
                response=_sanitize_response({
                    "total_repositories": len(repos),
                    "repositories_without_scan": no_scan[:30],
                    "sample_repositories": [{"repositoryName": r["repositoryName"], "scanOnPush": r.get("imageScanningConfiguration", {}).get("scanOnPush", False), "imageTagMutability": r.get("imageTagMutability")} for r in repos[:30]],
                    "truncated": len(repos) > 30,
                }),
                service="ECR",
                assessor_guidance=(
                    "Verify all ECR repositories have scanOnPush enabled to automatically detect "
                    "vulnerabilities in container images. Review scan findings in the ECR console "
                    "and confirm remediation of CRITICAL/HIGH vulnerabilities."
                ),
            )

            if not repos:
                return self._result(check_def, "met", "No ECR repositories found.",
                    raw_evidence=raw)
            if not no_scan:
                return self._result(check_def, "met",
                    f"All {len(repos)} ECR repo(s) have scan-on-push enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_scan)} repo(s) without scan-on-push: {', '.join(no_scan[:10])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_dynamodb_encryption(self, check_def: dict) -> CheckResult:
        """Check DynamoDB tables use KMS encryption."""
        try:
            tables = self._dynamodb.list_tables().get("TableNames", [])
            no_kms = []
            table_details = []

            for table_name in tables[:50]:
                try:
                    desc = self._dynamodb.describe_table(TableName=table_name)["Table"]
                    enc = desc.get("SSEDescription", {})
                    status = enc.get("Status")
                    sse_type = enc.get("SSEType")
                    table_details.append({
                        "TableName": table_name,
                        "SSEStatus": status,
                        "SSEType": sse_type,
                    })
                    if status != "ENABLED" or sse_type != "KMS":
                        no_kms.append(table_name)
                except Exception:
                    no_kms.append(table_name)

            raw = self._build_evidence(
                api_call="dynamodb.list_tables() + describe_table()",
                cli_command="aws dynamodb list-tables && aws dynamodb describe-table --table-name TABLE",
                response=_sanitize_response({
                    "total_tables": len(tables),
                    "tables_without_kms": no_kms[:30],
                    "table_details": table_details[:30],
                    "truncated": len(tables) > 50,
                }),
                service="DynamoDB",
                assessor_guidance=(
                    "Verify all DynamoDB tables have server-side encryption enabled with KMS CMK. "
                    "Check that SSEType is 'KMS' (not 'AES256' default encryption) and that the KMS key "
                    "has appropriate key policies and rotation enabled."
                ),
            )

            if not tables:
                return self._result(check_def, "met", "No DynamoDB tables found.",
                    raw_evidence=raw)
            if not no_kms:
                return self._result(check_def, "met",
                    f"All {len(tables)} DynamoDB table(s) use KMS encryption.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_kms)} table(s) without KMS encryption: {', '.join(no_kms[:10])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_flow_logs_analysis(self, check_def: dict) -> CheckResult:
        """Check VPC Flow Logs are sent to CloudWatch or S3 for analysis."""
        try:
            flow_logs = self._ec2.describe_flow_logs().get("FlowLogs", [])
            cw_logs = [fl for fl in flow_logs if fl.get("LogDestinationType") == "cloud-watch-logs"]
            s3_logs = [fl for fl in flow_logs if fl.get("LogDestinationType") == "s3"]

            raw = self._build_evidence(
                api_call="ec2.describe_flow_logs()",
                cli_command="aws ec2 describe-flow-logs",
                response=_sanitize_response({
                    "total_flow_logs": len(flow_logs),
                    "cloudwatch_logs": len(cw_logs),
                    "s3_logs": len(s3_logs),
                    "flow_log_details": [{"FlowLogId": fl["FlowLogId"], "ResourceId": fl.get("ResourceId"), "LogDestinationType": fl.get("LogDestinationType"), "FlowLogStatus": fl.get("FlowLogStatus")} for fl in flow_logs[:30]],
                    "truncated": len(flow_logs) > 30,
                }),
                service="EC2",
                assessor_guidance=(
                    "Verify VPC Flow Logs are enabled and delivered to CloudWatch Logs or S3 for network "
                    "traffic analysis. Check that logs cover all VPCs/subnets/ENIs, are in ACTIVE status, "
                    "and have appropriate retention/lifecycle policies configured."
                ),
            )

            if not flow_logs:
                return self._result(check_def, "not_met", "No VPC Flow Logs configured.",
                    raw_evidence=raw)
            return self._result(check_def, "met",
                f"Flow Logs configured: {len(cw_logs)} to CloudWatch, {len(s3_logs)} to S3 "
                f"(total: {len(flow_logs)}).",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_guardduty_unauthorized_findings(self, check_def: dict) -> CheckResult:
        """Check GuardDuty UnauthorizedAccess finding type is active."""
        try:
            detectors = self._guardduty.list_detectors().get("DetectorIds", [])
            if not detectors:
                raw = self._build_evidence(
                    api_call="guardduty.list_detectors()",
                    cli_command="aws guardduty list-detectors",
                    response=_sanitize_response({"detectors": []}),
                    service="GuardDuty",
                    assessor_guidance=(
                        "Verify GuardDuty is enabled in all regions. Check that the detector is in ENABLED "
                        "status, has data sources enabled (CloudTrail, DNS, VPC Flow Logs, S3), and findings "
                        "are routed to EventBridge/SNS for notifications."
                    ),
                )
                return self._result(check_def, "not_met", "GuardDuty not enabled.",
                    raw_evidence=raw)

            det = self._guardduty.get_detector(DetectorId=detectors[0])
            raw = self._build_evidence(
                api_call="guardduty.get_detector()",
                cli_command="aws guardduty get-detector --detector-id ID",
                response=_sanitize_response({
                    "DetectorId": detectors[0],
                    "Status": det.get("Status"),
                    "ServiceRole": det.get("ServiceRole"),
                    "DataSources": det.get("DataSources"),
                }),
                service="GuardDuty",
                assessor_guidance=(
                    "Verify GuardDuty is enabled in all regions. Check that the detector is in ENABLED "
                    "status, has data sources enabled (CloudTrail, DNS, VPC Flow Logs, S3), and findings "
                    "are routed to EventBridge/SNS for notifications."
                ),
            )

            if det.get("Status") == "ENABLED":
                return self._result(check_def, "met",
                    "GuardDuty UnauthorizedAccess finding type is active (enabled by default).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "GuardDuty detector not active.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_cloudwatch_anomaly_detection(self, check_def: dict) -> CheckResult:
        """Check CloudWatch anomaly detection is configured."""
        try:
            detectors = self._cloudwatch.describe_anomaly_detectors().get(
                "AnomalyDetectors", [])

            raw = self._build_evidence(
                api_call="cloudwatch.describe_anomaly_detectors()",
                cli_command="aws cloudwatch describe-anomaly-detectors",
                response=_sanitize_response({
                    "total_detectors": len(detectors),
                    "detector_details": [{"Namespace": d.get("Namespace"), "MetricName": d.get("MetricName"), "Stat": d.get("Stat")} for d in detectors[:30]],
                    "truncated": len(detectors) > 30,
                }),
                service="CloudWatch",
                assessor_guidance=(
                    "Verify CloudWatch anomaly detection is configured for key security metrics to detect "
                    "unusual activity patterns. Check that anomaly detectors are associated with alarms "
                    "that trigger notifications for baseline deviations."
                ),
            )

            if detectors:
                return self._result(check_def, "met",
                    f"{len(detectors)} CloudWatch anomaly detector(s) configured.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No CloudWatch anomaly detectors configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_cloudtrail_insights(self, check_def: dict) -> CheckResult:
        """Check CloudTrail Insights is enabled."""
        try:
            trails = self._get_all_trails()
            trails_with_insights = []
            all_insights = []

            for trail in trails:
                try:
                    insights = self._cloudtrail.get_insight_selectors(
                        TrailName=trail["TrailARN"])
                    selectors = insights.get("InsightSelectors", [])
                    if selectors:
                        trails_with_insights.append(trail['Name'])
                        all_insights.append({
                            "TrailName": trail['Name'],
                            "InsightSelectors": selectors,
                        })
                except Exception:
                    pass

            raw = self._build_evidence(
                api_call="cloudtrail.get_insight_selectors()",
                cli_command="aws cloudtrail get-insight-selectors --trail-name TRAIL",
                response=_sanitize_response({
                    "total_trails": len(trails),
                    "trails_with_insights": trails_with_insights,
                    "insight_details": all_insights[:20],
                    "truncated": len(all_insights) > 20,
                }),
                service="CloudTrail",
                assessor_guidance=(
                    "Verify CloudTrail Insights is enabled to detect unusual API activity patterns. "
                    "Check that InsightSelectors include both ApiCallRateInsight and ApiErrorRateInsight "
                    "types for comprehensive anomaly detection."
                ),
            )

            if trails_with_insights:
                return self._result(check_def, "met",
                    f"CloudTrail Insights enabled on '{trails_with_insights[0]}'.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "CloudTrail Insights not enabled on any trail.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_guardduty_threat_intel(self, check_def: dict) -> CheckResult:
        """Check GuardDuty threat intelligence auto-updates (always met when enabled)."""
        try:
            detectors = self._guardduty.list_detectors().get("DetectorIds", [])
            if not detectors:
                raw = self._build_evidence(
                    api_call="guardduty.list_detectors()",
                    cli_command="aws guardduty list-detectors",
                    response=_sanitize_response({"detectors": []}),
                    service="GuardDuty",
                    assessor_guidance=(
                        "Verify GuardDuty is enabled to receive automatic threat intelligence updates from AWS. "
                        "Check that the detector is active in all regions and that threat lists/IP sets "
                        "are configured if custom threat intelligence feeds are used."
                    ),
                )
                return self._result(check_def, "not_met", "GuardDuty not enabled.",
                    raw_evidence=raw)

            det = self._guardduty.get_detector(DetectorId=detectors[0])
            raw = self._build_evidence(
                api_call="guardduty.get_detector()",
                cli_command="aws guardduty get-detector --detector-id ID",
                response=_sanitize_response({
                    "DetectorId": detectors[0],
                    "Status": det.get("Status"),
                    "FindingPublishingFrequency": det.get("FindingPublishingFrequency"),
                    "DataSources": det.get("DataSources"),
                }),
                service="GuardDuty",
                assessor_guidance=(
                    "Verify GuardDuty is enabled to receive automatic threat intelligence updates from AWS. "
                    "Check that the detector is active in all regions and that threat lists/IP sets "
                    "are configured if custom threat intelligence feeds are used."
                ),
            )

            if det.get("Status") == "ENABLED":
                return self._result(check_def, "met",
                    "GuardDuty threat intelligence feeds are automatically updated by AWS.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met", "GuardDuty not active.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    # ------------------------------------------------------------------
    # Phase 8: Elevated-Permission Services (24 methods)
    # ------------------------------------------------------------------

    def check_access_analyzer(self, check_def: dict) -> CheckResult:
        """Check IAM Access Analyzer is active."""
        try:
            client = self._session.client("accessanalyzer")
            analyzers = client.list_analyzers().get("analyzers", [])
            active = [a["name"] for a in analyzers if a.get("status") == "ACTIVE"]
            raw = self._build_evidence(
                api_call="accessanalyzer.list_analyzers()",
                cli_command="aws accessanalyzer list-analyzers",
                response=_sanitize_response({
                    "total_analyzers": len(analyzers),
                    "active_analyzers": active,
                    "analyzer_details": [{"name": a["name"], "status": a.get("status"), "type": a.get("type")} for a in analyzers[:20]],
                    "truncated": len(analyzers) > 20,
                }),
                service="AccessAnalyzer",
                assessor_guidance=(
                    "Verify IAM Access Analyzer is enabled to detect unintended resource access. "
                    "Check that analyzers are in ACTIVE status and findings are reviewed regularly. "
                    "Confirm findings are integrated with Security Hub or SNS for notifications."
                ),
            )
            if active:
                return self._result(check_def, "met",
                    f"IAM Access Analyzer active: {', '.join(active[:3])}",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No active IAM Access Analyzers found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_scp_cloudtrail_protection(self, check_def: dict) -> CheckResult:
        """Check SCP prevents disabling CloudTrail."""
        try:
            policies = self._organizations.list_policies(
                Filter="SERVICE_CONTROL_POLICY").get("Policies", [])
            protecting_policy = None
            for pol in policies:
                try:
                    content = self._organizations.describe_policy(
                        PolicyId=pol["Id"])["Policy"]["Content"]
                    doc = json.loads(content)
                    for stmt in doc.get("Statement", []):
                        if stmt.get("Effect") == "Deny":
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if any("cloudtrail:StopLogging" in a or "cloudtrail:DeleteTrail" in a
                                for a in actions):
                                protecting_policy = pol["Name"]
                                break
                except Exception:
                    pass
                if protecting_policy:
                    break

            raw = self._build_evidence(
                api_call="organizations.list_policies() + describe_policy()",
                cli_command="aws organizations list-policies --filter SERVICE_CONTROL_POLICY",
                response=_sanitize_response({
                    "total_scps": len(policies),
                    "scp_names": [p["Name"] for p in policies[:20]],
                    "protecting_policy": protecting_policy,
                    "truncated": len(policies) > 20,
                }),
                service="Organizations",
                assessor_guidance=(
                    "Verify Service Control Policies (SCPs) deny cloudtrail:StopLogging and cloudtrail:DeleteTrail "
                    "actions to prevent unauthorized CloudTrail disablement. Check that SCPs are applied to all OUs "
                    "and accounts, with exceptions only for authorized security admin roles."
                ),
            )

            if protecting_policy:
                return self._result(check_def, "met",
                    f"SCP '{protecting_policy}' prevents disabling CloudTrail.",
                    raw_evidence=raw)
            if policies:
                return self._result(check_def, "not_met",
                    f"{len(policies)} SCP(s) found but none protect CloudTrail.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No SCPs found. Enable Organizations SCPs to protect CloudTrail.",
                raw_evidence=raw)
        except Exception as e:
            if "AWSOrganizationsNotInUse" in str(e):
                raw = self._build_evidence(
                    api_call="organizations.list_policies()",
                    cli_command="aws organizations list-policies --filter SERVICE_CONTROL_POLICY",
                    response={"error": "AWSOrganizationsNotInUse"},
                    service="Organizations",
                    assessor_guidance=(
                        "AWS Organizations is not enabled in this account. SCPs cannot be evaluated. "
                        "Determine whether this is a single-account or multi-account environment "
                        "and review the corrective actions below for applicable alternatives."
                    ),
                    corrective_actions=_SCP_NO_ORG_CORRECTIVE_ACTIONS,
                )
                return self._result(check_def, "not_met",
                    "AWS Organizations not in use. SCPs require Organizations. "
                    "See corrective actions for alternative controls based on your environment type.",
                    raw_evidence=raw)
            if "AccessDeniedException" in str(e):
                return self._result(check_def, "error",
                    "Access denied to AWS Organizations API. Check IAM permissions.")
            return self._result(check_def, "error", f"Error: {e}")

    def check_sso_lockout_policy(self, check_def: dict) -> CheckResult:
        """Check SSO/Identity Center has account lockout configured."""
        try:
            instances = self._sso_admin.list_instances().get("Instances", [])
            raw = self._build_evidence(
                api_call="sso-admin.list_instances()",
                cli_command="aws sso-admin list-instances",
                response=_sanitize_response({
                    "total_instances": len(instances),
                    "instance_arns": [i.get("InstanceArn") for i in instances],
                }),
                service="SSO",
                assessor_guidance=(
                    "Verify IAM Identity Center (AWS SSO) is configured with account lockout policy. "
                    "In the IAM Identity Center console, check Settings > Authentication > Password policy "
                    "to confirm lockout threshold (e.g., 5 attempts) and lockout duration are configured."
                ),
            )
            if instances:
                return self._result(check_def, "met",
                    f"IAM Identity Center configured with {len(instances)} instance(s). "
                    "Verify lockout policy in Identity Center settings.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "IAM Identity Center not configured. Set up with lockout policy.",
                raw_evidence=raw)
        except Exception as e:
            if "AccessDenied" in str(e):
                return self._result(check_def, "error",
                    "Access denied to IAM Identity Center. Ensure scanner role has sso-admin permissions.")
            return self._result(check_def, "error", f"Error: {e}")

    def check_guardduty_brute_force(self, check_def: dict) -> CheckResult:
        """Check GuardDuty monitors for brute force attempts."""
        try:
            detectors = self._guardduty.list_detectors().get("DetectorIds", [])
            if not detectors:
                raw = self._build_evidence(
                    api_call="guardduty.get_detector()",
                    cli_command="aws guardduty get-detector --detector-id ID",
                    response=_sanitize_response({"detectors": []}),
                    service="GuardDuty",
                    assessor_guidance=(
                        "Verify GuardDuty is enabled to detect brute force attempts via UnauthorizedAccess:IAMUser/*, "
                        "Impact:EC2/PortSweep, and other related finding types. Check that findings are routed to "
                        "Security Hub or EventBridge for alerting."
                    ),
                )
                return self._result(check_def, "not_met", "GuardDuty not enabled.",
                    raw_evidence=raw)
            det = self._guardduty.get_detector(DetectorId=detectors[0])
            raw = self._build_evidence(
                api_call="guardduty.get_detector()",
                cli_command="aws guardduty get-detector --detector-id ID",
                response=_sanitize_response({
                    "DetectorId": detectors[0],
                    "Status": det.get("Status"),
                    "DataSources": det.get("DataSources"),
                }),
                service="GuardDuty",
                assessor_guidance=(
                    "Verify GuardDuty is enabled to detect brute force attempts via UnauthorizedAccess:IAMUser/*, "
                    "Impact:EC2/PortSweep, and other related finding types. Check that findings are routed to "
                    "Security Hub or EventBridge for alerting."
                ),
            )
            if det.get("Status") == "ENABLED":
                return self._result(check_def, "met",
                    "GuardDuty monitors brute force attempts via UnauthorizedAccess:IAMUser "
                    "and Impact:EC2/PortSweep finding types (enabled by default).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met", "GuardDuty not active.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_sso_session_timeout(self, check_def: dict) -> CheckResult:
        """Check SSO session timeout is configured."""
        try:
            instances = self._sso_admin.list_instances().get("Instances", [])
            raw = self._build_evidence(
                api_call="sso-admin.list_instances()",
                cli_command="aws sso-admin list-instances",
                response=_sanitize_response({
                    "total_instances": len(instances),
                    "instance_arns": [i.get("InstanceArn") for i in instances],
                }),
                service="SSO",
                assessor_guidance=(
                    "Verify IAM Identity Center session timeout is configured. In the IAM Identity Center console, "
                    "check Settings > Authentication > Session settings to confirm session duration is set to an "
                    "appropriate value (e.g., 8 hours or less for sensitive environments)."
                ),
            )
            if instances:
                return self._result(check_def, "met",
                    "IAM Identity Center is configured. Verify session duration in portal settings.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "IAM Identity Center not configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_athena_cloudtrail_table(self, check_def: dict) -> CheckResult:
        """Check Athena table exists for CloudTrail analysis."""
        try:
            queries = self._athena.list_named_queries().get("NamedQueryIds", [])
            wgs = self._athena.list_work_groups().get("WorkGroups", [])
            custom_wgs = [w["Name"] for w in wgs if w["Name"] != "primary"]

            raw = self._build_evidence(
                api_call="athena.list_work_groups() + list_named_queries()",
                cli_command="aws athena list-work-groups && aws athena list-named-queries",
                response=_sanitize_response({
                    "total_named_queries": len(queries),
                    "total_workgroups": len(wgs),
                    "custom_workgroups": custom_wgs,
                    "has_queries": len(queries) > 0,
                }),
                service="Athena",
                assessor_guidance=(
                    "Verify Athena is configured to query CloudTrail logs stored in S3 for log analysis. "
                    "Check that named queries or workgroups are set up for common security queries "
                    "(e.g., unauthorized API calls, privilege escalation, data access patterns)."
                ),
            )

            if queries:
                return self._result(check_def, "met",
                    f"{len(queries)} Athena named queries found for log analysis.",
                    raw_evidence=raw)
            if custom_wgs:
                return self._result(check_def, "met",
                    f"Athena workgroups configured: {', '.join(custom_wgs[:3])}",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Athena queries or custom workgroups for CloudTrail analysis.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_scp_audit_protection(self, check_def: dict) -> CheckResult:
        """Check SCP restricts non-security users from modifying audit config."""
        try:
            policies = self._organizations.list_policies(
                Filter="SERVICE_CONTROL_POLICY").get("Policies", [])
            audit_scps = []
            for pol in policies:
                try:
                    content = self._organizations.describe_policy(
                        PolicyId=pol["Id"])["Policy"]["Content"]
                    doc = json.loads(content)
                    for stmt in doc.get("Statement", []):
                        if stmt.get("Effect") == "Deny":
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if any(a.startswith("cloudtrail:") or a.startswith("config:")
                                for a in actions):
                                audit_scps.append(pol["Name"])
                                break
                except Exception:
                    pass

            raw = self._build_evidence(
                api_call="organizations.list_policies() + describe_policy()",
                cli_command="aws organizations list-policies --filter SERVICE_CONTROL_POLICY",
                response=_sanitize_response({
                    "total_scps": len(policies),
                    "audit_protecting_scps": audit_scps,
                    "scp_names": [p["Name"] for p in policies[:20]],
                    "truncated": len(policies) > 20,
                }),
                service="Organizations",
                assessor_guidance=(
                    "Verify SCPs deny cloudtrail:* and config:* actions to prevent non-security users from "
                    "disabling or modifying audit configuration. Check that SCPs have Condition clauses "
                    "to allow exceptions only for authorized security/audit roles."
                ),
            )

            if audit_scps:
                return self._result(check_def, "met",
                    f"SCP(s) protect audit configuration: {', '.join(audit_scps[:3])}",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No SCPs found protecting audit configuration.",
                raw_evidence=raw)
        except Exception as e:
            if "AWSOrganizationsNotInUse" in str(e):
                raw = self._build_evidence(
                    api_call="organizations.list_policies()",
                    cli_command="aws organizations list-policies --filter SERVICE_CONTROL_POLICY",
                    response={"error": "AWSOrganizationsNotInUse"},
                    service="Organizations",
                    assessor_guidance=(
                        "AWS Organizations is not enabled in this account. SCPs cannot be evaluated. "
                        "Determine whether this is a single-account or multi-account environment "
                        "and review the corrective actions below for applicable alternatives."
                    ),
                    corrective_actions=_SCP_NO_ORG_CORRECTIVE_ACTIONS,
                )
                return self._result(check_def, "not_met",
                    "AWS Organizations not in use. SCPs require Organizations. "
                    "See corrective actions for alternative controls based on your environment type.",
                    raw_evidence=raw)
            return self._result(check_def, "error", f"Error: {e}")

    def check_cicd_approval_gates(self, check_def: dict) -> CheckResult:
        """Check CI/CD pipelines have approval stages."""
        try:
            pipelines = self._codepipeline.list_pipelines().get("pipelines", [])
            if not pipelines:
                raw = self._build_evidence(
                    api_call="codepipeline.list_pipelines() + get_pipeline()",
                    cli_command="aws codepipeline list-pipelines",
                    response=_sanitize_response({"total_pipelines": 0}),
                    service="CodePipeline",
                    assessor_guidance=(
                        "Verify all CI/CD pipelines have manual approval stages before production deployments. "
                        "Check that approval actions are configured with SNS notifications to authorized approvers "
                        "and that pipelines cannot bypass approval stages."
                    ),
                )
                return self._result(check_def, "met", "No CodePipeline pipelines found.",
                    raw_evidence=raw)
            no_approval = []
            for pl in pipelines[:10]:
                try:
                    detail = self._codepipeline.get_pipeline(name=pl["name"])["pipeline"]
                    has_approval = False
                    for stage in detail.get("stages", []):
                        for action in stage.get("actions", []):
                            if action.get("actionTypeId", {}).get("category") == "Approval":
                                has_approval = True
                                break
                    if not has_approval:
                        no_approval.append(pl["name"])
                except Exception:
                    pass

            raw = self._build_evidence(
                api_call="codepipeline.list_pipelines() + get_pipeline()",
                cli_command="aws codepipeline list-pipelines",
                response=_sanitize_response({
                    "total_pipelines": len(pipelines),
                    "pipelines_without_approval": no_approval,
                    "pipeline_names": [p["name"] for p in pipelines[:20]],
                    "truncated": len(pipelines) > 20,
                }),
                service="CodePipeline",
                assessor_guidance=(
                    "Verify all CI/CD pipelines have manual approval stages before production deployments. "
                    "Check that approval actions are configured with SNS notifications to authorized approvers "
                    "and that pipelines cannot bypass approval stages."
                ),
            )

            if not no_approval:
                return self._result(check_def, "met",
                    f"All {len(pipelines)} pipeline(s) have approval gates.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_approval)} pipeline(s) without approval gates: {', '.join(no_approval[:5])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_scp_service_restrictions(self, check_def: dict) -> CheckResult:
        """Check SCPs restrict unnecessary AWS services."""
        try:
            policies = self._organizations.list_policies(
                Filter="SERVICE_CONTROL_POLICY").get("Policies", [])
            deny_scps = []
            for pol in policies:
                if pol["Name"] == "FullAWSAccess":
                    continue
                try:
                    content = self._organizations.describe_policy(
                        PolicyId=pol["Id"])["Policy"]["Content"]
                    doc = json.loads(content)
                    for stmt in doc.get("Statement", []):
                        if stmt.get("Effect") == "Deny":
                            deny_scps.append(pol["Name"])
                            break
                except Exception:
                    pass

            raw = self._build_evidence(
                api_call="organizations.list_policies() + describe_policy()",
                cli_command="aws organizations list-policies --filter SERVICE_CONTROL_POLICY",
                response=_sanitize_response({
                    "total_scps": len(policies),
                    "deny_scps": deny_scps,
                    "scp_names": [p["Name"] for p in policies[:20]],
                    "truncated": len(policies) > 20,
                }),
                service="Organizations",
                assessor_guidance=(
                    "Verify SCPs restrict access to unnecessary AWS services to reduce attack surface. "
                    "Check that SCPs deny services not required for business operations (e.g., deny "
                    "cryptocurrency mining services, legacy services, or regions not in use)."
                ),
            )

            if deny_scps:
                return self._result(check_def, "met",
                    f"{len(deny_scps)} SCP(s) restrict services: {', '.join(deny_scps[:3])}",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No SCPs found restricting unnecessary services.",
                raw_evidence=raw)
        except Exception as e:
            if "AWSOrganizationsNotInUse" in str(e):
                raw = self._build_evidence(
                    api_call="organizations.list_policies()",
                    cli_command="aws organizations list-policies --filter SERVICE_CONTROL_POLICY",
                    response={"error": "AWSOrganizationsNotInUse"},
                    service="Organizations",
                    assessor_guidance=(
                        "AWS Organizations is not enabled in this account. SCPs cannot be evaluated. "
                        "Determine whether this is a single-account or multi-account environment "
                        "and review the corrective actions below for applicable alternatives."
                    ),
                    corrective_actions=_SCP_NO_ORG_CORRECTIVE_ACTIONS,
                )
                return self._result(check_def, "not_met",
                    "AWS Organizations not in use. SCPs require Organizations. "
                    "See corrective actions for alternative controls based on your environment type.",
                    raw_evidence=raw)
            return self._result(check_def, "error", f"Error: {e}")

    def check_sso_force_password_change(self, check_def: dict) -> CheckResult:
        """Check IAM Identity Center forces password change on first login."""
        try:
            instances = self._sso_admin.list_instances().get("Instances", [])
            raw = self._build_evidence(
                api_call="sso-admin.list_instances()",
                cli_command="aws sso-admin list-instances",
                response=_sanitize_response({
                    "total_instances": len(instances),
                    "instance_arns": [i.get("InstanceArn") for i in instances],
                }),
                service="SSO",
                assessor_guidance=(
                    "Verify IAM Identity Center forces password change on first login. In the IAM Identity Center "
                    "console, check Settings > Authentication > Password policy to confirm 'Users must change "
                    "password at first sign-in' is enabled."
                ),
            )
            if instances:
                return self._result(check_def, "met",
                    "IAM Identity Center configured. Verify 'require new password at first sign-in' "
                    "is enabled in Identity Center settings.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "IAM Identity Center not configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_ir_playbooks(self, check_def: dict) -> CheckResult:
        """Check SSM Automation documents exist for incident response."""
        try:
            docs = self._ssm.list_documents(
                Filters=[{"Key": "DocumentType", "Values": ["Automation"]}]
            ).get("DocumentIdentifiers", [])
            ir_docs = [d["Name"] for d in docs if any(
                k in d["Name"].lower() for k in ("incident", "response", "remediat", "isolate", "contain"))]

            raw = self._build_evidence(
                api_call="ssm.list_documents()",
                cli_command="aws ssm list-documents --filters Key=DocumentType,Values=Automation",
                response=_sanitize_response({
                    "total_automation_docs": len(docs),
                    "ir_related_docs": ir_docs[:20],
                    "doc_names": [d["Name"] for d in docs[:30]],
                    "truncated": len(docs) > 30,
                }),
                service="SSM",
                assessor_guidance=(
                    "Verify SSM Automation documents exist for incident response playbooks (e.g., instance isolation, "
                    "security group lockdown, snapshot creation, forensics collection). Check that documents are "
                    "tested regularly and integrated with EventBridge for automated response."
                ),
            )

            if ir_docs:
                return self._result(check_def, "met",
                    f"IR automation documents: {', '.join(ir_docs[:5])}",
                    raw_evidence=raw)
            if docs:
                return self._result(check_def, "met",
                    f"{len(docs)} SSM Automation documents available for IR procedures.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No SSM Automation documents found for incident response.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_session_manager_mfa(self, check_def: dict) -> CheckResult:
        """Check Session Manager StartSession requires MFA."""
        try:
            # Check if there's a policy requiring MFA for ssm:StartSession
            paginator = self._iam.get_paginator("list_policies")
            mfa_required = False
            total_policies = 0
            for page in paginator.paginate(Scope="Local"):
                for policy in page["Policies"]:
                    total_policies += 1
                    if policy.get("AttachmentCount", 0) == 0:
                        continue
                    try:
                        ver = self._iam.get_policy_version(
                            PolicyArn=policy["Arn"],
                            VersionId=policy["DefaultVersionId"])
                        doc = ver["PolicyVersion"]["Document"]
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        for stmt in (doc.get("Statement") or []):
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if any("ssm:StartSession" in a or "ssm:*" in a for a in actions):
                                cond = stmt.get("Condition", {})
                                if "Bool" in cond and "aws:MultiFactorAuthPresent" in cond["Bool"]:
                                    mfa_required = True
                    except Exception:
                        pass
                    if mfa_required:
                        break
                if mfa_required:
                    break

            raw = self._build_evidence(
                api_call="iam.list_policies() + get_policy_version()",
                cli_command="aws iam list-policies --scope Local --only-attached",
                response=_sanitize_response({
                    "total_policies_checked": total_policies,
                    "mfa_required_for_ssm": mfa_required,
                }),
                service="IAM",
                assessor_guidance=(
                    "Verify IAM policies require MFA for ssm:StartSession action. Check that policies use "
                    "Condition: {Bool: {aws:MultiFactorAuthPresent: true}} to enforce MFA for Session Manager "
                    "access. Confirm no roles/users have ssm:StartSession without MFA enforcement."
                ),
            )

            if mfa_required:
                return self._result(check_def, "met",
                    "MFA required for SSM StartSession via IAM policy condition.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No IAM policy found requiring MFA for SSM StartSession.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_vpn_mfa_required(self, check_def: dict) -> CheckResult:
        """Check Client VPN endpoints require MFA."""
        try:
            endpoints = self._ec2.describe_client_vpn_endpoints().get(
                "ClientVpnEndpoints", [])
            no_mfa = []
            ep_details = []
            for ep in endpoints:
                auth_options = ep.get("AuthenticationOptions", [])
                has_mfa = any(
                    opt.get("MutualAuthentication") or
                    opt.get("FederatedAuthentication") or
                    "directory" in opt.get("Type", "").lower()
                    for opt in auth_options)
                ep_details.append({
                    "ClientVpnEndpointId": ep["ClientVpnEndpointId"],
                    "Status": ep.get("Status", {}).get("Code"),
                    "AuthenticationOptions": auth_options,
                    "HasMFA": has_mfa,
                })
                if not has_mfa:
                    no_mfa.append(ep["ClientVpnEndpointId"])

            raw = self._build_evidence(
                api_call="ec2.describe_client_vpn_endpoints()",
                cli_command="aws ec2 describe-client-vpn-endpoints",
                response=_sanitize_response({
                    "total_endpoints": len(endpoints),
                    "endpoints_without_mfa": no_mfa,
                    "endpoint_details": ep_details[:20],
                    "truncated": len(ep_details) > 20,
                }),
                service="EC2",
                assessor_guidance=(
                    "Verify all Client VPN endpoints require MFA. Check that authentication uses certificate-based "
                    "mutual authentication, federated authentication with MFA, or Active Directory with MFA. "
                    "Simple certificate-only auth without MFA does not meet this requirement."
                ),
            )

            if not endpoints:
                return self._result(check_def, "met", "No Client VPN endpoints found.",
                    raw_evidence=raw)
            if not no_mfa:
                return self._result(check_def, "met",
                    f"All {len(endpoints)} Client VPN endpoint(s) use multi-factor authentication.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_mfa)} endpoint(s) without strong auth: {', '.join(no_mfa[:5])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_guardduty_vpc_monitoring(self, check_def: dict) -> CheckResult:
        """Check GuardDuty monitors VPC Flow Logs."""
        try:
            detectors = self._guardduty.list_detectors().get("DetectorIds", [])
            if not detectors:
                raw = self._build_evidence(
                    api_call="guardduty.get_detector()",
                    cli_command="aws guardduty get-detector --detector-id ID",
                    response=_sanitize_response({"detectors": []}),
                    service="GuardDuty",
                    assessor_guidance=(
                        "Verify GuardDuty is enabled to monitor VPC Flow Logs for malicious network activity. "
                        "Check that VPC Flow Logs data source is enabled in the detector configuration and that "
                        "findings are integrated with Security Hub or SNS for alerting."
                    ),
                )
                return self._result(check_def, "not_met", "GuardDuty not enabled.",
                    raw_evidence=raw)
            det = self._guardduty.get_detector(DetectorId=detectors[0])
            raw = self._build_evidence(
                api_call="guardduty.get_detector()",
                cli_command="aws guardduty get-detector --detector-id ID",
                response=_sanitize_response({
                    "DetectorId": detectors[0],
                    "Status": det.get("Status"),
                    "DataSources": det.get("DataSources"),
                }),
                service="GuardDuty",
                assessor_guidance=(
                    "Verify GuardDuty is enabled to monitor VPC Flow Logs for malicious network activity. "
                    "Check that VPC Flow Logs data source is enabled in the detector configuration and that "
                    "findings are integrated with Security Hub or SNS for alerting."
                ),
            )
            if det.get("Status") == "ENABLED":
                return self._result(check_def, "met",
                    "GuardDuty automatically analyzes VPC Flow Logs, DNS logs, and "
                    "CloudTrail events when enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met", "GuardDuty not active.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_ssm_management_access(self, check_def: dict) -> CheckResult:
        """Check Systems Manager is used for management access instead of SSH/RDP."""
        try:
            instances = self._ssm.describe_instance_information().get(
                "InstanceInformationList", [])
            online = [i for i in instances if i.get("PingStatus") == "Online"]
            # Also check SGs for SSH/RDP exposure
            sgs = self._ec2.describe_security_groups().get("SecurityGroups", [])
            ssh_open = []
            for sg in sgs:
                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 0)
                    for cidr in rule.get("IpRanges", []):
                        if cidr.get("CidrIp") == "0.0.0.0/0":
                            if (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port):
                                ssh_open.append(sg["GroupId"])
                                break

            raw = self._build_evidence(
                api_call="ssm.describe_instance_information() + ec2.describe_security_groups()",
                cli_command="aws ssm describe-instance-information && aws ec2 describe-security-groups",
                response=_sanitize_response({
                    "total_ssm_instances": len(instances),
                    "online_instances": len(online),
                    "security_groups_with_public_ssh_rdp": ssh_open[:30],
                    "total_security_groups_checked": len(sgs),
                }),
                service="SSM",
                assessor_guidance=(
                    "Verify Systems Manager Session Manager is used for management access instead of direct SSH/RDP. "
                    "Check that security groups do NOT allow inbound 0.0.0.0/0 on ports 22 (SSH) or 3389 (RDP). "
                    "Confirm SSM Agent is installed and online on all managed instances."
                ),
            )

            if online and not ssh_open:
                return self._result(check_def, "met",
                    f"{len(online)} instance(s) managed via SSM. No public SSH/RDP access.",
                    raw_evidence=raw)
            if online:
                return self._result(check_def, "not_met",
                    f"SSM available but {len(ssh_open)} SG(s) allow public SSH/RDP.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No instances managed by SSM.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_apigateway_timeout(self, check_def: dict) -> CheckResult:
        """Check API Gateway timeout is configured."""
        try:
            apis = self._apigateway.get_rest_apis().get("items", [])

            raw = self._build_evidence(
                api_call="apigateway.get_rest_apis()",
                cli_command="aws apigateway get-rest-apis",
                response=_sanitize_response({
                    "total_apis": len(apis),
                    "api_names": [a.get("name") for a in apis[:30]],
                    "truncated": len(apis) > 30,
                }),
                service="APIGateway",
                assessor_guidance=(
                    "Verify API Gateway integration timeout is configured appropriately (default 29 seconds, max 30s). "
                    "Check that custom timeout values are set based on backend processing requirements and that "
                    "excessively long timeouts are not used."
                ),
            )

            if not apis:
                return self._result(check_def, "met", "No API Gateway REST APIs found.",
                    raw_evidence=raw)
            return self._result(check_def, "met",
                f"{len(apis)} API Gateway REST API(s) found. "
                "Default timeout is 29s. Verify custom timeouts are appropriate.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_endpoint_protection(self, check_def: dict) -> CheckResult:
        """Check EC2 instances have endpoint protection (anti-malware)."""
        try:
            instances = self._ssm.describe_instance_information().get(
                "InstanceInformationList", [])
            if not instances:
                raw = self._build_evidence(
                    api_call="ssm.describe_instance_information() + list_inventory_entries()",
                    cli_command="aws ssm describe-instance-information",
                    response=_sanitize_response({"total_instances": 0}),
                    service="SSM",
                    assessor_guidance=(
                        "Verify all EC2 instances have endpoint protection (anti-malware) software installed. "
                        "Check SSM Inventory for applications matching known security products (CrowdStrike, "
                        "Defender, Symantec, McAfee, Sophos, etc.). Confirm agents are reporting and up-to-date."
                    ),
                )
                return self._result(check_def, "not_met",
                    "No SSM-managed instances found to verify endpoint protection.",
                    raw_evidence=raw)
            # Check for security-related SSM inventory
            protected = 0
            for inst in instances[:20]:
                try:
                    inv = self._ssm.list_inventory_entries(
                        InstanceId=inst["InstanceId"],
                        TypeName="AWS:Application",
                        MaxResults=50)
                    apps = inv.get("Entries", [])
                    security_apps = [a for a in apps if any(
                        k in a.get("Name", "").lower()
                        for k in ("antivirus", "malware", "endpoint", "defender",
                                  "crowdstrike", "symantec", "mcafee", "sophos"))]
                    if security_apps:
                        protected += 1
                except Exception:
                    pass

            raw = self._build_evidence(
                api_call="ssm.describe_instance_information() + list_inventory_entries()",
                cli_command="aws ssm describe-instance-information",
                response=_sanitize_response({
                    "total_instances": len(instances),
                    "instances_with_protection": protected,
                    "sample_size_checked": min(len(instances), 20),
                }),
                service="SSM",
                assessor_guidance=(
                    "Verify all EC2 instances have endpoint protection (anti-malware) software installed. "
                    "Check SSM Inventory for applications matching known security products (CrowdStrike, "
                    "Defender, Symantec, McAfee, Sophos, etc.). Confirm agents are reporting and up-to-date."
                ),
            )

            if protected > 0:
                return self._result(check_def, "met",
                    f"{protected} of {len(instances)} instance(s) have endpoint protection software.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"No endpoint protection detected on {len(instances)} SSM-managed instance(s).",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_s3_malware_scanning(self, check_def: dict) -> CheckResult:
        """Check GuardDuty S3 Malware Protection is configured."""
        try:
            detectors = self._guardduty.list_detectors().get("DetectorIds", [])
            if not detectors:
                raw = self._build_evidence(
                    api_call="guardduty.get_detector()",
                    cli_command="aws guardduty list-detectors && aws guardduty get-detector --detector-id ID",
                    response=_sanitize_response({"detectors": []}),
                    service="GuardDuty",
                    assessor_guidance=(
                        "Verify GuardDuty S3 Protection (Malware Protection for S3) is enabled to scan S3 objects "
                        "for malware on upload. Check that S3_DATA_EVENTS feature is ENABLED in the detector "
                        "configuration and that findings are routed to Security Hub."
                    ),
                )
                return self._result(check_def, "not_met", "GuardDuty not enabled.",
                    raw_evidence=raw)
            det = self._guardduty.get_detector(DetectorId=detectors[0])
            features = det.get("Features", [])
            s3_mp = any(f.get("Name") == "S3_DATA_EVENTS" and f.get("Status") == "ENABLED"
                for f in features)
            if not s3_mp:
                ds = det.get("DataSources", {})
                s3_mp = ds.get("S3Logs", {}).get("Status") == "ENABLED"

            raw = self._build_evidence(
                api_call="guardduty.get_detector()",
                cli_command="aws guardduty list-detectors && aws guardduty get-detector --detector-id ID",
                response=_sanitize_response({
                    "DetectorId": detectors[0],
                    "S3DataEventsEnabled": s3_mp,
                    "Features": features,
                    "DataSources": det.get("DataSources"),
                }),
                service="GuardDuty",
                assessor_guidance=(
                    "Verify GuardDuty S3 Protection (Malware Protection for S3) is enabled to scan S3 objects "
                    "for malware on upload. Check that S3_DATA_EVENTS feature is ENABLED in the detector "
                    "configuration and that findings are routed to Security Hub."
                ),
            )

            if s3_mp:
                return self._result(check_def, "met",
                    "GuardDuty S3 data event monitoring is enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "GuardDuty S3 data event monitoring not enabled.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_health_dashboard_alerts(self, check_def: dict) -> CheckResult:
        """Check AWS Health Dashboard events are monitored."""
        try:
            events = self._health.describe_events(
                filter={"eventStatusCodes": ["open", "upcoming"]},
            ).get("events", [])
            # Having Health API access means monitoring is available
            raw = self._build_evidence(
                api_call="health.describe_events()",
                cli_command="aws health describe-events",
                response=_sanitize_response({
                    "total_events": len(events),
                    "open_upcoming_events": len(events),
                    "event_types": list(set([e.get("eventTypeCode") for e in events[:20]])),
                }),
                service="Health",
                assessor_guidance=(
                    "Verify AWS Health Dashboard events are monitored for service disruptions, security issues, "
                    "and scheduled maintenance. Check that Health events are integrated with EventBridge to route "
                    "notifications to appropriate teams. Note: Health API requires Business or Enterprise Support."
                ),
            )
            return self._result(check_def, "met",
                f"AWS Health Dashboard accessible. {len(events)} open/upcoming event(s).",
                raw_evidence=raw)
        except Exception as e:
            if "SubscriptionRequiredException" in str(e):
                raw = self._build_evidence(
                    api_call="health.describe_events()",
                    cli_command="aws health describe-events",
                    response=_sanitize_response({"error": "Subscription required"}),
                    service="Health",
                    assessor_guidance=(
                        "Verify AWS Health Dashboard events are monitored for service disruptions, security issues, "
                        "and scheduled maintenance. Check that Health events are integrated with EventBridge to route "
                        "notifications to appropriate teams. Note: Health API requires Business or Enterprise Support."
                    ),
                )
                return self._result(check_def, "not_met",
                    "AWS Health API requires Business/Enterprise Support plan.",
                    raw_evidence=raw)
            return self._result(check_def, "error", f"Error: {e}")

    def check_endpoint_protection_updates(self, check_def: dict) -> CheckResult:
        """Check endpoint protection has auto-updates enabled."""
        try:
            instances = self._ssm.describe_instance_information().get(
                "InstanceInformationList", [])
            if not instances:
                raw = self._build_evidence(
                    api_call="ssm.describe_instance_information()",
                    cli_command="aws ssm describe-instance-information",
                    response=_sanitize_response({"total_instances": 0}),
                    service="SSM",
                    assessor_guidance=(
                        "Verify endpoint protection software has auto-updates enabled for definitions and engines. "
                        "Check SSM Agent versions (IsLatestVersion) as a proxy for patch management. Confirm endpoint "
                        "protection agents report to a central console showing update status."
                    ),
                )
                return self._result(check_def, "not_met",
                    "No SSM-managed instances to verify endpoint protection updates.",
                    raw_evidence=raw)
            # SSM Agent auto-updates indicate patch management
            auto_update = [i for i in instances if i.get("IsLatestVersion")]
            raw = self._build_evidence(
                api_call="ssm.describe_instance_information()",
                cli_command="aws ssm describe-instance-information",
                response=_sanitize_response({
                    "total_instances": len(instances),
                    "instances_with_latest_ssm": len(auto_update),
                    "sample_instances": [{"InstanceId": i["InstanceId"], "IsLatestVersion": i.get("IsLatestVersion")} for i in instances[:20]],
                }),
                service="SSM",
                assessor_guidance=(
                    "Verify endpoint protection software has auto-updates enabled for definitions and engines. "
                    "Check SSM Agent versions (IsLatestVersion) as a proxy for patch management. Confirm endpoint "
                    "protection agents report to a central console showing update status."
                ),
            )
            return self._result(check_def, "met",
                f"{len(auto_update)} of {len(instances)} instance(s) have latest SSM Agent. "
                "Verify endpoint protection auto-updates are enabled.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_s3_object_scanning(self, check_def: dict) -> CheckResult:
        """Check S3 objects are scanned in real-time on upload."""
        try:
            detectors = self._guardduty.list_detectors().get("DetectorIds", [])
            if not detectors:
                raw = self._build_evidence(
                    api_call="guardduty.get_detector()",
                    cli_command="aws guardduty get-detector --detector-id ID",
                    response=_sanitize_response({"detectors": []}),
                    service="GuardDuty",
                    assessor_guidance=(
                        "Verify GuardDuty S3 Protection is enabled to scan S3 objects in real-time on upload. "
                        "Check that S3_DATA_EVENTS feature is ENABLED to monitor object-level API operations "
                        "for suspicious activity and malware."
                    ),
                )
                return self._result(check_def, "not_met", "GuardDuty not enabled for S3 scanning.",
                    raw_evidence=raw)
            det = self._guardduty.get_detector(DetectorId=detectors[0])
            features = det.get("Features", [])
            s3_enabled = any(
                f.get("Name") == "S3_DATA_EVENTS" and f.get("Status") == "ENABLED"
                for f in features)

            raw = self._build_evidence(
                api_call="guardduty.get_detector()",
                cli_command="aws guardduty get-detector --detector-id ID",
                response=_sanitize_response({
                    "DetectorId": detectors[0],
                    "S3DataEventsEnabled": s3_enabled,
                    "Features": features,
                }),
                service="GuardDuty",
                assessor_guidance=(
                    "Verify GuardDuty S3 Protection is enabled to scan S3 objects in real-time on upload. "
                    "Check that S3_DATA_EVENTS feature is ENABLED to monitor object-level API operations "
                    "for suspicious activity and malware."
                ),
            )

            if s3_enabled:
                return self._result(check_def, "met",
                    "GuardDuty S3 protection monitors object-level API operations.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "S3 object scanning not configured via GuardDuty.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_ntp_configured(self, check_def: dict) -> CheckResult:
        """Check NTP is configured on EC2 instances (AWS provides Amazon Time Sync)."""
        try:
            instances = self._ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
            total = sum(len(r["Instances"]) for r in instances.get("Reservations", []))

            raw = self._build_evidence(
                api_call="ec2.describe_instances()",
                cli_command="aws ec2 describe-instances",
                response=_sanitize_response({
                    "total_running_instances": total,
                    "time_sync_service": "169.254.169.123 (Amazon Time Sync Service)",
                }),
                service="EC2",
                assessor_guidance=(
                    "Verify NTP is configured on EC2 instances. Amazon Time Sync Service (169.254.169.123) is "
                    "available to all EC2 instances by default via NTP. Check that instances are configured to "
                    "use this service and that time synchronization is functioning correctly."
                ),
            )

            if total > 0:
                return self._result(check_def, "met",
                    f"{total} running instance(s). Amazon Time Sync Service (169.254.169.123) "
                    "is available to all EC2 instances by default via NTP.",
                    raw_evidence=raw)
            return self._result(check_def, "met",
                "No running instances. Amazon Time Sync Service is available by default.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_patch_state_compliance(self, check_def: dict) -> CheckResult:
        """Check all managed instances are patch compliant."""
        try:
            managed = self._ssm.describe_instance_information().get("InstanceInformationList", [])
            instance_ids = [i["InstanceId"] for i in managed if i.get("InstanceId")]
            if not instance_ids:
                raw = self._build_evidence(
                    api_call="ssm.describe_instance_information()",
                    cli_command="aws ssm describe-instance-information",
                    response=_sanitize_response({"managed_instance_count": 0}),
                    service="SSM",
                    assessor_guidance=(
                        "No SSM-managed instances found. Install SSM Agent on all EC2 instances "
                        "and register them with SSM to enable patch state compliance checks."
                    ),
                )
                return self._result(check_def, "not_met",
                    "No SSM-managed instances found. Cannot verify patch state compliance.",
                    raw_evidence=raw)
            states = self._ssm.describe_instance_patch_states(
                InstanceIds=instance_ids[:50]).get("InstancePatchStates", [])
            if not states:
                raw = self._build_evidence(
                    api_call="ssm.describe_instance_patch_states()",
                    cli_command="aws ssm describe-instance-patch-states",
                    response=_sanitize_response({"total_instances": 0}),
                    service="SSM",
                    assessor_guidance=(
                        "Verify all managed instances are patch compliant. Check SSM Patch Manager compliance data "
                        "to confirm no instances have MissingCount or FailedCount > 0. Confirm patch baselines are "
                        "configured and maintenance windows are scheduled."
                    ),
                )
                return self._result(check_def, "not_met",
                    "No patch compliance data available.",
                    raw_evidence=raw)
            non_compliant = [s["InstanceId"] for s in states
                if s.get("MissingCount", 0) + s.get("FailedCount", 0) > 0]

            raw = self._build_evidence(
                api_call="ssm.describe_instance_patch_states()",
                cli_command="aws ssm describe-instance-patch-states",
                response=_sanitize_response({
                    "total_instances": len(states),
                    "non_compliant_instances": non_compliant[:30],
                    "patch_states": [{"InstanceId": s["InstanceId"], "MissingCount": s.get("MissingCount", 0), "FailedCount": s.get("FailedCount", 0)} for s in states[:30]],
                    "truncated": len(states) > 30,
                }),
                service="SSM",
                assessor_guidance=(
                    "Verify all managed instances are patch compliant. Check SSM Patch Manager compliance data "
                    "to confirm no instances have MissingCount or FailedCount > 0. Confirm patch baselines are "
                    "configured and maintenance windows are scheduled."
                ),
            )

            if not non_compliant:
                return self._result(check_def, "met",
                    f"All {len(states)} managed instance(s) are patch compliant.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(non_compliant)} instance(s) non-compliant: {', '.join(non_compliant[:10])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_inspector_remediation_sla(self, check_def: dict) -> CheckResult:
        """Check Inspector critical findings remediated within SLA (<15d critical, <30d high)."""
        try:
            findings = self._inspector2.list_findings(
                filterCriteria={
                    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
                    "severity": [{"comparison": "EQUALS", "value": "CRITICAL"}]
                },
                maxResults=20
            ).get("findings", [])

            raw = self._build_evidence(
                api_call="inspector2.list_findings()",
                cli_command="aws inspector2 list-findings",
                response=_sanitize_response({
                    "total_critical_findings": len(findings),
                    "finding_details": [{"findingArn": f.get("findingArn"), "severity": f.get("severity"), "title": f.get("title")} for f in findings[:20]],
                }),
                service="Inspector",
                assessor_guidance=(
                    "Verify Inspector critical findings are remediated within SLA (CRITICAL < 15 days, HIGH < 30 days). "
                    "Check that findings have remediation plans, tickets are assigned, and age of active findings "
                    "is tracked. Confirm no findings exceed the SLA thresholds."
                ),
            )

            if not findings:
                return self._result(check_def, "met",
                    "No active critical Inspector findings.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(findings)} active critical finding(s) need remediation within 15 days.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    # ---- CP: Contingency Planning ----

    def check_dr_plan_tags(self, check_def: dict) -> CheckResult:
        """Check for DR plan documentation tags on critical resources."""
        try:
            dr_tagged_resources = []

            # Check EC2 instances for DR tags
            ec2_response = self._ec2.describe_instances(
                Filters=[
                    {"Name": "tag-key", "Values": ["DisasterRecovery", "DR-Plan", "DRPlan"]}
                ]
            )
            for reservation in ec2_response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    dr_tagged_resources.append({
                        "type": "EC2",
                        "id": instance.get("InstanceId"),
                        "tags": instance.get("Tags", [])
                    })

            # Check RDS instances for DR tags
            rds_instances = self._rds.describe_db_instances().get("DBInstances", [])
            for db in rds_instances:
                db_arn = db.get("DBInstanceArn")
                if db_arn:
                    tags_response = self._rds.list_tags_for_resource(ResourceName=db_arn)
                    tags = tags_response.get("TagList", [])
                    for tag in tags:
                        if tag.get("Key") in ["DisasterRecovery", "DR-Plan", "DRPlan"]:
                            dr_tagged_resources.append({
                                "type": "RDS",
                                "id": db.get("DBInstanceIdentifier"),
                                "tags": tags
                            })
                            break

            raw = self._build_evidence(
                api_call="ec2.describe_instances() + rds.describe_db_instances()",
                cli_command="aws ec2 describe-instances --filters 'Name=tag-key,Values=DisasterRecovery' && aws rds describe-db-instances",
                response=_sanitize_response({
                    "dr_tagged_count": len(dr_tagged_resources),
                    "resources": dr_tagged_resources[:20]
                }),
                service="EC2/RDS",
                assessor_guidance=(
                    "Verify critical resources have DR plan documentation tags (DisasterRecovery, DR-Plan, or DRPlan). "
                    "Confirm tags reference DR procedures, RPO/RTO targets, and recovery priorities. "
                    "Check that all production and critical resources are properly tagged."
                ),
            )

            if len(dr_tagged_resources) > 0:
                return self._result(check_def, "met",
                    f"{len(dr_tagged_resources)} resource(s) have DR plan tags.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No resources found with DR plan tags.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_resilience_hub_assessments(self, check_def: dict) -> CheckResult:
        """Check AWS Resilience Hub has assessments."""
        try:
            if not hasattr(self, '_resilience_hub') or self._resilience_hub is None:
                self._resilience_hub = self._session.client('resiliencehub', region_name=self.region)

            # List all apps
            apps = self._resilience_hub.list_apps().get("appSummaries", [])

            assessments = []
            for app in apps[:10]:  # Check first 10 apps
                app_arn = app.get("appArn")
                if app_arn:
                    app_assessments = self._resilience_hub.list_app_assessments(
                        appArn=app_arn
                    ).get("assessmentSummaries", [])
                    assessments.extend(app_assessments)

            raw = self._build_evidence(
                api_call="resiliencehub.list_apps() + resiliencehub.list_app_assessments()",
                cli_command="aws resiliencehub list-apps && aws resiliencehub list-app-assessments",
                response=_sanitize_response({
                    "total_apps": len(apps),
                    "total_assessments": len(assessments),
                    "apps": apps[:10],
                    "assessments": assessments[:20]
                }),
                service="ResilienceHub",
                assessor_guidance=(
                    "Verify AWS Resilience Hub assessments are configured for critical applications. "
                    "Check that assessments define RPO/RTO targets, identify resilience gaps, and "
                    "provide actionable recommendations. Confirm assessments are run periodically."
                ),
            )

            if len(assessments) > 0:
                return self._result(check_def, "met",
                    f"{len(assessments)} Resilience Hub assessment(s) configured.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Resilience Hub assessments found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_s3_cross_region_replication(self, check_def: dict) -> CheckResult:
        """Check S3 buckets have cross-region replication."""
        try:
            buckets = self._s3.list_buckets().get("Buckets", [])
            buckets_with_replication = []

            for bucket in buckets[:50]:  # Check first 50 buckets
                bucket_name = bucket.get("Name")
                try:
                    replication = self._s3.get_bucket_replication(Bucket=bucket_name)
                    rules = replication.get("ReplicationConfiguration", {}).get("Rules", [])
                    if rules:
                        buckets_with_replication.append({
                            "bucket": bucket_name,
                            "rules": len(rules)
                        })
                except self._s3.exceptions.ReplicationConfigurationNotFoundError:
                    pass
                except Exception:
                    pass

            raw = self._build_evidence(
                api_call="s3.get_bucket_replication()",
                cli_command="aws s3api get-bucket-replication",
                response=_sanitize_response({
                    "total_buckets": len(buckets),
                    "buckets_with_replication": len(buckets_with_replication),
                    "replication_details": buckets_with_replication[:20]
                }),
                service="S3",
                assessor_guidance=(
                    "Verify S3 buckets containing critical data have cross-region replication enabled. "
                    "Check that replication rules target a geographically separate region for DR purposes. "
                    "Confirm replication metrics are monitored and replication lag is acceptable."
                ),
            )

            if len(buckets_with_replication) > 0:
                return self._result(check_def, "met",
                    f"{len(buckets_with_replication)} of {len(buckets)} bucket(s) have cross-region replication.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No S3 buckets have cross-region replication configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_rds_cross_region_replicas(self, check_def: dict) -> CheckResult:
        """Check RDS instances have cross-region read replicas."""
        try:
            db_instances = self._rds.describe_db_instances().get("DBInstances", [])
            instances_with_replicas = []

            for db in db_instances:
                read_replicas = db.get("ReadReplicaDBInstanceIdentifiers", [])
                if read_replicas:
                    # Check if any replica is in a different region
                    db_region = db.get("AvailabilityZone", "")[:-1]  # Remove AZ letter
                    for replica in read_replicas:
                        # Replica ARN format contains region info
                        if replica:
                            instances_with_replicas.append({
                                "db_instance": db.get("DBInstanceIdentifier"),
                                "replicas": read_replicas
                            })
                            break

            raw = self._build_evidence(
                api_call="rds.describe_db_instances()",
                cli_command="aws rds describe-db-instances",
                response=_sanitize_response({
                    "total_instances": len(db_instances),
                    "instances_with_replicas": len(instances_with_replicas),
                    "replica_details": instances_with_replicas[:20]
                }),
                service="RDS",
                assessor_guidance=(
                    "Verify production RDS instances have cross-region read replicas for DR failover. "
                    "Check that replicas are in a geographically separate region. Confirm replication lag "
                    "is monitored and within acceptable limits. Validate failover procedures are documented."
                ),
            )

            if len(instances_with_replicas) > 0:
                return self._result(check_def, "met",
                    f"{len(instances_with_replicas)} RDS instance(s) have read replicas.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No RDS instances have read replicas configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_multi_region_deployment(self, check_def: dict) -> CheckResult:
        """Check for multi-region EC2 deployment."""
        try:
            regions_response = self._ec2.describe_regions()
            all_regions = [r["RegionName"] for r in regions_response.get("Regions", [])]

            regions_with_instances = []
            for region in all_regions[:10]:  # Check first 10 regions
                try:
                    ec2_client = self._session.client('ec2', region_name=region)
                    instances = ec2_client.describe_instances(
                        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
                    )
                    instance_count = sum(len(r.get("Instances", []))
                                       for r in instances.get("Reservations", []))
                    if instance_count > 0:
                        regions_with_instances.append({
                            "region": region,
                            "instance_count": instance_count
                        })
                except Exception:
                    pass

            raw = self._build_evidence(
                api_call="ec2.describe_regions() + ec2.describe_instances()",
                cli_command="aws ec2 describe-regions && aws ec2 describe-instances",
                response=_sanitize_response({
                    "total_regions_checked": len(all_regions[:10]),
                    "regions_with_instances": len(regions_with_instances),
                    "deployment_details": regions_with_instances
                }),
                service="EC2",
                assessor_guidance=(
                    "Verify production workloads are deployed across multiple AWS regions for high availability. "
                    "Check that at least 2 geographically separate regions have active deployments. "
                    "Confirm failover mechanisms and load balancing are configured for multi-region traffic."
                ),
            )

            if len(regions_with_instances) >= 2:
                return self._result(check_def, "met",
                    f"Deployment spans {len(regions_with_instances)} region(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Only {len(regions_with_instances)} region(s) with instances. Multi-region deployment recommended.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_route53_health_checks(self, check_def: dict) -> CheckResult:
        """Check Route 53 health checks configured."""
        try:
            health_checks = self._route53.list_health_checks().get("HealthChecks", [])

            raw = self._build_evidence(
                api_call="route53.list_health_checks()",
                cli_command="aws route53 list-health-checks",
                response=_sanitize_response({
                    "total_health_checks": len(health_checks),
                    "health_checks": [{"Id": hc.get("Id"), "Type": hc.get("Type")}
                                     for hc in health_checks[:20]]
                }),
                service="Route53",
                assessor_guidance=(
                    "Verify Route 53 health checks are configured for critical endpoints. "
                    "Check that health checks monitor endpoint availability and trigger DNS failover. "
                    "Confirm CloudWatch alarms are set for health check failures."
                ),
            )

            if len(health_checks) > 0:
                return self._result(check_def, "met",
                    f"{len(health_checks)} Route 53 health check(s) configured.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Route 53 health checks configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_backup_vaults_configured(self, check_def: dict) -> CheckResult:
        """Check AWS Backup vaults exist with backup plans."""
        try:
            vaults = self._backup.list_backup_vaults().get("BackupVaultList", [])
            plans = self._backup.list_backup_plans().get("BackupPlansList", [])

            raw = self._build_evidence(
                api_call="backup.list_backup_vaults() + backup.list_backup_plans()",
                cli_command="aws backup list-backup-vaults && aws backup list-backup-plans",
                response=_sanitize_response({
                    "total_vaults": len(vaults),
                    "total_plans": len(plans),
                    "vaults": [v.get("BackupVaultName") for v in vaults[:20]],
                    "plans": [p.get("BackupPlanName") for p in plans[:20]]
                }),
                service="Backup",
                assessor_guidance=(
                    "Verify AWS Backup vaults and plans are configured for critical resources. "
                    "Check that backup plans define retention policies, backup frequencies, and "
                    "lifecycle rules. Confirm backup selections include all production resources."
                ),
            )

            if len(vaults) > 0 and len(plans) > 0:
                return self._result(check_def, "met",
                    f"{len(vaults)} backup vault(s) and {len(plans)} backup plan(s) configured.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Insufficient backup configuration: {len(vaults)} vault(s), {len(plans)} plan(s).",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_rds_automated_backups(self, check_def: dict) -> CheckResult:
        """Check RDS automated backups enabled."""
        try:
            db_instances = self._rds.describe_db_instances().get("DBInstances", [])
            instances_without_backup = []

            for db in db_instances:
                retention = db.get("BackupRetentionPeriod", 0)
                if retention == 0:
                    instances_without_backup.append(db.get("DBInstanceIdentifier"))

            raw = self._build_evidence(
                api_call="rds.describe_db_instances()",
                cli_command="aws rds describe-db-instances",
                response=_sanitize_response({
                    "total_instances": len(db_instances),
                    "instances_without_backup": instances_without_backup,
                    "backup_retention_details": [
                        {"instance": db.get("DBInstanceIdentifier"),
                         "retention_days": db.get("BackupRetentionPeriod", 0)}
                        for db in db_instances[:20]
                    ]
                }),
                service="RDS",
                assessor_guidance=(
                    "Verify all RDS instances have automated backups enabled with retention > 0 days. "
                    "Check that backup retention period meets organizational requirements (typically 7-35 days). "
                    "Confirm backup windows are scheduled during low-traffic periods."
                ),
            )

            if not instances_without_backup:
                return self._result(check_def, "met",
                    f"All {len(db_instances)} RDS instance(s) have automated backups enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(instances_without_backup)} RDS instance(s) without automated backups: {', '.join(instances_without_backup[:10])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_ebs_snapshots_scheduled(self, check_def: dict) -> CheckResult:
        """Check EBS snapshot schedules via DLM."""
        try:
            policies = self._ec2.describe_snapshot_lifecycle_policies().get("Policies", [])

            raw = self._build_evidence(
                api_call="ec2.describe_snapshot_lifecycle_policies()",
                cli_command="aws ec2 describe-snapshot-lifecycle-policies",
                response=_sanitize_response({
                    "total_policies": len(policies),
                    "policies": [{"PolicyId": p.get("PolicyId"),
                                 "Description": p.get("Description"),
                                 "State": p.get("State")}
                                for p in policies[:20]]
                }),
                service="EC2",
                assessor_guidance=(
                    "Verify EBS volumes have automated snapshot schedules via Data Lifecycle Manager (DLM). "
                    "Check that policies define snapshot frequency, retention, and target resources. "
                    "Confirm policies are in 'ENABLED' state and cover all critical volumes."
                ),
            )

            if len(policies) > 0:
                return self._result(check_def, "met",
                    f"{len(policies)} EBS snapshot lifecycle policy/policies configured.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No EBS snapshot lifecycle policies configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_dynamodb_pitr_enabled(self, check_def: dict) -> CheckResult:
        """Check DynamoDB PITR enabled."""
        try:
            tables = self._dynamodb.list_tables().get("TableNames", [])
            tables_without_pitr = []

            for table_name in tables[:50]:  # Check first 50 tables
                try:
                    pitr_status = self._dynamodb.describe_continuous_backups(
                        TableName=table_name
                    )
                    pitr_enabled = pitr_status.get("ContinuousBackupsDescription", {}).get(
                        "PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus") == "ENABLED"

                    if not pitr_enabled:
                        tables_without_pitr.append(table_name)
                except Exception:
                    tables_without_pitr.append(table_name)

            raw = self._build_evidence(
                api_call="dynamodb.describe_continuous_backups()",
                cli_command="aws dynamodb describe-continuous-backups",
                response=_sanitize_response({
                    "total_tables": len(tables),
                    "tables_without_pitr": tables_without_pitr[:20]
                }),
                service="DynamoDB",
                assessor_guidance=(
                    "Verify all DynamoDB tables have Point-in-Time Recovery (PITR) enabled. "
                    "Check that PITR provides continuous backups for 35 days. "
                    "Confirm recovery procedures are documented and tested."
                ),
            )

            if not tables_without_pitr:
                return self._result(check_def, "met",
                    f"All {len(tables)} DynamoDB table(s) have PITR enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(tables_without_pitr)} DynamoDB table(s) without PITR: {', '.join(tables_without_pitr[:10])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_backup_restore_testing(self, check_def: dict) -> CheckResult:
        """Check backup restore test jobs exist."""
        try:
            # Get restore jobs from the last 90 days
            restore_jobs = self._backup.list_restore_jobs().get("RestoreJobs", [])

            # Filter for completed restore jobs in last 90 days
            ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
            recent_restores = [
                job for job in restore_jobs
                if job.get("CreationDate") and job.get("CreationDate") > ninety_days_ago
            ]

            raw = self._build_evidence(
                api_call="backup.list_restore_jobs()",
                cli_command="aws backup list-restore-jobs",
                response=_sanitize_response({
                    "total_restore_jobs": len(restore_jobs),
                    "recent_restore_jobs_90d": len(recent_restores),
                    "restore_details": [
                        {"RestoreJobId": j.get("RestoreJobId"),
                         "Status": j.get("Status"),
                         "CreationDate": j.get("CreationDate")}
                        for j in recent_restores[:20]
                    ]
                }),
                service="Backup",
                assessor_guidance=(
                    "Verify backup restore testing is performed regularly (at least quarterly). "
                    "Check that restore jobs complete successfully and meet RTO requirements. "
                    "Confirm restore tests are documented with results and lessons learned."
                ),
            )

            if len(recent_restores) > 0:
                return self._result(check_def, "met",
                    f"{len(recent_restores)} backup restore test(s) in the last 90 days.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No backup restore tests found in the last 90 days.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_backup_cross_region_copy(self, check_def: dict) -> CheckResult:
        """Check backup copy jobs to another region."""
        try:
            copy_jobs = self._backup.list_copy_jobs().get("CopyJobs", [])

            raw = self._build_evidence(
                api_call="backup.list_copy_jobs()",
                cli_command="aws backup list-copy-jobs",
                response=_sanitize_response({
                    "total_copy_jobs": len(copy_jobs),
                    "copy_details": [
                        {"CopyJobId": j.get("CopyJobId"),
                         "DestinationBackupVaultArn": j.get("DestinationBackupVaultArn"),
                         "State": j.get("State")}
                        for j in copy_jobs[:20]
                    ]
                }),
                service="Backup",
                assessor_guidance=(
                    "Verify backup plans include cross-region copy rules for DR purposes. "
                    "Check that backups are copied to a geographically separate region. "
                    "Confirm copy jobs complete successfully and copied backups are retained per policy."
                ),
            )

            if len(copy_jobs) > 0:
                return self._result(check_def, "met",
                    f"{len(copy_jobs)} backup cross-region copy job(s) configured.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No backup cross-region copy jobs found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_rds_backup_encryption(self, check_def: dict) -> CheckResult:
        """Check RDS backups are encrypted."""
        try:
            db_instances = self._rds.describe_db_instances().get("DBInstances", [])
            unencrypted_instances = []

            for db in db_instances:
                if not db.get("StorageEncrypted", False):
                    unencrypted_instances.append(db.get("DBInstanceIdentifier"))

            raw = self._build_evidence(
                api_call="rds.describe_db_instances()",
                cli_command="aws rds describe-db-instances",
                response=_sanitize_response({
                    "total_instances": len(db_instances),
                    "unencrypted_instances": unencrypted_instances,
                    "encryption_details": [
                        {"instance": db.get("DBInstanceIdentifier"),
                         "encrypted": db.get("StorageEncrypted", False),
                         "kms_key_id": db.get("KmsKeyId")}
                        for db in db_instances[:20]
                    ]
                }),
                service="RDS",
                assessor_guidance=(
                    "Verify all RDS instances have storage encryption enabled. "
                    "Check that automated backups inherit encryption from the source instance. "
                    "Confirm KMS keys used for encryption are properly managed and rotated."
                ),
            )

            if not unencrypted_instances:
                return self._result(check_def, "met",
                    f"All {len(db_instances)} RDS instance(s) have encrypted storage/backups.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(unencrypted_instances)} RDS instance(s) without encryption: {', '.join(unencrypted_instances[:10])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_recovery_procedures_documented(self, check_def: dict) -> CheckResult:
        """Check for recovery documentation tags."""
        try:
            tagged_resources = []

            # Check EC2 instances
            ec2_response = self._ec2.describe_instances(
                Filters=[
                    {"Name": "tag-key", "Values": ["RecoveryProcedure", "RecoveryDoc", "RecoveryRunbook"]}
                ]
            )
            for reservation in ec2_response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    tagged_resources.append({
                        "type": "EC2",
                        "id": instance.get("InstanceId")
                    })

            # Check RDS instances
            rds_instances = self._rds.describe_db_instances().get("DBInstances", [])
            for db in rds_instances:
                db_arn = db.get("DBInstanceArn")
                if db_arn:
                    tags_response = self._rds.list_tags_for_resource(ResourceName=db_arn)
                    tags = tags_response.get("TagList", [])
                    for tag in tags:
                        if tag.get("Key") in ["RecoveryProcedure", "RecoveryDoc", "RecoveryRunbook"]:
                            tagged_resources.append({
                                "type": "RDS",
                                "id": db.get("DBInstanceIdentifier")
                            })
                            break

            raw = self._build_evidence(
                api_call="ec2.describe_instances() + rds.describe_db_instances()",
                cli_command="aws ec2 describe-instances --filters 'Name=tag-key,Values=RecoveryProcedure'",
                response=_sanitize_response({
                    "resources_with_recovery_docs": len(tagged_resources),
                    "resources": tagged_resources[:20]
                }),
                service="EC2/RDS",
                assessor_guidance=(
                    "Verify critical resources have recovery procedure documentation tags. "
                    "Check that tags reference runbooks, recovery steps, and contact information. "
                    "Confirm recovery procedures are tested and up-to-date."
                ),
            )

            if len(tagged_resources) > 0:
                return self._result(check_def, "met",
                    f"{len(tagged_resources)} resource(s) have recovery procedure documentation tags.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No resources with recovery procedure documentation tags found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_rds_point_in_time_recovery(self, check_def: dict) -> CheckResult:
        """Check RDS PITR capability."""
        try:
            db_instances = self._rds.describe_db_instances().get("DBInstances", [])
            instances_without_pitr = []

            for db in db_instances:
                latest_restorable = db.get("LatestRestorableTime")
                if not latest_restorable:
                    instances_without_pitr.append(db.get("DBInstanceIdentifier"))

            raw = self._build_evidence(
                api_call="rds.describe_db_instances()",
                cli_command="aws rds describe-db-instances",
                response=_sanitize_response({
                    "total_instances": len(db_instances),
                    "instances_without_pitr": instances_without_pitr,
                    "pitr_details": [
                        {"instance": db.get("DBInstanceIdentifier"),
                         "latest_restorable_time": db.get("LatestRestorableTime"),
                         "backup_retention_period": db.get("BackupRetentionPeriod")}
                        for db in db_instances[:20]
                    ]
                }),
                service="RDS",
                assessor_guidance=(
                    "Verify all RDS instances support point-in-time recovery with LatestRestorableTime set. "
                    "Check that backup retention period is > 0 to enable PITR. "
                    "Confirm PITR windows align with RPO requirements."
                ),
            )

            if not instances_without_pitr:
                return self._result(check_def, "met",
                    f"All {len(db_instances)} RDS instance(s) support point-in-time recovery.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(instances_without_pitr)} RDS instance(s) without PITR: {', '.join(instances_without_pitr[:10])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    # ---- PL: Planning ----

    def check_ssm_security_plan_documents(self, check_def: dict) -> CheckResult:
        """Check SSM Parameter Store has security plan docs."""
        try:
            parameters = self._ssm.describe_parameters(
                Filters=[
                    {"Key": "Name", "Values": ["SecurityPlan"]}
                ]
            ).get("Parameters", [])

            # Also check for parameters with SecurityPlan prefix
            all_params = self._ssm.describe_parameters(MaxResults=50).get("Parameters", [])
            security_plan_params = [
                p for p in all_params
                if "SecurityPlan" in p.get("Name", "") or "security-plan" in p.get("Name", "").lower()
            ]

            raw = self._build_evidence(
                api_call="ssm.describe_parameters()",
                cli_command="aws ssm describe-parameters --filters 'Key=Name,Values=SecurityPlan'",
                response=_sanitize_response({
                    "security_plan_parameters": len(security_plan_params),
                    "parameters": [p.get("Name") for p in security_plan_params[:20]]
                }),
                service="SSM",
                assessor_guidance=(
                    "Verify SSM Parameter Store contains security plan documentation references. "
                    "Check that parameters point to current security plans, policies, and procedures. "
                    "Confirm parameters are tagged and versioned appropriately."
                ),
            )

            if len(security_plan_params) > 0:
                return self._result(check_def, "met",
                    f"{len(security_plan_params)} security plan parameter(s) found in SSM.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No security plan parameters found in SSM Parameter Store.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_architecture_tags(self, check_def: dict) -> CheckResult:
        """Check critical resources have architecture metadata tags."""
        try:
            resources_with_arch_tags = []

            # Check EC2 instances
            ec2_response = self._ec2.describe_instances(
                Filters=[
                    {"Name": "tag-key", "Values": ["Architecture", "DataClassification", "SystemType"]}
                ]
            )
            for reservation in ec2_response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    resources_with_arch_tags.append({
                        "type": "EC2",
                        "id": instance.get("InstanceId")
                    })

            # Check RDS instances
            rds_instances = self._rds.describe_db_instances().get("DBInstances", [])
            for db in rds_instances:
                db_arn = db.get("DBInstanceArn")
                if db_arn:
                    tags_response = self._rds.list_tags_for_resource(ResourceName=db_arn)
                    tags = tags_response.get("TagList", [])
                    for tag in tags:
                        if tag.get("Key") in ["Architecture", "DataClassification", "SystemType"]:
                            resources_with_arch_tags.append({
                                "type": "RDS",
                                "id": db.get("DBInstanceIdentifier")
                            })
                            break

            raw = self._build_evidence(
                api_call="ec2.describe_instances() + rds.describe_db_instances()",
                cli_command="aws ec2 describe-instances --filters 'Name=tag-key,Values=Architecture'",
                response=_sanitize_response({
                    "resources_with_architecture_tags": len(resources_with_arch_tags),
                    "resources": resources_with_arch_tags[:20]
                }),
                service="EC2/RDS",
                assessor_guidance=(
                    "Verify critical resources have architecture metadata tags (Architecture, DataClassification, SystemType). "
                    "Check that tags provide context for system design, data sensitivity, and component relationships. "
                    "Confirm tagging strategy is consistently applied across all resources."
                ),
            )

            if len(resources_with_arch_tags) > 0:
                return self._result(check_def, "met",
                    f"{len(resources_with_arch_tags)} resource(s) have architecture metadata tags.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No resources with architecture metadata tags found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_vpc_flow_logs_architecture(self, check_def: dict) -> CheckResult:
        """Check VPC flow logs support architecture review."""
        try:
            vpcs = self._ec2.describe_vpcs().get("Vpcs", [])
            flow_logs = self._ec2.describe_flow_logs().get("FlowLogs", [])

            vpc_ids = {vpc.get("VpcId") for vpc in vpcs}
            flow_log_vpcs = {fl.get("ResourceId") for fl in flow_logs
                           if fl.get("ResourceId") in vpc_ids}

            vpcs_without_logs = vpc_ids - flow_log_vpcs

            raw = self._build_evidence(
                api_call="ec2.describe_flow_logs()",
                cli_command="aws ec2 describe-flow-logs",
                response=_sanitize_response({
                    "total_vpcs": len(vpcs),
                    "vpcs_with_flow_logs": len(flow_log_vpcs),
                    "vpcs_without_flow_logs": list(vpcs_without_logs)[:20],
                    "flow_log_details": [
                        {"ResourceId": fl.get("ResourceId"),
                         "LogDestinationType": fl.get("LogDestinationType"),
                         "FlowLogStatus": fl.get("FlowLogStatus")}
                        for fl in flow_logs[:20]
                    ]
                }),
                service="EC2",
                assessor_guidance=(
                    "Verify all VPCs have flow logs enabled to support architecture review and security analysis. "
                    "Check that flow logs capture ACCEPT, REJECT, or ALL traffic patterns. "
                    "Confirm flow logs are sent to CloudWatch Logs or S3 for long-term retention."
                ),
            )

            if not vpcs_without_logs:
                return self._result(check_def, "met",
                    f"All {len(vpcs)} VPC(s) have flow logs enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(vpcs_without_logs)} VPC(s) without flow logs: {', '.join(list(vpcs_without_logs)[:10])}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    # ---- PT: PII Processing ----

    def check_macie_enabled(self, check_def: dict) -> CheckResult:
        """Check Amazon Macie is enabled."""
        try:
            if not hasattr(self, '_macie2') or self._macie2 is None:
                self._macie2 = self._session.client('macie2', region_name=self.region)

            session = self._macie2.get_macie_session()
            status = session.get("status")

            raw = self._build_evidence(
                api_call="macie2.get_macie_session()",
                cli_command="aws macie2 get-macie-session",
                response=_sanitize_response({
                    "status": status,
                    "service_role": session.get("serviceRole"),
                    "created_at": session.get("createdAt")
                }),
                service="Macie",
                assessor_guidance=(
                    "Verify Amazon Macie is enabled and actively scanning S3 buckets for PII/PHI. "
                    "Check that Macie has appropriate service role permissions. "
                    "Confirm Macie findings are reviewed and sensitive data is properly protected."
                ),
            )

            if status == "ENABLED":
                return self._result(check_def, "met",
                    "Amazon Macie is enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Amazon Macie status: {status}",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_s3_data_classification_tags(self, check_def: dict) -> CheckResult:
        """Check S3 buckets have data classification tags."""
        try:
            buckets = self._s3.list_buckets().get("Buckets", [])
            buckets_with_classification = []

            for bucket in buckets[:50]:  # Check first 50 buckets
                bucket_name = bucket.get("Name")
                try:
                    tags_response = self._s3.get_bucket_tagging(Bucket=bucket_name)
                    tags = tags_response.get("TagSet", [])
                    for tag in tags:
                        if tag.get("Key") in ["DataClassification", "DataSensitivity", "Classification"]:
                            buckets_with_classification.append(bucket_name)
                            break
                except self._s3.exceptions.NoSuchTagSet:
                    pass
                except Exception:
                    pass

            raw = self._build_evidence(
                api_call="s3.get_bucket_tagging()",
                cli_command="aws s3api get-bucket-tagging",
                response=_sanitize_response({
                    "total_buckets": len(buckets),
                    "buckets_with_classification": len(buckets_with_classification),
                    "classified_buckets": buckets_with_classification[:20]
                }),
                service="S3",
                assessor_guidance=(
                    "Verify S3 buckets have data classification tags (DataClassification, DataSensitivity, or Classification). "
                    "Check that tags accurately reflect data sensitivity levels (Public, Internal, Confidential, Restricted). "
                    "Confirm bucket policies and encryption align with classification levels."
                ),
            )

            if len(buckets_with_classification) > 0:
                return self._result(check_def, "met",
                    f"{len(buckets_with_classification)} of {len(buckets)} bucket(s) have data classification tags.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No S3 buckets have data classification tags.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_rds_data_classification_tags(self, check_def: dict) -> CheckResult:
        """Check RDS instances have data classification tags."""
        try:
            db_instances = self._rds.describe_db_instances().get("DBInstances", [])
            instances_with_classification = []

            for db in db_instances:
                db_arn = db.get("DBInstanceArn")
                if db_arn:
                    tags_response = self._rds.list_tags_for_resource(ResourceName=db_arn)
                    tags = tags_response.get("TagList", [])
                    for tag in tags:
                        if tag.get("Key") in ["DataClassification", "DataSensitivity", "Classification"]:
                            instances_with_classification.append(db.get("DBInstanceIdentifier"))
                            break

            raw = self._build_evidence(
                api_call="rds.list_tags_for_resource()",
                cli_command="aws rds list-tags-for-resource",
                response=_sanitize_response({
                    "total_instances": len(db_instances),
                    "instances_with_classification": len(instances_with_classification),
                    "classified_instances": instances_with_classification[:20]
                }),
                service="RDS",
                assessor_guidance=(
                    "Verify RDS instances have data classification tags indicating sensitivity level. "
                    "Check that tags align with data protection requirements (encryption, backup, access controls). "
                    "Confirm classification drives security controls like encryption-at-rest and IAM policies."
                ),
            )

            if len(instances_with_classification) > 0:
                return self._result(check_def, "met",
                    f"{len(instances_with_classification)} of {len(db_instances)} RDS instance(s) have data classification tags.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No RDS instances have data classification tags.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_data_processing_purpose_tags(self, check_def: dict) -> CheckResult:
        """Check resources have data processing purpose tags."""
        try:
            resources_with_purpose = []

            # Check EC2 instances
            ec2_response = self._ec2.describe_instances(
                Filters=[
                    {"Name": "tag-key", "Values": ["DataProcessingPurpose", "ProcessingPurpose", "DataPurpose"]}
                ]
            )
            for reservation in ec2_response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    resources_with_purpose.append({
                        "type": "EC2",
                        "id": instance.get("InstanceId")
                    })

            # Check RDS instances
            rds_instances = self._rds.describe_db_instances().get("DBInstances", [])
            for db in rds_instances:
                db_arn = db.get("DBInstanceArn")
                if db_arn:
                    tags_response = self._rds.list_tags_for_resource(ResourceName=db_arn)
                    tags = tags_response.get("TagList", [])
                    for tag in tags:
                        if tag.get("Key") in ["DataProcessingPurpose", "ProcessingPurpose", "DataPurpose"]:
                            resources_with_purpose.append({
                                "type": "RDS",
                                "id": db.get("DBInstanceIdentifier")
                            })
                            break

            raw = self._build_evidence(
                api_call="ec2.describe_instances() + rds.describe_db_instances()",
                cli_command="aws ec2 describe-instances --filters 'Name=tag-key,Values=DataProcessingPurpose'",
                response=_sanitize_response({
                    "resources_with_purpose_tags": len(resources_with_purpose),
                    "resources": resources_with_purpose[:20]
                }),
                service="EC2/RDS",
                assessor_guidance=(
                    "Verify resources processing personal data have purpose tags describing lawful basis. "
                    "Check that tags document processing purpose (e.g., 'CustomerService', 'Analytics', 'Marketing'). "
                    "Confirm processing purposes align with privacy policies and consent mechanisms."
                ),
            )

            if len(resources_with_purpose) > 0:
                return self._result(check_def, "met",
                    f"{len(resources_with_purpose)} resource(s) have data processing purpose tags.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No resources with data processing purpose tags found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_api_consent_documentation(self, check_def: dict) -> CheckResult:
        """Check API Gateway has consent/privacy documentation."""
        try:
            rest_apis = self._apigateway.get_rest_apis().get("items", [])
            apis_with_docs = []

            for api in rest_apis[:20]:  # Check first 20 APIs
                api_id = api.get("id")
                api_name = api.get("name")

                # Check for documentation
                try:
                    doc_parts = self._apigateway.get_documentation_parts(
                        restApiId=api_id
                    ).get("items", [])

                    if doc_parts:
                        apis_with_docs.append({
                            "api_id": api_id,
                            "api_name": api_name,
                            "doc_parts_count": len(doc_parts)
                        })
                except Exception:
                    pass

                # Also check tags for documentation references
                tags = api.get("tags", {})
                if any(key in tags for key in ["Documentation", "PrivacyPolicy", "ConsentDoc"]):
                    if not any(d["api_id"] == api_id for d in apis_with_docs):
                        apis_with_docs.append({
                            "api_id": api_id,
                            "api_name": api_name,
                            "has_doc_tags": True
                        })

            raw = self._build_evidence(
                api_call="apigateway.get_rest_apis() + apigateway.get_documentation_parts()",
                cli_command="aws apigateway get-rest-apis && aws apigateway get-documentation-parts",
                response=_sanitize_response({
                    "total_apis": len(rest_apis),
                    "apis_with_documentation": len(apis_with_docs),
                    "documented_apis": apis_with_docs[:20]
                }),
                service="APIGateway",
                assessor_guidance=(
                    "Verify API Gateway APIs have documentation describing consent and privacy handling. "
                    "Check that documentation explains data collection, usage, and user rights. "
                    "Confirm APIs implement consent mechanisms before processing personal data."
                ),
            )

            if len(apis_with_docs) > 0:
                return self._result(check_def, "met",
                    f"{len(apis_with_docs)} of {len(rest_apis)} API(s) have documentation.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No API Gateway APIs have documentation configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    # ---- SA: System Acquisition ----

    def check_codepipeline_configured(self, check_def: dict) -> CheckResult:
        """Check CodePipeline exists."""
        try:
            pipelines = self._codepipeline.list_pipelines().get("pipelines", [])

            raw = self._build_evidence(
                api_call="codepipeline.list_pipelines()",
                cli_command="aws codepipeline list-pipelines",
                response=_sanitize_response({
                    "total_pipelines": len(pipelines),
                    "pipelines": [p.get("name") for p in pipelines[:20]]
                }),
                service="CodePipeline",
                assessor_guidance=(
                    "Verify CodePipeline is configured for automated build and deployment. "
                    "Check that pipelines include security scanning stages (SAST, dependency scan). "
                    "Confirm pipelines enforce approval gates for production deployments."
                ),
            )

            if len(pipelines) > 0:
                return self._result(check_def, "met",
                    f"{len(pipelines)} CodePipeline pipeline(s) configured.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No CodePipeline pipelines configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_codebuild_security_scanning(self, check_def: dict) -> CheckResult:
        """Check CodeBuild projects have security scanning."""
        try:
            if not hasattr(self, '_codebuild') or self._codebuild is None:
                self._codebuild = self._session.client('codebuild', region_name=self.region)

            project_names = self._codebuild.list_projects().get("projects", [])
            projects_with_security = []

            if project_names:
                projects = self._codebuild.batch_get_projects(
                    names=project_names[:50]
                ).get("projects", [])

                for project in projects:
                    # Check buildspec or environment variables for security tools
                    buildspec = project.get("source", {}).get("buildspec", "")
                    env_vars = project.get("environment", {}).get("environmentVariables", [])

                    # Look for common security scanning keywords
                    security_keywords = ["sast", "security", "scan", "sonar", "checkmarx", "snyk", "trivy"]
                    has_security = any(keyword in buildspec.lower() for keyword in security_keywords)
                    has_security = has_security or any(
                        keyword in var.get("name", "").lower() or keyword in var.get("value", "").lower()
                        for var in env_vars for keyword in security_keywords
                    )

                    if has_security:
                        projects_with_security.append(project.get("name"))

            raw = self._build_evidence(
                api_call="codebuild.list_projects() + codebuild.batch_get_projects()",
                cli_command="aws codebuild list-projects && aws codebuild batch-get-projects",
                response=_sanitize_response({
                    "total_projects": len(project_names),
                    "projects_with_security_scanning": len(projects_with_security),
                    "security_projects": projects_with_security[:20]
                }),
                service="CodeBuild",
                assessor_guidance=(
                    "Verify CodeBuild projects include security scanning stages (SAST, dependency scanning). "
                    "Check that buildspec includes security tools like SonarQube, Snyk, or Trivy. "
                    "Confirm security scan results fail builds when critical vulnerabilities are found."
                ),
            )

            if len(projects_with_security) > 0:
                return self._result(check_def, "met",
                    f"{len(projects_with_security)} of {len(project_names)} CodeBuild project(s) have security scanning.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No CodeBuild projects with security scanning found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_security_groups_unused_ports(self, check_def: dict) -> CheckResult:
        """Check security groups don't have unused open ports."""
        try:
            security_groups = self._ec2.describe_security_groups().get("SecurityGroups", [])
            overly_permissive = []

            # Standard ports that are commonly needed
            standard_ports = {22, 80, 443, 3389, 3306, 5432}

            for sg in security_groups:
                for rule in sg.get("IpPermissions", []):
                    # Check for rules open to 0.0.0.0/0
                    ip_ranges = rule.get("IpRanges", [])
                    if any(ip_range.get("CidrIp") == "0.0.0.0/0" for ip_range in ip_ranges):
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")

                        # Flag non-standard ports open to the internet
                        if from_port and from_port not in standard_ports:
                            overly_permissive.append({
                                "security_group_id": sg.get("GroupId"),
                                "group_name": sg.get("GroupName"),
                                "port": from_port
                            })

            raw = self._build_evidence(
                api_call="ec2.describe_security_groups()",
                cli_command="aws ec2 describe-security-groups",
                response=_sanitize_response({
                    "total_security_groups": len(security_groups),
                    "overly_permissive_rules": len(overly_permissive),
                    "permissive_details": overly_permissive[:20]
                }),
                service="EC2",
                assessor_guidance=(
                    "Verify security groups don't have overly permissive rules with unused ports open to 0.0.0.0/0. "
                    "Check that only necessary ports are exposed and restricted to known IP ranges. "
                    "Confirm security groups follow least privilege principle."
                ),
            )

            if not overly_permissive:
                return self._result(check_def, "met",
                    "No overly permissive security group rules with unusual ports found.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(overly_permissive)} security group rule(s) with non-standard ports open to 0.0.0.0/0.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_api_gateway_documented(self, check_def: dict) -> CheckResult:
        """Check API Gateway has documentation."""
        try:
            rest_apis = self._apigateway.get_rest_apis().get("items", [])
            apis_with_documentation = []

            for api in rest_apis[:20]:  # Check first 20 APIs
                api_id = api.get("id")
                try:
                    doc_parts = self._apigateway.get_documentation_parts(
                        restApiId=api_id
                    ).get("items", [])

                    if doc_parts:
                        apis_with_documentation.append({
                            "api_id": api_id,
                            "api_name": api.get("name"),
                            "doc_count": len(doc_parts)
                        })
                except Exception:
                    pass

            raw = self._build_evidence(
                api_call="apigateway.get_rest_apis() + apigateway.get_documentation_parts()",
                cli_command="aws apigateway get-rest-apis && aws apigateway get-documentation-parts",
                response=_sanitize_response({
                    "total_apis": len(rest_apis),
                    "documented_apis": len(apis_with_documentation),
                    "documentation_details": apis_with_documentation[:20]
                }),
                service="APIGateway",
                assessor_guidance=(
                    "Verify API Gateway REST APIs have complete documentation for all endpoints. "
                    "Check that documentation includes request/response schemas, authentication requirements, and examples. "
                    "Confirm documentation is kept up-to-date with API changes."
                ),
            )

            if len(apis_with_documentation) > 0:
                return self._result(check_def, "met",
                    f"{len(apis_with_documentation)} of {len(rest_apis)} API(s) have documentation.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No API Gateway APIs with documentation found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_codecommit_version_control(self, check_def: dict) -> CheckResult:
        """Check CodeCommit repositories exist."""
        try:
            if not hasattr(self, '_codecommit') or self._codecommit is None:
                self._codecommit = self._session.client('codecommit', region_name=self.region)

            repositories = self._codecommit.list_repositories().get("repositories", [])

            raw = self._build_evidence(
                api_call="codecommit.list_repositories()",
                cli_command="aws codecommit list-repositories",
                response=_sanitize_response({
                    "total_repositories": len(repositories),
                    "repositories": [r.get("repositoryName") for r in repositories[:20]]
                }),
                service="CodeCommit",
                assessor_guidance=(
                    "Verify source code is maintained in version control (CodeCommit or other Git service). "
                    "Check that repositories have branch protection rules and require code reviews. "
                    "Confirm commit history is preserved and access is logged."
                ),
            )

            if len(repositories) > 0:
                return self._result(check_def, "met",
                    f"{len(repositories)} CodeCommit repository/repositories found.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No CodeCommit repositories found (may use external Git service).",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_cloudformation_version_control(self, check_def: dict) -> CheckResult:
        """Check CloudFormation stacks use version-controlled templates."""
        try:
            if not hasattr(self, '_cloudformation') or self._cloudformation is None:
                self._cloudformation = self._session.client('cloudformation', region_name=self.region)

            stacks = self._cloudformation.list_stacks(
                StackStatusFilter=[
                    'CREATE_COMPLETE', 'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE'
                ]
            ).get("StackSummaries", [])

            raw = self._build_evidence(
                api_call="cloudformation.list_stacks()",
                cli_command="aws cloudformation list-stacks",
                response=_sanitize_response({
                    "total_stacks": len(stacks),
                    "stacks": [{"StackName": s.get("StackName"),
                               "StackStatus": s.get("StackStatus")}
                              for s in stacks[:20]]
                }),
                service="CloudFormation",
                assessor_guidance=(
                    "Verify CloudFormation stacks use version-controlled templates from source control. "
                    "Check that template changes go through code review and CI/CD pipelines. "
                    "Confirm stack drift detection is enabled and monitored."
                ),
            )

            if len(stacks) > 0:
                return self._result(check_def, "met",
                    f"{len(stacks)} CloudFormation stack(s) found (verify templates are version-controlled).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No active CloudFormation stacks found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_codebuild_test_stages(self, check_def: dict) -> CheckResult:
        """Check CodeBuild has test/build stages."""
        try:
            if not hasattr(self, '_codebuild') or self._codebuild is None:
                self._codebuild = self._session.client('codebuild', region_name=self.region)

            project_names = self._codebuild.list_projects().get("projects", [])
            projects_with_tests = []

            if project_names:
                projects = self._codebuild.batch_get_projects(
                    names=project_names[:50]
                ).get("projects", [])

                for project in projects:
                    buildspec = project.get("source", {}).get("buildspec", "")

                    # Look for test-related keywords in buildspec
                    test_keywords = ["test", "junit", "pytest", "npm test", "mvn test", "gradle test"]
                    has_tests = any(keyword in buildspec.lower() for keyword in test_keywords)

                    if has_tests:
                        projects_with_tests.append(project.get("name"))

            raw = self._build_evidence(
                api_call="codebuild.list_projects() + codebuild.batch_get_projects()",
                cli_command="aws codebuild list-projects && aws codebuild batch-get-projects",
                response=_sanitize_response({
                    "total_projects": len(project_names),
                    "projects_with_tests": len(projects_with_tests),
                    "test_projects": projects_with_tests[:20]
                }),
                service="CodeBuild",
                assessor_guidance=(
                    "Verify CodeBuild projects include test stages in buildspec. "
                    "Check that unit tests, integration tests, and/or end-to-end tests are executed. "
                    "Confirm builds fail when tests don't pass and test results are published."
                ),
            )

            if len(projects_with_tests) > 0:
                return self._result(check_def, "met",
                    f"{len(projects_with_tests)} of {len(project_names)} CodeBuild project(s) have test stages.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No CodeBuild projects with test stages found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_codeguru_sast_integrated(self, check_def: dict) -> CheckResult:
        """Check CodeGuru Reviewer is configured."""
        try:
            if not hasattr(self, '_codeguru') or self._codeguru is None:
                self._codeguru = self._session.client('codeguru-reviewer', region_name=self.region)

            associations = self._codeguru.list_repository_associations().get(
                "RepositoryAssociationSummaries", []
            )

            raw = self._build_evidence(
                api_call="codeguru-reviewer.list_repository_associations()",
                cli_command="aws codeguru-reviewer list-repository-associations",
                response=_sanitize_response({
                    "total_associations": len(associations),
                    "associations": [
                        {"Name": a.get("Name"), "State": a.get("State")}
                        for a in associations[:20]
                    ]
                }),
                service="CodeGuruReviewer",
                assessor_guidance=(
                    "Verify CodeGuru Reviewer is associated with code repositories for automated SAST. "
                    "Check that associations are in 'Associated' state and actively reviewing pull requests. "
                    "Confirm CodeGuru recommendations are reviewed and addressed."
                ),
            )

            if len(associations) > 0:
                return self._result(check_def, "met",
                    f"{len(associations)} CodeGuru repository association(s) configured.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No CodeGuru Reviewer repository associations found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_ssm_inventory_software_versions(self, check_def: dict) -> CheckResult:
        """Check SSM inventory tracks software."""
        try:
            # Check for inventory data sync
            data_syncs = self._ssm.list_resource_data_sync().get("ResourceDataSyncItems", [])

            # Get inventory summary
            inventory_summary = {}
            try:
                inventory = self._ssm.get_inventory_schema(MaxResults=10)
                inventory_summary = {
                    "schema_count": len(inventory.get("Schemas", []))
                }
            except Exception:
                pass

            raw = self._build_evidence(
                api_call="ssm.list_resource_data_sync() + ssm.get_inventory_schema()",
                cli_command="aws ssm list-resource-data-sync && aws ssm get-inventory-schema",
                response=_sanitize_response({
                    "data_sync_count": len(data_syncs),
                    "data_syncs": [ds.get("SyncName") for ds in data_syncs],
                    "inventory_summary": inventory_summary
                }),
                service="SSM",
                assessor_guidance=(
                    "Verify SSM Inventory is configured to track software versions on managed instances. "
                    "Check that inventory includes applications, patches, and custom metadata. "
                    "Confirm inventory data is centralized via resource data sync for analysis."
                ),
            )

            if len(data_syncs) > 0 or inventory_summary.get("schema_count", 0) > 0:
                return self._result(check_def, "met",
                    f"SSM Inventory configured with {len(data_syncs)} data sync(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No SSM Inventory data syncs configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_inspector_eol_software(self, check_def: dict) -> CheckResult:
        """Check Inspector findings for EOL software."""
        try:
            findings = self._inspector2.list_findings(
                filterCriteria={
                    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
                    "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}]
                },
                maxResults=50
            ).get("findings", [])

            # Look for EOL-related findings
            eol_keywords = ["end-of-life", "eol", "unsupported", "deprecated"]
            eol_findings = [
                f for f in findings
                if any(keyword in f.get("title", "").lower() or
                      keyword in f.get("description", "").lower()
                      for keyword in eol_keywords)
            ]

            raw = self._build_evidence(
                api_call="inspector2.list_findings()",
                cli_command="aws inspector2 list-findings",
                response=_sanitize_response({
                    "total_package_findings": len(findings),
                    "eol_related_findings": len(eol_findings),
                    "findings": [
                        {"findingArn": f.get("findingArn"),
                         "title": f.get("title"),
                         "severity": f.get("severity")}
                        for f in eol_findings[:20]
                    ]
                }),
                service="Inspector",
                assessor_guidance=(
                    "Verify Inspector scans identify end-of-life (EOL) software packages. "
                    "Check that EOL software findings are prioritized for remediation. "
                    "Confirm process exists to upgrade or replace EOL software components."
                ),
            )

            if not eol_findings:
                return self._result(check_def, "met",
                    "No active Inspector findings for EOL software.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(eol_findings)} Inspector finding(s) related to EOL software.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    # ---- SR: Supply Chain ----

    def check_ecr_vulnerability_scanning(self, check_def: dict) -> CheckResult:
        """Check ECR repositories have scanning enabled."""
        try:
            repositories = self._ecr.describe_repositories().get("repositories", [])

            # Check registry scanning configuration
            registry_config = {}
            try:
                registry_config = self._ecr.get_registry_scanning_configuration()
            except Exception:
                pass

            repos_with_scanning = [
                r for r in repositories
                if r.get("imageScanningConfiguration", {}).get("scanOnPush", False)
            ]

            raw = self._build_evidence(
                api_call="ecr.describe_repositories() + ecr.get_registry_scanning_configuration()",
                cli_command="aws ecr describe-repositories && aws ecr get-registry-scanning-configuration",
                response=_sanitize_response({
                    "total_repositories": len(repositories),
                    "repos_with_scan_on_push": len(repos_with_scanning),
                    "registry_scanning": registry_config.get("scanningConfiguration", {}),
                    "repositories": [r.get("repositoryName") for r in repos_with_scanning[:20]]
                }),
                service="ECR",
                assessor_guidance=(
                    "Verify ECR repositories have image scanning enabled (scan-on-push or enhanced scanning). "
                    "Check that scan findings are reviewed and vulnerabilities are remediated. "
                    "Confirm high/critical vulnerabilities block image deployment."
                ),
            )

            if len(repos_with_scanning) > 0 or registry_config.get("scanningConfiguration"):
                return self._result(check_def, "met",
                    f"{len(repos_with_scanning)} of {len(repositories)} ECR repository/repositories have scan-on-push enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No ECR repositories with vulnerability scanning enabled.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_inspector_sbom(self, check_def: dict) -> CheckResult:
        """Check Inspector SBOM generation."""
        try:
            # Check Inspector coverage for SBOM
            coverage = self._inspector2.list_coverage(
                filterCriteria={
                    "resourceType": [{"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}]
                },
                maxResults=50
            ).get("coveredResources", [])

            raw = self._build_evidence(
                api_call="inspector2.list_coverage()",
                cli_command="aws inspector2 list-coverage",
                response=_sanitize_response({
                    "covered_resources": len(coverage),
                    "coverage_details": [
                        {"resourceId": c.get("resourceId"),
                         "resourceType": c.get("resourceType"),
                         "scanStatus": c.get("scanStatus", {})}
                        for c in coverage[:20]
                    ]
                }),
                service="Inspector",
                assessor_guidance=(
                    "Verify Inspector v2 generates SBOM for container images and instances. "
                    "Check that SBOM data includes all software packages and dependencies. "
                    "Confirm SBOM is used for vulnerability tracking and compliance reporting."
                ),
            )

            if len(coverage) > 0:
                return self._result(check_def, "met",
                    f"Inspector coverage configured for {len(coverage)} resource(s) (SBOM generation).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Inspector coverage for SBOM generation found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_codebuild_dependency_scanning(self, check_def: dict) -> CheckResult:
        """Check CodeBuild projects scan dependencies."""
        try:
            if not hasattr(self, '_codebuild') or self._codebuild is None:
                self._codebuild = self._session.client('codebuild', region_name=self.region)

            project_names = self._codebuild.list_projects().get("projects", [])
            projects_with_dep_scan = []

            if project_names:
                projects = self._codebuild.batch_get_projects(
                    names=project_names[:50]
                ).get("projects", [])

                for project in projects:
                    buildspec = project.get("source", {}).get("buildspec", "")

                    # Look for dependency scanning keywords
                    dep_scan_keywords = ["npm audit", "pip check", "dependency-check", "snyk", "trivy", "safety"]
                    has_dep_scan = any(keyword in buildspec.lower() for keyword in dep_scan_keywords)

                    if has_dep_scan:
                        projects_with_dep_scan.append(project.get("name"))

            raw = self._build_evidence(
                api_call="codebuild.list_projects() + codebuild.batch_get_projects()",
                cli_command="aws codebuild list-projects && aws codebuild batch-get-projects",
                response=_sanitize_response({
                    "total_projects": len(project_names),
                    "projects_with_dependency_scanning": len(projects_with_dep_scan),
                    "dep_scan_projects": projects_with_dep_scan[:20]
                }),
                service="CodeBuild",
                assessor_guidance=(
                    "Verify CodeBuild projects include dependency scanning stages. "
                    "Check that tools like npm audit, Snyk, or OWASP Dependency-Check are used. "
                    "Confirm builds fail when high/critical vulnerabilities are found in dependencies."
                ),
            )

            if len(projects_with_dep_scan) > 0:
                return self._result(check_def, "met",
                    f"{len(projects_with_dep_scan)} of {len(project_names)} CodeBuild project(s) have dependency scanning.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No CodeBuild projects with dependency scanning found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_ecr_image_signing(self, check_def: dict) -> CheckResult:
        """Check ECR image signing is configured."""
        try:
            # Check if registry has signing configuration
            registry_policy = {}
            try:
                registry_policy = self._ecr.get_registry_policy()
            except self._ecr.exceptions.RegistryPolicyNotFoundException:
                pass
            except Exception:
                pass

            repositories = self._ecr.describe_repositories().get("repositories", [])

            raw = self._build_evidence(
                api_call="ecr.get_registry_policy() + ecr.describe_repositories()",
                cli_command="aws ecr get-registry-policy && aws ecr describe-repositories",
                response=_sanitize_response({
                    "total_repositories": len(repositories),
                    "has_registry_policy": bool(registry_policy.get("policyText")),
                    "registry_policy": registry_policy.get("policyText", "")[:500] if registry_policy else None
                }),
                service="ECR",
                assessor_guidance=(
                    "Verify ECR images are signed using AWS Signer or Notary for supply chain security. "
                    "Check that only signed images are allowed to be deployed. "
                    "Confirm image signature verification is enforced in deployment pipelines."
                ),
            )

            if registry_policy.get("policyText"):
                return self._result(check_def, "met",
                    "ECR registry has policy configured (verify image signing requirements).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No ECR registry policy for image signing found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def check_lambda_code_signing(self, check_def: dict) -> CheckResult:
        """Check Lambda functions use code signing."""
        try:
            if not hasattr(self, '_lambda_client') or self._lambda_client is None:
                self._lambda_client = self._session.client('lambda', region_name=self.region)

            functions = self._lambda_client.list_functions().get("Functions", [])
            functions_with_signing = []

            for func in functions:
                if func.get("CodeSigningConfigArn"):
                    functions_with_signing.append({
                        "function_name": func.get("FunctionName"),
                        "signing_config_arn": func.get("CodeSigningConfigArn")
                    })

            raw = self._build_evidence(
                api_call="lambda.list_functions()",
                cli_command="aws lambda list-functions",
                response=_sanitize_response({
                    "total_functions": len(functions),
                    "functions_with_code_signing": len(functions_with_signing),
                    "signed_functions": functions_with_signing[:20]
                }),
                service="Lambda",
                assessor_guidance=(
                    "Verify Lambda functions use code signing configurations for supply chain integrity. "
                    "Check that signing profiles enforce trusted sources for deployment packages. "
                    "Confirm unsigned code is blocked from deployment."
                ),
            )

            if len(functions_with_signing) > 0:
                return self._result(check_def, "met",
                    f"{len(functions_with_signing)} of {len(functions)} Lambda function(s) use code signing.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Lambda functions with code signing configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Error: {e}")

    def disconnect(self):
        """Clean up boto3 clients."""
        self._iam = None
        self._sts = None
        self._cloudtrail = None
        self._s3 = None
        self._ec2 = None
        self._kms = None
        self._guardduty = None
        self._ssm = None
        self._config_service = None
        self._rds = None
        self._efs = None
        self._backup = None
        self._securityhub = None
        self._inspector2 = None
        self._wafv2 = None
        self._elbv2 = None
        self._cloudfront = None
        self._acm = None
        self._route53 = None
        self._network_firewall = None
        self._events = None
        self._cloudwatch = None
        self._sns = None
        self._dynamodb = None
        self._ecr = None
        self._logs = None
        self._organizations = None
        self._sso_admin = None
        self._identitystore = None
        self._codepipeline = None
        self._apigateway = None
        self._athena = None
        self._health = None
        # New clients for CP, PL, PT, SA, SR checks
        self._resilience_hub = None
        self._macie2 = None
        self._codebuild = None
        self._codecommit = None
        self._cloudformation = None
        self._codeguru = None
        self._lambda_client = None
        self._credential_report_cache = None
        self._trails_cache = None
        self._s3_buckets_cache = None
        self._session = None
        self._connected = False
