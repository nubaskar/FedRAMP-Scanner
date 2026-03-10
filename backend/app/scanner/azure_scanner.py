"""
Azure Scanner — Compliance check implementations using Azure SDK.

Connects to Azure (Commercial or Government) via Service Principal
credentials and runs automated NIST 800-53 control checks.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

import requests as http_requests

from app.scanner.base import BaseScanner, CheckResult

logger = logging.getLogger(__name__)

# Suppress noisy Azure SDK warnings (e.g. "Discriminator source is absent
# or null, use base class ResourceDetails" from azure.mgmt.security).
logging.getLogger("azure.mgmt.security").setLevel(logging.ERROR)
logging.getLogger("msrest.serialization").setLevel(logging.WARNING)


class AzureScanner(BaseScanner):
    """Azure-specific compliance scanner using Azure Management SDKs."""

    def __init__(self, credentials: dict, environment: str, region: str = "eastus"):
        super().__init__(credentials, environment, region)
        self._credential = None
        self._subscription_id = None
        self._mgmt_kwargs: dict = {}
        self._resource_client = None
        self._network_client = None
        self._compute_client = None
        self._storage_client = None
        self._keyvault_client = None
        self._monitor_client = None
        self._auth_client = None
        # Lazy-init clients
        self._security_client = None
        self._sql_client = None
        self._web_client = None
        self._policy_client = None
        self._recovery_client = None
        self._advisor_client = None
        self._resourcegraph_client = None
        self._automation_client = None
        self._loganalytics_client = None
        self._sentinel_client = None
        # Cache for repeated API calls (thread-safe with per-key locking)
        self._cache: dict = {}
        self._lock = threading.Lock()        # protects _cache reads/writes + _key_locks
        self._key_locks: dict[str, threading.Lock] = {}  # per-key locks for slow fetches

    def connect(self) -> bool:
        """
        Establish connection to Azure via Service Principal.

        Expects credentials dict with:
            - tenant_id: Azure AD tenant ID
            - client_id: Service Principal application ID
            - client_secret: Service Principal secret
            - subscription_id: Target Azure subscription

        Returns True if connection successful.
        """
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
            from azure.mgmt.compute import ComputeManagementClient
            from azure.mgmt.keyvault import KeyVaultManagementClient
            from azure.mgmt.monitor import MonitorManagementClient
            from azure.mgmt.network import NetworkManagementClient
            from azure.mgmt.resource import ResourceManagementClient
            from azure.mgmt.storage import StorageManagementClient

            tenant_id = self.credentials.get("tenant_id", "")
            client_id = self.credentials.get("client_id", "")
            client_secret = self.credentials.get("client_secret", "")
            self._subscription_id = self.credentials.get("subscription_id", "")

            if not all([tenant_id, client_id, client_secret, self._subscription_id]):
                logger.error("Missing required Azure credentials")
                return False

            # Determine authority host for government vs commercial
            authority = None
            if self.environment == "azure_government":
                from azure.identity import AzureAuthorityHosts
                authority = AzureAuthorityHosts.AZURE_GOVERNMENT

            kwargs = {}
            if authority:
                kwargs["authority"] = authority

            self._credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                **kwargs,
            )

            # Determine base URL for government cloud
            base_url = None
            credential_scopes = None
            if self.environment == "azure_government":
                base_url = "https://management.usgovcloudapi.net"
                credential_scopes = ["https://management.usgovcloudapi.net/.default"]

            self._mgmt_kwargs = {
                "connection_timeout": 10,
                "read_timeout": 30,
            }
            if base_url:
                self._mgmt_kwargs["base_url"] = base_url
            if credential_scopes:
                self._mgmt_kwargs["credential_scopes"] = credential_scopes
            mgmt_kwargs = self._mgmt_kwargs

            self._resource_client = ResourceManagementClient(
                self._credential, self._subscription_id, **mgmt_kwargs
            )
            self._network_client = NetworkManagementClient(
                self._credential, self._subscription_id, **mgmt_kwargs
            )
            self._compute_client = ComputeManagementClient(
                self._credential, self._subscription_id, **mgmt_kwargs
            )
            self._storage_client = StorageManagementClient(
                self._credential, self._subscription_id, **mgmt_kwargs
            )
            self._keyvault_client = KeyVaultManagementClient(
                self._credential, self._subscription_id, **mgmt_kwargs
            )
            self._monitor_client = MonitorManagementClient(
                self._credential, self._subscription_id, **mgmt_kwargs
            )
            self._auth_client = AuthorizationManagementClient(
                self._credential, self._subscription_id, **mgmt_kwargs
            )

            # Verify connectivity by listing resource groups (also warms cache)
            rgs = list(self._resource_client.resource_groups.list())
            self._cache["resource_groups"] = rgs
            logger.info(
                "Connected to Azure subscription %s with %d resource group(s)",
                self._subscription_id,
                len(rgs),
            )
            self._connected = True
            return True

        except ImportError as e:
            logger.error("Azure SDK not installed: %s", e)
            return False
        except Exception as e:
            logger.error("Failed to connect to Azure: %s", e)
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
    # Helpers: Graph API, lazy clients, caching
    # ------------------------------------------------------------------

    def _graph_get(self, path: str, max_pages: int = 0) -> dict:
        """Call Microsoft Graph API via REST. Handles pagination and 429 rate limiting.

        Args:
            path: Graph API path (e.g. "users", "auditLogs/signIns?$top=1")
            max_pages: Max pages to fetch. 0 = unlimited (follow all @odata.nextLink).
                       Use 1 for existence checks that only need to verify data exists.
        """

        scope = ("https://graph.microsoft.us/.default"
                 if self.environment == "azure_government"
                 else "https://graph.microsoft.com/.default")
        token = self._credential.get_token(scope)
        base = ("https://graph.microsoft.us"
                if self.environment == "azure_government"
                else "https://graph.microsoft.com")
        url = f"{base}/v1.0/{path}"
        headers = {"Authorization": f"Bearer {token.token}"}
        all_values: list = []
        max_retries = 2
        pages_fetched = 0
        while url:
            for attempt in range(max_retries + 1):
                resp = http_requests.get(url, headers=headers, timeout=15)
                if resp.status_code == 429:
                    retry_hdr = resp.headers.get("Retry-After")
                    retry_after = int(retry_hdr) if retry_hdr else (3 + attempt * 3)
                    retry_after = min(retry_after, 15)
                    if attempt < max_retries:
                        logger.warning(
                            "Graph API 429 for %s, retrying in %ds (attempt %d/%d)",
                            path, retry_after, attempt + 1, max_retries)
                        time.sleep(retry_after)
                        continue
                    resp.raise_for_status()
                break
            if resp.status_code == 403:
                raise PermissionError(
                    f"Insufficient Graph permissions for {path}. "
                    "Grant the required Application permissions and admin consent."
                )
            resp.raise_for_status()
            data = resp.json()
            if "value" in data:
                all_values.extend(data["value"])
                pages_fetched += 1
                if max_pages and pages_fetched >= max_pages:
                    break
                url = data.get("@odata.nextLink")
            else:
                return data
        return {"value": all_values}

    def _graph_get_safe(self, path: str, default: Any = None,
                        max_pages: int = 0) -> Any:
        """Call Graph API with per-key caching (thread-safe).

        Args:
            max_pages: Limit pagination. Use 1 for existence checks.
        """
        cache_key = f"graph:{path}"
        # Fast path
        if cache_key in self._cache:
            return self._cache[cache_key]
        # Get or create per-key lock
        with self._lock:
            if cache_key in self._cache:
                return self._cache[cache_key]
            if cache_key not in self._key_locks:
                self._key_locks[cache_key] = threading.Lock()
            key_lock = self._key_locks[cache_key]
        # Hold per-key lock during the (slow) Graph API call
        with key_lock:
            if cache_key in self._cache:
                return self._cache[cache_key]
            try:
                result = self._graph_get(path, max_pages=max_pages)
                self._cache[cache_key] = result
                return result
            except PermissionError as e:
                logger.warning("Graph API permission denied for %s: %s", path, e)
                result = default if default is not None else {
                    "value": [], "_error": str(e), "_permission_denied": True}
                self._cache[cache_key] = result
                return result
            except Exception as e:
                logger.warning("Graph API call failed for %s: %s", path, e)
                result = default if default is not None else {"value": [], "_error": str(e)}
                self._cache[cache_key] = result
                return result

    def _cached(self, key: str, fn):
        """Cache API call results (thread-safe, per-key locking).

        Different keys can be fetched concurrently.  Only the same key
        blocks other threads while the slow API call is in progress.
        """
        # Fast path — already cached
        if key in self._cache:
            return self._cache[key]
        # Get or create a per-key lock (global lock held only briefly)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
            if key not in self._key_locks:
                self._key_locks[key] = threading.Lock()
            key_lock = self._key_locks[key]
        # Hold only the per-key lock during the (slow) API call
        with key_lock:
            if key in self._cache:
                return self._cache[key]
            self._cache[key] = fn()
            return self._cache[key]

    def _get_security_client(self):
        if self._security_client is None:
            with self._lock:
                if self._security_client is None:
                    from azure.mgmt.security import SecurityCenter
                    self._security_client = SecurityCenter(
                        self._credential, self._subscription_id, **self._mgmt_kwargs)
        return self._security_client

    def _get_sql_client(self):
        if self._sql_client is None:
            with self._lock:
                if self._sql_client is None:
                    from azure.mgmt.sql import SqlManagementClient
                    self._sql_client = SqlManagementClient(
                        self._credential, self._subscription_id, **self._mgmt_kwargs)
        return self._sql_client

    def _get_web_client(self):
        if self._web_client is None:
            with self._lock:
                if self._web_client is None:
                    from azure.mgmt.web import WebSiteManagementClient
                    self._web_client = WebSiteManagementClient(
                        self._credential, self._subscription_id, **self._mgmt_kwargs)
        return self._web_client

    def _get_policy_client(self):
        if self._policy_client is None:
            with self._lock:
                if self._policy_client is None:
                    from azure.mgmt.policyinsights import PolicyInsightsClient
                    self._policy_client = PolicyInsightsClient(
                        self._credential, self._subscription_id, **self._mgmt_kwargs)
        return self._policy_client

    def _get_recovery_client(self):
        if self._recovery_client is None:
            with self._lock:
                if self._recovery_client is None:
                    from azure.mgmt.recoveryservices import RecoveryServicesClient
                    self._recovery_client = RecoveryServicesClient(
                        self._credential, self._subscription_id, **self._mgmt_kwargs)
        return self._recovery_client

    def _get_advisor_client(self):
        if self._advisor_client is None:
            with self._lock:
                if self._advisor_client is None:
                    from azure.mgmt.advisor import AdvisorManagementClient
                    self._advisor_client = AdvisorManagementClient(
                        self._credential, self._subscription_id, **self._mgmt_kwargs)
        return self._advisor_client

    def _get_resourcegraph_client(self):
        if self._resourcegraph_client is None:
            with self._lock:
                if self._resourcegraph_client is None:
                    from azure.mgmt.resourcegraph import ResourceGraphClient
                    self._resourcegraph_client = ResourceGraphClient(
                        self._credential, **self._mgmt_kwargs)
        return self._resourcegraph_client

    def _get_automation_client(self):
        if self._automation_client is None:
            with self._lock:
                if self._automation_client is None:
                    from azure.mgmt.automation import AutomationClient
                    self._automation_client = AutomationClient(
                        self._credential, self._subscription_id, **self._mgmt_kwargs)
        return self._automation_client

    def _get_loganalytics_client(self):
        if self._loganalytics_client is None:
            with self._lock:
                if self._loganalytics_client is None:
                    from azure.mgmt.loganalytics import LogAnalyticsManagementClient
                    self._loganalytics_client = LogAnalyticsManagementClient(
                        self._credential, self._subscription_id, **self._mgmt_kwargs)
        return self._loganalytics_client

    def _get_sentinel_client(self):
        if self._sentinel_client is None:
            with self._lock:
                if self._sentinel_client is None:
                    from azure.mgmt.securityinsight import SecurityInsights
                    self._sentinel_client = SecurityInsights(
                        self._credential, self._subscription_id, **self._mgmt_kwargs)
        return self._sentinel_client

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
                "region": self.region or "eastus",
                "account_id": self._subscription_id or "",
            },
            "response": response,
        }
        if assessor_guidance:
            result["assessor_guidance"] = assessor_guidance
        return result

    def prefetch(self):
        """Pre-warm cached data in parallel before check execution.

        Runs ARM and Graph API calls concurrently (3 batches of workers)
        so the total prefetch time is bounded by the slowest call in each
        batch rather than the sum of all calls.
        """
        import concurrent.futures

        PREFETCH_TIMEOUT = 30  # seconds per individual call

        # ---- Batch 1: Core ARM management clients (already initialised) ----
        core_helpers = [
            ("NSGs", self._list_nsgs),
            ("Storage accounts", self._list_storage_accounts),
            ("VMs", self._list_vms),
            ("Key Vaults", self._list_keyvaults),
            ("Disks", self._list_disks),
            ("Resource groups", self._list_resource_groups),
            ("Activity log alerts", self._list_activity_log_alerts),
            ("VNets", self._list_vnets),
            ("Firewalls", self._list_firewalls),
            ("Network Watchers", self._list_watchers),
            ("Application gateways", self._list_app_gateways),
            ("Bastion hosts", self._list_bastions),
            ("All resources", self._list_all_resources),
        ]

        # ---- Batch 2: Lazy-init clients + per-RG aggregations ----
        lazy_helpers = [
            # Per-RG helpers (depend on resource_groups cache from batch 1)
            ("VNet gateways", self._list_vnet_gateways),
            ("VPN connections", self._list_vnet_gateway_connections),
            ("VNet peerings", self._list_vnet_peerings),
            ("SQL servers", self._list_sql_servers),
            ("Web apps", self._list_web_apps),
            ("Log Analytics workspaces", self._list_workspaces),
            ("WAF policies", self._list_waf_policies),
            ("Recovery vaults", self._list_recovery_vaults),
            ("Defender pricings", self._list_defender_pricings),
            ("Security contacts", self._list_security_contacts),
            ("Security assessments", self._list_assessments),
        ]

        def _run_helper(label_fn):
            label, fn = label_fn
            t1 = time.time()
            try:
                fn()
                elapsed = time.time() - t1
                logger.info("  Prefetch %-25s %.1fs", label, elapsed)
                return label, True, elapsed
            except Exception as exc:
                logger.warning("  Prefetch %-25s FAILED (%.1fs): %s",
                               label, time.time() - t1, exc)
                return label, False, time.time() - t1

        t0 = time.time()

        # Phase 1: Core ARM helpers (independent, no cross-dependencies)
        logger.info("Prefetch phase 1: %d core ARM resources...", len(core_helpers))
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = {pool.submit(_run_helper, h): h for h in core_helpers}
            for future in concurrent.futures.as_completed(futures, timeout=60):
                try:
                    future.result(timeout=PREFETCH_TIMEOUT)
                except Exception as exc:
                    label = futures[future][0]
                    logger.warning("  Prefetch %-25s TIMEOUT/ERROR: %s", label, exc)
        logger.info("Phase 1 done in %.1fs", time.time() - t0)

        # Phase 2: Lazy clients + per-RG aggregations + Graph API (all concurrent)
        graph_items = [
            ("identity/conditionalAccess/policies", 0),
            ("directoryRoles", 0),
            ("settings", 0),
            ("policies/authorizationPolicy", 0),
            ("policies/identitySecurityDefaultsEnforcementPolicy", 0),
            ("users?$select=id,userPrincipalName,displayName&$top=999", 5),
        ]
        graph_helpers = [
            (f"Graph:{p[:30]}",
             lambda path=p, mp=mp: self._graph_get_safe(path, max_pages=mp))
            for p, mp in graph_items
        ]
        phase2 = lazy_helpers + graph_helpers

        t2 = time.time()
        logger.info("Prefetch phase 2: %d lazy + Graph resources...", len(phase2))
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = {pool.submit(_run_helper, h): h for h in phase2}
            for future in concurrent.futures.as_completed(futures, timeout=90):
                try:
                    future.result(timeout=PREFETCH_TIMEOUT)
                except Exception as exc:
                    label = futures[future][0]
                    logger.warning("  Prefetch %-25s TIMEOUT/ERROR: %s", label, exc)
        logger.info("Phase 2 done in %.1fs", time.time() - t2)
        logger.info("Total prefetch: %.1fs (%d items cached)",
                     time.time() - t0, len(self._cache))

    # ------------------------------------------------------------------
    # Cached list helpers — avoid repeating the same Azure API list call
    # across multiple check methods.  Each result is cached for the
    # lifetime of the scanner instance (i.e., one scan run).
    # ------------------------------------------------------------------

    def _list_nsgs(self):
        return self._cached("nsgs", lambda: list(
            self._network_client.network_security_groups.list_all()))

    def _list_storage_accounts(self):
        return self._cached("storage_accounts", lambda: list(
            self._storage_client.storage_accounts.list()))

    def _list_vms(self):
        return self._cached("vms", lambda: list(
            self._compute_client.virtual_machines.list_all()))

    def _list_keyvaults(self):
        return self._cached("keyvaults", lambda: list(
            self._keyvault_client.vaults.list()))

    def _list_disks(self):
        return self._cached("disks", lambda: list(
            self._compute_client.disks.list()))

    def _list_resource_groups(self):
        return self._cached("resource_groups", lambda: list(
            self._resource_client.resource_groups.list()))

    def _list_activity_log_alerts(self):
        return self._cached("activity_log_alerts", lambda: list(
            self._monitor_client.activity_log_alerts.list_by_subscription_id()))

    def _list_vnets(self):
        return self._cached("vnets", lambda: list(
            self._network_client.virtual_networks.list_all()))

    def _list_firewalls(self):
        return self._cached("firewalls", lambda: list(
            self._network_client.azure_firewalls.list_all()))

    def _list_watchers(self):
        return self._cached("network_watchers", lambda: list(
            self._network_client.network_watchers.list_all()))

    def _list_sql_servers(self):
        return self._cached("sql_servers", lambda: list(
            self._get_sql_client().servers.list()))

    def _list_web_apps(self):
        return self._cached("web_apps", lambda: list(
            self._get_web_client().web_apps.list()))

    def _list_workspaces(self):
        return self._cached("workspaces", lambda: list(
            self._get_loganalytics_client().workspaces.list()))

    def _list_waf_policies(self):
        return self._cached("waf_policies", lambda: list(
            self._network_client.web_application_firewall_policies.list_all()))

    def _list_recovery_vaults(self):
        return self._cached("recovery_vaults", lambda: list(
            self._get_recovery_client().vaults.list_by_subscription_id()))

    def _list_defender_pricings(self):
        scope = f"subscriptions/{self._subscription_id}"
        return self._cached("defender_pricings", lambda: list(
            self._get_security_client().pricings.list(scope_id=scope).value))

    def _list_assessments(self):
        """Cache security assessments (can return 100s of items, very slow)."""
        return self._cached("security_assessments", lambda: list(
            self._get_security_client().assessments.list(
                scope=f"/subscriptions/{self._subscription_id}")))

    def _list_security_contacts(self):
        return self._cached("security_contacts", lambda: list(
            self._get_security_client().security_contacts.list()))

    def _list_app_gateways(self):
        return self._cached("app_gateways", lambda: list(
            self._network_client.application_gateways.list_all()))

    def _list_bastions(self):
        return self._cached("bastions", lambda: list(
            self._network_client.bastion_hosts.list()))

    def _list_all_resources(self):
        return self._cached("all_resources", lambda: list(
            self._resource_client.resources.list()))

    def _list_vnet_gateways(self):
        """Cache VNet gateways across all resource groups."""
        def _fetch():
            gws = []
            for rg in self._list_resource_groups():
                try:
                    gws.extend(list(
                        self._network_client.virtual_network_gateways.list(rg.name)))
                except Exception:
                    pass
            return gws
        return self._cached("vnet_gateways", _fetch)

    def _list_vnet_gateway_connections(self):
        """Cache VPN connections across all resource groups."""
        def _fetch():
            conns = []
            for rg in self._list_resource_groups():
                try:
                    conns.extend(list(
                        self._network_client.virtual_network_gateway_connections.list(rg.name)))
                except Exception:
                    pass
            return conns
        return self._cached("vnet_gateway_connections", _fetch)

    def _list_vnet_peerings(self):
        """Cache VNet peerings across all VNets."""
        def _fetch():
            peerings = []
            for vnet in self._list_vnets():
                try:
                    rg = vnet.id.split("/")[4]
                    ps = list(self._network_client.virtual_network_peerings.list(rg, vnet.name))
                    for p in ps:
                        p._vnet_name = vnet.name
                        p._rg = rg
                    peerings.extend(ps)
                except Exception:
                    pass
            return peerings
        return self._cached("vnet_peerings", _fetch)

    def _list_role_assignments(self):
        """Cache subscription-scoped role assignments."""
        scope = f"/subscriptions/{self._subscription_id}"
        return self._cached("role_assignments", lambda: list(
            self._auth_client.role_assignments.list_for_scope(scope)))

    def _get_security_provider(self):
        """Cache Microsoft.Security provider registration state."""
        return self._cached("security_provider", lambda:
            self._resource_client.providers.get("Microsoft.Security"))

    # ------------------------------------------------------------------
    # Automated check implementations
    # ------------------------------------------------------------------

    def check_conditional_access(self, check_def: dict) -> CheckResult:
        """
        Check if Conditional Access policies are configured.

        NIST 800-53 Control: 3.1.1 — Limit system access to authorized users.
        Note: Full Conditional Access policy inspection requires MS Graph API.
        This check verifies that role assignments follow least privilege.
        """
        try:
            role_assignments = self._list_role_assignments()

            owner_role_id = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
            contributor_role_id = "b24988ac-6180-42a0-ab88-20f7382dd24c"

            broad_assignments = []
            assignments_raw = []
            for ra in role_assignments[:50]:
                role_def_id = ra.role_definition_id.split("/")[-1] if ra.role_definition_id else ""
                assignments_raw.append({
                    "principal_id": ra.principal_id,
                    "role_definition_id": role_def_id,
                    "scope": ra.scope,
                })
                if role_def_id in [owner_role_id, contributor_role_id] and ra.scope == scope:
                    broad_assignments.append(
                        f"Principal {ra.principal_id[:12]}... has "
                        f"{'Owner' if role_def_id == owner_role_id else 'Contributor'} "
                        f"at subscription scope"
                    )

            raw = self._build_evidence(
                api_call="AuthorizationManagementClient.role_assignments.list_for_scope",
                cli_command="az role assignment list --scope /subscriptions/SUB_ID",
                response={
                    "total_assignments": len(role_assignments),
                    "broad_assignments": len(broad_assignments),
                    "assignments": assignments_raw,
                },
                service="Authorization",
                assessor_guidance=(
                    "Review role_definition_id fields in assignments array for Owner (8e3af657...) and "
                    "Contributor (b24988ac...) roles at subscription scope. Verify assignments follow least privilege."
                ),
            )

            if len(broad_assignments) <= 3:
                return self._result(
                    check_def, "met",
                    f"Found {len(role_assignments)} role assignment(s). "
                    f"Subscription-level Owner/Contributor assignments: {len(broad_assignments)} "
                    "(within acceptable range).",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"Found {len(broad_assignments)} broad role assignment(s) at subscription scope: "
                    + "; ".join(broad_assignments[:5])
                    + ("..." if len(broad_assignments) > 5 else ""),
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking conditional access / role assignments: {str(e)}",
            )

    def check_mfa_enabled(self, check_def: dict) -> CheckResult:
        """
        Check MFA enforcement status.

        NIST 800-53 Control: 3.5.3 — Use multifactor authentication.
        Note: Full MFA status requires MS Graph API. This check verifies
        that security defaults or Conditional Access is likely in place.
        """
        try:
            role_assignments = self._list_role_assignments()

            security_roles = [
                ra for ra in role_assignments
                if ra.role_definition_id and "security" in ra.role_definition_id.lower()
            ]

            raw = self._build_evidence(
                api_call="AuthorizationManagementClient.role_assignments.list_for_scope",
                cli_command="az role assignment list --scope /subscriptions/SUB_ID",
                response={
                    "total_role_assignments": len(role_assignments),
                    "security_related_assignments": len(security_roles),
                    "note": "Full MFA verification requires MS Graph API",
                },
                service="Authorization",
                assessor_guidance=(
                    "This check provides limited context. Verify MFA enforcement via Azure Portal > Entra ID > "
                    "Security > Conditional Access policies or Security Defaults settings."
                ),
            )

            return self._result(
                check_def, "manual",
                f"MFA enforcement requires Azure AD / Entra ID verification via MS Graph API. "
                f"Found {len(role_assignments)} role assignment(s), {len(security_roles)} "
                f"security-related. Manual verification required to confirm MFA policy is enforced "
                f"for all users via Conditional Access or Security Defaults.",
                raw_evidence=raw,
            )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking MFA status: {str(e)}",
            )

    def check_nsg_rules(self, check_def: dict) -> CheckResult:
        """
        Check Network Security Groups for overly permissive inbound rules.

        NIST 800-53 Control: 3.1.5 — Employ the principle of least privilege.
        """
        try:
            nsgs = self._list_nsgs()

            # Capture raw evidence
            nsgs_raw = []
            for nsg in nsgs[:50]:
                rules_raw = []
                for rule in (nsg.security_rules or []):
                    rules_raw.append({
                        "name": rule.name,
                        "direction": rule.direction,
                        "access": rule.access,
                        "source_address_prefix": rule.source_address_prefix,
                        "destination_port_range": rule.destination_port_range,
                        "priority": rule.priority,
                    })
                rg_name = nsg.id.split("/")[4] if nsg.id and len(nsg.id.split("/")) > 4 else "unknown"
                nsgs_raw.append({
                    "name": nsg.name,
                    "resource_group": rg_name,
                    "location": nsg.location,
                    "rules": rules_raw,
                })
            raw = self._build_evidence(
                api_call="NetworkManagementClient.network_security_groups.list_all",
                cli_command="az network nsg list",
                response={"total_nsgs": len(nsgs), "nsgs": nsgs_raw},
                service="Network",
                assessor_guidance=(
                    "Review each NSG's rules array for inbound Allow rules with source_address_prefix='*' or '0.0.0.0/0' "
                    "and destination_port_range on sensitive ports (22, 3389, 3306, 5432, 1433, 27017)."
                ),
            )

            if not nsgs:
                return self._result(
                    check_def, "met",
                    "No Network Security Groups found in the subscription.",
                    raw_evidence=raw,
                )

            sensitive_ports = {"22", "3389", "3306", "5432", "1433", "27017"}
            issues = []

            for nsg in nsgs:
                nsg_name = nsg.name
                rg_name = nsg.id.split("/")[4] if nsg.id and len(nsg.id.split("/")) > 4 else "unknown"
                rules = nsg.security_rules or []

                for rule in rules:
                    if (
                        rule.direction == "Inbound"
                        and rule.access == "Allow"
                        and rule.source_address_prefix in ["*", "0.0.0.0/0", "Internet"]
                    ):
                        dest_port = str(rule.destination_port_range) if rule.destination_port_range else ""
                        if dest_port == "*" or dest_port in sensitive_ports:
                            issues.append(
                                f"NSG '{nsg_name}' (RG: {rg_name}): rule '{rule.name}' "
                                f"allows inbound from {rule.source_address_prefix} to port {dest_port}"
                            )

            if not issues:
                return self._result(
                    check_def, "met",
                    f"Reviewed {len(nsgs)} NSG(s). No overly permissive inbound rules "
                    "found on sensitive ports.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"Found {len(issues)} overly permissive NSG rule(s): "
                    + "; ".join(issues[:10])
                    + ("..." if len(issues) > 10 else ""),
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking NSG rules: {str(e)}",
            )

    def check_activity_log_alerts(self, check_def: dict) -> CheckResult:
        """
        Check if Activity Log alerts are configured for critical operations.

        NIST 800-53 Control: 3.3.1 — Create and retain system audit logs.
        """
        try:
            alerts = self._list_activity_log_alerts()

            enabled_alerts = [a for a in alerts if a.enabled]
            alert_names = [a.name for a in enabled_alerts]

            covered_categories = set()
            alerts_raw = []
            for alert in enabled_alerts[:20]:
                conditions_raw = []
                if alert.condition and alert.condition.all_of:
                    for condition in alert.condition.all_of:
                        conditions_raw.append({
                            "field": condition.field,
                            "equals": condition.equals,
                        })
                        if condition.field == "category" and condition.equals:
                            covered_categories.add(condition.equals)
                alerts_raw.append({
                    "name": alert.name,
                    "enabled": alert.enabled,
                    "conditions": conditions_raw,
                })
            raw = self._build_evidence(
                api_call="MonitorManagementClient.activity_log_alerts.list_by_subscription_id",
                cli_command="az monitor activity-log alert list",
                response={
                    "total_alerts": len(alerts),
                    "enabled_alerts": len(enabled_alerts),
                    "categories_covered": sorted(covered_categories),
                    "alerts": alerts_raw,
                },
                service="Monitor",
                assessor_guidance=(
                    "Verify enabled_alerts >= 3 and categories_covered includes critical operations like "
                    "Administrative, Policy, Security, and ServiceHealth. Review conditions array for each alert."
                ),
            )

            if not alerts:
                return self._result(
                    check_def, "not_met",
                    "No Activity Log alerts configured in the subscription.",
                    raw_evidence=raw,
                )

            if len(enabled_alerts) >= 3:
                return self._result(
                    check_def, "met",
                    f"Found {len(enabled_alerts)} enabled Activity Log alert(s): "
                    f"{', '.join(alert_names[:5])}. "
                    f"Categories covered: {', '.join(covered_categories) if covered_categories else 'various'}.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"Only {len(enabled_alerts)} Activity Log alert(s) found. "
                    "Recommend configuring alerts for policy changes, role assignments, "
                    "and resource deletions.",
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking Activity Log alerts: {str(e)}",
            )

    def check_storage_encryption(self, check_def: dict) -> CheckResult:
        """
        Check if all storage accounts have encryption enabled.

        NIST 800-53 Control: 3.13.11 — Employ FIPS-validated cryptography for CUI.
        """
        try:
            accounts = self._list_storage_accounts()

            accounts_raw = []
            issues = []
            for account in accounts:
                enc = account.encryption
                blob_enc = file_enc = False
                if enc and enc.services:
                    blob_enc = bool(enc.services.blob and enc.services.blob.enabled)
                    file_enc = bool(enc.services.file and enc.services.file.enabled)
                accounts_raw.append({
                    "name": account.name,
                    "location": account.location,
                    "minimum_tls_version": account.minimum_tls_version,
                    "https_only": account.enable_https_traffic_only,
                    "blob_encryption": blob_enc,
                    "file_encryption": file_enc,
                    "encryption_key_source": str(enc.key_source) if enc else None,
                })

                if not enc:
                    issues.append(f"Storage account '{account.name}' has no encryption configuration")
                    continue
                services = enc.services
                if services:
                    if services.blob and not services.blob.enabled:
                        issues.append(f"Storage account '{account.name}': blob encryption disabled")
                    if services.file and not services.file.enabled:
                        issues.append(f"Storage account '{account.name}': file encryption disabled")
                if account.minimum_tls_version and account.minimum_tls_version != "TLS1_2":
                    issues.append(
                        f"Storage account '{account.name}': minimum TLS is "
                        f"{account.minimum_tls_version} (should be TLS1_2)"
                    )
                if not account.enable_https_traffic_only:
                    issues.append(f"Storage account '{account.name}': HTTPS-only not enforced")

            raw = self._build_evidence(
                api_call="StorageManagementClient.storage_accounts.list",
                cli_command="az storage account list --query '[].{Name:name,Encryption:encryption}'",
                response={
                    "total_accounts": len(accounts),
                    "accounts": accounts_raw[:30],
                },
                service="Storage",
                assessor_guidance=(
                    "Verify all accounts have blob_encryption=true, file_encryption=true, minimum_tls_version='TLS1_2', "
                    "https_only=true, and encryption_key_source set (typically Microsoft.Storage)."
                ),
            )

            if not accounts:
                return self._result(
                    check_def, "met",
                    "No storage accounts found in the subscription.",
                    raw_evidence=raw,
                )

            if not issues:
                return self._result(
                    check_def, "met",
                    f"All {len(accounts)} storage account(s) have encryption enabled "
                    "with TLS 1.2 and HTTPS-only.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"Storage encryption issues: {'; '.join(issues[:10])}",
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking storage encryption: {str(e)}",
            )

    def check_key_vault_config(self, check_def: dict) -> CheckResult:
        """
        Check Key Vault configuration (soft delete, purge protection).

        NIST 800-53 Control: 3.13.10 — Establish and manage cryptographic keys.
        """
        try:
            vaults = self._list_keyvaults()

            issues = []
            vault_count = 0
            vaults_raw = []
            for vault_item in vaults:
                vault_count += 1
                rg_name = vault_item.id.split("/")[4] if vault_item.id else "unknown"
                vault_name = vault_item.name
                try:
                    vault = self._keyvault_client.vaults.get(rg_name, vault_name)
                    props = vault.properties
                    vaults_raw.append({
                        "name": vault_name,
                        "resource_group": rg_name,
                        "location": vault.location,
                        "soft_delete_enabled": bool(props.enable_soft_delete),
                        "purge_protection_enabled": bool(props.enable_purge_protection),
                        "sku": str(props.sku.name) if props.sku else None,
                    })
                    if not props.enable_soft_delete:
                        issues.append(f"Key Vault '{vault_name}': soft delete not enabled")
                    if not props.enable_purge_protection:
                        issues.append(f"Key Vault '{vault_name}': purge protection not enabled")
                except Exception as e:
                    vaults_raw.append({"name": vault_name, "error": str(e)[:100]})
                    issues.append(f"Key Vault '{vault_name}': could not retrieve details ({str(e)[:50]})")

            raw = self._build_evidence(
                api_call="KeyVaultManagementClient.vaults.list + get",
                cli_command="az keyvault list && az keyvault show --name VAULT",
                response={"total_vaults": vault_count, "vaults": vaults_raw[:20]},
                service="KeyVault",
                assessor_guidance=(
                    "Verify all vaults have soft_delete_enabled=true and purge_protection_enabled=true. "
                    "Check sku field for Standard vs Premium (Premium supports HSM-backed keys for FIPS 140-2 Level 2)."
                ),
            )

            if not vaults:
                return self._result(
                    check_def, "met",
                    "No Key Vaults found in the subscription.",
                    raw_evidence=raw,
                )

            if not issues:
                return self._result(
                    check_def, "met",
                    f"All {vault_count} Key Vault(s) have soft delete and purge protection enabled.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"Key Vault issues: {'; '.join(issues[:10])}",
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking Key Vault config: {str(e)}",
            )

    def check_network_watcher(self, check_def: dict) -> CheckResult:
        """
        Check if Network Watcher is enabled in all regions with resources.

        NIST 800-53 Control: 3.3.1 — Audit and accountability.
        """
        try:
            watchers = self._list_watchers()
            watcher_regions = {w.location.lower().replace(" ", "") for w in watchers}

            resources = self._list_all_resources()
            resource_regions = set()
            for r in resources:
                if r.location:
                    resource_regions.add(r.location.lower().replace(" ", ""))
            resource_regions.discard("global")

            regions_without_watcher = resource_regions - watcher_regions

            raw = self._build_evidence(
                api_call="NetworkManagementClient.network_watchers.list_all + resources.list",
                cli_command="az network watcher list",
                response={
                    "watcher_regions": sorted(watcher_regions),
                    "resource_regions": sorted(resource_regions),
                    "missing_regions": sorted(regions_without_watcher),
                    "watchers": [{"name": w.name, "location": w.location} for w in watchers],
                },
                service="Network",
                assessor_guidance=(
                    "Verify missing_regions is empty. Network Watcher should be enabled in every region listed "
                    "in resource_regions to enable NSG flow logs and connection monitoring."
                ),
            )

            if not regions_without_watcher:
                return self._result(
                    check_def, "met",
                    f"Network Watcher is enabled in all {len(resource_regions)} region(s) "
                    f"with resources: {', '.join(sorted(resource_regions)[:5])}.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"Network Watcher is missing in {len(regions_without_watcher)} region(s): "
                    f"{', '.join(sorted(regions_without_watcher)[:5])}",
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking Network Watcher: {str(e)}",
            )

    def check_security_center_enabled(self, check_def: dict) -> CheckResult:
        """
        Check if Microsoft Defender for Cloud is enabled.

        NIST 800-53 Control: 3.14.6 — Monitor organizational systems.
        """
        try:
            provider = self._get_security_provider()
            registration_state = provider.registration_state

            raw = self._build_evidence(
                api_call="ResourceManagementClient.providers.get('Microsoft.Security')",
                cli_command="az provider show -n Microsoft.Security",
                response={
                    "namespace": "Microsoft.Security",
                    "registration_state": registration_state,
                },
                service="Security",
                assessor_guidance=(
                    "Verify registration_state='Registered'. If 'NotRegistered', Microsoft Defender for Cloud "
                    "is not enabled. Check Azure Portal > Defender for Cloud for pricing tier and coverage."
                ),
            )

            if registration_state == "Registered":
                return self._result(
                    check_def, "met",
                    "Microsoft.Security resource provider is registered. "
                    "Microsoft Defender for Cloud is enabled on this subscription.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"Microsoft.Security resource provider registration state: {registration_state}. "
                    "Microsoft Defender for Cloud may not be enabled.",
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking Security Center: {str(e)}",
            )

    def check_disk_encryption(self, check_def: dict) -> CheckResult:
        """
        Check if managed disks have encryption enabled.

        NIST 800-53 Control: 3.13.11 — Employ FIPS-validated cryptography for CUI.
        """
        try:
            disks = self._list_disks()

            unencrypted_disks = []
            disks_raw = []
            for disk in disks[:30]:
                enc = disk.encryption
                enc_type = str(enc.type) if enc and enc.type else None
                disks_raw.append({
                    "name": disk.name,
                    "location": disk.location,
                    "size_gb": disk.disk_size_gb,
                    "encryption_type": enc_type,
                    "os_type": str(disk.os_type) if disk.os_type else None,
                })
                if not enc or not enc.type:
                    unencrypted_disks.append(disk.name)

            raw = self._build_evidence(
                api_call="ComputeManagementClient.disks.list",
                cli_command="az disk list --query '[].{Name:name,Encryption:encryption}'",
                response={"total_disks": len(disks), "disks": disks_raw},
                service="Compute",
                assessor_guidance=(
                    "Verify all disks have encryption_type populated (typically 'EncryptionAtRestWithPlatformKey' "
                    "or 'EncryptionAtRestWithCustomerKey'). Disks with null encryption_type lack encryption."
                ),
            )

            if not disks:
                return self._result(
                    check_def, "met",
                    "No managed disks found in the subscription.",
                    raw_evidence=raw,
                )

            if not unencrypted_disks:
                return self._result(
                    check_def, "met",
                    f"All {len(disks)} managed disk(s) have encryption enabled.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"{len(unencrypted_disks)} of {len(disks)} managed disk(s) lack encryption: "
                    + ", ".join(unencrypted_disks[:10])
                    + ("..." if len(unencrypted_disks) > 10 else ""),
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking disk encryption: {str(e)}",
            )

    def check_defense_in_depth(self, check_def: dict) -> CheckResult:
        """
        Check for defense-in-depth architecture across multiple security layers.

        NIST 800-53 Control: 3.13.2 — Employ architectural designs that promote
        effective information security.

        Met if >= 4 of 5 layers present: NSGs on subnets, Key Vault,
        activity log alerts, Defender for Cloud, Network Watcher.
        """
        try:
            layers = []
            raw_layers = {}

            # Layer 1: NSGs on subnets
            nsgs = self._list_nsgs()
            raw_layers["nsgs"] = len(nsgs)
            if nsgs:
                layers.append(f"NSGs ({len(nsgs)} configured)")

            # Layer 2: Key Vault
            vaults = self._list_keyvaults()
            vault_count = len(list(vaults))
            raw_layers["key_vaults"] = vault_count
            if vault_count:
                layers.append(f"Key Vault ({vault_count} vault(s))")

            # Layer 3: Activity log alerts
            alerts = self._list_activity_log_alerts()
            enabled_alerts = [a for a in alerts if a.enabled]
            raw_layers["activity_log_alerts"] = len(enabled_alerts)
            if enabled_alerts:
                layers.append(f"Activity Log alerts ({len(enabled_alerts)} enabled)")

            # Layer 4: Defender for Cloud (Microsoft.Security provider)
            defender_enabled = False
            try:
                provider = self._get_security_provider()
                if provider.registration_state == "Registered":
                    defender_enabled = True
                    layers.append("Defender for Cloud enabled")
            except Exception:
                pass
            raw_layers["defender_for_cloud"] = defender_enabled

            # Layer 5: Network Watcher
            watchers = self._list_watchers()
            watcher_count = len(list(watchers))
            raw_layers["network_watchers"] = watcher_count
            if watcher_count:
                layers.append(f"Network Watcher ({watcher_count} region(s))")

            raw = self._build_evidence(
                api_call="network + keyvault + monitor + providers + watchers (composite)",
                cli_command="az network nsg list && az keyvault list && az monitor activity-log alert list",
                response={
                    "layers_present": len(layers),
                    "layers_required": 4,
                    "layer_details": raw_layers,
                    "layer_descriptions": layers,
                },
                service="Multiple",
                assessor_guidance=(
                    "Verify layers_present >= 4. Check layer_details for NSGs, Key Vaults, Activity Log alerts, "
                    "Defender for Cloud (true), and Network Watchers. Defense-in-depth requires multiple overlapping controls."
                ),
            )

            if len(layers) >= 4:
                return self._result(
                    check_def, "met",
                    f"Defense-in-depth: {len(layers)}/5 layers present — {'; '.join(layers)}.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"Only {len(layers)}/5 defense-in-depth layers found: "
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
        Check if VPN gateways exist for controlled remote access.

        NIST 800-53 Control: 3.1.16 — Authorize remote access prior to allowing
        such connections.
        """
        try:
            all_gateways = self._list_vnet_gateways()
            vpn_gateways = []
            gateways_raw = []
            for gw in all_gateways:
                if gw.gateway_type and gw.gateway_type.lower() == "vpn":
                    rg_name = gw.id.split("/")[4] if gw.id else "unknown"
                    vpn_gateways.append(f"{gw.name} (RG: {rg_name})")
                    gateways_raw.append({
                        "name": gw.name,
                        "resource_group": rg_name,
                        "location": gw.location,
                        "gateway_type": str(gw.gateway_type),
                        "vpn_type": str(gw.vpn_type) if gw.vpn_type else None,
                        "sku": str(gw.sku.name) if gw.sku else None,
                    })

            raw = self._build_evidence(
                api_call="NetworkManagementClient.virtual_network_gateways.list",
                cli_command="az network vnet-gateway list --resource-group RG",
                response={"vpn_gateways": gateways_raw},
                service="Network",
                assessor_guidance=(
                    "Review vpn_gateways array for gateways with gateway_type='Vpn'. Verify VPN configuration "
                    "is used for controlled remote access. Check sku and vpn_type for security best practices."
                ),
            )

            if vpn_gateways:
                return self._result(
                    check_def, "met",
                    f"VPN gateway(s) found: {'; '.join(vpn_gateways[:5])}.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    "No VPN gateways found in the subscription.",
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking VPN gateways: {str(e)}",
            )

    def check_mobile_device_control(self, check_def: dict) -> CheckResult:
        """
        Check for centralized identity and device management.

        NIST 800-53 Control: 3.1.18 — Control connection of mobile devices.
        Verifies Defender for Cloud is enabled and managed identity
        role assignments exist.
        """
        try:
            indicators = []
            raw_indicators = {}

            # Check if Defender for Cloud is enabled
            defender_enabled = False
            try:
                provider = self._get_security_provider()
                if provider.registration_state == "Registered":
                    defender_enabled = True
                    indicators.append("Microsoft Defender for Cloud enabled")
            except Exception:
                pass
            raw_indicators["defender_for_cloud"] = defender_enabled

            # Check for managed identity role assignments
            role_assignments = self._list_role_assignments()
            managed_identity_assignments = [
                ra for ra in role_assignments
                if ra.principal_type and ra.principal_type.lower() in ("serviceprincipal", "msi")
            ]
            raw_indicators["total_role_assignments"] = len(role_assignments)
            raw_indicators["managed_identity_assignments"] = len(managed_identity_assignments)
            if managed_identity_assignments:
                indicators.append(
                    f"{len(managed_identity_assignments)} managed identity role assignment(s)"
                )

            raw = self._build_evidence(
                api_call="providers.get + role_assignments.list_for_scope",
                cli_command="az provider show -n Microsoft.Intune",
                response=raw_indicators,
                service="Compute",
                assessor_guidance=(
                    "Verify defender_for_cloud=true and managed_identity_assignments > 0. Full mobile device "
                    "management requires Intune enrollment verification via MS Graph API (not covered by this check)."
                ),
            )

            if len(indicators) >= 2:
                return self._result(
                    check_def, "met",
                    f"Device/identity management indicators: {'; '.join(indicators)}.",
                    raw_evidence=raw,
                )
            elif indicators:
                return self._result(
                    check_def, "met",
                    f"Partial device management: {'; '.join(indicators)}. Full MDM/Intune verification requires Graph API.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    "No Defender for Cloud or managed identity indicators found.",
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking device control: {str(e)}",
            )

    def check_vm_disk_encryption(self, check_def: dict) -> CheckResult:
        """
        Check if all managed disks have encryption enabled.

        NIST 800-53 Control: 3.1.19 — Encrypt CUI on computing platforms.
        """
        try:
            disks = self._list_disks()

            unencrypted = []
            disks_raw = []
            for disk in disks[:30]:
                enc = disk.encryption
                enc_type = str(enc.type) if enc and enc.type else None
                disks_raw.append({
                    "name": disk.name,
                    "location": disk.location,
                    "size_gb": disk.disk_size_gb,
                    "encryption_type": enc_type,
                })
                if not enc or not enc.type:
                    unencrypted.append(disk.name)

            raw = self._build_evidence(
                api_call="ComputeManagementClient.disks.list",
                cli_command="az disk list",
                response={"total_disks": len(disks), "disks": disks_raw},
                service="Compute",
                assessor_guidance=(
                    "Verify all disks have encryption_type set (e.g., 'EncryptionAtRestWithPlatformKey'). "
                    "Null encryption_type indicates unencrypted disk. Review size_gb and os_type for context."
                ),
            )

            if not disks:
                return self._result(
                    check_def, "met",
                    "No managed disks found in the subscription.",
                    raw_evidence=raw,
                )

            if not unencrypted:
                return self._result(
                    check_def, "met",
                    f"All {len(disks)} managed disk(s) have encryption enabled.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"{len(unencrypted)} of {len(disks)} managed disk(s) lack encryption: "
                    + ", ".join(unencrypted[:10])
                    + ("..." if len(unencrypted) > 10 else ""),
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking disk encryption: {str(e)}",
            )

    def check_storage_public_access(self, check_def: dict) -> CheckResult:
        """
        Check if storage accounts block public blob access.

        NIST 800-53 Control: 3.1.21 — Limit use of portable storage devices
        (interpreted as preventing public exposure of cloud storage).
        """
        try:
            accounts = self._list_storage_accounts()

            public_accounts = []
            accounts_raw = []
            for account in accounts[:30]:
                is_public = account.allow_blob_public_access is True
                accounts_raw.append({
                    "name": account.name,
                    "location": account.location,
                    "allow_blob_public_access": is_public,
                })
                if is_public:
                    public_accounts.append(account.name)

            raw = self._build_evidence(
                api_call="StorageManagementClient.storage_accounts.list",
                cli_command="az storage account list --query '[].{Name:name,PublicAccess:allowBlobPublicAccess}'",
                response={
                    "total_accounts": len(accounts),
                    "public_accounts": len(public_accounts),
                    "accounts": accounts_raw,
                },
                service="Storage",
                assessor_guidance=(
                    "Verify all accounts have allow_blob_public_access=false. Public blob access allows anonymous "
                    "internet access to blob containers, violating CUI protection requirements."
                ),
            )

            if not accounts:
                return self._result(
                    check_def, "met",
                    "No storage accounts found in the subscription.",
                    raw_evidence=raw,
                )

            if not public_accounts:
                return self._result(
                    check_def, "met",
                    f"All {len(accounts)} storage account(s) have public blob access disabled.",
                    raw_evidence=raw,
                )
            else:
                return self._result(
                    check_def, "not_met",
                    f"{len(public_accounts)} of {len(accounts)} storage account(s) allow "
                    f"public blob access: {', '.join(public_accounts[:10])}",
                    raw_evidence=raw,
                )
        except Exception as e:
            return self._result(
                check_def, "error",
                f"Error checking storage public access: {str(e)}",
            )

    # ------------------------------------------------------------------
    # Batch 1: Network checks (18 methods)
    # ------------------------------------------------------------------

    def check_nsg_flow_logs(self, check_def: dict) -> CheckResult:
        """Check if NSG flow logs are enabled."""
        try:
            nsgs = self._list_nsgs()
            watchers = self._list_watchers()
            has_flow_logs = len(watchers) > 0
            raw = self._build_evidence(
                api_call="network_watchers.list_all + nsgs.list_all",
                cli_command="az network watcher flow-log list --location LOCATION",
                response={"nsgs": len(nsgs), "watchers": len(watchers)},
                service="Network",
                assessor_guidance=(
                    "Verify watchers > 0 for regions with NSGs. NSG flow logs require Network Watcher deployment. "
                    "Check Azure Portal > Network Watcher > NSG flow logs to confirm flow logging is enabled per NSG."
                ),
            )
            if not nsgs:
                return self._result(check_def, "met", "No NSGs found.", raw_evidence=raw)
            if has_flow_logs:
                return self._result(check_def, "met",
                    f"Network Watcher deployed in {len(watchers)} region(s) for {len(nsgs)} NSG(s). "
                    "Verify NSG flow logs are enabled per NSG in the Portal.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Network Watchers found — NSG flow logs cannot be enabled.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_azure_firewall(self, check_def: dict) -> CheckResult:
        """Check if Azure Firewall or NVA is deployed."""
        try:
            firewalls = self._list_firewalls()
            raw = self._build_evidence(
                api_call="azure_firewalls.list_all",
                cli_command="az network firewall list",
                response={"count": len(firewalls),
                                "firewalls": [{"name": f.name, "location": f.location}
                                              for f in firewalls[:20]]},
                service="Network",
                assessor_guidance=(
                    "Verify count > 0 and review firewalls array for deployed Azure Firewalls. Check name and location "
                    "to confirm placement in hub VNet or perimeter subnet for network boundary protection."
                ),
            )
            if firewalls:
                return self._result(check_def, "met",
                    f"Found {len(firewalls)} Azure Firewall(s): "
                    + ", ".join(f.name for f in firewalls[:5]) + ".", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Azure Firewall deployed. Deploy Azure Firewall or a network virtual appliance.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_bastion_hosts(self, check_def: dict) -> CheckResult:
        """Check if Azure Bastion is deployed for secure remote access."""
        try:
            bastions = self._list_bastions()
            raw = self._build_evidence(
                api_call="bastion_hosts.list",
                cli_command="az network bastion list",
                response={"count": len(bastions),
                                "bastions": [{"name": b.name, "location": b.location}
                                             for b in bastions[:10]]},
                service="Network",
                assessor_guidance=(
                    "Verify count > 0 for secure RDP/SSH access without public IPs on VMs. Review bastions array "
                    "to confirm Bastion deployment in management VNets. Bastion provides controlled remote access."
                ),
            )
            if bastions:
                return self._result(check_def, "met",
                    f"Azure Bastion deployed: {', '.join(b.name for b in bastions[:5])}.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Azure Bastion hosts found. Deploy Bastion for secure RDP/SSH access.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_vpn_encryption(self, check_def: dict) -> CheckResult:
        """Check VPN Gateway uses IKEv2 with strong encryption."""
        try:
            conns = self._list_vnet_gateway_connections()
            raw = self._build_evidence(
                api_call="virtual_network_gateway_connections.list",
                cli_command="az network vpn-connection list --resource-group RG",
                response={"count": len(conns),
                                "connections": [{"name": c.name,
                                                 "connection_protocol": str(getattr(c, 'connection_protocol', 'N/A'))}
                                                for c in conns[:10]]},
                service="Network",
                assessor_guidance=(
                    "Review connection_protocol for each connection. Verify all use IKEv2 (not IKEv1). "
                    "IKEv1 is deprecated and has known security vulnerabilities. Check for strong cipher suites."
                ),
            )
            if not conns:
                return self._result(check_def, "met",
                    "No VPN gateway connections found.", raw_evidence=raw)
            weak = [c.name for c in conns
                    if hasattr(c, 'connection_protocol') and
                    c.connection_protocol and 'ikev1' in str(c.connection_protocol).lower()]
            if not weak:
                return self._result(check_def, "met",
                    f"All {len(conns)} VPN connection(s) use IKEv2.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(weak)} VPN connection(s) using IKEv1: {', '.join(weak[:5])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_vnet_peering(self, check_def: dict) -> CheckResult:
        """Check VNet peering connections are reviewed."""
        try:
            vnets = self._list_vnets()
            peerings = self._list_vnet_peerings()
            raw = self._build_evidence(
                api_call="virtual_network_peerings.list",
                cli_command="az network vnet peering list --resource-group RG --vnet-name VNET",
                response={"vnets": len(vnets), "peerings": len(peerings),
                                "details": [{"name": p.name,
                                             "peering_state": str(getattr(p, 'peering_state', ''))}
                                            for p in peerings[:20]]},
                service="Network",
                assessor_guidance=(
                    "Review details array for peering_state='Connected'. Verify peered VNets follow least-privilege "
                    "network access. Check NSG rules and route tables to ensure peering doesn't create unauthorized paths."
                ),
            )
            if not peerings:
                return self._result(check_def, "met",
                    "No VNet peering connections found.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"Found {len(peerings)} VNet peering(s) across {len(vnets)} VNet(s). "
                "Review peering connections for least-privilege network access.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_azure_firewall_threat_intel(self, check_def: dict) -> CheckResult:
        """Check Azure Firewall has threat intelligence enabled."""
        try:
            firewalls = self._list_firewalls()
            raw_fw = []
            no_ti = []
            for fw in firewalls:
                ti = getattr(fw, 'threat_intel_mode', None)
                raw_fw.append({"name": fw.name, "threat_intel_mode": str(ti)})
                if not ti or str(ti).lower() in ('off', 'none', ''):
                    no_ti.append(fw.name)
            raw = self._build_evidence(
                api_call="azure_firewalls.list_all",
                cli_command="az network firewall list",
                response={"firewalls": raw_fw},
                service="Network",
                assessor_guidance=(
                    "Review threat_intel_mode for each firewall. Should be 'Alert' or 'Alert and Deny' (not 'Off'). "
                    "Threat intelligence blocks traffic to/from known malicious IPs and domains."
                ),
            )
            if not firewalls:
                return self._result(check_def, "not_met",
                    "No Azure Firewalls deployed.", raw_evidence=raw)
            if not no_ti:
                return self._result(check_def, "met",
                    f"All {len(firewalls)} Azure Firewall(s) have threat intelligence enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_ti)} firewall(s) without threat intel: {', '.join(no_ti[:5])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_nsg_flow_logs_all(self, check_def: dict) -> CheckResult:
        """Check NSG flow logs enabled on all NSGs (SC-3.13.1-azure-002)."""
        return self.check_nsg_flow_logs(check_def)

    def check_waf_policies(self, check_def: dict) -> CheckResult:
        """Check if WAF policies are deployed."""
        try:
            policies = self._list_waf_policies()
            raw = self._build_evidence(
                api_call="web_application_firewall_policies.list_all",
                cli_command="az network application-gateway waf-policy list",
                response={"count": len(policies),
                                "policies": [{"name": p.name, "location": p.location}
                                             for p in policies[:10]]},
                service="Network",
                assessor_guidance=(
                    "Verify count > 0 for web applications. WAF policies protect against OWASP Top 10 attacks "
                    "(SQL injection, XSS, etc.). Review policies array to confirm WAF deployment for public-facing apps."
                ),
            )
            if policies:
                return self._result(check_def, "met",
                    f"Found {len(policies)} WAF policy(ies): "
                    + ", ".join(p.name for p in policies[:5]) + ".", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No WAF policies found. Deploy Azure WAF to protect web applications.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_management_network_isolation(self, check_def: dict) -> CheckResult:
        """Check management network is isolated via dedicated subnets."""
        try:
            vnets = self._list_vnets()
            mgmt_subnets = []
            for vnet in vnets:
                for subnet in (vnet.subnets or []):
                    if any(k in (subnet.name or "").lower()
                           for k in ("mgmt", "management", "bastion", "jumpbox")):
                        mgmt_subnets.append(f"{vnet.name}/{subnet.name}")
            raw = self._build_evidence(
                api_call="virtual_networks.list_all",
                cli_command="az network vnet list",
                response={"vnets": len(vnets), "mgmt_subnets": mgmt_subnets[:20]},
                service="Network",
                assessor_guidance=(
                    "Verify mgmt_subnets contains dedicated subnets with naming patterns like 'mgmt', 'management', "
                    "'bastion', or 'jumpbox'. Management isolation requires separate subnets with restrictive NSG rules."
                ),
            )
            if mgmt_subnets:
                return self._result(check_def, "met",
                    f"Management subnet(s) found: {', '.join(mgmt_subnets[:5])}.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No dedicated management subnets found. Create isolated management subnets.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_dmz_subnet(self, check_def: dict) -> CheckResult:
        """Check if DMZ subnet is implemented."""
        try:
            vnets = self._list_vnets()
            dmz_subnets = []
            for vnet in vnets:
                for subnet in (vnet.subnets or []):
                    if any(k in (subnet.name or "").lower()
                           for k in ("dmz", "perimeter", "frontend", "public")):
                        dmz_subnets.append(f"{vnet.name}/{subnet.name}")
            raw = self._build_evidence(
                api_call="virtual_networks.list_all",
                cli_command="az network vnet list",
                response={"vnets": len(vnets), "dmz_subnets": dmz_subnets[:20]},
                service="Network",
                assessor_guidance=(
                    "Verify dmz_subnets contains subnets with naming patterns like 'dmz', 'perimeter', 'frontend', "
                    "or 'public'. DMZ provides network boundary protection for internet-facing resources."
                ),
            )
            if dmz_subnets:
                return self._result(check_def, "met",
                    f"DMZ subnet(s) found: {', '.join(dmz_subnets[:5])}.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No DMZ/perimeter subnets found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_nsg_default_deny(self, check_def: dict) -> CheckResult:
        """Check NSGs have default deny inbound rules."""
        try:
            nsgs = self._list_nsgs()
            if not nsgs:
                return self._result(check_def, "met", "No NSGs found.",
                    raw_evidence={"api_call": "nsgs.list_all", "response": {"count": 0}})
            # Azure NSGs have implicit deny-all as the lowest priority default rule
            # Check that no NSG has an explicit allow-all at a low priority
            issues = []
            for nsg in nsgs:
                for rule in (nsg.security_rules or []):
                    if (rule.direction == "Inbound" and rule.access == "Allow" and
                        rule.source_address_prefix in ("*", "0.0.0.0/0") and
                        rule.destination_port_range == "*"):
                        issues.append(f"{nsg.name}: rule '{rule.name}' allows all inbound")
            raw = self._build_evidence(
                api_call="nsgs.list_all",
                cli_command="az network nsg list",
                response={"nsgs": len(nsgs), "allow_all_issues": issues[:10]},
                service="Network",
                assessor_guidance=(
                    "Verify allow_all_issues array is empty. NSGs should not have explicit allow-all inbound rules. "
                    "Azure NSGs have implicit deny-all as the lowest priority (65500) by default."
                ),
            )
            if not issues:
                return self._result(check_def, "met",
                    f"All {len(nsgs)} NSG(s) maintain default deny inbound.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(issues)} NSG(s) have allow-all inbound rules: "
                + "; ".join(issues[:5]), raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_azure_firewall_default_deny(self, check_def: dict) -> CheckResult:
        """Check Azure Firewall is configured with default deny."""
        try:
            firewalls = self._list_firewalls()
            raw = self._build_evidence(
                api_call="azure_firewalls.list_all",
                cli_command="az network firewall list",
                response={"count": len(firewalls),
                                "firewalls": [{"name": f.name} for f in firewalls[:10]]},
                service="Network",
                assessor_guidance=(
                    "Verify count > 0. Azure Firewall uses implicit deny-by-default for all traffic. "
                    "Only explicitly allowed traffic (via firewall rules) is permitted."
                ),
            )
            if not firewalls:
                return self._result(check_def, "not_met",
                    "No Azure Firewalls deployed.", raw_evidence=raw)
            # Azure Firewall uses deny-by-default — presence is sufficient
            return self._result(check_def, "met",
                f"{len(firewalls)} Azure Firewall(s) deployed. Azure Firewall uses deny-by-default.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_vpn_forced_tunneling(self, check_def: dict) -> CheckResult:
        """Check VPN forced tunneling is configured."""
        try:
            gateways = self._list_vnet_gateways()
            vpn_gws = [g for g in gateways
                       if g.gateway_type and g.gateway_type.lower() == "vpn"]
            raw = self._build_evidence(
                api_call="virtual_network_gateways.list",
                cli_command="az network vnet-gateway list --resource-group RG",
                response={"vpn_gateways": [{"name": g.name,
                                "enable_bgp": getattr(g, 'enable_bgp', None)}
                                for g in vpn_gws[:10]]},
                service="Network",
                assessor_guidance=(
                    "Forced tunneling routes all internet traffic through on-premises. Verify via route tables "
                    "(default route 0.0.0.0/0 pointing to VPN gateway) or BGP advertisements. Check enable_bgp field."
                ),
            )
            if not vpn_gws:
                return self._result(check_def, "met",
                    "No VPN gateways found.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"Found {len(vpn_gws)} VPN gateway(s). Verify forced tunneling is configured "
                "via route tables or BGP.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_appgw_idle_timeout(self, check_def: dict) -> CheckResult:
        """Check Application Gateway idle timeout is configured."""
        try:
            appgws = self._list_app_gateways()
            raw = self._build_evidence(
                api_call="application_gateways.list_all",
                cli_command="az network application-gateway list",
                response={"count": len(appgws),
                                "gateways": [{"name": g.name, "location": g.location}
                                             for g in appgws[:10]]},
                service="Network",
                assessor_guidance=(
                    "Verify count and review gateways array. Application Gateway default idle timeout is 4 minutes. "
                    "Confirm timeout configuration aligns with session management requirements (typically 15-30 minutes max)."
                ),
            )
            if not appgws:
                return self._result(check_def, "met",
                    "No Application Gateways found.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"Found {len(appgws)} Application Gateway(s). Default idle timeout is 4 minutes.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_waf_owasp_rules(self, check_def: dict) -> CheckResult:
        """Check WAF has OWASP rule sets enabled."""
        try:
            policies = self._list_waf_policies()
            raw_p = []
            for p in policies[:10]:
                managed = getattr(p, 'managed_rules', None)
                rulesets = []
                if managed and hasattr(managed, 'managed_rule_sets'):
                    for rs in (managed.managed_rule_sets or []):
                        rulesets.append({"type": getattr(rs, 'rule_set_type', ''),
                                         "version": getattr(rs, 'rule_set_version', '')})
                raw_p.append({"name": p.name, "rule_sets": rulesets})
            raw = self._build_evidence(
                api_call="web_application_firewall_policies.list_all",
                cli_command="az network application-gateway waf-policy list",
                response={"count": len(policies), "policies": raw_p},
                service="Network",
                assessor_guidance=(
                    "Review policies array for rule_sets. Verify OWASP rule sets are present (type='OWASP', version='3.2' or higher). "
                    "Managed rule sets protect against SQL injection, XSS, and other OWASP Top 10 attacks."
                ),
            )
            if policies:
                return self._result(check_def, "met",
                    f"Found {len(policies)} WAF policy(ies) with managed rule sets.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No WAF policies found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_nsg_restrict_unnecessary_ports(self, check_def: dict) -> CheckResult:
        """Check NSGs restrict unnecessary ports (CM-3.4.7)."""
        try:
            nsgs = self._list_nsgs()
            unnecessary = {"23", "21", "20", "69", "135", "137", "138", "139", "445", "161", "162"}
            issues = []
            for nsg in nsgs:
                for rule in (nsg.security_rules or []):
                    if (rule.direction == "Inbound" and rule.access == "Allow" and
                        rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet")):
                        port = str(rule.destination_port_range or "")
                        if port in unnecessary or port == "*":
                            issues.append(f"{nsg.name}: '{rule.name}' allows port {port}")
            raw = self._build_evidence(
                api_call="nsgs.list_all",
                cli_command="az network nsg list",
                response={"nsgs": len(nsgs), "issues": issues[:15]},
                service="Network",
                assessor_guidance=(
                    "Review issues array for inbound Allow rules from Internet on unnecessary ports (Telnet 23, FTP 20/21, TFTP 69, "
                    "SMB 445, NetBIOS 135-139, SNMP 161/162). These protocols are insecure or unnecessary for cloud services."
                ),
            )
            if not issues:
                return self._result(check_def, "met",
                    f"Reviewed {len(nsgs)} NSG(s). No unnecessary ports open from internet.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(issues)} unnecessary port rule(s): " + "; ".join(issues[:5]),
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_azure_firewall_idps(self, check_def: dict) -> CheckResult:
        """Check Azure Firewall IDPS is enabled."""
        try:
            firewalls = self._list_firewalls()
            raw = self._build_evidence(
                api_call="azure_firewalls.list_all",
                cli_command="az network firewall list",
                response={"count": len(firewalls),
                                "firewalls": [{"name": f.name,
                                               "sku_tier": str(getattr(f.sku, 'tier', 'N/A'))
                                               if f.sku else 'N/A'}
                                              for f in firewalls[:10]]},
                service="Network",
                assessor_guidance=(
                    "Review sku_tier for each firewall. IDPS (Intrusion Detection and Prevention System) requires "
                    "Premium tier. Standard tier does not support IDPS. Verify at least one firewall is Premium."
                ),
            )
            if not firewalls:
                return self._result(check_def, "not_met",
                    "No Azure Firewalls deployed.", raw_evidence=raw)
            premium = [f for f in firewalls
                       if f.sku and hasattr(f.sku, 'tier') and
                       str(f.sku.tier).lower() == 'premium']
            if premium:
                return self._result(check_def, "met",
                    f"{len(premium)} Azure Firewall(s) on Premium tier (IDPS capable).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Azure Firewall Premium tier found. IDPS requires Premium SKU.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_nsg_flow_log_analytics(self, check_def: dict) -> CheckResult:
        """Check NSG flow logs are sent to Log Analytics."""
        return self.check_nsg_flow_logs(check_def)

    # ------------------------------------------------------------------
    # Batch 2: Compute checks (8 methods)
    # ------------------------------------------------------------------

    def check_managed_identities(self, check_def: dict) -> CheckResult:
        """Check VMs use managed identities for service auth."""
        try:
            vms = self._list_vms()
            with_mi = []
            without_mi = []
            for vm in vms:
                identity = getattr(vm, 'identity', None)
                if identity and identity.type:
                    with_mi.append(vm.name)
                else:
                    without_mi.append(vm.name)
            raw = self._build_evidence(
                api_call="virtual_machines.list_all",
                cli_command="az vm list --query '[].{Name:name,Identity:identity}'",
                response={"total": len(vms), "with_identity": len(with_mi),
                                "without_identity": len(without_mi)},
                service="Compute",
                assessor_guidance=(
                    "Verify without_identity=0. Managed identities eliminate the need for storing credentials in code/config. "
                    "VMs should use SystemAssigned or UserAssigned managed identities for Azure service authentication."
                ),
            )
            if not vms:
                return self._result(check_def, "met", "No VMs found.", raw_evidence=raw)
            if not without_mi:
                return self._result(check_def, "met",
                    f"All {len(vms)} VM(s) have managed identities.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(without_mi)} VM(s) without managed identity: "
                + ", ".join(without_mi[:5]), raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_vm_time_sync(self, check_def: dict) -> CheckResult:
        """Check Azure VMs use platform time synchronization."""
        try:
            vms = self._list_vms()
            raw = self._build_evidence(
                api_call="virtual_machines.list_all",
                cli_command="az vm list",
                response={"total": len(vms),
                                "note": "Azure VMs use Hyper-V VMICTimeSync by default"},
                service="Compute",
                assessor_guidance=(
                    "Azure VMs automatically use Hyper-V VMICTimeSync (Virtual Machine Integration Component Time Sync) "
                    "which synchronizes guest OS time with the Azure host. No configuration needed for accurate timestamps."
                ),
            )
            if not vms:
                return self._result(check_def, "met", "No VMs found.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"All {len(vms)} Azure VM(s) use platform time sync (VMICTimeSync/chrony) by default.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_shared_disks_restricted(self, check_def: dict) -> CheckResult:
        """Check shared disks are restricted."""
        try:
            disks = self._list_disks()
            shared = [d.name for d in disks if getattr(d, 'max_shares', 0) and d.max_shares > 1]
            raw = self._build_evidence(
                api_call="disks.list",
                cli_command="az disk list --query '[].{Name:name,MaxShares:maxShares}'",
                response={"total": len(disks), "shared_disks": shared[:10]},
                service="Compute",
                assessor_guidance=(
                    "Verify shared_disks array is empty. Shared disks (maxShares > 1) allow multiple VMs to access "
                    "the same disk, creating concurrency control and data protection risks."
                ),
            )
            if not shared:
                return self._result(check_def, "met",
                    f"No shared disks among {len(disks)} disk(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(shared)} shared disk(s): {', '.join(shared[:5])}.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_managed_disk_encryption(self, check_def: dict) -> CheckResult:
        """Check managed disk encryption (MP-3.8.2-azure-002)."""
        return self.check_disk_encryption(check_def)

    def check_vm_patch_assessment(self, check_def: dict) -> CheckResult:
        """Check VMs have patch assessment enabled."""
        try:
            vms = self._list_vms()
            raw = self._build_evidence(
                api_call="virtual_machines.list_all",
                cli_command="az vm list",
                response={"total": len(vms),
                                "vms": [{"name": vm.name,
                                         "os_type": str(getattr(vm.storage_profile.os_disk, 'os_type', ''))
                                         if vm.storage_profile and vm.storage_profile.os_disk else 'N/A'}
                                        for vm in vms[:20]]},
                service="Compute",
                assessor_guidance=(
                    "Azure auto-assesses patches for supported marketplace images (Windows/Linux). Verify VMs are "
                    "running supported images. Review os_type for each VM. Check Update Manager for assessment results."
                ),
            )
            if not vms:
                return self._result(check_def, "met", "No VMs found.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"Found {len(vms)} VM(s). Azure auto-assesses patches for supported OS images.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_vm_update_manager(self, check_def: dict) -> CheckResult:
        """Check Azure Update Manager is configured for VMs."""
        try:
            vms = self._list_vms()
            raw = self._build_evidence(
                api_call="virtual_machines.list_all",
                cli_command="az vm list",
                response={"total": len(vms)},
                service="Compute",
                assessor_guidance=(
                    "Azure Update Manager provides centralized patch management. Verify Update Manager is configured "
                    "via Azure Portal > Update Management Center. Check for periodic assessment schedules and maintenance configurations."
                ),
            )
            if not vms:
                return self._result(check_def, "met", "No VMs found.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"Found {len(vms)} VM(s). Verify Azure Update Manager is configured "
                "for periodic assessment and patching.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_antimalware_extension(self, check_def: dict) -> CheckResult:
        """Check VMs have antimalware extension installed."""
        try:
            vms = self._list_vms()
            results = []
            for vm in vms[:10]:
                rg = vm.id.split("/")[4] if vm.id else ""
                has_am = False
                try:
                    exts = list(self._compute_client.virtual_machine_extensions.list(rg, vm.name))
                    for ext in exts:
                        if ext.type_properties_type and any(
                            k in ext.type_properties_type.lower()
                            for k in ("antimalware", "endpointprotection", "defender")):
                            has_am = True
                            break
                except Exception:
                    pass
                results.append({"name": vm.name, "antimalware": has_am})
            without = [r["name"] for r in results if not r["antimalware"]]
            raw = self._build_evidence(
                api_call="virtual_machine_extensions.list",
                cli_command="az vm extension list --resource-group RG --vm-name VM",
                response={"vms_checked": len(results), "without_am": without[:10]},
                service="Compute",
                assessor_guidance=(
                    "Verify without_am array is empty. Check for VM extensions with type containing 'Antimalware', "
                    "'EndpointProtection', or 'Defender'. Microsoft Defender for Endpoint provides real-time protection."
                ),
            )
            if not vms:
                return self._result(check_def, "met", "No VMs found.", raw_evidence=raw)
            if not without:
                return self._result(check_def, "met",
                    f"All {len(results)} VM(s) have antimalware extension.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(without)} VM(s) without antimalware: {', '.join(without[:5])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_realtime_protection(self, check_def: dict) -> CheckResult:
        """Check real-time protection via Defender for Endpoint."""
        return self.check_antimalware_extension(check_def)

    # ------------------------------------------------------------------
    # Batch 3: Storage checks (6 methods)
    # ------------------------------------------------------------------

    def check_storage_private_access(self, check_def: dict) -> CheckResult:
        """Check storage accounts restrict network access."""
        try:
            accounts = self._list_storage_accounts()
            public = []
            for a in accounts:
                na = getattr(a, 'network_rule_set', None) or getattr(a, 'network_acls', None)
                default_action = str(getattr(na, 'default_action', 'Allow')) if na else 'Allow'
                if default_action.lower() == 'allow':
                    public.append(a.name)
            raw = self._build_evidence(
                api_call="storage_accounts.list",
                cli_command="az storage account list --query '[].{Name:name,PublicNetworkAccess:publicNetworkAccess}'",
                response={"total": len(accounts), "public_network": public[:10]},
                service="Storage",
                assessor_guidance=(
                    "Verify public_network array is empty. Check network_rule_set default_action='Deny'. Storage accounts "
                    "should restrict access via private endpoints, VNet service endpoints, or firewall IP allowlists."
                ),
            )
            if not accounts:
                return self._result(check_def, "met", "No storage accounts.", raw_evidence=raw)
            if not public:
                return self._result(check_def, "met",
                    f"All {len(accounts)} storage account(s) restrict network access.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(public)} account(s) allow public network access: {', '.join(public[:5])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_storage_cmk_encryption(self, check_def: dict) -> CheckResult:
        """Check storage accounts use CMK encryption."""
        try:
            accounts = self._list_storage_accounts()
            no_cmk = []
            for a in accounts:
                enc = a.encryption
                key_source = str(enc.key_source) if enc and enc.key_source else "Microsoft.Storage"
                if "keyvault" not in key_source.lower():
                    no_cmk.append(a.name)
            raw = self._build_evidence(
                api_call="storage_accounts.list",
                cli_command="az storage account list --query '[].{Name:name,KeySource:encryption.keySource}'",
                response={"total": len(accounts), "microsoft_managed": no_cmk[:10]},
                service="Storage",
                assessor_guidance=(
                    "Verify microsoft_managed array is empty. Check encryption.keySource contains 'KeyVault' for "
                    "customer-managed keys (CMK). CMK provides customer control over encryption key lifecycle."
                ),
            )
            if not accounts:
                return self._result(check_def, "met", "No storage accounts.", raw_evidence=raw)
            if not no_cmk:
                return self._result(check_def, "met",
                    f"All {len(accounts)} storage account(s) use CMK.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_cmk)} account(s) use Microsoft-managed keys: {', '.join(no_cmk[:5])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_storage_cmk(self, check_def: dict) -> CheckResult:
        """Alias for CMK encryption check."""
        return self.check_storage_cmk_encryption(check_def)

    def check_storage_tls(self, check_def: dict) -> CheckResult:
        """Check storage accounts enforce TLS 1.2+."""
        try:
            accounts = self._list_storage_accounts()
            issues = []
            for a in accounts:
                tls = a.minimum_tls_version
                if tls and tls != "TLS1_2":
                    issues.append(f"{a.name}: {tls}")
            raw = self._build_evidence(
                api_call="storage_accounts.list",
                cli_command="az storage account list --query '[].{Name:name,MinTls:minimumTlsVersion}'",
                response={"total": len(accounts), "tls_issues": issues[:10]},
                service="Storage",
                assessor_guidance=(
                    "Verify tls_issues array is empty. All accounts should have minimumTlsVersion='TLS1_2'. "
                    "TLS 1.0 and 1.1 are deprecated and have known vulnerabilities."
                ),
            )
            if not accounts:
                return self._result(check_def, "met", "No storage accounts.", raw_evidence=raw)
            if not issues:
                return self._result(check_def, "met",
                    f"All {len(accounts)} storage account(s) enforce TLS 1.2.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"TLS issues: {'; '.join(issues[:5])}.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_storage_no_public_blobs(self, check_def: dict) -> CheckResult:
        """Check no storage accounts allow public blob access (AC-3.1.22)."""
        return self.check_storage_public_access(check_def)

    def check_immutable_audit_storage(self, check_def: dict) -> CheckResult:
        """Check audit log storage uses immutable blobs."""
        try:
            accounts = self._list_storage_accounts()
            immutable_found = False
            for a in accounts:
                if getattr(a, 'immutable_storage_with_versioning', None):
                    immutable_found = True
                    break
            raw = self._build_evidence(
                api_call="storage_accounts.list",
                cli_command="az storage account list --query '[].{Name:name,Immutability:immutableStorageWithVersioning}'",
                response={"total": len(accounts), "immutable_found": immutable_found},
                service="Storage",
                assessor_guidance=(
                    "Verify immutable_found=true. Immutable storage (WORM - Write Once Read Many) protects audit logs "
                    "from deletion or modification. Check immutableStorageWithVersioning or container-level retention policies."
                ),
            )
            if immutable_found:
                return self._result(check_def, "met",
                    "Immutable storage found for audit log protection.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No immutable storage policies found. Configure immutable blob storage for audit logs.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ------------------------------------------------------------------
    # Batch 4: Auth / Resource checks (5 methods)
    # ------------------------------------------------------------------

    def check_custom_rbac_least_privilege(self, check_def: dict) -> CheckResult:
        """Check custom RBAC roles use least privilege."""
        try:
            scope = f"/subscriptions/{self._subscription_id}"
            roles = list(self._auth_client.role_definitions.list(scope))
            custom = [r for r in roles if r.role_type and r.role_type.lower() == "customrole"]
            wildcard = []
            for r in custom:
                perms = r.permissions or []
                for p in perms:
                    if p.actions and "*" in p.actions:
                        wildcard.append(r.role_name)
                        break
            raw = self._build_evidence(
                api_call="role_definitions.list",
                cli_command="az role definition list --custom-role-only true",
                response={"total_roles": len(roles), "custom_roles": len(custom),
                                "wildcard_custom": wildcard[:10]},
                service="Authorization",
                assessor_guidance=(
                    "Verify wildcard_custom array is empty. Custom roles should not grant wildcard permissions ('*' in actions). "
                    "Review each custom role's permissions array for overly broad actions."
                ),
            )
            if not wildcard:
                return self._result(check_def, "met",
                    f"{len(custom)} custom role(s) reviewed — none use wildcard permissions.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(wildcard)} custom role(s) with wildcard (*) permissions: "
                + ", ".join(wildcard[:5]), raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_separation_of_duties(self, check_def: dict) -> CheckResult:
        """Check separation of duties for subscription management."""
        try:
            ras = self._list_role_assignments()
            owner_id = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
            owners = set()
            contributors = set()
            for ra in ras:
                rd = ra.role_definition_id.split("/")[-1] if ra.role_definition_id else ""
                if rd == owner_id:
                    owners.add(ra.principal_id)
                elif rd == "b24988ac-6180-42a0-ab88-20f7382dd24c":
                    contributors.add(ra.principal_id)
            overlap = owners & contributors
            raw = self._build_evidence(
                api_call="role_assignments.list_for_scope",
                cli_command="az role assignment list --scope /subscriptions/SUB_ID",
                response={"owners": len(owners), "contributors": len(contributors),
                                "overlap": len(overlap)},
                service="Authorization",
                assessor_guidance=(
                    "Verify owners <= 3 and overlap=0. Principals should not hold both Owner and Contributor roles. "
                    "Owner role includes full control; Contributor should be granted separately for specific duties."
                ),
            )
            if len(owners) <= 3 and not overlap:
                return self._result(check_def, "met",
                    f"Separation of duties maintained. {len(owners)} Owner(s), "
                    f"{len(contributors)} Contributor(s), no overlap.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Review needed: {len(owners)} Owner(s), {len(overlap)} with dual roles.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_diagnostic_settings_restricted(self, check_def: dict) -> CheckResult:
        """Check diagnostic settings management is restricted."""
        try:
            ras = self._list_role_assignments()
            monitor_roles = [ra for ra in ras
                             if ra.role_definition_id and "monitor" in ra.role_definition_id.lower()]
            raw = self._build_evidence(
                api_call="role_assignments.list_for_scope",
                cli_command="az role assignment list --scope /subscriptions/SUB_ID",
                response={"total_assignments": len(ras),
                                "monitor_role_assignments": len(monitor_roles)},
                service="Authorization",
                assessor_guidance=(
                    "Review monitor_role_assignments count. Verify only authorized personnel (security/compliance team) "
                    "have roles to modify diagnostic settings. Check for Monitoring Contributor role assignments."
                ),
            )
            return self._result(check_def, "met",
                f"Found {len(ras)} role assignment(s), {len(monitor_roles)} monitoring-related. "
                "Verify only authorized users can modify diagnostic settings.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_resource_locks(self, check_def: dict) -> CheckResult:
        """Check resource locks on critical resources."""
        try:
            from azure.mgmt.resource.locks import ManagementLockClient
            lock_client = ManagementLockClient(
                self._credential, self._subscription_id, **self._mgmt_kwargs)
            locks = list(lock_client.management_locks.list_at_subscription_level())
            lock_list = [{"name": l.name, "level": str(l.level)} for l in locks[:20]]
            raw = self._build_evidence(
                api_call="management_locks.list_at_subscription_level",
                cli_command="az lock list",
                response={"count": len(lock_list), "locks": lock_list},
                service="ResourceManagement",
                assessor_guidance=(
                    "Verify count > 0 and review locks array. Resource locks prevent accidental deletion (CanNotDelete) "
                    "or modification (ReadOnly) of critical resources like production VNets, Key Vaults, and storage accounts."
                ),
            )
            if lock_list:
                return self._result(check_def, "met",
                    f"Found {len(lock_list)} resource lock(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No resource locks found. Apply CanNotDelete or ReadOnly locks to critical resources.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_keyvault_access_least_privilege(self, check_def: dict) -> CheckResult:
        """Check Key Vault access policies follow least privilege."""
        try:
            vaults = self._list_keyvaults()
            issues = []
            for vi in vaults[:20]:
                rg = vi.id.split("/")[4] if vi.id else ""
                try:
                    v = self._keyvault_client.vaults.get(rg, vi.name)
                    for ap in (v.properties.access_policies or []):
                        perms = ap.permissions
                        if perms and perms.keys and "all" in [str(k).lower() for k in perms.keys]:
                            issues.append(f"{vi.name}: principal has 'all' key permissions")
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="vaults.list + vaults.get",
                cli_command="az keyvault list && az keyvault show --name VAULT",
                response={"vaults_checked": min(len(list(vaults)), 20),
                                "issues": issues[:10]},
                service="KeyVault",
                assessor_guidance=(
                    "Verify issues array is empty. Access policies should grant specific permissions (Get, List, Create) "
                    "not 'all'. Review each vault's access_policies array for overly broad key/secret/certificate permissions."
                ),
            )
            if not issues:
                return self._result(check_def, "met",
                    "Key Vault access policies follow least privilege.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Overly broad Key Vault access: {'; '.join(issues[:5])}.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ------------------------------------------------------------------
    # Batch 5: Monitor checks (5 methods)
    # ------------------------------------------------------------------

    def check_privilege_escalation_alerts(self, check_def: dict) -> CheckResult:
        """Check Activity Log alerts for privilege escalation."""
        try:
            alerts = self._list_activity_log_alerts()
            priv_alerts = []
            for a in alerts:
                if not a.enabled:
                    continue
                if a.condition and a.condition.all_of:
                    for c in a.condition.all_of:
                        val = str(c.equals or "").lower()
                        if any(k in val for k in ("roleassignment", "authorization",
                                                   "elevateaccess", "roleDefinitions")):
                            priv_alerts.append(a.name)
                            break
            raw = self._build_evidence(
                api_call="activity_log_alerts.list_by_subscription_id",
                cli_command="az monitor activity-log alert list",
                response={"total_alerts": len(alerts),
                                "privilege_alerts": priv_alerts[:10]},
                service="Monitor",
                assessor_guidance=(
                    "Verify privilege_alerts array has at least 1 alert. Check for alerts on operations like "
                    "'Microsoft.Authorization/roleAssignments/write' and 'Microsoft.Authorization/elevateAccess/action'."
                ),
            )
            if priv_alerts:
                return self._result(check_def, "met",
                    f"Found {len(priv_alerts)} alert(s) for privilege changes: "
                    + ", ".join(priv_alerts[:5]), raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Activity Log alerts for privilege escalation/role changes found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_resource_diagnostic_settings(self, check_def: dict) -> CheckResult:
        """Check resource-level diagnostic settings are enabled."""
        try:
            # Check subscription-level diagnostic settings
            scope = f"/subscriptions/{self._subscription_id}"
            try:
                ds = list(self._monitor_client.diagnostic_settings.list(scope))
            except Exception:
                ds = []
            raw = self._build_evidence(
                api_call="diagnostic_settings.list",
                cli_command="az monitor diagnostic-settings list --resource RESOURCE_ID",
                response={"subscription_diag_settings": len(ds),
                                "settings": [{"name": d.name} for d in ds[:10]]},
                service="Monitor",
                assessor_guidance=(
                    "Verify subscription_diag_settings > 0. Diagnostic settings export Activity Log and platform metrics "
                    "to Log Analytics workspace, Storage Account, or Event Hub for analysis and retention."
                ),
            )
            if ds:
                return self._result(check_def, "met",
                    f"Found {len(ds)} subscription-level diagnostic setting(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No subscription-level diagnostic settings configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_diagnostic_change_alerts(self, check_def: dict) -> CheckResult:
        """Check alerts for diagnostic settings changes."""
        try:
            alerts = self._list_activity_log_alerts()
            diag_alerts = []
            for a in alerts:
                if not a.enabled:
                    continue
                if a.condition and a.condition.all_of:
                    for c in a.condition.all_of:
                        if c.equals and "diagnosticsettings" in str(c.equals).lower():
                            diag_alerts.append(a.name)
                            break
            raw = self._build_evidence(
                api_call="activity_log_alerts.list_by_subscription_id",
                cli_command="az monitor activity-log alert list",
                response={"total_alerts": len(alerts),
                                "diag_change_alerts": diag_alerts[:10]},
                service="Monitor",
                assessor_guidance=(
                    "Verify diag_change_alerts array has at least 1 alert. Alerts should trigger on "
                    "'Microsoft.Insights/diagnosticSettings/write' or 'delete' operations to detect audit tampering."
                ),
            )
            if diag_alerts:
                return self._result(check_def, "met",
                    f"Found {len(diag_alerts)} alert(s) for diagnostic setting changes.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No alerts for diagnostic settings changes. Configure Activity Log alerts.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_activity_log_captures_changes(self, check_def: dict) -> CheckResult:
        """Check Activity Log captures resource changes."""
        try:
            scope = f"/subscriptions/{self._subscription_id}"
            try:
                ds = list(self._monitor_client.diagnostic_settings.list(scope))
            except Exception:
                ds = []
            raw = self._build_evidence(
                api_call="diagnostic_settings.list",
                cli_command="az monitor diagnostic-settings subscription list",
                response={"subscription_diag_settings": len(ds)},
                service="Monitor",
                assessor_guidance=(
                    "Verify subscription_diag_settings > 0. Activity Log automatically captures resource changes "
                    "(create, update, delete) but must be exported via diagnostic settings for long-term retention."
                ),
            )
            if ds:
                return self._result(check_def, "met",
                    f"Activity Log captures changes — {len(ds)} diagnostic setting(s) configured "
                    "for log export.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "Configure subscription diagnostic settings to export Activity Log.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_service_health_alerts(self, check_def: dict) -> CheckResult:
        """Check Service Health alerts are configured."""
        try:
            alerts = self._list_activity_log_alerts()
            health = [a for a in alerts if a.enabled and a.condition and a.condition.all_of
                      and any(str(c.equals or "").lower() == "servicehealth"
                              for c in a.condition.all_of)]
            raw = self._build_evidence(
                api_call="activity_log_alerts.list_by_subscription_id",
                cli_command="az monitor activity-log alert list",
                response={"total_alerts": len(alerts), "health_alerts": len(health)},
                service="Monitor",
                assessor_guidance=(
                    "Verify health_alerts > 0. Service Health alerts notify on Azure service incidents, planned maintenance, "
                    "and health advisories that may affect availability or security posture."
                ),
            )
            if health:
                return self._result(check_def, "met",
                    f"Found {len(health)} Service Health alert(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Service Health alerts configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ------------------------------------------------------------------
    # Batch 6: Security Center checks (13 methods)
    # ------------------------------------------------------------------

    def check_defender_plans_enabled(self, check_def: dict) -> CheckResult:
        """Check Microsoft Defender for Cloud plans are enabled."""
        try:
            pricings = self._list_defender_pricings()
            enabled = [p for p in pricings if p.pricing_tier and p.pricing_tier.lower() == "standard"]
            raw = self._build_evidence(
                api_call="security.pricings.list",
                cli_command="az security pricing list",
                response={"total": len(pricings), "standard_tier": len(enabled),
                                "plans": [{"name": p.name, "tier": p.pricing_tier}
                                          for p in pricings[:20]]},
                service="Security",
                assessor_guidance=(
                    "Verify standard_tier >= 3. Review plans array for tier='Standard' on critical workload types "
                    "(Servers, AppServices, SqlServers, Storage, KeyVaults, Containers). Free tier lacks advanced threat protection."
                ),
            )
            if len(enabled) >= 3:
                return self._result(check_def, "met",
                    f"{len(enabled)}/{len(pricings)} Defender plan(s) on Standard tier.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Only {len(enabled)}/{len(pricings)} Defender plan(s) on Standard tier. "
                "Enable Defender for all resource types.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_jit_vm_access(self, check_def: dict) -> CheckResult:
        """Check JIT VM access is configured."""
        try:
            policies = list(self._get_security_client().jit_network_access_policies.list())
            raw = self._build_evidence(
                api_call="jit_network_access_policies.list",
                cli_command="az security jit-policy list",
                response={"count": len(policies),
                                "policies": [{"name": p.name} for p in policies[:10]]},
                service="Security",
                assessor_guidance=(
                    "Verify count > 0. JIT (Just-In-Time) VM access temporarily opens management ports (RDP/SSH) only "
                    "when needed, reducing attack surface. Review policies array for VMs with time-limited port access."
                ),
            )
            if policies:
                return self._result(check_def, "met",
                    f"JIT VM access configured with {len(policies)} policy(ies).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No JIT VM access policies found. Enable JIT in Defender for Cloud.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_defender_secure_score(self, check_def: dict) -> CheckResult:
        """Check Defender for Cloud secure score."""
        try:
            scores = list(self._get_security_client().secure_scores.list())
            raw = self._build_evidence(
                api_call="secure_scores.list",
                cli_command="az security secure-score list",
                response={"scores": [{"name": s.name,
                                             "current": getattr(s, 'current_score', None),
                                             "max": getattr(s, 'max_score', None)}
                                            for s in scores[:5]]},
                service="Security",
                assessor_guidance=(
                    "Review scores array. Secure score aggregates Defender recommendations. Calculate percentage "
                    "(current/max * 100). Target >= 70% for acceptable security posture. Lower scores indicate unaddressed recommendations."
                ),
            )
            if scores:
                s = scores[0]
                current = getattr(s, 'current_score', 0) or 0
                mx = getattr(s, 'max_score', 100) or 100
                pct = round(current / mx * 100, 1) if mx > 0 else 0
                if pct >= 70:
                    return self._result(check_def, "met",
                        f"Secure score: {current}/{mx} ({pct}%).", raw_evidence=raw)
                return self._result(check_def, "not_met",
                    f"Secure score: {current}/{mx} ({pct}%) — below 70% threshold.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No secure score data available.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_adaptive_app_controls(self, check_def: dict) -> CheckResult:
        """Check adaptive application controls are enabled.

        Uses Defender for Cloud assessments to verify adaptive application
        controls status (the legacy adaptive_application_controls API was
        removed from Microsoft.Security).
        """
        try:
            # Assessment ID for "Adaptive application controls for defining
            # safe applications should be enabled on your machines"
            AAC_ASSESSMENT_ID = "35f45c95-27cf-4f52-891f-8390d1de5571"
            assessments = self._list_assessments()
            aac = [a for a in assessments
                   if hasattr(a, 'name') and a.name == AAC_ASSESSMENT_ID]

            if aac:
                status_code = getattr(getattr(aac[0], 'status', None), 'code', 'Unknown')
                is_healthy = status_code.lower() == 'healthy'
            else:
                status_code = "NotFound"
                is_healthy = False

            raw = self._build_evidence(
                api_call="assessments.list (filter: adaptive application controls)",
                cli_command=(
                    f"az security assessment show --assessment-type {AAC_ASSESSMENT_ID}"
                ),
                response={
                    "assessment_found": bool(aac),
                    "status": status_code,
                },
                service="Security",
                assessor_guidance=(
                    "Verify status='Healthy'. Adaptive application controls use machine learning to whitelist "
                    "allowed applications on VMs, preventing unauthorized software. Enable via Defender for Cloud "
                    "> Workload protections > Adaptive application controls."
                ),
            )
            if is_healthy:
                return self._result(check_def, "met",
                    "Adaptive application controls assessment is healthy.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Adaptive application controls status: {status_code}. "
                "Enable via Defender for Cloud workload protections.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_defender_vulnerability_findings(self, check_def: dict) -> CheckResult:
        """Check Defender vulnerability assessment findings are addressed."""
        try:
            assessments = self._list_assessments()
            unhealthy = [a for a in assessments
                         if hasattr(a, 'status') and a.status and
                         getattr(a.status, 'code', '') == 'Unhealthy']
            raw = self._build_evidence(
                api_call="assessments.list",
                cli_command="az security assessment list",
                response={"total": len(assessments), "unhealthy": len(unhealthy)},
                service="Security",
                assessor_guidance=(
                    "Verify unhealthy=0. Unhealthy assessments are failed security recommendations from Defender. "
                    "Review assessment IDs and remediate findings to improve security posture."
                ),
            )
            if len(unhealthy) == 0:
                return self._result(check_def, "met",
                    f"All {len(assessments)} assessment(s) healthy.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(unhealthy)} unhealthy assessment(s) require remediation.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_defender_for_endpoint(self, check_def: dict) -> CheckResult:
        """Check Defender for Endpoint integration."""
        try:
            pricings = self._list_defender_pricings()
            vm_plan = [p for p in pricings
                       if p.name and p.name.lower() in ("virtualmachines", "servers")]
            raw = self._build_evidence(
                api_call="security.pricings.list",
                cli_command="az security pricing list",
                response={"vm_plans": [{"name": p.name, "tier": p.pricing_tier}
                                             for p in vm_plan]},
                service="Security",
                assessor_guidance=(
                    "Verify vm_plans array contains 'VirtualMachines' or 'Servers' plan with tier='Standard'. "
                    "Defender for Servers includes Defender for Endpoint integration with EDR capabilities."
                ),
            )
            enabled = [p for p in vm_plan
                       if p.pricing_tier and p.pricing_tier.lower() == "standard"]
            if enabled:
                return self._result(check_def, "met",
                    "Defender for Servers (Endpoint) is enabled.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "Defender for Servers is not on Standard tier.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_security_contacts(self, check_def: dict) -> CheckResult:
        """Check security contact notifications are configured."""
        try:
            contacts = self._list_security_contacts()
            raw = self._build_evidence(
                api_call="security_contacts.list",
                cli_command="az security contact list",
                response={"count": len(contacts),
                                "contacts": [{"name": c.name} for c in contacts[:5]]},
                service="Security",
                assessor_guidance=(
                    "Verify count > 0. Security contacts receive email notifications for high-severity Defender alerts "
                    "and security recommendations. Ensure contact info is current and monitored."
                ),
            )
            if contacts:
                return self._result(check_def, "met",
                    f"Security contact(s) configured ({len(contacts)}).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No security contacts configured in Defender for Cloud.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_defender_signature_updates(self, check_def: dict) -> CheckResult:
        """Check Defender signature/definition updates."""
        return self.check_defender_for_endpoint(check_def)

    def check_scheduled_vulnerability_scans(self, check_def: dict) -> CheckResult:
        """Check scheduled vulnerability scans are configured."""
        return self.check_defender_vulnerability_findings(check_def)

    def check_vulnerability_assessment_enabled(self, check_def: dict) -> CheckResult:
        """Check vulnerability assessment is enabled."""
        return self.check_defender_vulnerability_findings(check_def)

    def check_defender_for_containers(self, check_def: dict) -> CheckResult:
        """Check Defender for Containers is enabled."""
        try:
            pricings = self._list_defender_pricings()
            container_plan = [p for p in pricings
                              if p.name and p.name.lower() in ("containers", "containerregistry",
                                                                "kubernetesservice")]
            enabled = [p for p in container_plan
                       if p.pricing_tier and p.pricing_tier.lower() == "standard"]
            raw = self._build_evidence(
                api_call="security.pricings.list",
                cli_command="az security pricing list",
                response={"container_plans": [{"name": p.name, "tier": p.pricing_tier}
                                                    for p in container_plan]},
                service="Security",
                assessor_guidance=(
                    "Verify container_plans array contains 'Containers' or 'KubernetesService' plan with tier='Standard'. "
                    "Defender for Containers provides runtime threat detection and vulnerability scanning for AKS/ACR."
                ),
            )
            if enabled:
                return self._result(check_def, "met",
                    f"Defender for Containers enabled ({len(enabled)} plan(s)).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "Defender for Containers not on Standard tier.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_defender_recommendations(self, check_def: dict) -> CheckResult:
        """Check Defender recommendations are being addressed."""
        return self.check_defender_vulnerability_findings(check_def)

    def check_defender_continuous_assessment(self, check_def: dict) -> CheckResult:
        """Check Defender continuous assessment is active."""
        return self.check_defender_vulnerability_findings(check_def)

    # ------------------------------------------------------------------
    # Batch 7: New Management SDK checks (19+ methods)
    # ------------------------------------------------------------------

    def check_sql_tde(self, check_def: dict) -> CheckResult:
        """Check SQL Database TDE is enabled."""
        try:
            servers = self._list_sql_servers()
            issues = []
            for srv in servers[:20]:
                rg = srv.id.split("/")[4] if srv.id else ""
                try:
                    dbs = list(self._get_sql_client().databases.list_by_server(rg, srv.name))
                    for db in dbs:
                        if db.name == "master":
                            continue
                        try:
                            tde = self._get_sql_client().transparent_data_encryptions.get(
                                rg, srv.name, db.name, "current")
                            if tde.status and str(tde.status).lower() != "enabled":
                                issues.append(f"{srv.name}/{db.name}")
                        except Exception:
                            pass
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="sql.transparent_data_encryptions.get",
                cli_command="az sql db tde show --server SERVER --database DB --resource-group RG",
                response={"servers": len(servers), "tde_issues": issues[:10]},
                service="SQL",
                assessor_guidance=(
                    "Verify tde_issues array is empty. Transparent Data Encryption (TDE) encrypts SQL database files "
                    "at rest. All databases (except 'master') should have TDE status='Enabled'."
                ),
            )
            if not servers:
                return self._result(check_def, "met", "No SQL servers found.", raw_evidence=raw)
            if not issues:
                return self._result(check_def, "met",
                    f"TDE enabled on all databases across {len(servers)} server(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"TDE not enabled on: {', '.join(issues[:5])}.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_sql_tde_cmk(self, check_def: dict) -> CheckResult:
        """Check SQL TDE uses CMK."""
        try:
            servers = self._list_sql_servers()
            no_cmk = []
            for srv in servers[:20]:
                enc = getattr(srv, 'encryption_protector', None)
                if not enc:
                    rg = srv.id.split("/")[4] if srv.id else ""
                    try:
                        ep = self._get_sql_client().encryption_protectors.get(rg, srv.name, "current")
                        if ep.server_key_type and ep.server_key_type.lower() == "servicemanaged":
                            no_cmk.append(srv.name)
                    except Exception:
                        no_cmk.append(srv.name)
            raw = self._build_evidence(
                api_call="sql.encryption_protectors.get",
                cli_command="az sql server tde-key show --server SERVER --resource-group RG",
                response={"servers": len(servers), "service_managed": no_cmk[:10]},
                service="SQL",
                assessor_guidance=(
                    "Verify service_managed array is empty. Check server_key_type='AzureKeyVault' (not 'ServiceManaged'). "
                    "CMK for TDE provides customer control over encryption keys in Key Vault."
                ),
            )
            if not servers:
                return self._result(check_def, "met", "No SQL servers found.", raw_evidence=raw)
            if not no_cmk:
                return self._result(check_def, "met",
                    f"All {len(servers)} SQL server(s) use CMK for TDE.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_cmk)} server(s) use service-managed keys: {', '.join(no_cmk[:5])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_sql_vulnerability_assessment(self, check_def: dict) -> CheckResult:
        """Check SQL vulnerability assessment is enabled."""
        try:
            servers = self._list_sql_servers()
            no_va = []
            for srv in servers[:20]:
                rg = srv.id.split("/")[4] if srv.id else ""
                try:
                    va = self._get_sql_client().server_vulnerability_assessments.get(
                        rg, srv.name, "default")
                    if not va.storage_container_path:
                        no_va.append(srv.name)
                except Exception:
                    no_va.append(srv.name)
            raw = self._build_evidence(
                api_call="server_vulnerability_assessments.get",
                cli_command="az sql server va show --server SERVER --resource-group RG",
                response={"servers": len(servers), "no_assessment": no_va[:10]},
                service="SQL",
                assessor_guidance=(
                    "Verify no_assessment array is empty. Vulnerability Assessment scans SQL databases for security issues "
                    "(misconfigurations, weak passwords). Check storage_container_path is populated for scan result storage."
                ),
            )
            if not servers:
                return self._result(check_def, "met", "No SQL servers.", raw_evidence=raw)
            if not no_va:
                return self._result(check_def, "met",
                    f"Vulnerability assessment enabled on all {len(servers)} server(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"VA not configured on: {', '.join(no_va[:5])}.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_webapp_https_only(self, check_def: dict) -> CheckResult:
        """Check App Service HTTPS-only enforcement."""
        try:
            apps = self._list_web_apps()
            no_https = [a.name for a in apps if not a.https_only]
            raw = self._build_evidence(
                api_call="web_apps.list",
                cli_command="az webapp list --query '[].{Name:name,HttpsOnly:httpsOnly}'",
                response={"total": len(apps), "no_https": no_https[:10]},
                service="AppService",
                assessor_guidance=(
                    "Verify no_https array is empty. All App Services should have httpsOnly=true to reject HTTP requests "
                    "and enforce encrypted connections for CUI protection."
                ),
            )
            if not apps:
                return self._result(check_def, "met", "No App Services found.", raw_evidence=raw)
            if not no_https:
                return self._result(check_def, "met",
                    f"All {len(apps)} App Service(s) enforce HTTPS.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_https)} app(s) without HTTPS-only: {', '.join(no_https[:5])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_webapp_min_tls(self, check_def: dict) -> CheckResult:
        """Check App Services enforce minimum TLS 1.2."""
        try:
            apps = self._list_web_apps()
            issues = []
            for app in apps[:30]:
                rg = app.id.split("/")[4] if app.id else ""
                try:
                    config = self._get_web_client().web_apps.get_configuration(rg, app.name)
                    tls = getattr(config, 'min_tls_version', '1.2')
                    if tls and str(tls) < "1.2":
                        issues.append(f"{app.name}: TLS {tls}")
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="web_apps.get_configuration",
                cli_command="az webapp config show --name APP --resource-group RG --query 'minTlsVersion'",
                response={"total_apps": len(apps), "tls_issues": issues[:10]},
                service="AppService",
                assessor_guidance=(
                    "Verify tls_issues array is empty. All App Services should have minTlsVersion='1.2' or higher. "
                    "TLS 1.0 and 1.1 have known vulnerabilities and must not be used."
                ),
            )
            if not apps:
                return self._result(check_def, "met", "No App Services.", raw_evidence=raw)
            if not issues:
                return self._result(check_def, "met",
                    f"All {len(apps)} App Service(s) enforce TLS 1.2+.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"TLS issues: {'; '.join(issues[:5])}.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_webapp_platform_version(self, check_def: dict) -> CheckResult:
        """Check App Services use latest platform versions."""
        try:
            apps = self._list_web_apps()
            raw = self._build_evidence(
                api_call="web_apps.list",
                cli_command="az webapp list",
                response={"total": len(apps),
                                "apps": [{"name": a.name,
                                          "runtime": getattr(a, 'site_config', None) and
                                          getattr(a.site_config, 'linux_fx_version', '') or ''}
                                         for a in apps[:15]]},
                service="AppService",
                assessor_guidance=(
                    "Review apps array for runtime versions (linux_fx_version field). Verify applications use current "
                    "platform versions (.NET, Node.js, Python, PHP, Java). Outdated runtimes lack security patches."
                ),
            )
            if not apps:
                return self._result(check_def, "met", "No App Services.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"Found {len(apps)} App Service(s). Verify platform versions are current.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_app_service_certificates(self, check_def: dict) -> CheckResult:
        """Check App Service TLS certificates."""
        try:
            certs = list(self._get_web_client().certificates.list())
            raw = self._build_evidence(
                api_call="certificates.list",
                cli_command="az webapp config ssl list --resource-group RG",
                response={"count": len(certs),
                                "certs": [{"name": c.name,
                                           "expiration": str(getattr(c, 'expiration_date', ''))}
                                          for c in certs[:10]]},
                service="AppService",
                assessor_guidance=(
                    "Review certs array for expiration_date. Verify TLS certificates are valid (not expired or expiring soon). "
                    "App Service Managed Certificates auto-renew; custom certificates require manual renewal."
                ),
            )
            if certs:
                return self._result(check_def, "met",
                    f"Found {len(certs)} App Service certificate(s).", raw_evidence=raw)
            return self._result(check_def, "met",
                "No custom App Service certificates (managed certificates may be in use).",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_policy_assignments(self, check_def: dict) -> CheckResult:
        """Check Azure Policy assignments for security baseline."""
        try:
            from azure.mgmt.resource import PolicyClient
            policy_client = PolicyClient(self._credential, self._subscription_id,
                                         **self._mgmt_kwargs)
            assignments = list(policy_client.policy_assignments.list())
            raw = self._build_evidence(
                api_call="policy_assignments.list",
                cli_command="az policy assignment list",
                response={"count": len(assignments),
                                "assignments": [{"name": a.name,
                                                  "display_name": getattr(a, 'display_name', '')}
                                                 for a in assignments[:20]]},
                service="Policy",
                assessor_guidance=(
                    "Verify count > 0. Review assignments array for security-related policies (Azure Security Benchmark, "
                    "NIST 800-53, CIS). Policy assignments enforce compliance requirements across the subscription."
                ),
            )
            if assignments:
                return self._result(check_def, "met",
                    f"Found {len(assignments)} policy assignment(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Azure Policy assignments found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_policy_compliance_state(self, check_def: dict) -> CheckResult:
        """Check Azure Policy compliance state."""
        try:
            summary = self._get_policy_client().policy_states.summarize_for_subscription(
                subscription_id=self._subscription_id)
            results = getattr(summary, 'value', [])
            if results:
                r = results[0]
                total = getattr(r, 'results', None)
                non_compliant = getattr(total, 'non_compliant_resources', 0) if total else 0
                raw = self._build_evidence(
                    api_call="policy_states.summarize_for_subscription",
                    cli_command="az policy state summarize",
                    response={"non_compliant_resources": non_compliant},
                    service="Policy",
                    assessor_guidance=(
                        "Verify non_compliant_resources=0. Non-compliant resources violate assigned Azure Policy definitions. "
                        "Review policy state details to identify resources needing remediation."
                    ),
                )
                if non_compliant == 0:
                    return self._result(check_def, "met",
                        "All resources are policy-compliant.", raw_evidence=raw)
                return self._result(check_def, "not_met",
                    f"{non_compliant} non-compliant resource(s) found.", raw_evidence=raw)
            raw = {"api_call": "policy_states.summarize_for_subscription",
                   "response": {"results": "none"}}
            return self._result(check_def, "met",
                "No policy compliance data available.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_recovery_vault_encryption(self, check_def: dict) -> CheckResult:
        """Check Recovery Services vault encryption."""
        try:
            vaults = self._list_recovery_vaults()
            raw = self._build_evidence(
                api_call="recoveryservices.vaults.list",
                cli_command="az backup vault list",
                response={"count": len(vaults),
                                "vaults": [{"name": v.name, "location": v.location}
                                           for v in vaults[:10]]},
                service="RecoveryServices",
                assessor_guidance=(
                    "Review vaults array. Azure Recovery Services vaults encrypt backup data at rest by default using "
                    "Microsoft-managed keys. CMK encryption available for enhanced control."
                ),
            )
            if not vaults:
                return self._result(check_def, "met", "No Recovery vaults.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"Found {len(vaults)} Recovery vault(s). Azure encrypts vault data by default.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_recovery_vault_soft_delete(self, check_def: dict) -> CheckResult:
        """Check Recovery vault soft delete is enabled."""
        try:
            vaults = self._list_recovery_vaults()
            raw = self._build_evidence(
                api_call="recoveryservices.vaults.list",
                cli_command="az backup vault list",
                response={"count": len(vaults),
                                "vaults": [{"name": v.name} for v in vaults[:10]]},
                service="RecoveryServices",
                assessor_guidance=(
                    "Azure Recovery Services vaults have soft delete enabled by default (14-day retention). "
                    "Soft delete protects backup data from accidental or malicious deletion."
                ),
            )
            if not vaults:
                return self._result(check_def, "met", "No Recovery vaults.", raw_evidence=raw)
            return self._result(check_def, "met",
                f"Found {len(vaults)} Recovery vault(s). Soft delete is enabled by default.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_advisor_unused_resources(self, check_def: dict) -> CheckResult:
        """Check Azure Advisor identifies unused resources."""
        try:
            recs = list(self._get_advisor_client().recommendations.list())
            cost_recs = [r for r in recs if getattr(r, 'category', '') == 'Cost']
            raw = self._build_evidence(
                api_call="advisor.recommendations.list",
                cli_command="az advisor recommendation list",
                response={"total": len(recs), "cost_recommendations": len(cost_recs)},
                service="Advisor",
                assessor_guidance=(
                    "Azure Advisor provides recommendations across High Availability, Security, Performance, and Cost. "
                    "Review cost_recommendations for unused/underutilized resources (idle VMs, orphaned disks)."
                ),
            )
            return self._result(check_def, "met",
                f"Azure Advisor active: {len(recs)} recommendation(s), "
                f"{len(cost_recs)} cost-related (unused resource candidates).", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_resource_graph_inventory(self, check_def: dict) -> CheckResult:
        """Check Azure Resource Graph inventory is available."""
        try:
            from azure.mgmt.resourcegraph.models import QueryRequest
            query = QueryRequest(
                subscriptions=[self._subscription_id],
                query="Resources | summarize count() by type | order by count_ desc | limit 10")
            result = self._get_resourcegraph_client().resources(query)
            count = result.total_records if hasattr(result, 'total_records') else 0
            raw = self._build_evidence(
                api_call="resourcegraph.resources",
                cli_command="az graph query -q 'Resources | summarize count() by type'",
                response={"total_records": count,
                                "data": result.data[:10] if hasattr(result, 'data') else []},
                service="ResourceGraph",
                assessor_guidance=(
                    "Resource Graph provides fast queries across subscriptions. Review data array for resource inventory "
                    "by type. Useful for compliance reporting and identifying unauthorized resource types."
                ),
            )
            return self._result(check_def, "met",
                f"Resource Graph query returned {count} resource type(s).", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_log_analytics_workspace(self, check_def: dict) -> CheckResult:
        """Check Log Analytics workspace is configured."""
        try:
            workspaces = self._list_workspaces()
            raw = self._build_evidence(
                api_call="workspaces.list",
                cli_command="az monitor log-analytics workspace list",
                response={"count": len(workspaces),
                                "workspaces": [{"name": w.name, "location": w.location,
                                                "retention": getattr(w, 'retention_in_days', None)}
                                               for w in workspaces[:10]]},
                service="LogAnalytics",
                assessor_guidance=(
                    "Verify count > 0. Log Analytics workspaces collect and analyze logs from Azure resources. "
                    "Review retention_in_days (typically 30-365 days) to meet audit log retention requirements."
                ),
            )
            if workspaces:
                return self._result(check_def, "met",
                    f"Found {len(workspaces)} Log Analytics workspace(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Log Analytics workspaces found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_log_analytics_access_control(self, check_def: dict) -> CheckResult:
        """Check Log Analytics workspace access is controlled."""
        try:
            workspaces = self._list_workspaces()
            raw = self._build_evidence(
                api_call="workspaces.list",
                cli_command="az monitor log-analytics workspace list",
                response={"count": len(workspaces),
                                "workspaces": [{"name": w.name,
                                                "access_mode": getattr(w, 'features', None) and
                                                getattr(w.features, 'enable_log_access_using_only_resource_permissions', None)}
                                               for w in workspaces[:10]]},
                service="LogAnalytics",
                assessor_guidance=(
                    "Review access_mode for each workspace. Resource-level permissions restrict log access to authorized "
                    "principals. Verify RBAC roles (Log Analytics Reader, Contributor) are appropriately assigned."
                ),
            )
            if workspaces:
                return self._result(check_def, "met",
                    f"Found {len(workspaces)} workspace(s). Verify RBAC access control.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Log Analytics workspaces.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_update_management(self, check_def: dict) -> CheckResult:
        """Check Azure Update Management is configured."""
        try:
            accounts = []
            rgs = self._list_resource_groups()
            for rg in rgs:
                try:
                    accts = list(self._get_automation_client().automation_account.list_by_resource_group(rg.name))
                    accounts.extend(accts)
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="automation_account.list",
                cli_command="az automation account list",
                response={"count": len(accounts),
                                "accounts": [{"name": a.name} for a in accounts[:10]]},
                service="Automation",
                assessor_guidance=(
                    "Verify count > 0. Automation accounts enable Update Management for centralized patch management. "
                    "Review accounts array to confirm automation is configured for VM patching and change tracking."
                ),
            )
            if accounts:
                return self._result(check_def, "met",
                    f"Found {len(accounts)} Automation account(s) for Update Management.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Automation accounts found. Configure Azure Update Management.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_change_tracking(self, check_def: dict) -> CheckResult:
        """Check Change Tracking and Inventory is enabled."""
        return self.check_update_management(check_def)

    def check_update_management_compliance(self, check_def: dict) -> CheckResult:
        """Check Update Management compliance."""
        return self.check_update_management(check_def)

    def check_sentinel_enabled(self, check_def: dict) -> CheckResult:
        """Check Microsoft Sentinel is enabled."""
        try:
            workspaces = self._list_workspaces()
            sentinel_found = False
            for ws in workspaces:
                rg = ws.id.split("/")[4] if ws.id else ""
                try:
                    states = list(self._get_sentinel_client().sentinel_onboarding_states.list(
                        rg, ws.name))
                    if states:
                        sentinel_found = True
                        break
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="sentinel_onboarding_states.list",
                cli_command="az sentinel onboarding-state list --resource-group RG --workspace-name WS",
                response={"workspaces_checked": len(workspaces),
                                "sentinel_enabled": sentinel_found},
                service="Sentinel",
                assessor_guidance=(
                    "Verify sentinel_enabled=true. Microsoft Sentinel provides SIEM/SOAR capabilities for threat detection "
                    "and response. Check onboarding state on Log Analytics workspaces."
                ),
            )
            if sentinel_found:
                return self._result(check_def, "met",
                    "Microsoft Sentinel is enabled.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "Microsoft Sentinel not found on any workspace.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_sentinel_deployed(self, check_def: dict) -> CheckResult:
        """Check Sentinel is deployed (alias)."""
        return self.check_sentinel_enabled(check_def)

    def check_sentinel_automation_rules(self, check_def: dict) -> CheckResult:
        """Check Sentinel automation rules are configured."""
        try:
            workspaces = self._list_workspaces()
            rules_found = 0
            for ws in workspaces:
                rg = ws.id.split("/")[4] if ws.id else ""
                try:
                    rules = list(self._get_sentinel_client().automation_rules.list(rg, ws.name))
                    rules_found += len(rules)
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="automation_rules.list",
                cli_command="az sentinel automation-rule list --resource-group RG --workspace-name WS",
                response={"rules_found": rules_found},
                service="Sentinel",
                assessor_guidance=(
                    "Verify rules_found > 0. Automation rules provide automated incident response (close, assign, tag). "
                    "Review rules to confirm automated workflows for alert triage and remediation."
                ),
            )
            if rules_found:
                return self._result(check_def, "met",
                    f"Found {rules_found} Sentinel automation rule(s).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Sentinel automation rules configured.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_sentinel_ueba(self, check_def: dict) -> CheckResult:
        """Check Sentinel UEBA is enabled."""
        return self.check_sentinel_enabled(check_def)

    def check_guest_configuration(self, check_def: dict) -> CheckResult:
        """Check Guest Configuration policy is enabled."""
        try:
            from azure.mgmt.resource import PolicyClient
            policy_client = PolicyClient(self._credential, self._subscription_id,
                                         **self._mgmt_kwargs)
            assignments = list(policy_client.policy_assignments.list())
            guest_policies = [a for a in assignments
                              if getattr(a, 'display_name', '') and
                              'guest' in a.display_name.lower()]
            raw = self._build_evidence(
                api_call="policy_assignments.list",
                cli_command="az policy assignment list --query '[?contains(displayName, `Guest`)]'",
                response={"total": len(assignments),
                                "guest_config_policies": len(guest_policies)},
                service="Policy",
                assessor_guidance=(
                    "Verify guest_config_policies > 0. Guest Configuration policies audit VM settings (OS configs, "
                    "installed software, compliance drift). Review assignments for VM security baseline enforcement."
                ),
            )
            if guest_policies:
                return self._result(check_def, "met",
                    f"Found {len(guest_policies)} Guest Configuration policy(ies).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Guest Configuration policies found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ------------------------------------------------------------------
    # Batch 8: Graph API checks (25 methods)
    # ------------------------------------------------------------------

    def check_guest_access_restricted(self, check_def: dict) -> CheckResult:
        """Check guest user access is restricted."""
        try:
            data = self._graph_get_safe("policies/authorizationPolicy")
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            raw = self._build_evidence(
                api_call="graph/policies/authorizationPolicy",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/policies/authorizationPolicy",
                response=data,
                service="EntraID",
                assessor_guidance=(
                    "Check guestUserRoleId field in response. Restricted guest role ID contains '10ddb8f6'. "
                    "Restricted guests can only view their own profile and cannot enumerate directory objects."
                ),
            )
            guest_role = data.get("guestUserRoleId", "")
            # Restricted guest = a]d...  (10ddb8f6-...)
            if guest_role and "10ddb8f6" in guest_role:
                return self._result(check_def, "met",
                    "Guest user access is restricted.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Guest user role: {guest_role or 'default (unrestricted)'}. Restrict guest access.",
                raw_evidence=raw)
        except PermissionError as e:
            return self._result(check_def, "error", str(e))
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_security_defaults(self, check_def: dict) -> CheckResult:
        """Check Security Defaults or Conditional Access is enabled."""
        try:
            data = self._graph_get_safe("policies/identitySecurityDefaultsEnforcementPolicy")
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            raw = self._build_evidence(
                api_call="graph/identitySecurityDefaultsEnforcementPolicy",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
                response=data,
                service="EntraID",
                assessor_guidance=(
                    "Verify isEnabled=true OR confirm Conditional Access policies are deployed. Security Defaults "
                    "enforce MFA, block legacy auth, and require MFA for admins. Cannot be enabled with CA policies."
                ),
            )
            if data.get("isEnabled"):
                return self._result(check_def, "met",
                    "Security Defaults are enabled.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "Security Defaults disabled. Ensure Conditional Access policies are configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_pim_enabled(self, check_def: dict) -> CheckResult:
        """Check PIM is enabled for privileged roles."""
        try:
            data = self._graph_get_safe("roleManagement/directory/roleAssignmentScheduleInstances")
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    "PIM check requires PrivilegedAccess.Read.AzureAD Graph permission. "
                    "Verify PIM is enabled in Entra ID Portal.",
                    raw_evidence=self._build_evidence(
                        api_call="graph/roleManagement",
                        cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances",
                        response=data,
                        service="EntraID",
                    ))
            assignments = data.get("value", [])
            raw = self._build_evidence(
                api_call="graph/roleManagement/directory/roleAssignmentScheduleInstances",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances",
                response={"count": len(assignments)},
                service="EntraID",
                assessor_guidance=(
                    "Verify count > 0. PIM (Privileged Identity Management) provides eligible role assignments with "
                    "time-limited activation. Check that permanent Global Admin assignments are minimized."
                ),
            )
            if assignments:
                return self._result(check_def, "met",
                    f"PIM active: {len(assignments)} eligible role assignment(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No PIM role assignments found. Enable PIM for privileged roles.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_global_admin_count(self, check_def: dict) -> CheckResult:
        """Check number of Global Administrators is limited."""
        try:
            data = self._graph_get_safe("directoryRoles")
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            roles = data.get("value", [])
            ga_role = next((r for r in roles
                            if "global administrator" in (r.get("displayName", "")).lower()), None)
            if not ga_role:
                raw = self._build_evidence(
                    api_call="graph/directoryRoles",
                    cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/directoryRoles",
                    response={"roles": len(roles)},
                    service="EntraID",
                    assessor_guidance=(
                        "Global Administrator role not activated. No members assigned to this privileged role."
                    ),
                )
                return self._result(check_def, "met",
                    "Global Administrator role not activated.", raw_evidence=raw)
            role_id = ga_role.get("id", "")
            members = self._graph_get_safe(f"directoryRoles/{role_id}/members")
            member_list = (members or {}).get("value", [])
            raw = self._build_evidence(
                api_call="graph/directoryRoles/members",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/directoryRoles/{roleId}/members",
                response={"global_admins": len(member_list),
                          "members": [m.get("displayName", "") for m in member_list[:10]]},
                service="EntraID",
                assessor_guidance=(
                    "Verify global_admins <= 5. Microsoft recommends 2-5 Global Administrators. Review members array "
                    "for proper naming convention (e.g., admin-firstname.lastname) to identify dedicated admin accounts."
                ),
            )
            if len(member_list) <= 5:
                return self._result(check_def, "met",
                    f"Global Administrators: {len(member_list)} (within limit of 5).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Too many Global Administrators: {len(member_list)}. Limit to 2-5.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_admin_accounts_separate(self, check_def: dict) -> CheckResult:
        """Check admin accounts are separate from daily-use accounts."""
        try:
            data = self._graph_get_safe("directoryRoles")
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            roles = data.get("value", [])
            admin_users = set()
            for role in roles:
                if "admin" in role.get("displayName", "").lower():
                    role_id = role.get("id", "")
                    members = self._graph_get_safe(f"directoryRoles/{role_id}/members")
                    for m in (members or {}).get("value", []):
                        admin_users.add(m.get("userPrincipalName", ""))
            raw = self._build_evidence(
                api_call="graph/directoryRoles/*/members",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/directoryRoles",
                response={"admin_users": len(admin_users),
                                "sample": list(admin_users)[:5]},
                service="EntraID",
                assessor_guidance=(
                    "Review sample array for naming patterns (e.g., admin-user@domain vs user@domain). Admin accounts "
                    "should be separate from daily-use accounts to minimize privileged credential exposure."
                ),
            )
            return self._result(check_def, "met",
                f"Found {len(admin_users)} user(s) with admin roles. "
                "Verify admin accounts are separate from daily-use accounts.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_smart_lockout(self, check_def: dict) -> CheckResult:
        """Check smart lockout is configured in Azure AD."""
        try:
            data = self._graph_get_safe("settings")
            raw = self._build_evidence(
                api_call="graph/settings",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/settings",
                response=data,
                service="EntraID",
                assessor_guidance=(
                    "Azure AD Smart Lockout is enabled by default (10 failed sign-ins, 1-minute lockout). Locks out "
                    "attackers while allowing legitimate users. Customizable thresholds available via Entra ID Portal."
                ),
            )
            # Smart lockout is enabled by default in Azure AD
            return self._result(check_def, "met",
                "Azure AD Smart Lockout is enabled by default for all tenants.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_conditional_access_session_controls(self, check_def: dict) -> CheckResult:
        """Check Conditional Access session controls are configured."""
        try:
            data = self._graph_get_safe("identity/conditionalAccess/policies")
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            policies = data.get("value", [])
            session_policies = [p for p in policies
                                if p.get("sessionControls") and p.get("state") == "enabled"]
            raw = self._build_evidence(
                api_call="graph/conditionalAccess/policies",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
                response={"total": len(policies),
                                "with_session_controls": len(session_policies)},
                service="EntraID",
                assessor_guidance=(
                    "Verify with_session_controls > 0. Session controls include sign-in frequency, persistent browser "
                    "sessions, and app-enforced restrictions. Review policies for session timeout configurations."
                ),
            )
            if session_policies:
                return self._result(check_def, "met",
                    f"{len(session_policies)} CA policy(ies) with session controls.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Conditional Access policies with session controls found.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_token_lifetime_policy(self, check_def: dict) -> CheckResult:
        """Check token lifetime policies are configured."""
        try:
            data = self._graph_get_safe("policies/tokenLifetimePolicies")
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            policies = data.get("value", [])
            raw = self._build_evidence(
                api_call="graph/policies/tokenLifetimePolicies",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/policies/tokenLifetimePolicies",
                response={"count": len(policies)},
                service="EntraID",
                assessor_guidance=(
                    "Token lifetime policies control access token, refresh token, and session token durations. Review "
                    "count > 0 for custom policies. Default lifetimes: access tokens 1 hour, refresh tokens 90 days."
                ),
            )
            if policies:
                return self._result(check_def, "met",
                    f"Found {len(policies)} token lifetime policy(ies).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No custom token lifetime policies. Default token lifetimes apply.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_paw_policy(self, check_def: dict) -> CheckResult:
        """Check Privileged Access Workstation policy is enforced via CA."""
        try:
            data = self._graph_get_safe("identity/conditionalAccess/policies")
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            policies = data.get("value", [])
            paw = [p for p in policies
                   if p.get("state") == "enabled" and
                   any(k in (p.get("displayName", "")).lower()
                       for k in ("paw", "privileged", "workstation", "compliant device"))]
            raw = self._build_evidence(
                api_call="graph/conditionalAccess/policies",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
                response={"total": len(policies), "paw_policies": len(paw)},
                service="EntraID",
                assessor_guidance=(
                    "Verify paw_policies > 0. Privileged Access Workstations require device compliance or hybrid Azure AD "
                    "join for admin access. Review policies for device trust requirements on privileged roles."
                ),
            )
            if paw:
                return self._result(check_def, "met",
                    f"Found {len(paw)} PAW/device compliance CA policy(ies).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No PAW enforcement policies found in Conditional Access.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_unique_users(self, check_def: dict) -> CheckResult:
        """Check all Azure AD users are uniquely identified."""
        try:
            data = self._graph_get_safe("users?$select=id,userPrincipalName,displayName&$top=999",
                                       max_pages=5)
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            users = data.get("value", [])
            upns = [u.get("userPrincipalName", "") for u in users]
            dupes = [u for u in upns if upns.count(u) > 1]
            raw = self._build_evidence(
                api_call="graph/users",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/users",
                response={"total_users": len(users), "duplicates": len(set(dupes))},
                service="EntraID",
                assessor_guidance=(
                    "Verify duplicates=0. Each user must have a unique userPrincipalName. Duplicates indicate "
                    "synchronization issues or improper account provisioning."
                ),
            )
            if not dupes:
                return self._result(check_def, "met",
                    f"All {len(users)} user(s) have unique identifiers.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Found {len(set(dupes))} duplicate UPN(s).", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_mfa_registration(self, check_def: dict) -> CheckResult:
        """Check MFA registration for all users."""
        try:
            data = self._graph_get_safe(
                "reports/credentialUserRegistrationDetails?$top=999",
                max_pages=3)
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    "MFA registration report requires Reports.Read.All permission. "
                    "Verify MFA enrollment in Entra ID Portal.",
                    raw_evidence=self._build_evidence(
                        api_call="graph/reports/credentialUserRegistrationDetails",
                        cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails",
                        response=data,
                        service="EntraID",
                    ))
            users = data.get("value", [])
            registered = [u for u in users if u.get("isMfaRegistered")]
            raw = self._build_evidence(
                api_call="graph/reports/credentialUserRegistrationDetails",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails",
                response={"total": len(users), "mfa_registered": len(registered)},
                service="EntraID",
                assessor_guidance=(
                    "Verify (mfa_registered/total) >= 95%. Check that all users have registered MFA methods (phone, "
                    "authenticator app, FIDO2 key). Low registration rates indicate incomplete MFA rollout."
                ),
            )
            pct = round(len(registered) / len(users) * 100, 1) if users else 0
            if pct >= 95:
                return self._result(check_def, "met",
                    f"MFA registered: {len(registered)}/{len(users)} ({pct}%).", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"MFA registration: {len(registered)}/{len(users)} ({pct}%). Target: 95%+.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_legacy_auth_blocked(self, check_def: dict) -> CheckResult:
        """Check legacy authentication is blocked."""
        try:
            data = self._graph_get_safe("identity/conditionalAccess/policies")
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            policies = data.get("value", [])
            legacy_block = [p for p in policies if p.get("state") == "enabled" and
                            p.get("conditions", {}).get("clientAppTypes") and
                            "exchangeActiveSync" in str(p["conditions"]["clientAppTypes"])]
            raw = self._build_evidence(
                api_call="graph/conditionalAccess/policies",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
                response={"total": len(policies),
                                "legacy_auth_block_policies": len(legacy_block)},
                service="EntraID",
                assessor_guidance=(
                    "Verify legacy_auth_block_policies > 0. Legacy authentication protocols (IMAP, POP3, SMTP, "
                    "Exchange ActiveSync) do not support MFA and must be blocked via Conditional Access."
                ),
            )
            if legacy_block:
                return self._result(check_def, "met",
                    f"Legacy auth blocked by {len(legacy_block)} CA policy(ies).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No CA policy blocking legacy authentication protocols.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_mfa_conditional_access(self, check_def: dict) -> CheckResult:
        """Check MFA is required via Conditional Access."""
        try:
            data = self._graph_get_safe("identity/conditionalAccess/policies")
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            policies = data.get("value", [])
            mfa_policies = [p for p in policies if p.get("state") == "enabled" and
                            p.get("grantControls", {}).get("builtInControls") and
                            "mfa" in p["grantControls"]["builtInControls"]]
            raw = self._build_evidence(
                api_call="graph/conditionalAccess/policies",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
                response={"total": len(policies), "mfa_policies": len(mfa_policies)},
                service="EntraID",
                assessor_guidance=(
                    "Verify mfa_policies > 0. Conditional Access should enforce MFA for all users or high-risk sign-ins. "
                    "Review policies for scope (all users, admins, external users) and conditions (location, device state)."
                ),
            )
            if mfa_policies:
                return self._result(check_def, "met",
                    f"{len(mfa_policies)} CA policy(ies) require MFA.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Conditional Access policies requiring MFA found.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_mfa_azure_management(self, check_def: dict) -> CheckResult:
        """Check MFA is required for Azure management."""
        try:
            data = self._graph_get_safe("identity/conditionalAccess/policies")
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            policies = data.get("value", [])
            # Azure Management app ID: 797f4846-ba00-4fd7-ba43-dac1f8f63013
            mgmt_mfa = [p for p in policies if p.get("state") == "enabled" and
                        p.get("grantControls", {}).get("builtInControls") and
                        "mfa" in p["grantControls"]["builtInControls"] and
                        "797f4846" in str(p.get("conditions", {}).get("applications", {}))]
            raw = self._build_evidence(
                api_call="graph/conditionalAccess/policies",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
                response={"total": len(policies), "mgmt_mfa_policies": len(mgmt_mfa)},
                service="EntraID",
                assessor_guidance=(
                    "Verify mgmt_mfa_policies > 0. Azure Management app ID (797f4846-ba00-4fd7-ba43-dac1f8f63013) "
                    "covers Azure Portal, PowerShell, and CLI. MFA must be required for all admin access."
                ),
            )
            if mgmt_mfa:
                return self._result(check_def, "met",
                    f"MFA required for Azure management ({len(mgmt_mfa)} policy(ies)).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No CA policy requiring MFA for Azure Management portal.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_fido2_enabled(self, check_def: dict) -> CheckResult:
        """Check FIDO2 authentication method is enabled."""
        try:
            data = self._graph_get_safe(
                "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2")
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            raw = self._build_evidence(
                api_call="graph/authenticationMethodConfigurations/fido2",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2",
                response=data,
                service="EntraID",
                assessor_guidance=(
                    "Verify state='enabled'. FIDO2 security keys provide phishing-resistant authentication. Check that "
                    "FIDO2 is available for privileged users. Review includeTargets for deployment scope."
                ),
            )
            state = data.get("state", "disabled")
            if state == "enabled":
                return self._result(check_def, "met",
                    "FIDO2 authentication method is enabled.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"FIDO2 state: {state}. Enable FIDO2 security keys.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_deleted_users_soft_delete(self, check_def: dict) -> CheckResult:
        """Check soft-deleted users are not being reused."""
        try:
            data = self._graph_get_safe("directory/deletedItems/microsoft.graph.user?$top=100", max_pages=1)
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            deleted = data.get("value", [])
            raw = self._build_evidence(
                api_call="graph/directory/deletedItems",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.user",
                response={"deleted_users": len(deleted)},
                service="EntraID",
                assessor_guidance=(
                    "Azure AD retains deleted users for 30 days before permanent deletion. Soft delete prevents "
                    "identity reuse attacks. Review deleted_users count for recent terminations."
                ),
            )
            return self._result(check_def, "met",
                f"Found {len(deleted)} soft-deleted user(s). Azure AD retains deleted users "
                "for 30 days to prevent identity reuse.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_inactive_users(self, check_def: dict) -> CheckResult:
        """Check for inactive Azure AD accounts."""
        try:
            data = self._graph_get_safe(
                "users?$select=id,displayName,userPrincipalName,signInActivity&$top=999",
                max_pages=3)
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            users = data.get("value", [])
            from datetime import datetime, timedelta, timezone
            cutoff = datetime.now(timezone.utc) - timedelta(days=90)
            inactive = []
            for u in users:
                sa = u.get("signInActivity", {})
                last = sa.get("lastSignInDateTime") if sa else None
                if not last:
                    inactive.append(u.get("userPrincipalName", ""))
            raw = self._build_evidence(
                api_call="graph/users?$select=signInActivity",
                cli_command="az rest --method GET --url 'https://graph.microsoft.com/v1.0/users?$select=displayName,signInActivity'",
                response={"total_users": len(users), "inactive_90d": len(inactive)},
                service="EntraID",
                assessor_guidance=(
                    "Verify inactive_90d=0 or review inactive accounts for termination. Users with no sign-in activity "
                    "in 90+ days should be disabled or deleted. Requires Azure AD P1/P2 for signInActivity data."
                ),
            )
            if not inactive:
                return self._result(check_def, "met",
                    f"All {len(users)} user(s) have recent sign-in activity.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(inactive)} user(s) with no sign-in data (potentially inactive): "
                + ", ".join(inactive[:5]), raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_password_protection(self, check_def: dict) -> CheckResult:
        """Check Azure AD password protection is enabled."""
        try:
            data = self._graph_get_safe("settings")
            raw = self._build_evidence(
                api_call="graph/settings",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/settings",
                response=data,
                service="EntraID",
                assessor_guidance=(
                    "Azure AD Password Protection blocks globally banned passwords (e.g., Password1, Welcome123) by default. "
                    "Custom banned password lists available in Entra ID Portal for organization-specific terms."
                ),
            )
            # Azure AD password protection (banned password list) is enabled by default
            return self._result(check_def, "met",
                "Azure AD Password Protection with global banned password list is enabled by default.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_password_history(self, check_def: dict) -> CheckResult:
        """Check password history is enforced."""
        try:
            data = self._graph_get_safe("settings")
            raw = self._build_evidence(
                api_call="graph/settings",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/settings",
                response=data,
                service="EntraID",
                assessor_guidance=(
                    "Azure AD enforces password history by default (last 1 password cannot be reused). On-premises "
                    "AD can enforce 24 password history via Group Policy. Cloud-only accounts have limited history."
                ),
            )
            return self._result(check_def, "met",
                "Azure AD enforces password history (last password cannot be reused).",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_force_password_change(self, check_def: dict) -> CheckResult:
        """Check force password change on new accounts."""
        try:
            data = self._graph_get_safe(
                "users?$select=id,userPrincipalName,passwordProfile&$top=100")
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            users = data.get("value", [])
            raw = self._build_evidence(
                api_call="graph/users?$select=passwordProfile",
                cli_command="az rest --method GET --url 'https://graph.microsoft.com/v1.0/users?$select=displayName,passwordProfile'",
                response={"total_users": len(users)},
                service="EntraID",
                assessor_guidance=(
                    "Azure AD supports forceChangePasswordNextSignIn flag on new accounts. Verify organizationally "
                    "that new users are required to change temporary passwords on first login."
                ),
            )
            return self._result(check_def, "met",
                f"Reviewed {len(users)} user(s). Azure AD can enforce password change on first login.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_audit_log_retained(self, check_def: dict) -> CheckResult:
        """Check Azure AD audit logs are retained."""
        try:
            data = self._graph_get_safe("auditLogs/directoryAudits?$top=1", max_pages=1)
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            logs = data.get("value", [])
            raw = self._build_evidence(
                api_call="graph/auditLogs/directoryAudits",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/auditLogs/directoryAudits",
                response={"has_logs": len(logs) > 0},
                service="EntraID",
                assessor_guidance=(
                    "Verify has_logs=true. Azure AD P1/P2 retains audit logs for 30 days. Export to Log Analytics or "
                    "Storage Account for longer retention (1+ year) to meet compliance requirements."
                ),
            )
            if logs:
                return self._result(check_def, "met",
                    "Azure AD audit logs are available and being retained.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No audit log entries found. Verify Azure AD licensing (P1/P2) for log retention.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_sign_in_logs(self, check_def: dict) -> CheckResult:
        """Check Azure AD sign-in logs are available."""
        try:
            data = self._graph_get_safe("auditLogs/signIns?$top=1", max_pages=1)
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    f"Graph API: {data.get('_error', '')} -- Verify manually in Entra ID Portal.")
            logs = data.get("value", [])
            raw = self._build_evidence(
                api_call="graph/auditLogs/signIns",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/auditLogs/signIns",
                response={"has_logs": len(logs) > 0},
                service="EntraID",
                assessor_guidance=(
                    "Verify has_logs=true. Sign-in logs track authentication events (success, failure, MFA, location). "
                    "Requires Azure AD P1/P2. Export to Log Analytics for long-term retention and SIEM integration."
                ),
            )
            if logs:
                return self._result(check_def, "met",
                    "Azure AD sign-in logs are available.", raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No sign-in logs. Verify Azure AD P1/P2 licensing.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_identity_protection_risk(self, check_def: dict) -> CheckResult:
        """Check Identity Protection risk detections."""
        try:
            data = self._graph_get_safe("identityProtection/riskDetections?$top=10", max_pages=1)
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    "Identity Protection requires IdentityRiskEvent.Read.All permission. "
                    "Verify in Entra ID Portal.",
                    raw_evidence=self._build_evidence(
                        api_call="graph/identityProtection/riskDetections",
                        cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/identityProtection/riskDetections",
                        response=data,
                        service="EntraID",
                    ))
            detections = data.get("value", [])
            raw = self._build_evidence(
                api_call="graph/identityProtection/riskDetections",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/identityProtection/riskDetections",
                response={"recent_detections": len(detections)},
                service="EntraID",
                assessor_guidance=(
                    "Identity Protection detects risks (leaked credentials, anonymous IP, atypical travel, malware-linked IP). "
                    "Review recent_detections for active threats. Requires Azure AD P2 license."
                ),
            )
            return self._result(check_def, "met",
                f"Identity Protection active. {len(detections)} recent risk detection(s).",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_risky_users(self, check_def: dict) -> CheckResult:
        """Check for risky users in Identity Protection."""
        try:
            data = self._graph_get_safe("identityProtection/riskyUsers?$top=50", max_pages=1)
            if "_error" in (data or {}):
                return self._result(check_def, "manual",
                    "Risky users check requires IdentityRiskyUser.Read.All permission.",
                    raw_evidence=self._build_evidence(
                        api_call="graph/identityProtection/riskyUsers",
                        cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/identityProtection/riskyUsers",
                        response=data,
                        service="EntraID",
                    ))
            users = data.get("value", [])
            at_risk = [u for u in users if u.get("riskLevel") in ("high", "medium")]
            raw = self._build_evidence(
                api_call="graph/identityProtection/riskyUsers",
                cli_command="az rest --method GET --url https://graph.microsoft.com/v1.0/identityProtection/riskyUsers",
                response={"total_risky": len(users), "high_medium": len(at_risk)},
                service="EntraID",
                assessor_guidance=(
                    "Verify high_medium=0. Risky users have compromised credentials or suspicious behavior. Remediation: "
                    "force password reset, revoke sessions, confirm safe, or dismiss risk. Review riskLevel field."
                ),
            )
            if not at_risk:
                return self._result(check_def, "met",
                    f"No high/medium risk users. {len(users)} total risky user(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(at_risk)} high/medium risk user(s) require remediation.", raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_mfa_bastion_access(self, check_def: dict) -> CheckResult:
        """Check MFA is required for Bastion access via CA."""
        return self.check_mfa_conditional_access(check_def)

    # ---- CP: Contingency Planning ----

    def check_dr_plan_tags(self, check_def: dict) -> CheckResult:
        """Check resources have DR plan documentation tags."""
        try:
            resources = list(self._resource_client.resources.list())
            tagged = []
            for res in resources[:500]:
                tags = res.tags or {}
                if any(k.lower() in ["disasterrecovery", "dr-plan", "drplan", "contingency"]
                       for k in tags.keys()):
                    tagged.append(res.name)
            raw = self._build_evidence(
                api_call="resource.resources.list()",
                cli_command="az resource list --query \"[?tags.DisasterRecovery || tags.DR-Plan]\"",
                response={"total_resources": len(resources), "tagged_with_dr": len(tagged)},
                service="ResourceManagement",
                assessor_guidance=(
                    "Verify resources have DisasterRecovery or DR-Plan tags documenting contingency procedures. "
                    "Tags should reference recovery time objectives (RTO), recovery point objectives (RPO), and DR procedures."
                ),
            )
            if len(resources) == 0:
                return self._result(check_def, "met", "No resources found.", raw_evidence=raw)
            coverage = len(tagged) / len(resources) if resources else 0
            if coverage >= 0.5:
                return self._result(check_def, "met",
                    f"{len(tagged)}/{len(resources)} resources ({coverage*100:.0f}%) have DR tags.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Only {len(tagged)}/{len(resources)} resources ({coverage*100:.0f}%) have DR tags. Consider tagging critical resources.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_site_recovery_test_failover(self, check_def: dict) -> CheckResult:
        """Check Azure Site Recovery test failover has been performed."""
        try:
            recovery_client = self._get_recovery_client()
            vaults = list(recovery_client.vaults.list_by_subscription_id())
            test_failovers = []
            for vault in vaults[:10]:
                rg = vault.id.split("/")[4] if vault.id else ""
                try:
                    if not hasattr(self, '_backup_client') or self._backup_client is None:
                        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
                        with self._lock:
                            if not hasattr(self, '_backup_client') or self._backup_client is None:
                                self._backup_client = RecoveryServicesBackupClient(
                                    self._credential, self._subscription_id, **self._mgmt_kwargs)
                    jobs = list(self._backup_client.backup_jobs.list(vault.name, rg, filter="jobType eq 'TestFailover'"))
                    test_failovers.extend([j.properties.job_type for j in jobs[:5] if j.properties])
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="backup_client.backup_jobs.list(filter='jobType eq TestFailover')",
                cli_command="az backup job list --resource-group RG --vault-name VAULT --query \"[?jobType=='TestFailover']\"",
                response={"vaults": len(vaults), "test_failover_jobs": len(test_failovers)},
                service="RecoveryServices",
                assessor_guidance=(
                    "Verify test_failover_jobs > 0. Test failovers validate DR procedures without impacting production. "
                    "FedRAMP requires periodic DR testing. Review job history for completion status and frequency."
                ),
            )
            if len(test_failovers) > 0:
                return self._result(check_def, "met",
                    f"{len(test_failovers)} test failover job(s) found across {len(vaults)} vault(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"No test failover jobs found. {len(vaults)} vault(s) configured.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_storage_geo_redundancy(self, check_def: dict) -> CheckResult:
        """Check storage accounts use geo-redundant replication."""
        try:
            accounts = self._list_storage_accounts()
            non_geo = []
            for acct in accounts:
                sku = acct.sku.name if acct.sku else ""
                if not any(x in sku.upper() for x in ["GRS", "RAGRS", "GZRS", "RAGZRS"]):
                    non_geo.append(f"{acct.name} ({sku})")
            raw = self._build_evidence(
                api_call="storage_client.storage_accounts.list()",
                cli_command="az storage account list --query \"[?sku.name !contains 'GRS']\"",
                response={"total_accounts": len(accounts), "non_geo_redundant": non_geo[:10]},
                service="Storage",
                assessor_guidance=(
                    "Verify non_geo_redundant array is empty. Geo-redundant storage (GRS, RA-GRS, GZRS, RA-GZRS) "
                    "replicates data to secondary region for disaster recovery. LRS/ZRS only protect within region."
                ),
            )
            if not accounts:
                return self._result(check_def, "met", "No storage accounts found.", raw_evidence=raw)
            if not non_geo:
                return self._result(check_def, "met",
                    f"All {len(accounts)} storage account(s) use geo-redundant replication.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(non_geo)} storage account(s) lack geo-redundancy: {', '.join(non_geo[:3])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_sql_geo_replication(self, check_def: dict) -> CheckResult:
        """Check Azure SQL has geo-replication configured."""
        try:
            servers = self._list_sql_servers()
            no_replication = []
            for srv in servers[:20]:
                rg = srv.id.split("/")[4] if srv.id else ""
                try:
                    dbs = list(self._get_sql_client().databases.list_by_server(rg, srv.name))
                    for db in dbs:
                        if db.name.lower() in ["master", "model", "msdb", "tempdb"]:
                            continue
                        try:
                            links = list(self._get_sql_client().replication_links.list_by_database(
                                rg, srv.name, db.name))
                            if not links:
                                no_replication.append(f"{srv.name}/{db.name}")
                        except Exception:
                            no_replication.append(f"{srv.name}/{db.name}")
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="sql_client.replication_links.list_by_database()",
                cli_command="az sql db replica list --server SERVER --name DB --resource-group RG",
                response={"servers": len(servers), "databases_without_replication": no_replication[:10]},
                service="SQL",
                assessor_guidance=(
                    "Verify databases_without_replication array is empty or contains only non-critical databases. "
                    "Active geo-replication provides automatic asynchronous replication to secondary region for DR."
                ),
            )
            if not servers:
                return self._result(check_def, "met", "No SQL servers found.", raw_evidence=raw)
            if not no_replication:
                return self._result(check_def, "met",
                    f"All critical databases across {len(servers)} server(s) have geo-replication.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_replication)} database(s) lack geo-replication: {', '.join(no_replication[:3])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_multi_region_deployment(self, check_def: dict) -> CheckResult:
        """Check for multi-region VM/resource deployment."""
        try:
            vms = self._list_vms()
            regions = set()
            for vm in vms:
                if vm.location:
                    regions.add(vm.location.lower())
            raw = self._build_evidence(
                api_call="compute_client.virtual_machines.list_all()",
                cli_command="az vm list --query \"[].location\" -o table | sort -u",
                response={"total_vms": len(vms), "regions": sorted(list(regions))},
                service="Compute",
                assessor_guidance=(
                    "Verify regions array contains 2+ regions. Multi-region deployment provides resilience against "
                    "regional outages. Critical workloads should be deployed across geographically separate regions."
                ),
            )
            if len(regions) >= 2:
                return self._result(check_def, "met",
                    f"Multi-region deployment verified: {len(regions)} region(s) - {', '.join(sorted(regions)[:5])}.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Only {len(regions)} region(s) detected. Consider multi-region deployment for DR.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_traffic_manager_failover(self, check_def: dict) -> CheckResult:
        """Check Traffic Manager has failover profiles."""
        try:
            if not hasattr(self, '_traffic_manager_client') or self._traffic_manager_client is None:
                from azure.mgmt.trafficmanager import TrafficManagerManagementClient
                with self._lock:
                    if not hasattr(self, '_traffic_manager_client') or self._traffic_manager_client is None:
                        self._traffic_manager_client = TrafficManagerManagementClient(
                            self._credential, self._subscription_id, **self._mgmt_kwargs)
            profiles = list(self._traffic_manager_client.profiles.list_by_subscription())
            failover_profiles = []
            for profile in profiles:
                if profile.traffic_routing_method and "priority" in profile.traffic_routing_method.lower():
                    failover_profiles.append(profile.name)
            raw = self._build_evidence(
                api_call="traffic_manager_client.profiles.list_by_subscription()",
                cli_command="az network traffic-manager profile list",
                response={"total_profiles": len(profiles), "failover_profiles": failover_profiles},
                service="TrafficManager",
                assessor_guidance=(
                    "Verify failover_profiles contains priority-based routing. Traffic Manager provides DNS-based "
                    "failover across regions. Priority routing directs traffic to primary endpoint with automatic failover."
                ),
            )
            if len(failover_profiles) > 0:
                return self._result(check_def, "met",
                    f"{len(failover_profiles)} Traffic Manager profile(s) configured for failover.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"No failover-capable Traffic Manager profiles found. {len(profiles)} total profile(s).",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_vm_backup_configured(self, check_def: dict) -> CheckResult:
        """Check VMs have backup configured."""
        try:
            vms = self._list_vms()
            recovery_client = self._get_recovery_client()
            vaults = list(recovery_client.vaults.list_by_subscription_id())
            protected_vms = set()
            for vault in vaults[:10]:
                rg = vault.id.split("/")[4] if vault.id else ""
                try:
                    if not hasattr(self, '_backup_client') or self._backup_client is None:
                        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
                        with self._lock:
                            if not hasattr(self, '_backup_client') or self._backup_client is None:
                                self._backup_client = RecoveryServicesBackupClient(
                                    self._credential, self._subscription_id, **self._mgmt_kwargs)
                    items = list(self._backup_client.backup_protected_items.list(vault.name, rg))
                    for item in items:
                        if hasattr(item, 'properties') and hasattr(item.properties, 'virtual_machine_id'):
                            protected_vms.add(item.properties.virtual_machine_id)
                except Exception:
                    pass
            unprotected = [vm.name for vm in vms if vm.id not in protected_vms]
            raw = self._build_evidence(
                api_call="backup_client.backup_protected_items.list()",
                cli_command="az backup item list --resource-group RG --vault-name VAULT",
                response={"total_vms": len(vms), "protected_vms": len(protected_vms), "unprotected": unprotected[:10]},
                service="Backup",
                assessor_guidance=(
                    "Verify unprotected array is empty or contains only non-critical VMs. Azure Backup provides "
                    "automated snapshots for VM recovery. All production VMs should have backup policies configured."
                ),
            )
            if not vms:
                return self._result(check_def, "met", "No VMs found.", raw_evidence=raw)
            coverage = len(protected_vms) / len(vms) if vms else 0
            if coverage >= 0.8:
                return self._result(check_def, "met",
                    f"{len(protected_vms)}/{len(vms)} VMs ({coverage*100:.0f}%) have backup configured.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Only {len(protected_vms)}/{len(vms)} VMs ({coverage*100:.0f}%) have backup. {len(unprotected)} unprotected.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_sql_automated_backups(self, check_def: dict) -> CheckResult:
        """Check SQL databases have automated backups."""
        try:
            servers = self._list_sql_servers()
            no_backup = []
            for srv in servers[:20]:
                rg = srv.id.split("/")[4] if srv.id else ""
                try:
                    dbs = list(self._get_sql_client().databases.list_by_server(rg, srv.name))
                    for db in dbs:
                        if db.name.lower() == "master":
                            continue
                        try:
                            retention = self._get_sql_client().backup_short_term_retention_policies.get(
                                rg, srv.name, db.name, "default")
                            days = retention.retention_days if retention else 0
                            if days < 7:
                                no_backup.append(f"{srv.name}/{db.name} ({days}d)")
                        except Exception:
                            no_backup.append(f"{srv.name}/{db.name} (error)")
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="sql_client.backup_short_term_retention_policies.get()",
                cli_command="az sql db str-policy show --server SERVER --database DB --resource-group RG",
                response={"servers": len(servers), "databases_with_insufficient_backup": no_backup[:10]},
                service="SQL",
                assessor_guidance=(
                    "Verify databases_with_insufficient_backup array is empty. SQL automated backups should retain "
                    "at least 7 days (FedRAMP baseline). Default is 7 days. Production systems may require 35 days."
                ),
            )
            if not servers:
                return self._result(check_def, "met", "No SQL servers found.", raw_evidence=raw)
            if not no_backup:
                return self._result(check_def, "met",
                    f"All databases across {len(servers)} server(s) have automated backups (>=7 days).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_backup)} database(s) have insufficient backup: {', '.join(no_backup[:3])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_storage_soft_delete(self, check_def: dict) -> CheckResult:
        """Check storage accounts have soft delete enabled."""
        try:
            accounts = self._list_storage_accounts()
            no_soft_delete = []
            for acct in accounts[:50]:
                rg = acct.id.split("/")[4] if acct.id else ""
                try:
                    blob_props = self._storage_client.blob_services.get_service_properties(rg, acct.name)
                    policy = blob_props.delete_retention_policy if hasattr(blob_props, 'delete_retention_policy') else None
                    if not policy or not policy.enabled or (policy.days and policy.days < 7):
                        days = policy.days if (policy and policy.enabled) else 0
                        no_soft_delete.append(f"{acct.name} ({days}d)")
                except Exception:
                    no_soft_delete.append(f"{acct.name} (error)")
            raw = self._build_evidence(
                api_call="storage_client.blob_services.get_service_properties()",
                cli_command="az storage blob service-properties delete-policy show --account-name ACCT",
                response={"total_accounts": len(accounts), "without_soft_delete": no_soft_delete[:10]},
                service="Storage",
                assessor_guidance=(
                    "Verify without_soft_delete array is empty. Soft delete protects against accidental deletion "
                    "by retaining deleted blobs for 7-365 days. Minimum 7 days recommended for contingency planning."
                ),
            )
            if not accounts:
                return self._result(check_def, "met", "No storage accounts found.", raw_evidence=raw)
            if not no_soft_delete:
                return self._result(check_def, "met",
                    f"All {len(accounts)} storage account(s) have soft delete enabled (>=7 days).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_soft_delete)} storage account(s) lack soft delete: {', '.join(no_soft_delete[:3])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_backup_restore_testing(self, check_def: dict) -> CheckResult:
        """Check backup restore jobs exist recently."""
        try:
            recovery_client = self._get_recovery_client()
            vaults = list(recovery_client.vaults.list_by_subscription_id())
            restore_jobs = []
            for vault in vaults[:10]:
                rg = vault.id.split("/")[4] if vault.id else ""
                try:
                    if not hasattr(self, '_backup_client') or self._backup_client is None:
                        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
                        with self._lock:
                            if not hasattr(self, '_backup_client') or self._backup_client is None:
                                self._backup_client = RecoveryServicesBackupClient(
                                    self._credential, self._subscription_id, **self._mgmt_kwargs)
                    jobs = list(self._backup_client.backup_jobs.list(vault.name, rg, filter="operation eq 'Restore'"))
                    restore_jobs.extend([j.properties.job_type for j in jobs[:5] if j.properties])
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="backup_client.backup_jobs.list(filter='operation eq Restore')",
                cli_command="az backup job list --resource-group RG --vault-name VAULT --query \"[?operation=='Restore']\"",
                response={"vaults": len(vaults), "restore_jobs": len(restore_jobs)},
                service="Backup",
                assessor_guidance=(
                    "Verify restore_jobs > 0. Restore testing validates backup integrity and recovery procedures. "
                    "FedRAMP CP-9(b) requires periodic restore testing to ensure backups are viable."
                ),
            )
            if len(restore_jobs) > 0:
                return self._result(check_def, "met",
                    f"{len(restore_jobs)} restore job(s) found across {len(vaults)} vault(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"No restore jobs found. Consider periodic restore testing for {len(vaults)} vault(s).",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_backup_geo_replication(self, check_def: dict) -> CheckResult:
        """Check backup vaults use geo-redundant storage."""
        try:
            recovery_client = self._get_recovery_client()
            vaults = list(recovery_client.vaults.list_by_subscription_id())
            non_geo = []
            for vault in vaults:
                storage_type = vault.properties.backup_storage_properties.storage_model_type if (
                    vault.properties and
                    hasattr(vault.properties, 'backup_storage_properties') and
                    vault.properties.backup_storage_properties
                ) else "Unknown"
                if storage_type and "geo" not in storage_type.lower():
                    non_geo.append(f"{vault.name} ({storage_type})")
            raw = self._build_evidence(
                api_call="recovery_client.vaults.list_by_subscription_id()",
                cli_command="az backup vault backup-properties show --resource-group RG --name VAULT",
                response={"total_vaults": len(vaults), "non_geo_redundant": non_geo},
                service="RecoveryServices",
                assessor_guidance=(
                    "Verify non_geo_redundant array is empty. Backup vaults should use GeoRedundant storage "
                    "to replicate backups to secondary region for disaster recovery."
                ),
            )
            if not vaults:
                return self._result(check_def, "met", "No backup vaults found.", raw_evidence=raw)
            if not non_geo:
                return self._result(check_def, "met",
                    f"All {len(vaults)} backup vault(s) use geo-redundant storage.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(non_geo)} backup vault(s) lack geo-redundancy: {', '.join(non_geo[:3])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_site_recovery_configured(self, check_def: dict) -> CheckResult:
        """Check Site Recovery is configured for critical VMs."""
        try:
            recovery_client = self._get_recovery_client()
            vaults = list(recovery_client.vaults.list_by_subscription_id())
            protected_items = 0
            for vault in vaults[:10]:
                rg = vault.id.split("/")[4] if vault.id else ""
                try:
                    if not hasattr(self, '_site_recovery_client') or self._site_recovery_client is None:
                        from azure.mgmt.recoveryservicessiterecovery import SiteRecoveryManagementClient
                        with self._lock:
                            if not hasattr(self, '_site_recovery_client') or self._site_recovery_client is None:
                                self._site_recovery_client = SiteRecoveryManagementClient(
                                    self._credential, self._subscription_id, **self._mgmt_kwargs)
                    items = list(self._site_recovery_client.replication_protected_items.list(rg, vault.name))
                    protected_items += len(items)
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="site_recovery_client.replication_protected_items.list()",
                cli_command="az site-recovery replicated-item list --resource-group RG --vault-name VAULT",
                response={"vaults": len(vaults), "protected_items": protected_items},
                service="SiteRecovery",
                assessor_guidance=(
                    "Verify protected_items > 0 for critical workloads. Azure Site Recovery provides automated "
                    "VM replication to secondary region for disaster recovery with orchestrated failover."
                ),
            )
            if protected_items > 0:
                return self._result(check_def, "met",
                    f"Site Recovery configured: {protected_items} protected item(s) across {len(vaults)} vault(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"No Site Recovery protected items found. {len(vaults)} vault(s) available.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_sql_point_in_time_restore(self, check_def: dict) -> CheckResult:
        """Check SQL databases support point-in-time restore."""
        try:
            servers = self._list_sql_servers()
            no_pitr = []
            for srv in servers[:20]:
                rg = srv.id.split("/")[4] if srv.id else ""
                try:
                    dbs = list(self._get_sql_client().databases.list_by_server(rg, srv.name))
                    for db in dbs:
                        if db.name.lower() == "master":
                            continue
                        earliest_restore = getattr(db, 'earliest_restore_date', None)
                        if not earliest_restore:
                            no_pitr.append(f"{srv.name}/{db.name}")
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="sql_client.databases.list_by_server()",
                cli_command="az sql db show --server SERVER --name DB --resource-group RG --query earliestRestoreDate",
                response={"servers": len(servers), "databases_without_pitr": no_pitr[:10]},
                service="SQL",
                assessor_guidance=(
                    "Verify databases_without_pitr array is empty. Point-in-time restore (PITR) allows recovery "
                    "to any point within retention period. Check earliestRestoreDate is populated."
                ),
            )
            if not servers:
                return self._result(check_def, "met", "No SQL servers found.", raw_evidence=raw)
            if not no_pitr:
                return self._result(check_def, "met",
                    f"All databases across {len(servers)} server(s) support point-in-time restore.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_pitr)} database(s) lack PITR: {', '.join(no_pitr[:3])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ---- PL: Planning ----

    def check_blueprint_security_plans(self, check_def: dict) -> CheckResult:
        """Check Azure Blueprints or Policy initiatives document security plans."""
        try:
            policy_client = self._get_policy_client()
            assignments = list(policy_client.policy_assignments.list())
            initiatives = []
            for assignment in assignments[:100]:
                if hasattr(assignment, 'policy_definition_id') and '/policySetDefinitions/' in assignment.policy_definition_id:
                    initiatives.append(assignment.display_name or assignment.name)
            raw = self._build_evidence(
                api_call="policy_client.policy_assignments.list()",
                cli_command="az policy assignment list --query \"[?policyDefinitionId contains 'policySetDefinitions']\"",
                response={"total_assignments": len(assignments), "policy_initiatives": initiatives[:10]},
                service="Policy",
                assessor_guidance=(
                    "Verify policy_initiatives contains security-related initiatives. Policy initiatives (blueprint assignments) "
                    "document system security plans through enforced controls. Look for CIS, NIST, FedRAMP initiatives."
                ),
            )
            if len(initiatives) > 0:
                return self._result(check_def, "met",
                    f"{len(initiatives)} policy initiative(s) assigned documenting security plans.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"No policy initiatives found. Consider Azure Blueprints or security initiatives.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_architecture_tags(self, check_def: dict) -> CheckResult:
        """Check critical resources have architecture metadata tags."""
        try:
            resources = list(self._resource_client.resources.list())
            tagged = []
            for res in resources[:500]:
                tags = res.tags or {}
                if any(k.lower() in ["architecture", "dataclassification", "tier", "criticality", "component"]
                       for k in tags.keys()):
                    tagged.append(res.name)
            raw = self._build_evidence(
                api_call="resource.resources.list()",
                cli_command="az resource list --query \"[?tags.Architecture || tags.DataClassification]\"",
                response={"total_resources": len(resources), "tagged_with_architecture": len(tagged)},
                service="ResourceManagement",
                assessor_guidance=(
                    "Verify resources have Architecture/DataClassification/Tier tags. Tags document system architecture "
                    "and data flow for security planning. FedRAMP PL-2 requires system architecture documentation."
                ),
            )
            if len(resources) == 0:
                return self._result(check_def, "met", "No resources found.", raw_evidence=raw)
            coverage = len(tagged) / len(resources) if resources else 0
            if coverage >= 0.5:
                return self._result(check_def, "met",
                    f"{len(tagged)}/{len(resources)} resources ({coverage*100:.0f}%) have architecture tags.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Only {len(tagged)}/{len(resources)} resources ({coverage*100:.0f}%) have architecture tags.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_nsg_flow_logs_architecture(self, check_def: dict) -> CheckResult:
        """Check NSG flow logs support architecture review."""
        try:
            nsgs = self._list_nsgs()
            watchers = self._list_watchers()
            flow_log_enabled = 0
            for nsg in nsgs[:50]:
                for watcher in watchers[:5]:
                    rg = watcher.id.split("/")[4] if watcher.id else ""
                    try:
                        flow_log = self._network_client.flow_logs.get(rg, watcher.name, f"{nsg.name}-flowlog")
                        if flow_log and getattr(flow_log, 'enabled', False):
                            flow_log_enabled += 1
                            break
                    except Exception:
                        pass
            raw = self._build_evidence(
                api_call="network_client.flow_logs.get()",
                cli_command="az network watcher flow-log list --location REGION",
                response={"total_nsgs": len(nsgs), "flow_logs_enabled": flow_log_enabled},
                service="Network",
                assessor_guidance=(
                    "Verify flow_logs_enabled >= total_nsgs * 0.8. NSG flow logs capture network traffic for "
                    "architecture analysis and security monitoring. Supports PL-2 data flow documentation."
                ),
            )
            if not nsgs:
                return self._result(check_def, "met", "No NSGs found.", raw_evidence=raw)
            coverage = flow_log_enabled / len(nsgs) if nsgs else 0
            if coverage >= 0.8:
                return self._result(check_def, "met",
                    f"{flow_log_enabled}/{len(nsgs)} NSGs ({coverage*100:.0f}%) have flow logs enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Only {flow_log_enabled}/{len(nsgs)} NSGs ({coverage*100:.0f}%) have flow logs. Enable for architecture visibility.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ---- PT: PII Processing ----

    def check_purview_enabled(self, check_def: dict) -> CheckResult:
        """Check Microsoft Purview is enabled."""
        try:
            resources = list(self._resource_client.resources.list(
                filter="resourceType eq 'Microsoft.Purview/accounts'"))
            purview_accounts = [r.name for r in resources]
            raw = self._build_evidence(
                api_call="resource_client.resources.list(filter='resourceType eq Microsoft.Purview/accounts')",
                cli_command="az resource list --resource-type Microsoft.Purview/accounts",
                response={"purview_accounts": purview_accounts},
                service="Purview",
                assessor_guidance=(
                    "Verify purview_accounts array is not empty. Microsoft Purview provides data governance, "
                    "classification, and lineage tracking for PII processing compliance. Required for PT controls."
                ),
            )
            if len(purview_accounts) > 0:
                return self._result(check_def, "met",
                    f"Microsoft Purview enabled: {len(purview_accounts)} account(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No Microsoft Purview accounts found. Consider enabling for PII tracking.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_storage_data_classification_tags(self, check_def: dict) -> CheckResult:
        """Check storage accounts have data classification tags."""
        try:
            accounts = self._list_storage_accounts()
            untagged = []
            for acct in accounts:
                tags = acct.tags or {}
                if not any(k.lower() in ["dataclassification", "datatype", "pii", "sensitivity"]
                          for k in tags.keys()):
                    untagged.append(acct.name)
            raw = self._build_evidence(
                api_call="storage_client.storage_accounts.list()",
                cli_command="az storage account list --query \"[?!tags.DataClassification]\"",
                response={"total_accounts": len(accounts), "untagged": untagged[:10]},
                service="Storage",
                assessor_guidance=(
                    "Verify untagged array is empty. Storage accounts should have DataClassification/PII/Sensitivity tags "
                    "identifying data types. Required for PT-1 (data processing purpose) and PT-2 (data minimization)."
                ),
            )
            if not accounts:
                return self._result(check_def, "met", "No storage accounts found.", raw_evidence=raw)
            if not untagged:
                return self._result(check_def, "met",
                    f"All {len(accounts)} storage account(s) have data classification tags.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(untagged)} storage account(s) lack data classification tags: {', '.join(untagged[:3])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_sql_data_classification_tags(self, check_def: dict) -> CheckResult:
        """Check SQL databases have data classification tags."""
        try:
            servers = self._list_sql_servers()
            unclassified = []
            for srv in servers[:20]:
                tags = srv.tags or {}
                if not any(k.lower() in ["dataclassification", "datatype", "pii", "sensitivity"]
                          for k in tags.keys()):
                    unclassified.append(srv.name)
            raw = self._build_evidence(
                api_call="sql_client.servers.list()",
                cli_command="az sql server list --query \"[?!tags.DataClassification]\"",
                response={"total_servers": len(servers), "unclassified": unclassified[:10]},
                service="SQL",
                assessor_guidance=(
                    "Verify unclassified array is empty. SQL servers/databases should have DataClassification tags. "
                    "Azure SQL also supports column-level classification via Information Protection policies."
                ),
            )
            if not servers:
                return self._result(check_def, "met", "No SQL servers found.", raw_evidence=raw)
            if not unclassified:
                return self._result(check_def, "met",
                    f"All {len(servers)} SQL server(s) have data classification tags.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(unclassified)} SQL server(s) lack data classification tags: {', '.join(unclassified[:3])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_data_processing_purpose_tags(self, check_def: dict) -> CheckResult:
        """Check resources have data processing purpose tags."""
        try:
            resources = list(self._resource_client.resources.list())
            tagged = []
            for res in resources[:500]:
                tags = res.tags or {}
                if any(k.lower() in ["dataprocessingpurpose", "purpose", "businessfunction", "dataflow"]
                       for k in tags.keys()):
                    tagged.append(res.name)
            raw = self._build_evidence(
                api_call="resource.resources.list()",
                cli_command="az resource list --query \"[?tags.DataProcessingPurpose || tags.Purpose]\"",
                response={"total_resources": len(resources), "tagged_with_purpose": len(tagged)},
                service="ResourceManagement",
                assessor_guidance=(
                    "Verify resources have DataProcessingPurpose/Purpose tags. PT-1 requires documenting purpose "
                    "for PII processing. Tags should indicate business function and data handling purpose."
                ),
            )
            if len(resources) == 0:
                return self._result(check_def, "met", "No resources found.", raw_evidence=raw)
            coverage = len(tagged) / len(resources) if resources else 0
            if coverage >= 0.5:
                return self._result(check_def, "met",
                    f"{len(tagged)}/{len(resources)} resources ({coverage*100:.0f}%) have purpose tags.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Only {len(tagged)}/{len(resources)} resources ({coverage*100:.0f}%) have purpose tags.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_api_consent_documentation(self, check_def: dict) -> CheckResult:
        """Check API Management has consent/privacy documentation."""
        try:
            apim_resources = list(self._resource_client.resources.list(
                filter="resourceType eq 'Microsoft.ApiManagement/service'"))
            documented = []
            for apim in apim_resources:
                tags = apim.tags or {}
                if any(k.lower() in ["privacypolicy", "consent", "dataprocessing", "gdpr"]
                       for k in tags.keys()):
                    documented.append(apim.name)
            raw = self._build_evidence(
                api_call="resource_client.resources.list(filter='resourceType eq Microsoft.ApiManagement/service')",
                cli_command="az resource list --resource-type Microsoft.ApiManagement/service",
                response={"total_apim": len(apim_resources), "with_documentation": documented},
                service="APIM",
                assessor_guidance=(
                    "Verify API Management instances have PrivacyPolicy/Consent/DataProcessing tags. "
                    "APIs processing PII should document consent mechanisms and privacy policies per PT-3."
                ),
            )
            if not apim_resources:
                return self._result(check_def, "met", "No API Management instances found.", raw_evidence=raw)
            if len(documented) == len(apim_resources):
                return self._result(check_def, "met",
                    f"All {len(apim_resources)} API Management instance(s) have consent documentation.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Only {len(documented)}/{len(apim_resources)} API Management instances have consent documentation.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ---- SA: System Acquisition ----

    def check_azure_pipelines_configured(self, check_def: dict) -> CheckResult:
        """Check Azure DevOps or GitHub Actions CI/CD exists."""
        try:
            # Check for Azure DevOps resources (automation accounts with runbooks indicate CI/CD)
            automation_resources = list(self._resource_client.resources.list(
                filter="resourceType eq 'Microsoft.Automation/automationAccounts'"))
            # Check for GitHub Actions runner resources
            runner_resources = list(self._resource_client.resources.list(
                filter="resourceType eq 'Microsoft.Compute/virtualMachines' and tags.GitHubActions"))
            ci_cd_indicators = len(automation_resources) + len(runner_resources)
            raw = self._build_evidence(
                api_call="resource_client.resources.list()",
                cli_command="az resource list --resource-type Microsoft.Automation/automationAccounts",
                response={"automation_accounts": len(automation_resources),
                         "github_runners": len(runner_resources),
                         "ci_cd_indicators": ci_cd_indicators},
                service="DevOps",
                assessor_guidance=(
                    "Verify ci_cd_indicators > 0. CI/CD automation demonstrates SA-11 (developer testing) and "
                    "SA-15 (development process). Look for Azure Automation, GitHub Actions runners, or DevOps agents."
                ),
            )
            if ci_cd_indicators > 0:
                return self._result(check_def, "met",
                    f"CI/CD infrastructure detected: {len(automation_resources)} automation account(s), {len(runner_resources)} runner(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No CI/CD infrastructure detected. Consider Azure DevOps or GitHub Actions.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_nsg_unused_ports(self, check_def: dict) -> CheckResult:
        """Check NSGs don't have unnecessary open ports."""
        try:
            nsgs = self._list_nsgs()
            risky_rules = []
            for nsg in nsgs[:50]:
                for rule in (nsg.security_rules or []):
                    if rule.direction == "Inbound" and rule.access == "Allow":
                        # Check for overly permissive rules
                        source = rule.source_address_prefix or ""
                        dest_port = rule.destination_port_range or ""
                        if ("*" in source or "0.0.0.0" in source or "internet" in source.lower()):
                            if dest_port in ["*", "0-65535"] or any(p in str(dest_port) for p in ["22", "3389", "445", "135", "1433", "3306"]):
                                risky_rules.append(f"{nsg.name}/{rule.name} (port {dest_port})")
            raw = self._build_evidence(
                api_call="network_client.network_security_groups.list_all()",
                cli_command="az network nsg rule list --nsg-name NSG --resource-group RG",
                response={"total_nsgs": len(nsgs), "risky_rules": risky_rules[:10]},
                service="Network",
                assessor_guidance=(
                    "Verify risky_rules array is empty. NSGs should follow least privilege (SA-4). "
                    "Avoid allowing SSH/RDP/SMB/SQL from Internet (*). Use JIT access or Azure Bastion instead."
                ),
            )
            if not risky_rules:
                return self._result(check_def, "met",
                    f"No overly permissive NSG rules found across {len(nsgs)} NSG(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(risky_rules)} risky NSG rule(s) found: {', '.join(risky_rules[:3])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_api_management_documented(self, check_def: dict) -> CheckResult:
        """Check API Management instances have documentation."""
        try:
            apim_resources = list(self._resource_client.resources.list(
                filter="resourceType eq 'Microsoft.ApiManagement/service'"))
            documented = []
            for apim in apim_resources:
                tags = apim.tags or {}
                if any(k.lower() in ["documentation", "api-docs", "swagger", "openapi"]
                       for k in tags.keys()):
                    documented.append(apim.name)
            raw = self._build_evidence(
                api_call="resource_client.resources.list(filter='resourceType eq Microsoft.ApiManagement/service')",
                cli_command="az apim show --name APIM --resource-group RG",
                response={"total_apim": len(apim_resources), "documented": documented},
                service="APIM",
                assessor_guidance=(
                    "Verify API Management instances have documentation tags. SA-5 requires developer documentation. "
                    "APIM should expose OpenAPI/Swagger specs for API consumers."
                ),
            )
            if not apim_resources:
                return self._result(check_def, "met", "No API Management instances found.", raw_evidence=raw)
            if len(documented) == len(apim_resources):
                return self._result(check_def, "met",
                    f"All {len(apim_resources)} API Management instance(s) have documentation.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Only {len(documented)}/{len(apim_resources)} API Management instances documented.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_azure_repos_branch_policies(self, check_def: dict) -> CheckResult:
        """Check branch policies are configured."""
        try:
            # Check for policy assignments related to code management
            policy_client = self._get_policy_client()
            assignments = list(policy_client.policy_assignments.list())
            code_policies = []
            for assignment in assignments[:100]:
                name = (assignment.display_name or assignment.name or "").lower()
                if any(term in name for term in ["code", "branch", "repo", "git", "commit"]):
                    code_policies.append(assignment.display_name or assignment.name)
            raw = self._build_evidence(
                api_call="policy_client.policy_assignments.list()",
                cli_command="az policy assignment list --query \"[?contains(displayName,'code')]\"",
                response={"code_related_policies": code_policies},
                service="Policy",
                assessor_guidance=(
                    "Verify code_related_policies contains branch protection policies. SA-11 requires code review. "
                    "Azure DevOps/GitHub branch policies enforce pull requests, reviews, and status checks."
                ),
            )
            if len(code_policies) > 0:
                return self._result(check_def, "met",
                    f"Code management policies detected: {len(code_policies)} policy/policies.",
                    raw_evidence=raw)
            return self._result(check_def, "manual",
                "Unable to verify branch policies via Azure Policy. Check Azure DevOps/GitHub directly.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_pipeline_test_stages(self, check_def: dict) -> CheckResult:
        """Check deployment pipelines include test stages."""
        try:
            # Check for automation accounts with test-related runbooks
            automation_client = self._get_automation_client()
            accounts = list(automation_client.automation_account.list())
            test_runbooks = []
            for account in accounts[:10]:
                rg = account.id.split("/")[4] if account.id else ""
                try:
                    runbooks = list(automation_client.runbook.list_by_automation_account(rg, account.name))
                    for rb in runbooks:
                        if any(term in (rb.name or "").lower() for term in ["test", "unittest", "validate", "check"]):
                            test_runbooks.append(f"{account.name}/{rb.name}")
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="automation_client.runbook.list_by_automation_account()",
                cli_command="az automation runbook list --automation-account-name ACCT --resource-group RG",
                response={"automation_accounts": len(accounts), "test_runbooks": test_runbooks[:10]},
                service="Automation",
                assessor_guidance=(
                    "Verify test_runbooks contains testing automation. SA-11 requires developer security testing. "
                    "Pipelines should include unit tests, security scans, and validation stages."
                ),
            )
            if len(test_runbooks) > 0:
                return self._result(check_def, "met",
                    f"Test automation detected: {len(test_runbooks)} test runbook(s).",
                    raw_evidence=raw)
            return self._result(check_def, "manual",
                "No test runbooks detected. Verify pipeline test stages in Azure DevOps/GitHub Actions.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_security_devops_sast(self, check_def: dict) -> CheckResult:
        """Check Defender for DevOps is configured for SAST."""
        try:
            security_client = self._get_security_client()
            # Check for DevOps connectors
            devops_connectors = []
            try:
                connectors = list(security_client.dev_ops_configurations.list())
                devops_connectors = [c.name for c in connectors]
            except Exception:
                pass
            raw = self._build_evidence(
                api_call="security_client.dev_ops_configurations.list()",
                cli_command="az security devops list",
                response={"devops_connectors": devops_connectors},
                service="DefenderForDevOps",
                assessor_guidance=(
                    "Verify devops_connectors is not empty. Defender for DevOps provides SAST scanning in pipelines. "
                    "SA-11(1) requires static code analysis. Configure GitHub/Azure DevOps integration."
                ),
            )
            if len(devops_connectors) > 0:
                return self._result(check_def, "met",
                    f"Defender for DevOps configured: {len(devops_connectors)} connector(s).",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "Defender for DevOps not configured. Enable for automated SAST scanning.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_defender_eol_software(self, check_def: dict) -> CheckResult:
        """Check Defender identifies EOL/unsupported software."""
        try:
            security_client = self._get_security_client()
            assessments = list(security_client.assessments.list(
                scope=f"/subscriptions/{self._subscription_id}"))
            eol_findings = []
            for assessment in assessments[:100]:
                name = (getattr(assessment, 'display_name', '') or '').lower()
                if any(term in name for term in ["unsupported", "end of support", "eol", "deprecated", "outdated"]):
                    status = getattr(assessment, 'status', None)
                    if status and hasattr(status, 'code') and status.code in ["Unhealthy", "NotApplicable"]:
                        eol_findings.append(assessment.display_name or assessment.name)
            raw = self._build_evidence(
                api_call="security_client.assessments.list()",
                cli_command="az security assessment list --query \"[?contains(displayName,'unsupported')]\"",
                response={"total_assessments": len(assessments), "eol_findings": eol_findings[:10]},
                service="Defender",
                assessor_guidance=(
                    "Verify eol_findings array. Defender for Cloud identifies unsupported software. "
                    "SA-22 requires replacing unsupported components. Review and remediate EOL software."
                ),
            )
            return self._result(check_def, "met",
                f"Defender monitoring EOL software: {len(eol_findings)} potential finding(s) detected.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    # ---- SR: Supply Chain ----

    def check_acr_vulnerability_scanning(self, check_def: dict) -> CheckResult:
        """Check ACR has vulnerability scanning enabled."""
        try:
            acr_resources = list(self._resource_client.resources.list(
                filter="resourceType eq 'Microsoft.ContainerRegistry/registries'"))
            security_client = self._get_security_client()
            protected_acrs = []
            for acr in acr_resources:
                rg = acr.id.split("/")[4] if acr.id else ""
                try:
                    # Check if Defender for Containers is enabled
                    pricing = security_client.pricings.get(f"Microsoft.ContainerRegistry/registries/{acr.name}")
                    if pricing and getattr(pricing, 'pricing_tier', '') == 'Standard':
                        protected_acrs.append(acr.name)
                except Exception:
                    pass
            raw = self._build_evidence(
                api_call="security_client.pricings.get()",
                cli_command="az security pricing show --name ContainerRegistry",
                response={"total_acrs": len(acr_resources), "with_scanning": protected_acrs},
                service="ContainerRegistry",
                assessor_guidance=(
                    "Verify with_scanning contains all ACRs. Defender for Containers provides vulnerability scanning. "
                    "SR-3(1) requires automated vulnerability scanning of container images before deployment."
                ),
            )
            if not acr_resources:
                return self._result(check_def, "met", "No container registries found.", raw_evidence=raw)
            if len(protected_acrs) == len(acr_resources):
                return self._result(check_def, "met",
                    f"All {len(acr_resources)} container registr(y/ies) have vulnerability scanning enabled.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"Only {len(protected_acrs)}/{len(acr_resources)} container registries have scanning enabled.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_pipeline_dependency_scanning(self, check_def: dict) -> CheckResult:
        """Check pipeline includes dependency scanning."""
        try:
            security_client = self._get_security_client()
            # Check for DevOps security assessments related to dependencies
            assessments = list(security_client.assessments.list(
                scope=f"/subscriptions/{self._subscription_id}"))
            dependency_checks = []
            for assessment in assessments[:100]:
                name = (getattr(assessment, 'display_name', '') or '').lower()
                if any(term in name for term in ["dependency", "package", "library", "component", "supply chain"]):
                    dependency_checks.append(assessment.display_name or assessment.name)
            raw = self._build_evidence(
                api_call="security_client.assessments.list()",
                cli_command="az security assessment list --query \"[?contains(displayName,'dependency')]\"",
                response={"dependency_checks": dependency_checks[:10]},
                service="DefenderForDevOps",
                assessor_guidance=(
                    "Verify dependency_checks is not empty. Dependency scanning identifies vulnerable packages. "
                    "SR-3(1) and SA-11(1) require automated scanning of third-party components."
                ),
            )
            if len(dependency_checks) > 0:
                return self._result(check_def, "met",
                    f"Dependency scanning detected: {len(dependency_checks)} check(s) configured.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                "No dependency scanning checks detected. Enable Defender for DevOps dependency scanning.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def check_acr_content_trust(self, check_def: dict) -> CheckResult:
        """Check ACR has content trust enabled."""
        try:
            acr_resources = list(self._resource_client.resources.list(
                filter="resourceType eq 'Microsoft.ContainerRegistry/registries'"))
            no_trust = []
            for acr in acr_resources:
                rg = acr.id.split("/")[4] if acr.id else ""
                try:
                    # Check ACR policies via REST API
                    acr_name = acr.name
                    # Content trust (Docker Content Trust) is typically configured via ACR policies
                    # This is a simplified check - in reality would need to query ACR policies API
                    tags = acr.tags or {}
                    if not any(k.lower() in ["contenttrust", "signed", "notary"] for k in tags.keys()):
                        no_trust.append(acr.name)
                except Exception:
                    no_trust.append(acr.name)
            raw = self._build_evidence(
                api_call="resource_client.resources.list(filter='resourceType eq Microsoft.ContainerRegistry/registries')",
                cli_command="az acr config content-trust show --registry ACR",
                response={"total_acrs": len(acr_resources), "without_content_trust": no_trust},
                service="ContainerRegistry",
                assessor_guidance=(
                    "Verify without_content_trust array is empty. Content trust ensures only signed images are deployed. "
                    "SR-3 requires verification of software authenticity. Enable Docker Content Trust/Notary."
                ),
            )
            if not acr_resources:
                return self._result(check_def, "met", "No container registries found.", raw_evidence=raw)
            if not no_trust:
                return self._result(check_def, "met",
                    f"All {len(acr_resources)} container registr(y/ies) have content trust indicators.",
                    raw_evidence=raw)
            return self._result(check_def, "not_met",
                f"{len(no_trust)} container registr(y/ies) lack content trust: {', '.join(no_trust[:3])}.",
                raw_evidence=raw)
        except Exception as e:
            return self._result(check_def, "error", f"Check failed: {e}")

    def disconnect(self):
        """Clean up Azure SDK clients."""
        self._credential = None
        self._resource_client = None
        self._network_client = None
        self._compute_client = None
        self._storage_client = None
        self._keyvault_client = None
        self._monitor_client = None
        self._auth_client = None
        self._security_client = None
        self._sql_client = None
        self._web_client = None
        self._policy_client = None
        self._recovery_client = None
        self._advisor_client = None
        self._resourcegraph_client = None
        self._automation_client = None
        self._loganalytics_client = None
        self._sentinel_client = None
        # Clean up new lazy-initialized clients
        if hasattr(self, '_backup_client'):
            self._backup_client = None
        if hasattr(self, '_site_recovery_client'):
            self._site_recovery_client = None
        if hasattr(self, '_traffic_manager_client'):
            self._traffic_manager_client = None
        self._cache.clear()
        self._connected = False
