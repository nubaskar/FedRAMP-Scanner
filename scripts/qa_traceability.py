#!/usr/bin/env python3
"""
QA Traceability Validation Script for FedRAMP Scanner.

Statically analyzes config files and scanner source code to validate the
traceability chain:

  FedRAMP Level → NIST 800-53 Rev 5 Control → 800-53A Objective
    → Scanner Check → Cloud API Call → Met/Not Met

No cloud credentials or running services needed — purely offline analysis.

Usage:
    cd backend && python ../scripts/qa_traceability.py

Output:
    - Console summary (pass/fail/warn per QA check)
    - qa/qa_traceability_report.md (full detail)

Exit code: 0 if no errors, 1 if any ERROR-level findings.
"""
from __future__ import annotations

import ast
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Resolve project paths (works from backend/ or project root)
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
CONFIG_DIR = PROJECT_ROOT / "config"
CHECKS_DIR = CONFIG_DIR / "checks"
PRACTICES_FILE = CONFIG_DIR / "nist_800_53_controls.json"
ENGINE_FILE = PROJECT_ROOT / "backend" / "app" / "scanner" / "engine.py"
SCANNER_FILES = {
    "aws": PROJECT_ROOT / "backend" / "app" / "scanner" / "aws_scanner.py",
    "azure": PROJECT_ROOT / "backend" / "app" / "scanner" / "azure_scanner.py",
    "gcp": PROJECT_ROOT / "backend" / "app" / "scanner" / "gcp_scanner.py",
}
REPORT_DIR = PROJECT_ROOT / "qa"

# Required fields in every check definition
REQUIRED_CHECK_FIELDS = {"check_id", "name", "service", "api_call", "expected",
                         "severity", "supports_objectives"}

# Valid check_id pattern: {family}-{control}[-{enhancement}]-{provider}-{sequence}
# Examples: ac-2-aws-001, ac-6-3-azure-001, sc-7-5-gcp-002
CHECK_ID_RE = re.compile(
    r"^[a-z]{2}-"                    # family (ac, au, sc, ...)
    r"\d+"                           # control number (2, 6, 7, ...)
    r"(-\d+)?"                       # optional enhancement (-3, -5, ...)
    r"-(aws|azure|gcp)-"            # provider
    r"\d{3}$"                        # sequence (001, 002, ...)
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """A single QA finding — error, warning, or info."""
    level: str          # "ERROR", "WARNING", "INFO"
    qa_check: str       # e.g., "1.1 Structural Integrity"
    check_id: str       # config check_id or control_id affected
    message: str


@dataclass
class QACheckResult:
    """Aggregated result for one QA sub-check."""
    name: str
    passed: int = 0
    failed: int = 0
    warned: int = 0
    findings: list[Finding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------
def load_controls() -> dict:
    """Load nist_800_53_controls.json → {control_id: {requirement, level, objectives, automated, ...}}

    Includes both base controls (AC-2) and enhancements (AC-2(9), AC-6(3)).
    Enhancement IDs are normalized from JSON format (AC-6.3) to NIST format (AC-6(3)).
    """
    with open(PRACTICES_FILE) as f:
        data = json.load(f)
    controls: dict = {}
    for _fam_id, fam in data.get("families", {}).items():
        domain = fam.get("domain", "")
        for pid, pdata in fam.get("controls", {}).items():
            controls[pid] = {**pdata, "domain": domain}
            # Include enhancements with both ID formats
            for enh_id, enh_data in pdata.get("enhancements", {}).items():
                enh_entry = {**enh_data, "domain": domain}
                # Store as original dot format (AC-6.3)
                controls[enh_id] = enh_entry
                # Also store as paren format (AC-6(3)) used in some check files
                parts = enh_id.rsplit(".", 1)
                if len(parts) == 2:
                    nist_id = f"{parts[0]}({parts[1]})"
                    controls[nist_id] = enh_entry
    return controls


def load_all_checks() -> list[dict]:
    """Load every check from config/checks/*.json, preserving control_id and domain context."""
    checks: list[dict] = []
    for check_file in sorted(CHECKS_DIR.glob("*.json")):
        with open(check_file) as f:
            data = json.load(f)
        domain = data.get("domain", "")
        for control_id, control_data in data.get("checks", {}).items():
            if control_data.get("manual_only"):
                continue  # manual-only controls have no automated checks
            for provider in ("aws", "azure", "gcp"):
                for chk in control_data.get(provider, []):
                    chk["_control_id"] = control_id
                    chk["_domain"] = domain
                    chk["_provider"] = provider
                    chk["_file"] = check_file.name
                    checks.append(chk)
    return checks


def load_check_configs_raw() -> dict[str, dict]:
    """Load raw check configs keyed by domain file → full data."""
    configs: dict[str, dict] = {}
    for check_file in sorted(CHECKS_DIR.glob("*.json")):
        with open(check_file) as f:
            configs[check_file.name] = json.load(f)
    return configs


def extract_engine_check_methods() -> dict[str, dict[str, str]]:
    """
    Parse engine.py with AST to extract *_CHECK_METHODS dicts.

    Returns: {"aws": {check_id: method_name}, "azure": ..., "gcp": ...}
    """
    source = ENGINE_FILE.read_text()
    tree = ast.parse(source, filename=str(ENGINE_FILE))

    result: dict[str, dict[str, str]] = {}
    name_map = {
        "AWS_CHECK_METHODS": "aws",
        "AZURE_CHECK_METHODS": "azure",
        "GCP_CHECK_METHODS": "gcp",
    }

    for node in ast.walk(tree):
        # Handle both `X = {...}` (Assign) and `X: type = {...}` (AnnAssign)
        var_name = None
        value_node = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            var_name = node.target.id
            value_node = node.value
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    value_node = node.value
                    break

        if var_name and var_name in name_map and isinstance(value_node, ast.Dict):
            platform = name_map[var_name]
            methods: dict[str, str] = {}
            for k, v in zip(value_node.keys, value_node.values):
                if isinstance(k, ast.Constant) and isinstance(v, ast.Constant):
                    methods[k.value] = v.value
            result[platform] = methods
    return result


def extract_scanner_methods(filepath: Path) -> dict[str, tuple[int, int]]:
    """
    Parse a scanner .py file with AST to find all methods in scanner classes.

    Returns: {method_name: (start_line, end_line)}
    Includes check_* methods, helper methods (_list_*, _get_*), etc.
    """
    source = filepath.read_text()
    tree = ast.parse(source, filename=str(filepath))

    methods: dict[str, tuple[int, int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    end = item.end_lineno or item.lineno
                    methods[item.name] = (item.lineno, end)
    return methods


def extract_api_calls_from_method(source_lines: list[str], start: int, end: int) -> list[str]:
    """
    Extract API call patterns from a method body using regex.

    Looks for patterns like:
      - self._iam.get_account_summary(              — boto3 direct
      - self._network_client.azure_firewalls.list_all( — Azure chained
      - self._graph_get("path")                      — Azure Graph API
      - self._gcp_api_get("url")                     — GCP REST
      - client.get_iam_policy(                       — GCP local client
      - self._build_evidence(api_call="...")          — canonical declaration
    """
    body = "\n".join(source_lines[start - 1:end])
    calls: list[str] = []
    skip_clients = {"cache", "session", "connected", "account_id",
                    "credential", "subscription_id", "project_id",
                    "credentials", "build_evidence", "result", "cached"}

    # Pattern 1: self._<client>.<method>( — boto3 / simple SDK calls
    for m in re.finditer(r'self\._(\w+)\.(\w+)\(', body):
        client_name = m.group(1)
        method_name = m.group(2)
        if client_name in skip_clients or method_name.startswith("_"):
            continue
        calls.append(f"{client_name}.{method_name}")

    # Pattern 1b: self._<client>.<sub>.<method>( — Azure chained SDK calls
    for m in re.finditer(r'self\._(\w+)\.(\w+)\.(\w+)\(', body):
        client_name = m.group(1)
        sub = m.group(2)
        method_name = m.group(3)
        if client_name in skip_clients:
            continue
        calls.append(f"{sub}.{method_name}")

    # Pattern 2: self._graph_get("path") or self._graph_get_safe("path")
    for m in re.finditer(r'self\._graph_get(?:_safe)?\(\s*["\']([^"\']+)["\']', body):
        # Strip query parameters for matching
        path = m.group(1).split("?")[0]
        calls.append(f"graph/{path}")

    # Pattern 2b: self._gcp_api_get or self._gcp_api_get_safe — GCP REST calls
    for m in re.finditer(r'self\._gcp_api_get(?:_safe)?\(', body):
        # The actual API is declared in _build_evidence; flag that this is a GCP REST call
        calls.append("gcp_rest_call")

    # Pattern 3: GCP local client variable calls — <var>.method(
    # Match: client.get_iam_policy(, client.list_topics(, etc.
    for m in re.finditer(r'\b(\w+_?client|\w+_service)\s*\.\s*(\w+)\(', body):
        calls.append(f"client.{m.group(2)}")
    # Pattern 3b: Chained local client calls — local_client.sub.method(
    # Matches: policy_client.policy_assignments.list(, automation_client.runbook.list_by_...(
    for m in re.finditer(r'\b(\w+_client)\s*\.\s*(\w+)\s*\.\s*(\w+)\(', body):
        calls.append(f"{m.group(2)}.{m.group(3)}")
    # Also match: client = Foo.BarClient(...) then client.method(
    for m in re.finditer(r'(\w+)\s*=\s*\w+\.\w+Client\(', body):
        var_name = m.group(1)
        for m2 in re.finditer(rf'\b{re.escape(var_name)}\.(\w+)\(', body):
            if not m2.group(1).startswith("_"):
                calls.append(f"client.{m2.group(1)}")

    # Pattern 4: _build_evidence(api_call="...") — the canonical declared API call
    # Use re.DOTALL to handle multi-line _build_evidence calls
    for m in re.finditer(
        r'_build_evidence\(.*?api_call\s*=\s*["\']([^"\']+)["\']',
        body, re.DOTALL
    ):
        calls.append(f"evidence:{m.group(1)}")

    # Pattern 5: Delegation — return self.check_other_method(check_def)
    #            or return self._helper_method(check_def, ...)
    for m in re.finditer(r'return\s+self\.(\w+)\(', body):
        method = m.group(1)
        if method.startswith("check_") or method.startswith("_"):
            if method not in ("_result", "_build_evidence", "_cached"):
                calls.append(f"delegates:{method}")

    # Pattern 6: Helper method calls — self._list_firewalls(), self._get_*()
    for m in re.finditer(r'self\.(_list_\w+|_get_\w+)\(', body):
        helper = m.group(1)
        # Skip generic getters
        if helper in ("_get_monitoring_client", "_get_networks_client",
                       "_get_instances_client"):
            calls.append(f"helper:{helper}")
        elif helper.startswith("_list_") or helper.startswith("_get_"):
            calls.append(f"helper:{helper}")

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for c in calls:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def normalize_api_call(api_str: str) -> str:
    """Normalize an API call string for fuzzy comparison."""
    s = api_str.strip()
    # Apply camelCase splitting BEFORE lowering
    s = re.sub(r'([a-z])([A-Z])', r'\1_\2', s)
    s = s.lower()
    # Remove common prefixes
    for prefix in ("self._", "self.", "evidence:", "graph/", "graph.",
                   "client.", "identity/", "policies/"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    # Remove parentheses and trailing content
    s = re.sub(r'\(.*', '', s)
    # Normalize separators: / → . , - → _
    s = s.replace("/", ".").replace("-", "_")
    # Remove version prefixes (v1.0.)
    s = re.sub(r'v\d+(\.\d+)?\.', '', s)
    # Remove common class suffixes
    for suffix in ("_client", "_service"):
        s = s.replace(suffix, "")
    return s


def _tokenize(s: str) -> set[str]:
    """Split a normalized string into significant tokens."""
    tokens = set(re.split(r'[._\-/\s]+', s))
    generic = {"get", "list", "describe", "self", "check", "the", "a", "for",
               "all", "client", "safe", "projects", "v3", "v1", ""}
    return tokens - generic


def api_calls_match(config_api: str, code_apis: list[str]) -> tuple[bool, str]:
    """
    Check if the config api_call is represented in the extracted code APIs.

    Returns (match, detail_message).
    """
    if not config_api:
        return True, "No api_call in config"
    if not code_apis:
        return False, "No API calls found in code"

    # Handle composite api_call (contains +)
    config_parts = [normalize_api_call(p.strip()) for p in config_api.split("+")]
    config_tokens_all = set()
    for cp in config_parts:
        config_tokens_all |= _tokenize(cp)

    for code_api in code_apis:
        code_norm = normalize_api_call(code_api)
        code_tokens = _tokenize(code_norm)

        # 1. Substring match (either direction)
        for cp in config_parts:
            if cp in code_norm or code_norm in cp:
                return True, f"Matched: config='{config_api}' ~ code='{code_api}'"

        # 2. Token overlap — at least half of config tokens present
        if config_tokens_all and code_tokens:
            overlap = config_tokens_all & code_tokens
            threshold = max(1, len(config_tokens_all) * 0.4)
            if len(overlap) >= threshold:
                return True, (
                    f"Token match: config='{config_api}' ~ code='{code_api}' "
                    f"(overlap: {overlap})"
                )

    return False, f"No match: config='{config_api}' vs code={code_apis}"


# ---------------------------------------------------------------------------
# QA1: Config Validation
# ---------------------------------------------------------------------------
def qa1_1_structural_integrity(checks: list[dict]) -> QACheckResult:
    """1.1 — All checks have required fields."""
    r = QACheckResult(name="Structural Integrity")
    for chk in checks:
        check_id = chk.get("check_id", "<missing>")
        missing = REQUIRED_CHECK_FIELDS - set(chk.keys())
        if missing:
            r.failed += 1
            r.findings.append(Finding(
                "ERROR", r.name, check_id,
                f"Missing fields: {', '.join(sorted(missing))} (in {chk.get('_file', '?')})"
            ))
        else:
            r.passed += 1
    return r


def qa1_2_objective_crossref(checks: list[dict], controls: dict) -> QACheckResult:
    """1.2 — Every supports_objectives entry exists in nist_800_53_controls.json."""
    r = QACheckResult(name="Objective Cross-Reference")
    for chk in checks:
        check_id = chk.get("check_id", "?")
        control_id = chk.get("_control_id", "")
        supported = chk.get("supports_objectives", [])
        control = controls.get(control_id)

        if not control:
            r.failed += 1
            r.findings.append(Finding(
                "ERROR", r.name, check_id,
                f"Control {control_id} not found in nist_800_53_controls.json"
            ))
            continue

        objectives = control.get("objectives", {})
        all_valid = True
        for obj_id in supported:
            if obj_id not in objectives:
                r.failed += 1
                all_valid = False
                r.findings.append(Finding(
                    "ERROR", r.name, check_id,
                    f"Objective '{obj_id}' not found in control {control_id} "
                    f"(valid: {sorted(objectives.keys())})"
                ))
        if all_valid:
            r.passed += 1
    return r


def qa1_3_coverage_completeness(checks: list[dict], controls: dict,
                                raw_configs: dict[str, dict]) -> QACheckResult:
    """1.3 — Every control's objectives are covered, documented, or non-automatable."""
    r = QACheckResult(name="Coverage Completeness")

    # Build per-control coverage from automated checks
    control_covered_objs: dict[str, set[str]] = {}
    for chk in checks:
        pid = chk.get("_control_id", "")
        for obj_id in chk.get("supports_objectives", []):
            control_covered_objs.setdefault(pid, set()).add(obj_id)

    # Build per-control documentation requirements
    control_doc_objs: dict[str, set[str]] = {}
    for _fname, config in raw_configs.items():
        for pid, pdata in config.get("checks", {}).items():
            for doc in pdata.get("objectives_requiring_documentation", []):
                control_doc_objs.setdefault(pid, set()).add(doc.get("id", ""))

    for pid, pdata in controls.items():
        objectives = pdata.get("objectives", {})
        if not objectives:
            continue

        automated_flag = pdata.get("automated", False)
        covered = control_covered_objs.get(pid, set())
        documented = control_doc_objs.get(pid, set())

        gaps = []
        for obj_id, obj_info in objectives.items():
            automatable = obj_info.get("automatable", False)
            if obj_id in covered:
                continue
            if obj_id in documented:
                continue
            if automatable is False:
                continue
            # This is a gap
            gaps.append(obj_id)

        if gaps:
            # Only warn for partially-automatable — they may be intentional
            if automated_flag:
                r.warned += 1
                r.findings.append(Finding(
                    "WARNING", r.name, pid,
                    f"Objectives not covered by checks or documentation: {', '.join(sorted(gaps))}"
                ))
            else:
                r.passed += 1  # non-automated control, gaps are expected
        else:
            r.passed += 1
    return r


def qa1_4_method_mapping(checks: list[dict],
                         engine_methods: dict[str, dict[str, str]]) -> QACheckResult:
    """1.4 — Every config check_id has an entry in engine.py's *_CHECK_METHODS."""
    r = QACheckResult(name="Method Mapping")
    for chk in checks:
        check_id = chk.get("check_id", "?")
        provider = chk.get("_provider", "")
        method_map = engine_methods.get(provider, {})
        if check_id in method_map:
            r.passed += 1
        else:
            r.warned += 1
            r.findings.append(Finding(
                "WARNING", r.name, check_id,
                f"No entry in {provider.upper()}_CHECK_METHODS — "
                f"will run as 'not yet implemented'"
            ))
    return r


def qa1_5_method_existence(engine_methods: dict[str, dict[str, str]],
                           scanner_methods: dict[str, dict[str, tuple[int, int]]]) -> QACheckResult:
    """1.5 — Every method in *_CHECK_METHODS exists as check_* in the scanner class."""
    r = QACheckResult(name="Method Existence")
    for platform, method_map in engine_methods.items():
        available = scanner_methods.get(platform, {})
        for check_id, method_name in method_map.items():
            if method_name in available:
                r.passed += 1
            else:
                r.failed += 1
                r.findings.append(Finding(
                    "ERROR", r.name, check_id,
                    f"Method '{method_name}' not found in {platform}_scanner.py "
                    f"(referenced in {platform.upper()}_CHECK_METHODS)"
                ))
    return r


def qa1_6_check_id_format(checks: list[dict]) -> QACheckResult:
    """1.6 — All check_ids match the expected format."""
    r = QACheckResult(name="Check ID Format")
    for chk in checks:
        check_id = chk.get("check_id", "")
        if CHECK_ID_RE.match(check_id):
            r.passed += 1
        else:
            r.failed += 1
            r.findings.append(Finding(
                "ERROR", r.name, check_id,
                f"check_id '{check_id}' does not match pattern "
                f"{{domain}}-{{control}}-{{provider}}-{{seq}} (in {chk.get('_file', '?')})"
            ))
    return r


def qa1_7_control_completeness(checks: list[dict], controls: dict,
                                raw_configs: dict[str, dict]) -> QACheckResult:
    """1.7 — All base controls (non-enhancements) from nist_800_53_controls.json
    appear in config/checks/*.json (either as automated checks or manual-only entries)."""
    r = QACheckResult(name="Control Completeness")

    # Controls that appear in config (either as manual or automated)
    config_controls: set[str] = set()
    for _fname, config in raw_configs.items():
        for pid in config.get("checks", {}).keys():
            config_controls.add(pid)

    # Only check base controls that are marked as automated (have cloud checks).
    # Manual-only controls (PE, PS, etc.) intentionally have no check config entry.
    # Exclude enhancements (contain '(' or have a dot followed by digits like AC-6.3).
    import re
    _enh_re = re.compile(r'^[A-Z]{2}-\d+[.(]')
    base_controls = {pid: data for pid, data in controls.items()
                     if not _enh_re.search(pid + "(") and "(" not in pid
                     and not re.search(r'\.\d+$', pid)
                     and data.get("automated", False)}

    for pid in sorted(base_controls.keys()):
        if pid in config_controls:
            r.passed += 1
        else:
            r.failed += 1
            r.findings.append(Finding(
                "ERROR", r.name, pid,
                f"Automated control {pid} ({controls[pid].get('domain', '?')}) "
                f"not found in any config/checks/*.json file"
            ))
    return r


def qa1_8_provider_parity(checks: list[dict], controls: dict) -> QACheckResult:
    """1.8 — Flag controls where one CSP has checks but another doesn't."""
    r = QACheckResult(name="Provider Parity")

    # Count checks per control per provider
    control_providers: dict[str, dict[str, int]] = {}
    for chk in checks:
        pid = chk.get("_control_id", "")
        prov = chk.get("_provider", "")
        control_providers.setdefault(pid, {}).setdefault(prov, 0)
        control_providers[pid][prov] += 1

    for pid in sorted(control_providers.keys()):
        providers = control_providers[pid]
        # Only flag automated controls
        pdata = controls.get(pid, {})
        if not pdata.get("automated", False):
            continue

        present = set(providers.keys())
        missing = {"aws", "azure", "gcp"} - present
        if missing:
            r.warned += 1
            counts = ", ".join(f"{p}={providers.get(p, 0)}" for p in ("aws", "azure", "gcp"))
            r.findings.append(Finding(
                "WARNING", r.name, pid,
                f"Missing provider(s): {', '.join(sorted(missing))} ({counts})"
            ))
        else:
            r.passed += 1
    return r


# ---------------------------------------------------------------------------
# QA2: Scanner Logic Validation
# ---------------------------------------------------------------------------
def _resolve_api_calls(method_name: str, provider: str,
                       scanner_methods: dict[str, dict[str, tuple[int, int]]],
                       scanner_sources: dict[str, list[str]],
                       depth: int = 0) -> list[str]:
    """Extract API calls from a method, following delegation chains up to 2 levels."""
    if depth > 2:
        return []
    methods = scanner_methods.get(provider, {})
    line_range = methods.get(method_name)
    if not line_range:
        return []
    source_lines = scanner_sources.get(provider, [])
    code_apis = extract_api_calls_from_method(source_lines, line_range[0], line_range[1])

    # Follow delegation: if method delegates to another check_* method,
    # include the delegated method's API calls too
    resolved: list[str] = []
    for api in code_apis:
        if api.startswith("delegates:"):
            delegated = api[len("delegates:"):]
            delegated_apis = _resolve_api_calls(
                delegated, provider, scanner_methods, scanner_sources, depth + 1)
            resolved.extend(delegated_apis)
        elif api.startswith("helper:"):
            # Helper methods like _list_firewalls — try to find API calls in them
            helper_name = api[len("helper:"):]
            # Search for the helper method in the scanner class
            for item_name, lr in methods.items():
                if item_name == helper_name:
                    helper_apis = extract_api_calls_from_method(
                        source_lines, lr[0], lr[1])
                    resolved.extend(a for a in helper_apis
                                    if not a.startswith("delegates:"))
                    break
            # Also search non-check methods in the class
            # (helpers might not start with check_)
            pass  # covered above if helper is in methods dict
        else:
            resolved.append(api)
    return resolved


def qa2_1_api_call_match(checks: list[dict],
                         engine_methods: dict[str, dict[str, str]],
                         scanner_methods: dict[str, dict[str, tuple[int, int]]],
                         scanner_sources: dict[str, list[str]]) -> QACheckResult:
    """2.1 — Config api_call matches actual API calls in scanner code."""
    r = QACheckResult(name="API Call Match")

    for chk in checks:
        check_id = chk.get("check_id", "?")
        provider = chk.get("_provider", "")
        config_api = chk.get("api_call", "")

        # Find the method name from engine
        method_map = engine_methods.get(provider, {})
        method_name = method_map.get(check_id)
        if not method_name:
            continue  # Not implemented — already flagged by QA1.4

        # Find method line range
        methods = scanner_methods.get(provider, {})
        line_range = methods.get(method_name)
        if not line_range:
            continue  # Already flagged by QA1.5

        # Extract API calls from method body (with delegation resolution)
        code_apis = _resolve_api_calls(
            method_name, provider, scanner_methods, scanner_sources)

        matched, detail = api_calls_match(config_api, code_apis)
        if matched:
            r.passed += 1
        else:
            r.failed += 1
            r.findings.append(Finding(
                "ERROR", r.name, check_id,
                f"API mismatch: config says '{config_api}' but code uses: "
                f"{[c for c in code_apis if not c.startswith('evidence:')]}"
            ))
    return r


def qa2_2_expected_condition_match(checks: list[dict],
                                   engine_methods: dict[str, dict[str, str]],
                                   scanner_methods: dict[str, dict[str, tuple[int, int]]],
                                   scanner_sources: dict[str, list[str]]) -> QACheckResult:
    """2.2 — Heuristic: validation logic aligns with config expected field."""
    r = QACheckResult(name="Expected Condition Match")

    for chk in checks:
        check_id = chk.get("check_id", "?")
        provider = chk.get("_provider", "")
        expected = chk.get("expected", "")

        method_map = engine_methods.get(provider, {})
        method_name = method_map.get(check_id)
        if not method_name:
            continue

        methods = scanner_methods.get(provider, {})
        line_range = methods.get(method_name)
        if not line_range:
            continue

        source_lines = scanner_sources.get(provider, [])
        body = "\n".join(source_lines[line_range[0] - 1:line_range[1]])

        # Extract key terms from expected condition
        # e.g., "AccountAccessKeysPresent == 0" → ["accountaccesskeyspresent"]
        # e.g., "WAF web ACLs deployed on all internet-facing ALBs" → ["waf", "acls", "albs"]
        terms = re.findall(r'[A-Za-z][A-Za-z0-9_]{2,}', expected)
        significant_terms = [
            t.lower() for t in terms
            if t.lower() not in {"the", "all", "are", "has", "have", "for", "with",
                                 "and", "not", "that", "this", "any", "least", "one",
                                 "deployed", "configured", "enabled", "exists", "should",
                                 "must", "each", "every", "ensure", "verified", "active",
                                 "present", "found", "access", "policy", "policies"}
        ]

        if not significant_terms:
            r.passed += 1  # No meaningful terms to match
            continue

        body_lower = body.lower()
        matched_terms = [t for t in significant_terms if t in body_lower]
        match_ratio = len(matched_terms) / len(significant_terms) if significant_terms else 1.0

        if match_ratio >= 0.3:
            r.passed += 1
        elif match_ratio > 0:
            r.warned += 1
            missing = [t for t in significant_terms if t not in body_lower]
            r.findings.append(Finding(
                "WARNING", r.name, check_id,
                f"Partial match ({match_ratio:.0%}): expected terms missing from code: "
                f"{missing[:5]}"
            ))
        else:
            r.warned += 1
            r.findings.append(Finding(
                "WARNING", r.name, check_id,
                f"No expected terms found in code. Config expected: '{expected[:80]}'"
            ))
    return r


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
def generate_console_output(results: list[QACheckResult], findings: list[Finding]) -> None:
    """Print summary to console."""
    print()
    print("=" * 60)
    print("  FedRAMP Scanner QA Traceability Validation")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 60)
    print()

    # QA1
    print("QA1: Config Validation")
    for r in results[:8]:
        status = "PASS" if r.failed == 0 else "FAIL"
        print(f"  {r.name:<28s}: {r.passed:>4d} pass, {r.failed:>4d} fail, {r.warned:>4d} warn  [{status}]")
    print()

    # QA2
    print("QA2: Scanner Logic Validation")
    for r in results[8:]:
        status = "PASS" if r.failed == 0 else "FAIL"
        print(f"  {r.name:<28s}: {r.passed:>4d} pass, {r.failed:>4d} fail, {r.warned:>4d} warn  [{status}]")
    print()

    # Top discrepancies
    errors = [f for f in findings if f.level == "ERROR"]
    warnings = [f for f in findings if f.level == "WARNING"]
    if errors or warnings:
        print("TOP DISCREPANCIES:")
        for i, f in enumerate(errors[:10], 1):
            print(f"  {i:>2d}. [{f.level}] {f.check_id}: {f.message[:100]}")
        for i, f in enumerate(warnings[:5], len(errors[:10]) + 1):
            print(f"  {i:>2d}. [{f.level}] {f.check_id}: {f.message[:100]}")
        remaining = len(errors) + len(warnings) - 15
        if remaining > 0:
            print(f"  ... and {remaining} more (see full report)")
    print()

    total_errors = sum(r.failed for r in results)
    total_warnings = sum(r.warned for r in results)
    total_passed = sum(r.passed for r in results)
    print(f"TOTAL: {total_passed} passed, {total_errors} errors, {total_warnings} warnings")
    if total_errors > 0:
        print("RESULT: FAIL (errors found — exit code 1)")
    else:
        print("RESULT: PASS (no errors — exit code 0)")
    print()


def generate_markdown_report(results: list[QACheckResult],
                             findings: list[Finding],
                             checks: list[dict],
                             controls: dict) -> str:
    """Generate full markdown report."""
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines.append("# FedRAMP Scanner — QA Traceability Validation Report")
    lines.append("")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Config checks analyzed:** {len(checks)}")
    lines.append(f"**NIST controls:** {len(controls)}")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| # | QA Check | Pass | Fail | Warn | Status |")
    lines.append("|---|----------|------|------|------|--------|")
    for i, r in enumerate(results, 1):
        status = "PASS" if r.failed == 0 else "**FAIL**"
        lines.append(f"| {i} | {r.name} | {r.passed} | {r.failed} | {r.warned} | {status} |")
    lines.append("")

    total_errors = sum(r.failed for r in results)
    total_warnings = sum(r.warned for r in results)
    total_passed = sum(r.passed for r in results)
    lines.append(f"**Totals:** {total_passed} passed, {total_errors} errors, {total_warnings} warnings")
    lines.append("")

    # Detailed findings per QA check
    lines.append("## Detailed Findings")
    lines.append("")
    for r in results:
        if not r.findings:
            continue
        lines.append(f"### {r.name}")
        lines.append("")
        lines.append("| Level | Check ID | Message |")
        lines.append("|-------|----------|---------|")
        for f in r.findings:
            # Escape pipe characters in message
            msg = f.message.replace("|", "\\|")
            lines.append(f"| {f.level} | `{f.check_id}` | {msg} |")
        lines.append("")

    # Provider parity matrix
    lines.append("## Provider Parity Matrix")
    lines.append("")
    lines.append("Automated controls with check counts per CSP.")
    lines.append("")
    lines.append("| Control | Domain | AWS | Azure | GCP |")
    lines.append("|----------|--------|-----|-------|-----|")

    control_counts: dict[str, dict[str, int]] = {}
    for chk in checks:
        pid = chk.get("_control_id", "")
        prov = chk.get("_provider", "")
        control_counts.setdefault(pid, {}).setdefault(prov, 0)
        control_counts[pid][prov] += 1

    for pid in sorted(control_counts.keys()):
        pdata = controls.get(pid, {})
        if not pdata.get("automated", False):
            continue
        domain = pdata.get("domain", "?")
        counts = control_counts[pid]
        aws_c = counts.get("aws", 0)
        azure_c = counts.get("azure", 0)
        gcp_c = counts.get("gcp", 0)
        # Highlight gaps
        aws_s = f"**{aws_c}**" if aws_c == 0 else str(aws_c)
        azure_s = f"**{azure_c}**" if azure_c == 0 else str(azure_c)
        gcp_s = f"**{gcp_c}**" if gcp_c == 0 else str(gcp_c)
        lines.append(f"| {pid} | {domain} | {aws_s} | {azure_s} | {gcp_s} |")
    lines.append("")

    # Objective coverage gap table
    lines.append("## Objective Coverage Gaps")
    lines.append("")
    lines.append("Automatable objectives not covered by any check or documentation requirement.")
    lines.append("")
    lines.append("| Control | Domain | Objective | Text |")
    lines.append("|----------|--------|-----------|------|")

    # Re-compute gaps
    control_covered: dict[str, set[str]] = {}
    for chk in checks:
        pid = chk.get("_control_id", "")
        for obj_id in chk.get("supports_objectives", []):
            control_covered.setdefault(pid, set()).add(obj_id)

    raw_configs = load_check_configs_raw()
    control_doc: dict[str, set[str]] = {}
    for _fname, config in raw_configs.items():
        for pid, pdata_cfg in config.get("checks", {}).items():
            for doc in pdata_cfg.get("objectives_requiring_documentation", []):
                control_doc.setdefault(pid, set()).add(doc.get("id", ""))

    gap_count = 0
    for pid in sorted(controls.keys()):
        pdata = controls[pid]
        objectives = pdata.get("objectives", {})
        domain = pdata.get("domain", "?")
        covered = control_covered.get(pid, set())
        documented = control_doc.get(pid, set())
        for obj_id in sorted(objectives.keys()):
            obj_info = objectives[obj_id]
            if obj_info.get("automatable") is False:
                continue
            if obj_id in covered or obj_id in documented:
                continue
            text = obj_info.get("text", "")[:80]
            lines.append(f"| {pid} | {domain} | {obj_id} | {text} |")
            gap_count += 1

    if gap_count == 0:
        lines.append("| — | — | — | No gaps found |")
    lines.append("")
    lines.append(f"**Total objective gaps:** {gap_count}")
    lines.append("")

    lines.append("---")
    lines.append(f"*Report generated by `scripts/qa_traceability.py` on {now}*")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    """Run all QA checks and produce output."""
    print("Loading config files...")
    controls = load_controls()
    checks = load_all_checks()
    raw_configs = load_check_configs_raw()

    print(f"  {len(controls)} controls from nist_800_53_controls.json")
    print(f"  {len(checks)} automated checks from config/checks/")

    print("Parsing engine.py...")
    engine_methods = extract_engine_check_methods()
    for platform, methods in engine_methods.items():
        print(f"  {platform}: {len(methods)} entries in CHECK_METHODS")

    print("Parsing scanner source files (AST)...")
    scanner_methods: dict[str, dict[str, tuple[int, int]]] = {}
    scanner_sources: dict[str, list[str]] = {}
    for platform, filepath in SCANNER_FILES.items():
        if filepath.exists():
            scanner_methods[platform] = extract_scanner_methods(filepath)
            scanner_sources[platform] = filepath.read_text().splitlines()
            check_count = sum(1 for n in scanner_methods[platform] if n.startswith("check_"))
            print(f"  {platform}: {check_count} check_* methods ({len(scanner_methods[platform])} total)")
        else:
            print(f"  {platform}: FILE NOT FOUND ({filepath})")
            scanner_methods[platform] = {}
            scanner_sources[platform] = []

    print()
    print("Running QA checks...")
    print()

    # Run all QA checks
    results: list[QACheckResult] = [
        # QA1
        qa1_1_structural_integrity(checks),
        qa1_2_objective_crossref(checks, controls),
        qa1_3_coverage_completeness(checks, controls, raw_configs),
        qa1_4_method_mapping(checks, engine_methods),
        qa1_5_method_existence(engine_methods, scanner_methods),
        qa1_6_check_id_format(checks),
        qa1_7_control_completeness(checks, controls, raw_configs),
        qa1_8_provider_parity(checks, controls),
        # QA2
        qa2_1_api_call_match(checks, engine_methods, scanner_methods, scanner_sources),
        qa2_2_expected_condition_match(checks, engine_methods, scanner_methods, scanner_sources),
    ]

    # Collect all findings
    all_findings: list[Finding] = []
    for r in results:
        all_findings.extend(r.findings)

    # Console output
    generate_console_output(results, all_findings)

    # Markdown report
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / "qa_traceability_report.md"
    report_content = generate_markdown_report(results, all_findings, checks, controls)
    report_path.write_text(report_content)
    print(f"Full report written to: {report_path}")
    print()

    # Exit code
    total_errors = sum(r.failed for r in results)
    return 1 if total_errors > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
