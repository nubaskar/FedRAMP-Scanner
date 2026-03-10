# CMMC Scanner — QA Traceability Validation Report

**Generated:** 2026-03-07 20:24 UTC
**Config checks analyzed:** 393
**NIST practices:** 110

## Summary

| # | QA Check | Pass | Fail | Warn | Status |
|---|----------|------|------|------|--------|
| 1 | Structural Integrity | 393 | 0 | 0 | PASS |
| 2 | Objective Cross-Reference | 393 | 0 | 0 | PASS |
| 3 | Coverage Completeness | 110 | 0 | 0 | PASS |
| 4 | Method Mapping | 392 | 0 | 1 | PASS |
| 5 | Method Existence | 393 | 0 | 0 | PASS |
| 6 | Check ID Format | 393 | 0 | 0 | PASS |
| 7 | Practice Completeness | 110 | 0 | 0 | PASS |
| 8 | Provider Parity | 71 | 0 | 0 | PASS |
| 9 | API Call Match | 392 | 0 | 0 | PASS |
| 10 | Expected Condition Match | 354 | 0 | 38 | PASS |

**Totals:** 3001 passed, 0 errors, 39 warnings

## Detailed Findings

### Method Mapping

| Level | Check ID | Message |
|-------|----------|---------|
| WARNING | `ac-3.1.14-aws-001` | No entry in AWS_CHECK_METHODS — will run as 'not yet implemented' |

### Expected Condition Match

| Level | Check ID | Message |
|-------|----------|---------|
| WARNING | `ac-3.1.4-azure-001` | Partial match (29%): expected terms missing from code: ['user', 'administrator', 'assigned', 'different', 'individuals'] |
| WARNING | `ac-3.1.5-azure-002` | Partial match (25%): expected terms missing from code: ['management', 'ports', 'vms'] |
| WARNING | `ac-3.1.8-gcp-001` | Partial match (25%): expected terms missing from code: ['challenges', 'suspicious', 'activity'] |
| WARNING | `ac-3.1.10-azure-001` | Partial match (17%): expected terms missing from code: ['lifetime', 'enforce', 'authentication', 'after', 'inactivity'] |
| WARNING | `ac-3.1.10-gcp-001` | Partial match (14%): expected terms missing from code: ['authentication', 'required', 'after', 'defined', 'inactivity'] |
| WARNING | `ac-3.1.12-gcp-001` | Partial match (29%): expected terms missing from code: ['identity', 'aware', 'proxy', 'used', 'remote'] |
| WARNING | `ac-3.1.22-gcp-001` | Partial match (25%): expected terms missing from code: ['allusers', 'allauthenticatedusers', 'bindings'] |
| WARNING | `au-3.3.1-azure-002` | Partial match (14%): expected terms missing from code: ['azure', 'logs', 'exported', 'long', 'term'] |
| WARNING | `au-3.3.2-azure-001` | Partial match (29%): expected terms missing from code: ['capture', 'individual', 'user', 'identities', 'authentications'] |
| WARNING | `ca-3.12.3-gcp-001` | Partial match (14%): expected terms missing from code: ['security', 'health', 'analytics', 'event', 'threat'] |
| WARNING | `cm-3.4.2-gcp-002` | Partial match (17%): expected terms missing from code: ['security', 'health', 'analytics', 'reviewed', 'addressed'] |
| WARNING | `cm-3.4.6-gcp-001` | Partial match (29%): expected terms missing from code: ['zero', 'hit', 'counts', 'over', 'days'] |
| WARNING | `cm-3.4.8-aws-001` | Partial match (20%): expected terms missing from code: ['whitelisting', 'solution', 'managed', 'instances'] |
| WARNING | `cm-3.4.9-gcp-001` | Partial match (17%): expected terms missing from code: ['agent', 'reporting', 'software', 'inventory', 'instances'] |
| WARNING | `ia-3.5.1-aws-002` | Partial match (29%): expected terms missing from code: ['accounts', 'clearly', 'identifiable', 'purpose', 'descriptions'] |
| WARNING | `ia-3.5.3-gcp-001` | Partial match (17%): expected terms missing from code: ['step', 'verification', 'users', 'just', 'encouraged'] |
| WARNING | `ia-3.5.5-gcp-001` | Partial match (14%): expected terms missing from code: ['suspended', 'deleted', 'accounts', 'reassigned', 'within'] |
| WARNING | `ia-3.5.7-gcp-001` | Partial match (29%): expected terms missing from code: ['minimum', 'length', 'characters', 'complexity', 'requirements'] |
| WARNING | `ir-3.6.1-azure-002` | Partial match (25%): expected terms missing from code: ['workspace', 'data', 'connectors'] |
| WARNING | `ma-3.7.5-gcp-001` | Partial match (14%): expected terms missing from code: ['step', 'verification', 'enforced', 'accounts', 'used'] |
| WARNING | `mp-3.8.2-gcp-001` | Partial match (29%): expected terms missing from code: ['containing', 'cui', 'authorized', 'principals', 'only'] |
| WARNING | `mp-3.8.2-gcp-002` | Partial match (29%): expected terms missing from code: ['disks', 'use', 'customer', 'managed', 'keys'] |
| WARNING | `ra-3.11.3-azure-001` | Partial match (20%): expected terms missing from code: ['vms', 'show', 'compliant', 'status'] |
| WARNING | `ra-3.11.3-azure-002` | Partial match (14%): expected terms missing from code: ['unaddressed', 'critical', 'security', 'older', 'than'] |
| WARNING | `ra-3.11.3-gcp-001` | Partial match (20%): expected terms missing from code: ['instances', 'show', 'compliant', 'state'] |
| WARNING | `sc-3.13.1-azure-003` | Partial match (29%): expected terms missing from code: ['internet', 'facing', 'gateways', 'front', 'doors'] |
| WARNING | `sc-3.13.1-gcp-001` | Partial match (29%): expected terms missing from code: ['security', 'internet', 'facing', 'load', 'balancers'] |
| WARNING | `sc-3.13.4-azure-001` | Partial match (22%): expected terms missing from code: ['feature', 'limited', 'authorized', 'multi', 'attach'] |
| WARNING | `sc-3.13.11-azure-001` | Partial match (17%): expected terms missing from code: ['vms', 'government', 'regions', 'use', 'configurations'] |
| WARNING | `sc-3.13.16-gcp-001` | Partial match (12%): expected terms missing from code: ['buckets', 'cui', 'data', 'use', 'customer'] |
| WARNING | `si-3.14.1-gcp-003` | Partial match (17%): expected terms missing from code: ['critical', 'vulnerabilities', 'unresolved', 'beyond', 'days'] |
| WARNING | `si-3.14.4-azure-001` | Partial match (29%): expected terms missing from code: ['signatures', 'updated', 'within', 'last', 'hours'] |
| WARNING | `si-3.14.4-gcp-001` | No expected terms found in code. Config expected: 'Anti-malware agents on instances configured for automatic updates' |
| WARNING | `si-3.14.6-aws-001` | Partial match (14%): expected terms missing from code: ['vpc', 'flow', 'log', 'dns', 'log'] |
| WARNING | `si-3.14.6-azure-001` | No expected terms found in code. Config expected: 'Network threat protection enabled for traffic analysis' |
| WARNING | `si-3.14.7-azure-003` | No expected terms found in code. Config expected: 'Alerts configured for impossible travel, unfamiliar locations, and anomalous tok' |
| WARNING | `si-3.14.7-gcp-002` | Partial match (17%): expected terms missing from code: ['anomalous', 'login', 'patterns', 'api', 'usage'] |
| WARNING | `si-3.14.7-gcp-003` | Partial match (29%): expected terms missing from code: ['reviewed', 'google', 'admin', 'cui', 'data'] |

## Provider Parity Matrix

Automated practices with check counts per CSP.

| Practice | Domain | AWS | Azure | GCP |
|----------|--------|-----|-------|-----|
| 3.1.1 | AC | 3 | 3 | 3 |
| 3.1.10 | AC | 1 | 1 | 1 |
| 3.1.11 | AC | 2 | 1 | 1 |
| 3.1.12 | AC | 2 | 1 | 1 |
| 3.1.13 | AC | 2 | 1 | 1 |
| 3.1.14 | AC | 2 | 1 | 1 |
| 3.1.15 | AC | 1 | 1 | 1 |
| 3.1.2 | AC | 2 | 2 | 2 |
| 3.1.20 | AC | 2 | 1 | 1 |
| 3.1.22 | AC | 2 | 1 | 1 |
| 3.1.3 | AC | 2 | 2 | 2 |
| 3.1.4 | AC | 2 | 1 | 1 |
| 3.1.5 | AC | 3 | 2 | 2 |
| 3.1.6 | AC | 1 | 1 | 1 |
| 3.1.7 | AC | 2 | 1 | 2 |
| 3.1.8 | AC | 2 | 1 | 1 |
| 3.11.2 | RA | 3 | 3 | 3 |
| 3.11.3 | RA | 2 | 2 | 2 |
| 3.12.3 | CA | 3 | 2 | 2 |
| 3.13.1 | SC | 4 | 3 | 3 |
| 3.13.10 | SC | 3 | 2 | 2 |
| 3.13.11 | SC | 2 | 1 | 1 |
| 3.13.13 | SC | 1 | 1 | 1 |
| 3.13.15 | SC | 2 | 1 | 1 |
| 3.13.16 | SC | 4 | 3 | 3 |
| 3.13.3 | SC | 2 | 1 | 1 |
| 3.13.4 | SC | 2 | 1 | 1 |
| 3.13.5 | SC | 2 | 1 | 1 |
| 3.13.6 | SC | 2 | 2 | 2 |
| 3.13.7 | SC | 1 | 1 | 1 |
| 3.13.8 | SC | 3 | 2 | 2 |
| 3.13.9 | SC | 2 | 1 | 1 |
| 3.14.1 | SI | 4 | 3 | 3 |
| 3.14.2 | SI | 3 | 2 | 2 |
| 3.14.3 | SI | 3 | 2 | 2 |
| 3.14.4 | SI | 2 | 1 | 1 |
| 3.14.5 | SI | 3 | 2 | 2 |
| 3.14.6 | SI | 3 | 3 | 3 |
| 3.14.7 | SI | 3 | 3 | 3 |
| 3.3.1 | AU | 4 | 3 | 3 |
| 3.3.2 | AU | 2 | 1 | 1 |
| 3.3.4 | AU | 2 | 1 | 1 |
| 3.3.5 | AU | 2 | 1 | 1 |
| 3.3.6 | AU | 2 | 1 | 1 |
| 3.3.7 | AU | 1 | 1 | 1 |
| 3.3.8 | AU | 3 | 2 | 2 |
| 3.3.9 | AU | 2 | 1 | 1 |
| 3.4.1 | CM | 3 | 2 | 2 |
| 3.4.2 | CM | 2 | 2 | 2 |
| 3.4.3 | CM | 2 | 1 | 1 |
| 3.4.5 | CM | 2 | 1 | 1 |
| 3.4.6 | CM | 2 | 1 | 1 |
| 3.4.7 | CM | 2 | 1 | 1 |
| 3.4.8 | CM | 1 | 1 | 1 |
| 3.4.9 | CM | 1 | 1 | 1 |
| 3.5.1 | IA | 3 | 2 | 2 |
| 3.5.10 | IA | 2 | 1 | 1 |
| 3.5.2 | IA | 2 | 2 | 1 |
| 3.5.3 | IA | 3 | 2 | 2 |
| 3.5.4 | IA | 2 | 1 | 1 |
| 3.5.5 | IA | 1 | 1 | 1 |
| 3.5.6 | IA | 2 | 1 | 1 |
| 3.5.7 | IA | 1 | 1 | 1 |
| 3.5.8 | IA | 1 | 1 | 1 |
| 3.5.9 | IA | 1 | 1 | 1 |
| 3.6.1 | IR | 4 | 3 | 3 |
| 3.7.1 | MA | 3 | 2 | 2 |
| 3.7.5 | MA | 2 | 1 | 1 |
| 3.8.2 | MP | 3 | 2 | 2 |
| 3.8.6 | MP | 3 | 2 | 2 |
| 3.8.9 | MP | 3 | 2 | 1 |

## Objective Coverage Gaps

Automatable objectives not covered by any check or documentation requirement.

| Practice | Domain | Objective | Text |
|----------|--------|-----------|------|
| — | — | — | No gaps found |

**Total objective gaps:** 0

---
*Report generated by `scripts/qa_traceability.py` on 2026-03-07 20:24 UTC*
