# FedRAMP Scanner — QA Traceability Validation Report

**Generated:** 2026-03-11 02:21 UTC
**Config checks analyzed:** 496
**NIST controls:** 2068

## Summary

| # | QA Check | Pass | Fail | Warn | Status |
|---|----------|------|------|------|--------|
| 1 | Structural Integrity | 496 | 0 | 0 | PASS |
| 2 | Objective Cross-Reference | 496 | 0 | 0 | PASS |
| 3 | Coverage Completeness | 171 | 0 | 5 | PASS |
| 4 | Method Mapping | 495 | 0 | 1 | PASS |
| 5 | Method Existence | 493 | 0 | 0 | PASS |
| 6 | Check ID Format | 496 | 0 | 0 | PASS |
| 7 | Control Completeness | 0 | 0 | 0 | PASS |
| 8 | Provider Parity | 71 | 0 | 0 | PASS |
| 9 | API Call Match | 495 | 0 | 0 | PASS |
| 10 | Expected Condition Match | 461 | 0 | 34 | PASS |

**Totals:** 3674 passed, 0 errors, 40 warnings

## Detailed Findings

### Coverage Completeness

| Level | Check ID | Message |
|-------|----------|---------|
| WARNING | `AC-17.1` | Objectives not covered by checks or documentation: [a], [b], [c], [d] |
| WARNING | `AC-17.2` | Objectives not covered by checks or documentation: [a], [b] |
| WARNING | `AU-9.4` | Objectives not covered by checks or documentation: [a], [b] |
| WARNING | `IA-2.1` | Objectives not covered by checks or documentation: [a], [b], [c], [d] |
| WARNING | `MP-4.2` | Objectives not covered by checks or documentation: [a] |

### Method Mapping

| Level | Check ID | Message |
|-------|----------|---------|
| WARNING | `ac-17-3-aws-001` | No entry in AWS_CHECK_METHODS — will run as 'not yet implemented' |

### Expected Condition Match

| Level | Check ID | Message |
|-------|----------|---------|
| WARNING | `ac-5-azure-001` | Partial match (29%): expected terms missing from code: ['user', 'administrator', 'assigned', 'different', 'individuals'] |
| WARNING | `ac-7-gcp-001` | Partial match (25%): expected terms missing from code: ['challenges', 'suspicious', 'activity'] |
| WARNING | `ac-11-gcp-001` | Partial match (29%): expected terms missing from code: ['authentication', 'required', 'defined', 'inactivity', 'period'] |
| WARNING | `ac-4-4-gcp-001` | Partial match (25%): expected terms missing from code: ['allusers', 'allauthenticatedusers', 'bindings'] |
| WARNING | `au-2-azure-002` | Partial match (29%): expected terms missing from code: ['azure', 'exported', 'long', 'term', 'storage'] |
| WARNING | `au-3-azure-001` | Partial match (29%): expected terms missing from code: ['capture', 'individual', 'user', 'identities', 'authentications'] |
| WARNING | `ca-7-gcp-001` | Partial match (14%): expected terms missing from code: ['security', 'health', 'analytics', 'event', 'threat'] |
| WARNING | `cm-6-gcp-002` | Partial match (17%): expected terms missing from code: ['security', 'health', 'analytics', 'reviewed', 'addressed'] |
| WARNING | `cm-7-gcp-001` | Partial match (29%): expected terms missing from code: ['zero', 'hit', 'counts', 'over', 'days'] |
| WARNING | `cp-4-aws-001` | Partial match (29%): expected terms missing from code: ['recent', 'exist', 'showing', 'testing', 'results'] |
| WARNING | `cp-4-gcp-001` | Partial match (29%): expected terms missing from code: ['exist', 'showing', 'recent', 'testing', 'activity'] |
| WARNING | `cp-7-azure-001` | Partial match (29%): expected terms missing from code: ['balancers', 'application', 'gateways', 'exist', 'multiple'] |
| WARNING | `ia-2-1-gcp-001` | Partial match (17%): expected terms missing from code: ['step', 'verification', 'users', 'just', 'encouraged'] |
| WARNING | `ia-4-gcp-001` | Partial match (14%): expected terms missing from code: ['suspended', 'deleted', 'accounts', 'reassigned', 'within'] |
| WARNING | `ia-5-gcp-001` | Partial match (29%): expected terms missing from code: ['minimum', 'length', 'characters', 'complexity', 'requirements'] |
| WARNING | `ir-2-azure-002` | Partial match (25%): expected terms missing from code: ['workspace', 'data', 'connectors'] |
| WARNING | `ma-4-gcp-001` | Partial match (14%): expected terms missing from code: ['step', 'verification', 'enforced', 'accounts', 'used'] |
| WARNING | `mp-4-gcp-002` | Partial match (29%): expected terms missing from code: ['disks', 'use', 'customer', 'managed', 'keys'] |
| WARNING | `ra-5-5-azure-001` | Partial match (20%): expected terms missing from code: ['vms', 'show', 'compliant', 'status'] |
| WARNING | `ra-5-5-azure-002` | Partial match (14%): expected terms missing from code: ['unaddressed', 'critical', 'security', 'older', 'than'] |
| WARNING | `ra-5-5-gcp-001` | Partial match (20%): expected terms missing from code: ['instances', 'show', 'compliant', 'state'] |
| WARNING | `sc-7-gcp-001` | Partial match (29%): expected terms missing from code: ['security', 'internet', 'facing', 'load', 'balancers'] |
| WARNING | `sc-7-7-aws-001` | Partial match (14%): expected terms missing from code: ['management', 'subnets', 'isolated', 'from', 'application'] |
| WARNING | `sc-7-7-azure-001` | Partial match (14%): expected terms missing from code: ['dedicated', 'management', 'subnet', 'restricted', 'nsg'] |
| WARNING | `sc-7-7-gcp-001` | No expected terms found in code. Config expected: 'Dedicated management subnet with restricted firewall rules' |
| WARNING | `sc-13-azure-001` | Partial match (17%): expected terms missing from code: ['vms', 'government', 'regions', 'use', 'configurations'] |
| WARNING | `sc-28-1-gcp-001` | Partial match (12%): expected terms missing from code: ['buckets', 'cui', 'data', 'use', 'customer'] |
| WARNING | `si-2-gcp-003` | Partial match (17%): expected terms missing from code: ['critical', 'vulnerabilities', 'unresolved', 'beyond', 'days'] |
| WARNING | `si-3-1-azure-001` | Partial match (29%): expected terms missing from code: ['signatures', 'updated', 'within', 'last', 'hours'] |
| WARNING | `si-3-1-gcp-001` | No expected terms found in code. Config expected: 'Anti-malware agents on instances configured for automatic updates' |
| WARNING | `si-4-aws-001` | Partial match (14%): expected terms missing from code: ['vpc', 'flow', 'log', 'dns', 'log'] |
| WARNING | `si-4-azure-001` | No expected terms found in code. Config expected: 'Network threat protection enabled for traffic analysis' |
| WARNING | `si-4-4-azure-003` | No expected terms found in code. Config expected: 'Alerts configured for impossible travel, unfamiliar locations, and anomalous tok' |
| WARNING | `si-4-4-gcp-002` | Partial match (17%): expected terms missing from code: ['anomalous', 'login', 'patterns', 'api', 'usage'] |

## Provider Parity Matrix

Automated controls with check counts per CSP.

| Control | Domain | AWS | Azure | GCP |
|----------|--------|-----|-------|-----|
| AC-11 | AC | 1 | 1 | 1 |
| AC-12 | AC | 2 | 1 | 1 |
| AC-17(1) | AC | 2 | 1 | 1 |
| AC-17(2) | AC | 2 | 1 | 1 |
| AC-18 | AC | 1 | 1 | 1 |
| AC-19 | AC | 1 | 1 | 1 |
| AC-2 | AC | 3 | 3 | 3 |
| AC-20 | AC | 1 | 1 | 1 |
| AC-21 | AC | 2 | 1 | 1 |
| AC-3 | AC | 2 | 2 | 2 |
| AC-4 | AC | 2 | 2 | 2 |
| AC-5 | AC | 2 | 1 | 1 |
| AC-6 | AC | 3 | 2 | 2 |
| AC-7 | AC | 2 | 1 | 1 |
| AU-2 | AU | 4 | 3 | 3 |
| AU-3 | AU | 2 | 1 | 1 |
| AU-5 | AU | 2 | 1 | 1 |
| AU-6 | AU | 2 | 1 | 1 |
| AU-7 | AU | 2 | 1 | 1 |
| AU-8 | AU | 1 | 1 | 1 |
| AU-9 | AU | 3 | 2 | 2 |
| AU-9(4) | AU | 2 | 1 | 1 |
| CA-7 | CA | 3 | 2 | 2 |
| CM-2 | CM | 3 | 2 | 2 |
| CM-3 | CM | 2 | 1 | 1 |
| CM-5 | CM | 2 | 1 | 1 |
| CM-6 | CM | 2 | 2 | 2 |
| CM-7 | CM | 2 | 1 | 1 |
| CM-8 | CM | 1 | 1 | 1 |
| CP-10 | CP | 1 | 1 | 1 |
| CP-2 | CP | 1 | 1 | 1 |
| CP-4 | CP | 1 | 1 | 1 |
| CP-6 | CP | 2 | 2 | 2 |
| CP-7 | CP | 2 | 2 | 2 |
| CP-9 | CP | 4 | 3 | 3 |
| IA-2 | IA | 3 | 2 | 2 |
| IA-2(1) | IA | 3 | 2 | 2 |
| IA-3 | IA | 2 | 2 | 1 |
| IA-4 | IA | 1 | 1 | 1 |
| IA-5 | IA | 1 | 1 | 1 |
| IA-8 | IA | 2 | 1 | 1 |
| IR-2 | IR | 4 | 3 | 3 |
| MA-2 | MA | 3 | 2 | 2 |
| MA-4 | MA | 2 | 1 | 1 |
| MP-4 | MP | 3 | 2 | 2 |
| MP-4(2) | MP | 3 | 2 | 1 |
| MP-5 | MP | 3 | 2 | 2 |
| PL-2 | PL | 1 | 1 | 1 |
| PL-8 | PL | 2 | 2 | 2 |
| PT-2 | PT | 3 | 3 | 3 |
| PT-3 | PT | 1 | 1 | 1 |
| PT-4 | PT | 1 | 1 | 1 |
| RA-5 | RA | 3 | 3 | 3 |
| SA-10 | SA | 2 | 1 | 1 |
| SA-11 | SA | 1 | 1 | 1 |
| SA-22 | SA | 2 | 1 | 1 |
| SA-3 | SA | 2 | 1 | 1 |
| SC-10 | SC | 2 | 1 | 1 |
| SC-12 | SC | 3 | 2 | 2 |
| SC-13 | SC | 2 | 1 | 1 |
| SC-18 | SC | 1 | 1 | 1 |
| SC-23 | SC | 2 | 1 | 1 |
| SC-7 | SC | 4 | 3 | 3 |
| SC-8 | SC | 3 | 2 | 2 |
| SI-2 | SI | 4 | 3 | 3 |
| SI-3 | SI | 3 | 2 | 2 |
| SI-4 | SI | 3 | 3 | 3 |
| SI-5 | SI | 3 | 2 | 2 |
| SR-11 | SR | 2 | 1 | 1 |
| SR-2 | SR | 2 | 1 | 1 |
| SR-3 | SR | 1 | 1 | 1 |

## Objective Coverage Gaps

Automatable objectives not covered by any check or documentation requirement.

| Control | Domain | Objective | Text |
|----------|--------|-----------|------|
| AC-17.1 | AC | [a] | Employ automated mechanisms to monitor and control remote access methods. Monito |
| AC-17.1 | AC | [b] | automated mechanisms are employed to control remote access methods. Access contr |
| AC-17.1 | AC | [c] | automated mechanisms are employed to control remote access methods. Access contr |
| AC-17.1 | AC | [d] | automated mechanisms are employed to control remote access methods. Access contr |
| AC-17.2 | AC | [a] | Implement cryptographic mechanisms to protect the confidentiality and integrity  |
| AC-17.2 | AC | [b] | Implement cryptographic mechanisms to protect the confidentiality and integrity  |
| AC-17.3 | AC | [a] | Route remote accesses through authorized and managed network access control poin |
| AC-17.3 | AC | [b] | Route remote accesses through authorized and managed network access control poin |
| AC-2.9 | AC | [a] | Only permit the use of shared and group accounts that meet {{ insert: param, ac- |
| AC-2.9 | AC | [b] | Only permit the use of shared and group accounts that meet {{ insert: param, ac- |
| AC-2.9 | AC | [c] | Only permit the use of shared and group accounts that meet {{ insert: param, ac- |
| AC-2.9 | AC | [d] | Only permit the use of shared and group accounts that meet {{ insert: param, ac- |
| AC-4.4 | AC | [a] | Prevent encrypted information from bypassing {{ insert: param, ac-04.04_odp.01 } |
| AC-4.4 | AC | [b] | Prevent encrypted information from bypassing {{ insert: param, ac-04.04_odp.01 } |
| AC-4.4 | AC | [c] | Prevent encrypted information from bypassing {{ insert: param, ac-04.04_odp.01 } |
| AC-4.4 | AC | [d] | Prevent encrypted information from bypassing {{ insert: param, ac-04.04_odp.01 } |
| AC-4.4 | AC | [e] | Prevent encrypted information from bypassing {{ insert: param, ac-04.04_odp.01 } |
| AC-6.3 | AC | [a] | Authorize network access to {{ insert: param, ac-06.03_odp.01 }} only for {{ ins |
| AC-6.3 | AC | [b] | the rationale for authorizing network access to privileged commands is documente |
| AU-9.4 | AU | [a] | Authorize access to management of audit logging functionality to only {{ insert: |
| AU-9.4 | AU | [b] | Authorize access to management of audit logging functionality to only {{ insert: |
| CM-7.1 | CM | [a] | Review the system {{ insert: param, cm-07.01_odp.01 }} to identify unnecessary a |
| CM-7.1 | CM | [b] | and Disable or remove {{ insert: param, cm-7.1_prm_2 }}. Organizations review fu |
| CM-7.1 | CM | [c] | {{ insert: param, cm-07.01_odp.03 }} deemed to be unnecessary and/or non-secure  |
| CM-7.1 | CM | [d] | {{ insert: param, cm-07.01_odp.04 }} deemed to be unnecessary and/or non-secure  |
| CM-7.1 | CM | [e] | {{ insert: param, cm-07.01_odp.05 }} deemed to be unnecessary and/or non-secure  |
| CM-7.1 | CM | [f] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure  |
| CM-7.1 | CM | [g] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure  |
| CM-7.1 | CM | [h] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure  |
| CM-7.1 | CM | [i] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure  |
| CM-7.1 | CM | [j] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure  |
| CM-7.1 | CM | [k] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure  |
| CM-7.1 | CM | [l] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure  |
| CM-7.1 | CM | [m] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure  |
| CM-7.1 | CM | [n] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure  |
| CM-7.1 | CM | [o] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure  |
| CM-7.5 | CM | [a] | Identify {{ insert: param, cm-07.05_odp.01 }} |
| CM-7.5 | CM | [b] | Employ a deny-all, permit-by-exception policy to allow the execution of authoriz |
| CM-7.5 | CM | [c] | and Review and update the list of authorized software programs {{ insert: param, |
| CP-10(2) | CP | [a] | Implement transaction recovery for systems that are transaction-based. Transacti |
| CP-9(1) | CP | [a] | Test backup information {{ insert: param, cp-9.1_prm_1 }} to verify media reliab |
| CP-9(3) | CP | [a] | Store backup copies of {{ insert: param, cp-09.03_odp }} in a separate facility  |
| CP-9(8) | CP | [a] | Implement cryptographic mechanisms to prevent unauthorized disclosure and modifi |
| IA-2.1 | IA | [a] | Implement multi-factor authentication for access to privileged accounts. Multi-f |
| IA-2.1 | IA | [b] | Implement multi-factor authentication for access to privileged accounts. Multi-f |
| IA-2.1 | IA | [c] | Implement multi-factor authentication for access to privileged accounts. Multi-f |
| IA-2.1 | IA | [d] | Implement multi-factor authentication for access to privileged accounts. Multi-f |
| IA-2.2 | IA | [a] | Implement multi-factor authentication for access to non-privileged accounts. Mul |
| IA-4.4 | IA | [a] | Manage individual identifiers by uniquely identifying each individual as {{ inse |
| IA-4.4 | IA | [b] | Manage individual identifiers by uniquely identifying each individual as {{ inse |
| IA-5.1 | IA | [a] | For password-based authentication: Maintain a list of commonly-used, expected, o |
| IA-5.1 | IA | [b] | Verify, when users create or update passwords, that the passwords are not found  |
| IA-5.2 | IA | [a] | For public key-based authentication: Enforce authorized access to the correspond |
| MP-4.2 | MP | [a] | Restrict access to media storage areas and log access attempts and access grante |
| RA-5.5 | RA | [a] | Implement privileged access authorization to {{ insert: param, ra-05.05_odp.01 } |
| RA-5.5 | RA | [b] | Implement privileged access authorization to {{ insert: param, ra-05.05_odp.01 } |
| SA-11(1) | SA | [a] | Require the developer of the system, system component, or system service to empl |
| SA-4(9) | SA | [a] | Require the developer of the system, system component, or system service to iden |
| SA-9(2) | SA | [a] | Require providers of the following external system services to identify the func |
| SC-28.1 | SC | [a] | Implement cryptographic mechanisms to prevent unauthorized disclosure and modifi |
| SC-7.21 | SC | [a] | Employ boundary protection mechanisms to isolate {{ insert: param, sc-07.21_odp. |
| SC-7.21 | SC | [b] | cross-domain devices that separate subnetworks |
| SC-7.4 | SC | [a] | Implement a managed interface for each external telecommunication service |
| SC-7.4 | SC | [b] | Establish a traffic flow policy for each managed interface |
| SC-7.7 | SC | [a] | Prevent split tunneling for remote devices connecting to organizational systems  |
| SC-7.7 | SC | [b] | Prevent split tunneling for remote devices connecting to organizational systems  |
| SC-7.7 | SC | [c] | Prevent split tunneling for remote devices connecting to organizational systems  |
| SC-7.8 | SC | [a] | Route {{ insert: param, sc-07.08_odp.01 }} to {{ insert: param, sc-07.08_odp.02  |
| SI-3.1 | SI | [a] | Organization-defined requirement |
| SI-3.2 | SI | [a] | Organization-defined requirement |
| SI-3.2 | SI | [b] | Organization-defined requirement |
| SI-3.2 | SI | [c] | Organization-defined requirement |
| SI-4.4 | SI | [a] | Determine criteria for unusual or unauthorized activities or conditions for inbo |
| SI-4.4 | SI | [b] | Monitor inbound and outbound communications traffic {{ insert: param, si-4.4_prm |

**Total objective gaps:** 74

---
*Report generated by `scripts/qa_traceability.py` on 2026-03-11 02:21 UTC*
