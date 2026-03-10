# FedRAMP Scanner — QA Traceability Validation Report

**Generated:** 2026-03-10 22:37 UTC
**Config checks analyzed:** 496
**NIST controls:** 324

## Summary

| # | QA Check | Pass | Fail | Warn | Status |
|---|----------|------|------|------|--------|
| 1 | Structural Integrity | 496 | 0 | 0 | PASS |
| 2 | Objective Cross-Reference | 6 | 1153 | 0 | **FAIL** |
| 3 | Coverage Completeness | 0 | 0 | 0 | PASS |
| 4 | Method Mapping | 495 | 0 | 1 | PASS |
| 5 | Method Existence | 493 | 0 | 0 | PASS |
| 6 | Check ID Format | 0 | 496 | 0 | **FAIL** |
| 7 | Control Completeness | 90 | 234 | 0 | **FAIL** |
| 8 | Provider Parity | 8 | 0 | 0 | PASS |
| 9 | API Call Match | 462 | 33 | 0 | **FAIL** |
| 10 | Expected Condition Match | 461 | 0 | 34 | PASS |

**Totals:** 2511 passed, 1916 errors, 35 warnings

## Detailed Findings

### Objective Cross-Reference

| Level | Check ID | Message |
|-------|----------|---------|
| ERROR | `ac-2-aws-001` | Objective '[d]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-aws-002` | Objective '[a]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-aws-002` | Objective '[d]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-aws-003` | Objective '[a]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-aws-003` | Objective '[d]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-azure-001` | Objective '[a]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-azure-001` | Objective '[d]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-azure-001` | Objective '[f]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-azure-002` | Objective '[a]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-azure-002` | Objective '[d]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-azure-003` | Objective '[a]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-azure-003` | Objective '[d]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-azure-003` | Objective '[f]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-gcp-001` | Objective '[a]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-gcp-001` | Objective '[c]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-gcp-002` | Objective '[b]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-gcp-002` | Objective '[e]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-gcp-003` | Objective '[b]' not found in control AC-2 (valid: []) |
| ERROR | `ac-2-gcp-003` | Objective '[e]' not found in control AC-2 (valid: []) |
| ERROR | `ac-3-aws-001` | Objective '[b]' not found in control AC-3 (valid: []) |
| ERROR | `ac-3-aws-002` | Objective '[a]' not found in control AC-3 (valid: []) |
| ERROR | `ac-3-aws-002` | Objective '[b]' not found in control AC-3 (valid: []) |
| ERROR | `ac-3-azure-001` | Objective '[a]' not found in control AC-3 (valid: []) |
| ERROR | `ac-3-azure-001` | Objective '[b]' not found in control AC-3 (valid: []) |
| ERROR | `ac-3-azure-002` | Objective '[a]' not found in control AC-3 (valid: []) |
| ERROR | `ac-3-azure-002` | Objective '[b]' not found in control AC-3 (valid: []) |
| ERROR | `ac-3-gcp-001` | Objective '[a]' not found in control AC-3 (valid: []) |
| ERROR | `ac-3-gcp-001` | Objective '[b]' not found in control AC-3 (valid: []) |
| ERROR | `ac-3-gcp-002` | Objective '[a]' not found in control AC-3 (valid: []) |
| ERROR | `ac-3-gcp-002` | Objective '[b]' not found in control AC-3 (valid: []) |
| ERROR | `ac-4-aws-001` | Objective '[a]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-aws-001` | Objective '[b]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-aws-001` | Objective '[d]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-aws-001` | Objective '[e]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-aws-002` | Objective '[a]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-aws-002` | Objective '[b]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-aws-002` | Objective '[d]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-aws-002` | Objective '[e]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-azure-001` | Objective '[a]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-azure-001` | Objective '[b]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-azure-001` | Objective '[d]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-azure-001` | Objective '[e]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-azure-002` | Objective '[a]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-azure-002` | Objective '[b]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-azure-002` | Objective '[d]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-azure-002` | Objective '[e]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-gcp-001` | Objective '[a]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-gcp-001` | Objective '[b]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-gcp-001` | Objective '[d]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-gcp-001` | Objective '[e]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-gcp-002` | Objective '[a]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-gcp-002` | Objective '[b]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-gcp-002` | Objective '[d]' not found in control AC-4 (valid: []) |
| ERROR | `ac-4-gcp-002` | Objective '[e]' not found in control AC-4 (valid: []) |
| ERROR | `ac-5-aws-001` | Objective '[a]' not found in control AC-5 (valid: []) |
| ERROR | `ac-5-aws-001` | Objective '[b]' not found in control AC-5 (valid: []) |
| ERROR | `ac-5-aws-001` | Objective '[c]' not found in control AC-5 (valid: []) |
| ERROR | `ac-5-aws-002` | Objective '[a]' not found in control AC-5 (valid: []) |
| ERROR | `ac-5-aws-002` | Objective '[b]' not found in control AC-5 (valid: []) |
| ERROR | `ac-5-aws-002` | Objective '[c]' not found in control AC-5 (valid: []) |
| ERROR | `ac-5-azure-001` | Objective '[a]' not found in control AC-5 (valid: []) |
| ERROR | `ac-5-azure-001` | Objective '[b]' not found in control AC-5 (valid: []) |
| ERROR | `ac-5-azure-001` | Objective '[c]' not found in control AC-5 (valid: []) |
| ERROR | `ac-5-gcp-001` | Objective '[a]' not found in control AC-5 (valid: []) |
| ERROR | `ac-5-gcp-001` | Objective '[b]' not found in control AC-5 (valid: []) |
| ERROR | `ac-5-gcp-001` | Objective '[c]' not found in control AC-5 (valid: []) |
| ERROR | `ac-6-aws-001` | Objective '[b]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-aws-002` | Objective '[a]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-aws-002` | Objective '[b]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-aws-003` | Objective '[a]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-aws-003` | Objective '[b]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-aws-003` | Objective '[c]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-aws-003` | Objective '[d]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-azure-001` | Objective '[a]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-azure-001` | Objective '[b]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-azure-001` | Objective '[c]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-azure-001` | Objective '[d]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-azure-002` | Objective '[a]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-azure-002` | Objective '[b]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-azure-002` | Objective '[d]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-gcp-001` | Objective '[a]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-gcp-001` | Objective '[d]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-gcp-002` | Objective '[b]' not found in control AC-6 (valid: []) |
| ERROR | `ac-6-3-aws-001` | Control AC-6(3) not found in nist_800_53_controls.json |
| ERROR | `ac-6-3-azure-001` | Control AC-6(3) not found in nist_800_53_controls.json |
| ERROR | `ac-6-3-gcp-001` | Control AC-6(3) not found in nist_800_53_controls.json |
| ERROR | `ac-2-9-aws-001` | Control AC-2(9) not found in nist_800_53_controls.json |
| ERROR | `ac-2-9-aws-002` | Control AC-2(9) not found in nist_800_53_controls.json |
| ERROR | `ac-2-9-azure-001` | Control AC-2(9) not found in nist_800_53_controls.json |
| ERROR | `ac-2-9-gcp-001` | Control AC-2(9) not found in nist_800_53_controls.json |
| ERROR | `ac-2-9-gcp-002` | Control AC-2(9) not found in nist_800_53_controls.json |
| ERROR | `ac-7-aws-001` | Objective '[a]' not found in control AC-7 (valid: []) |
| ERROR | `ac-7-aws-001` | Objective '[b]' not found in control AC-7 (valid: []) |
| ERROR | `ac-7-aws-002` | Objective '[a]' not found in control AC-7 (valid: []) |
| ERROR | `ac-7-aws-002` | Objective '[b]' not found in control AC-7 (valid: []) |
| ERROR | `ac-7-azure-001` | Objective '[a]' not found in control AC-7 (valid: []) |
| ERROR | `ac-7-azure-001` | Objective '[b]' not found in control AC-7 (valid: []) |
| ERROR | `ac-7-gcp-001` | Objective '[a]' not found in control AC-7 (valid: []) |
| ERROR | `ac-7-gcp-001` | Objective '[b]' not found in control AC-7 (valid: []) |
| ERROR | `ac-11-aws-001` | Objective '[a]' not found in control AC-11 (valid: []) |
| ERROR | `ac-11-aws-001` | Objective '[b]' not found in control AC-11 (valid: []) |
| ERROR | `ac-11-aws-001` | Objective '[c]' not found in control AC-11 (valid: []) |
| ERROR | `ac-11-azure-001` | Objective '[a]' not found in control AC-11 (valid: []) |
| ERROR | `ac-11-azure-001` | Objective '[b]' not found in control AC-11 (valid: []) |
| ERROR | `ac-11-azure-001` | Objective '[c]' not found in control AC-11 (valid: []) |
| ERROR | `ac-11-gcp-001` | Objective '[a]' not found in control AC-11 (valid: []) |
| ERROR | `ac-11-gcp-001` | Objective '[b]' not found in control AC-11 (valid: []) |
| ERROR | `ac-11-gcp-001` | Objective '[c]' not found in control AC-11 (valid: []) |
| ERROR | `ac-12-aws-001` | Objective '[a]' not found in control AC-12 (valid: []) |
| ERROR | `ac-12-aws-001` | Objective '[b]' not found in control AC-12 (valid: []) |
| ERROR | `ac-12-aws-002` | Objective '[a]' not found in control AC-12 (valid: []) |
| ERROR | `ac-12-aws-002` | Objective '[b]' not found in control AC-12 (valid: []) |
| ERROR | `ac-12-azure-001` | Objective '[a]' not found in control AC-12 (valid: []) |
| ERROR | `ac-12-azure-001` | Objective '[b]' not found in control AC-12 (valid: []) |
| ERROR | `ac-12-gcp-001` | Objective '[a]' not found in control AC-12 (valid: []) |
| ERROR | `ac-12-gcp-001` | Objective '[b]' not found in control AC-12 (valid: []) |
| ERROR | `ac-17-1-aws-001` | Control AC-17(1) not found in nist_800_53_controls.json |
| ERROR | `ac-17-1-aws-002` | Control AC-17(1) not found in nist_800_53_controls.json |
| ERROR | `ac-17-1-azure-001` | Control AC-17(1) not found in nist_800_53_controls.json |
| ERROR | `ac-17-1-gcp-001` | Control AC-17(1) not found in nist_800_53_controls.json |
| ERROR | `ac-17-2-aws-001` | Control AC-17(2) not found in nist_800_53_controls.json |
| ERROR | `ac-17-2-aws-002` | Control AC-17(2) not found in nist_800_53_controls.json |
| ERROR | `ac-17-2-azure-001` | Control AC-17(2) not found in nist_800_53_controls.json |
| ERROR | `ac-17-2-gcp-001` | Control AC-17(2) not found in nist_800_53_controls.json |
| ERROR | `ac-17-3-aws-001` | Control AC-17(3) not found in nist_800_53_controls.json |
| ERROR | `ac-17-3-aws-002` | Control AC-17(3) not found in nist_800_53_controls.json |
| ERROR | `ac-17-3-azure-001` | Control AC-17(3) not found in nist_800_53_controls.json |
| ERROR | `ac-17-3-gcp-001` | Control AC-17(3) not found in nist_800_53_controls.json |
| ERROR | `ac-18-aws-001` | Objective '[a]' not found in control AC-18 (valid: []) |
| ERROR | `ac-18-aws-001` | Objective '[b]' not found in control AC-18 (valid: []) |
| ERROR | `ac-18-aws-001` | Objective '[c]' not found in control AC-18 (valid: []) |
| ERROR | `ac-18-aws-001` | Objective '[d]' not found in control AC-18 (valid: []) |
| ERROR | `ac-18-azure-001` | Objective '[a]' not found in control AC-18 (valid: []) |
| ERROR | `ac-18-azure-001` | Objective '[b]' not found in control AC-18 (valid: []) |
| ERROR | `ac-18-azure-001` | Objective '[c]' not found in control AC-18 (valid: []) |
| ERROR | `ac-18-azure-001` | Objective '[d]' not found in control AC-18 (valid: []) |
| ERROR | `ac-18-gcp-001` | Objective '[a]' not found in control AC-18 (valid: []) |
| ERROR | `ac-18-gcp-001` | Objective '[b]' not found in control AC-18 (valid: []) |
| ERROR | `ac-18-gcp-001` | Objective '[c]' not found in control AC-18 (valid: []) |
| ERROR | `ac-18-gcp-001` | Objective '[d]' not found in control AC-18 (valid: []) |
| ERROR | `ac-20-1-aws-001` | Control AC-20(1) not found in nist_800_53_controls.json |
| ERROR | `ac-20-1-azure-001` | Control AC-20(1) not found in nist_800_53_controls.json |
| ERROR | `ac-20-1-gcp-001` | Control AC-20(1) not found in nist_800_53_controls.json |
| ERROR | `ac-21-aws-001` | Objective '[a]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-aws-001` | Objective '[b]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-aws-001` | Objective '[c]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-aws-001` | Objective '[d]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-aws-001` | Objective '[e]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-aws-001` | Objective '[f]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-aws-002` | Objective '[a]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-aws-002` | Objective '[b]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-aws-002` | Objective '[c]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-aws-002` | Objective '[d]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-aws-002` | Objective '[e]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-aws-002` | Objective '[f]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-azure-001` | Objective '[a]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-azure-001` | Objective '[b]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-azure-001` | Objective '[c]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-azure-001` | Objective '[d]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-azure-001` | Objective '[e]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-azure-001` | Objective '[f]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-gcp-001` | Objective '[a]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-gcp-001` | Objective '[b]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-gcp-001` | Objective '[c]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-gcp-001` | Objective '[d]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-gcp-001` | Objective '[e]' not found in control AC-21 (valid: []) |
| ERROR | `ac-21-gcp-001` | Objective '[f]' not found in control AC-21 (valid: []) |
| ERROR | `ac-3-8-aws-001` | Control AC-3(8) not found in nist_800_53_controls.json |
| ERROR | `ac-3-8-azure-001` | Control AC-3(8) not found in nist_800_53_controls.json |
| ERROR | `ac-3-8-gcp-001` | Control AC-3(8) not found in nist_800_53_controls.json |
| ERROR | `ac-4-4-aws-001` | Control AC-4(4) not found in nist_800_53_controls.json |
| ERROR | `ac-4-4-aws-002` | Control AC-4(4) not found in nist_800_53_controls.json |
| ERROR | `ac-4-4-azure-001` | Control AC-4(4) not found in nist_800_53_controls.json |
| ERROR | `ac-4-4-gcp-001` | Control AC-4(4) not found in nist_800_53_controls.json |
| ERROR | `au-2-aws-001` | Objective '[a]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-001` | Objective '[b]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-001` | Objective '[c]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-001` | Objective '[d]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-001` | Objective '[e]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-001` | Objective '[f]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-002` | Objective '[a]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-002` | Objective '[b]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-002` | Objective '[c]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-002` | Objective '[d]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-002` | Objective '[e]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-002` | Objective '[f]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-003` | Objective '[a]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-003` | Objective '[b]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-003` | Objective '[c]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-003` | Objective '[d]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-003` | Objective '[e]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-003` | Objective '[f]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-004` | Objective '[a]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-004` | Objective '[b]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-004` | Objective '[c]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-004` | Objective '[d]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-004` | Objective '[e]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-aws-004` | Objective '[f]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-001` | Objective '[a]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-001` | Objective '[b]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-001` | Objective '[c]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-001` | Objective '[d]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-001` | Objective '[e]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-001` | Objective '[f]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-002` | Objective '[a]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-002` | Objective '[b]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-002` | Objective '[c]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-002` | Objective '[d]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-002` | Objective '[e]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-002` | Objective '[f]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-003` | Objective '[a]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-003` | Objective '[b]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-003` | Objective '[c]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-003` | Objective '[d]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-003` | Objective '[e]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-azure-003` | Objective '[f]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-001` | Objective '[a]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-001` | Objective '[b]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-001` | Objective '[c]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-001` | Objective '[d]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-001` | Objective '[e]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-001` | Objective '[f]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-002` | Objective '[a]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-002` | Objective '[b]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-002` | Objective '[c]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-002` | Objective '[d]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-002` | Objective '[e]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-002` | Objective '[f]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-003` | Objective '[a]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-003` | Objective '[b]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-003` | Objective '[c]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-003` | Objective '[d]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-003` | Objective '[e]' not found in control AU-2 (valid: []) |
| ERROR | `au-2-gcp-003` | Objective '[f]' not found in control AU-2 (valid: []) |
| ERROR | `au-3-aws-001` | Objective '[a]' not found in control AU-3 (valid: []) |
| ERROR | `au-3-aws-001` | Objective '[b]' not found in control AU-3 (valid: []) |
| ERROR | `au-3-aws-002` | Objective '[a]' not found in control AU-3 (valid: []) |
| ERROR | `au-3-aws-002` | Objective '[b]' not found in control AU-3 (valid: []) |
| ERROR | `au-3-azure-001` | Objective '[a]' not found in control AU-3 (valid: []) |
| ERROR | `au-3-azure-001` | Objective '[b]' not found in control AU-3 (valid: []) |
| ERROR | `au-3-gcp-001` | Objective '[a]' not found in control AU-3 (valid: []) |
| ERROR | `au-3-gcp-001` | Objective '[b]' not found in control AU-3 (valid: []) |
| ERROR | `au-5-aws-001` | Objective '[a]' not found in control AU-5 (valid: []) |
| ERROR | `au-5-aws-001` | Objective '[b]' not found in control AU-5 (valid: []) |
| ERROR | `au-5-aws-001` | Objective '[c]' not found in control AU-5 (valid: []) |
| ERROR | `au-5-aws-002` | Objective '[a]' not found in control AU-5 (valid: []) |
| ERROR | `au-5-aws-002` | Objective '[b]' not found in control AU-5 (valid: []) |
| ERROR | `au-5-aws-002` | Objective '[c]' not found in control AU-5 (valid: []) |
| ERROR | `au-5-azure-001` | Objective '[a]' not found in control AU-5 (valid: []) |
| ERROR | `au-5-azure-001` | Objective '[b]' not found in control AU-5 (valid: []) |
| ERROR | `au-5-azure-001` | Objective '[c]' not found in control AU-5 (valid: []) |
| ERROR | `au-5-gcp-001` | Objective '[a]' not found in control AU-5 (valid: []) |
| ERROR | `au-5-gcp-001` | Objective '[b]' not found in control AU-5 (valid: []) |
| ERROR | `au-5-gcp-001` | Objective '[c]' not found in control AU-5 (valid: []) |
| ERROR | `au-6-aws-001` | Objective '[a]' not found in control AU-6 (valid: []) |
| ERROR | `au-6-aws-001` | Objective '[b]' not found in control AU-6 (valid: []) |
| ERROR | `au-6-aws-002` | Objective '[a]' not found in control AU-6 (valid: []) |
| ERROR | `au-6-aws-002` | Objective '[b]' not found in control AU-6 (valid: []) |
| ERROR | `au-6-azure-001` | Objective '[a]' not found in control AU-6 (valid: []) |
| ERROR | `au-6-azure-001` | Objective '[b]' not found in control AU-6 (valid: []) |
| ERROR | `au-6-gcp-001` | Objective '[a]' not found in control AU-6 (valid: []) |
| ERROR | `au-6-gcp-001` | Objective '[b]' not found in control AU-6 (valid: []) |
| ERROR | `au-7-aws-001` | Objective '[a]' not found in control AU-7 (valid: []) |
| ERROR | `au-7-aws-001` | Objective '[b]' not found in control AU-7 (valid: []) |
| ERROR | `au-7-aws-002` | Objective '[a]' not found in control AU-7 (valid: []) |
| ERROR | `au-7-aws-002` | Objective '[b]' not found in control AU-7 (valid: []) |
| ERROR | `au-7-azure-001` | Objective '[a]' not found in control AU-7 (valid: []) |
| ERROR | `au-7-azure-001` | Objective '[b]' not found in control AU-7 (valid: []) |
| ERROR | `au-7-gcp-001` | Objective '[a]' not found in control AU-7 (valid: []) |
| ERROR | `au-7-gcp-001` | Objective '[b]' not found in control AU-7 (valid: []) |
| ERROR | `au-8-aws-001` | Objective '[a]' not found in control AU-8 (valid: []) |
| ERROR | `au-8-aws-001` | Objective '[b]' not found in control AU-8 (valid: []) |
| ERROR | `au-8-aws-001` | Objective '[c]' not found in control AU-8 (valid: []) |
| ERROR | `au-8-azure-001` | Objective '[a]' not found in control AU-8 (valid: []) |
| ERROR | `au-8-azure-001` | Objective '[b]' not found in control AU-8 (valid: []) |
| ERROR | `au-8-azure-001` | Objective '[c]' not found in control AU-8 (valid: []) |
| ERROR | `au-8-gcp-001` | Objective '[a]' not found in control AU-8 (valid: []) |
| ERROR | `au-8-gcp-001` | Objective '[b]' not found in control AU-8 (valid: []) |
| ERROR | `au-8-gcp-001` | Objective '[c]' not found in control AU-8 (valid: []) |
| ERROR | `au-9-aws-001` | Objective '[a]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-001` | Objective '[b]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-001` | Objective '[c]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-001` | Objective '[d]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-001` | Objective '[e]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-001` | Objective '[f]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-002` | Objective '[a]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-002` | Objective '[b]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-002` | Objective '[c]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-002` | Objective '[d]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-002` | Objective '[e]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-002` | Objective '[f]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-003` | Objective '[a]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-003` | Objective '[b]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-003` | Objective '[c]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-003` | Objective '[d]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-003` | Objective '[e]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-aws-003` | Objective '[f]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-azure-001` | Objective '[a]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-azure-001` | Objective '[b]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-azure-001` | Objective '[c]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-azure-001` | Objective '[d]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-azure-001` | Objective '[e]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-azure-001` | Objective '[f]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-azure-002` | Objective '[a]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-azure-002` | Objective '[b]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-azure-002` | Objective '[c]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-azure-002` | Objective '[d]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-azure-002` | Objective '[e]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-azure-002` | Objective '[f]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-gcp-001` | Objective '[a]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-gcp-001` | Objective '[b]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-gcp-001` | Objective '[c]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-gcp-001` | Objective '[d]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-gcp-001` | Objective '[e]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-gcp-001` | Objective '[f]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-gcp-002` | Objective '[a]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-gcp-002` | Objective '[b]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-gcp-002` | Objective '[c]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-gcp-002` | Objective '[d]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-gcp-002` | Objective '[e]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-gcp-002` | Objective '[f]' not found in control AU-9 (valid: []) |
| ERROR | `au-9-4-aws-001` | Control AU-9(4) not found in nist_800_53_controls.json |
| ERROR | `au-9-4-aws-002` | Control AU-9(4) not found in nist_800_53_controls.json |
| ERROR | `au-9-4-azure-001` | Control AU-9(4) not found in nist_800_53_controls.json |
| ERROR | `au-9-4-gcp-001` | Control AU-9(4) not found in nist_800_53_controls.json |
| ERROR | `ca-7-aws-001` | Objective '[a]' not found in control CA-7 (valid: []) |
| ERROR | `ca-7-aws-002` | Objective '[a]' not found in control CA-7 (valid: []) |
| ERROR | `ca-7-aws-003` | Objective '[a]' not found in control CA-7 (valid: []) |
| ERROR | `ca-7-azure-001` | Objective '[a]' not found in control CA-7 (valid: []) |
| ERROR | `ca-7-azure-002` | Objective '[a]' not found in control CA-7 (valid: []) |
| ERROR | `ca-7-gcp-001` | Objective '[a]' not found in control CA-7 (valid: []) |
| ERROR | `ca-7-gcp-002` | Objective '[a]' not found in control CA-7 (valid: []) |
| ERROR | `cm-2-aws-001` | Objective '[a]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-aws-001` | Objective '[c]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-aws-001` | Objective '[d]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-aws-001` | Objective '[f]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-aws-002` | Objective '[a]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-aws-002` | Objective '[c]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-aws-002` | Objective '[d]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-aws-002` | Objective '[f]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-aws-003` | Objective '[a]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-aws-003` | Objective '[c]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-aws-003` | Objective '[d]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-aws-003` | Objective '[f]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-azure-001` | Objective '[a]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-azure-001` | Objective '[c]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-azure-001` | Objective '[d]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-azure-001` | Objective '[f]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-azure-002` | Objective '[a]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-azure-002` | Objective '[c]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-azure-002` | Objective '[d]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-azure-002` | Objective '[f]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-gcp-001` | Objective '[a]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-gcp-001` | Objective '[c]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-gcp-001` | Objective '[d]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-gcp-001` | Objective '[f]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-gcp-002` | Objective '[a]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-gcp-002` | Objective '[c]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-gcp-002` | Objective '[d]' not found in control CM-2 (valid: []) |
| ERROR | `cm-2-gcp-002` | Objective '[f]' not found in control CM-2 (valid: []) |
| ERROR | `cm-6-aws-001` | Objective '[a]' not found in control CM-6 (valid: []) |
| ERROR | `cm-6-aws-001` | Objective '[b]' not found in control CM-6 (valid: []) |
| ERROR | `cm-6-aws-002` | Objective '[a]' not found in control CM-6 (valid: []) |
| ERROR | `cm-6-aws-002` | Objective '[b]' not found in control CM-6 (valid: []) |
| ERROR | `cm-6-azure-001` | Objective '[a]' not found in control CM-6 (valid: []) |
| ERROR | `cm-6-azure-001` | Objective '[b]' not found in control CM-6 (valid: []) |
| ERROR | `cm-6-azure-002` | Objective '[a]' not found in control CM-6 (valid: []) |
| ERROR | `cm-6-azure-002` | Objective '[b]' not found in control CM-6 (valid: []) |
| ERROR | `cm-6-gcp-001` | Objective '[a]' not found in control CM-6 (valid: []) |
| ERROR | `cm-6-gcp-001` | Objective '[b]' not found in control CM-6 (valid: []) |
| ERROR | `cm-6-gcp-002` | Objective '[a]' not found in control CM-6 (valid: []) |
| ERROR | `cm-6-gcp-002` | Objective '[b]' not found in control CM-6 (valid: []) |
| ERROR | `cm-3-aws-001` | Objective '[a]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-aws-001` | Objective '[b]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-aws-001` | Objective '[c]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-aws-001` | Objective '[d]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-aws-002` | Objective '[a]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-aws-002` | Objective '[b]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-aws-002` | Objective '[c]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-aws-002` | Objective '[d]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-azure-001` | Objective '[a]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-azure-001` | Objective '[b]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-azure-001` | Objective '[c]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-azure-001` | Objective '[d]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-gcp-001` | Objective '[a]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-gcp-001` | Objective '[b]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-gcp-001` | Objective '[c]' not found in control CM-3 (valid: []) |
| ERROR | `cm-3-gcp-001` | Objective '[d]' not found in control CM-3 (valid: []) |
| ERROR | `cm-5-aws-001` | Objective '[a]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-aws-001` | Objective '[c]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-aws-001` | Objective '[d]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-aws-001` | Objective '[e]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-aws-001` | Objective '[g]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-aws-001` | Objective '[h]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-aws-002` | Objective '[a]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-aws-002` | Objective '[c]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-aws-002` | Objective '[d]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-aws-002` | Objective '[e]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-aws-002` | Objective '[g]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-aws-002` | Objective '[h]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-azure-001` | Objective '[a]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-azure-001` | Objective '[c]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-azure-001` | Objective '[d]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-azure-001` | Objective '[e]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-azure-001` | Objective '[g]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-azure-001` | Objective '[h]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-gcp-001` | Objective '[a]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-gcp-001` | Objective '[c]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-gcp-001` | Objective '[d]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-gcp-001` | Objective '[e]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-gcp-001` | Objective '[g]' not found in control CM-5 (valid: []) |
| ERROR | `cm-5-gcp-001` | Objective '[h]' not found in control CM-5 (valid: []) |
| ERROR | `cm-7-aws-001` | Objective '[a]' not found in control CM-7 (valid: []) |
| ERROR | `cm-7-aws-001` | Objective '[b]' not found in control CM-7 (valid: []) |
| ERROR | `cm-7-aws-002` | Objective '[a]' not found in control CM-7 (valid: []) |
| ERROR | `cm-7-aws-002` | Objective '[b]' not found in control CM-7 (valid: []) |
| ERROR | `cm-7-azure-001` | Objective '[a]' not found in control CM-7 (valid: []) |
| ERROR | `cm-7-azure-001` | Objective '[b]' not found in control CM-7 (valid: []) |
| ERROR | `cm-7-gcp-001` | Objective '[a]' not found in control CM-7 (valid: []) |
| ERROR | `cm-7-gcp-001` | Objective '[b]' not found in control CM-7 (valid: []) |
| ERROR | `cm-7-1-aws-001` | Control CM-7(1) not found in nist_800_53_controls.json |
| ERROR | `cm-7-1-aws-002` | Control CM-7(1) not found in nist_800_53_controls.json |
| ERROR | `cm-7-1-azure-001` | Control CM-7(1) not found in nist_800_53_controls.json |
| ERROR | `cm-7-1-gcp-001` | Control CM-7(1) not found in nist_800_53_controls.json |
| ERROR | `cm-7-5-aws-001` | Control CM-7(5) not found in nist_800_53_controls.json |
| ERROR | `cm-7-5-azure-001` | Control CM-7(5) not found in nist_800_53_controls.json |
| ERROR | `cm-7-5-gcp-001` | Control CM-7(5) not found in nist_800_53_controls.json |
| ERROR | `cm-8-aws-001` | Objective '[a]' not found in control CM-8 (valid: []) |
| ERROR | `cm-8-aws-001` | Objective '[b]' not found in control CM-8 (valid: []) |
| ERROR | `cm-8-aws-001` | Objective '[c]' not found in control CM-8 (valid: []) |
| ERROR | `cm-8-azure-001` | Objective '[a]' not found in control CM-8 (valid: []) |
| ERROR | `cm-8-azure-001` | Objective '[b]' not found in control CM-8 (valid: []) |
| ERROR | `cm-8-azure-001` | Objective '[c]' not found in control CM-8 (valid: []) |
| ERROR | `cm-8-gcp-001` | Objective '[a]' not found in control CM-8 (valid: []) |
| ERROR | `cm-8-gcp-001` | Objective '[b]' not found in control CM-8 (valid: []) |
| ERROR | `cm-8-gcp-001` | Objective '[c]' not found in control CM-8 (valid: []) |
| ERROR | `cp-2-aws-001` | Objective '[a]' not found in control CP-2 (valid: []) |
| ERROR | `cp-2-aws-001` | Objective '[c]' not found in control CP-2 (valid: []) |
| ERROR | `cp-2-azure-001` | Objective '[a]' not found in control CP-2 (valid: []) |
| ERROR | `cp-2-azure-001` | Objective '[c]' not found in control CP-2 (valid: []) |
| ERROR | `cp-2-gcp-001` | Objective '[a]' not found in control CP-2 (valid: []) |
| ERROR | `cp-2-gcp-001` | Objective '[c]' not found in control CP-2 (valid: []) |
| ERROR | `cp-4-aws-001` | Objective '[a]' not found in control CP-4 (valid: []) |
| ERROR | `cp-4-aws-001` | Objective '[b]' not found in control CP-4 (valid: []) |
| ERROR | `cp-4-azure-001` | Objective '[a]' not found in control CP-4 (valid: []) |
| ERROR | `cp-4-azure-001` | Objective '[b]' not found in control CP-4 (valid: []) |
| ERROR | `cp-4-gcp-001` | Objective '[a]' not found in control CP-4 (valid: []) |
| ERROR | `cp-4-gcp-001` | Objective '[b]' not found in control CP-4 (valid: []) |
| ERROR | `cp-6-aws-001` | Objective '[a]' not found in control CP-6 (valid: []) |
| ERROR | `cp-6-aws-001` | Objective '[b]' not found in control CP-6 (valid: []) |
| ERROR | `cp-6-aws-002` | Objective '[a]' not found in control CP-6 (valid: []) |
| ERROR | `cp-6-aws-002` | Objective '[b]' not found in control CP-6 (valid: []) |
| ERROR | `cp-6-azure-001` | Objective '[a]' not found in control CP-6 (valid: []) |
| ERROR | `cp-6-azure-001` | Objective '[b]' not found in control CP-6 (valid: []) |
| ERROR | `cp-6-azure-002` | Objective '[a]' not found in control CP-6 (valid: []) |
| ERROR | `cp-6-azure-002` | Objective '[b]' not found in control CP-6 (valid: []) |
| ERROR | `cp-6-gcp-001` | Objective '[a]' not found in control CP-6 (valid: []) |
| ERROR | `cp-6-gcp-001` | Objective '[b]' not found in control CP-6 (valid: []) |
| ERROR | `cp-6-gcp-002` | Objective '[a]' not found in control CP-6 (valid: []) |
| ERROR | `cp-6-gcp-002` | Objective '[b]' not found in control CP-6 (valid: []) |
| ERROR | `cp-7-aws-001` | Objective '[a]' not found in control CP-7 (valid: []) |
| ERROR | `cp-7-aws-001` | Objective '[b]' not found in control CP-7 (valid: []) |
| ERROR | `cp-7-aws-001` | Objective '[d]' not found in control CP-7 (valid: []) |
| ERROR | `cp-7-aws-002` | Objective '[a]' not found in control CP-7 (valid: []) |
| ERROR | `cp-7-aws-002` | Objective '[d]' not found in control CP-7 (valid: []) |
| ERROR | `cp-7-azure-001` | Objective '[a]' not found in control CP-7 (valid: []) |
| ERROR | `cp-7-azure-001` | Objective '[b]' not found in control CP-7 (valid: []) |
| ERROR | `cp-7-azure-001` | Objective '[d]' not found in control CP-7 (valid: []) |
| ERROR | `cp-7-azure-002` | Objective '[a]' not found in control CP-7 (valid: []) |
| ERROR | `cp-7-azure-002` | Objective '[d]' not found in control CP-7 (valid: []) |
| ERROR | `cp-7-gcp-001` | Objective '[a]' not found in control CP-7 (valid: []) |
| ERROR | `cp-7-gcp-001` | Objective '[b]' not found in control CP-7 (valid: []) |
| ERROR | `cp-7-gcp-001` | Objective '[d]' not found in control CP-7 (valid: []) |
| ERROR | `cp-7-gcp-002` | Objective '[a]' not found in control CP-7 (valid: []) |
| ERROR | `cp-7-gcp-002` | Objective '[d]' not found in control CP-7 (valid: []) |
| ERROR | `cp-9-aws-001` | Objective '[a]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-aws-001` | Objective '[c]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-aws-001` | Objective '[d]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-aws-002` | Objective '[a]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-aws-002` | Objective '[c]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-aws-003` | Objective '[a]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-aws-003` | Objective '[c]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-aws-004` | Objective '[a]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-aws-004` | Objective '[c]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-azure-001` | Objective '[a]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-azure-001` | Objective '[c]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-azure-001` | Objective '[d]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-azure-002` | Objective '[a]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-azure-002` | Objective '[c]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-azure-003` | Objective '[a]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-azure-003` | Objective '[c]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-gcp-001` | Objective '[a]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-gcp-001` | Objective '[c]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-gcp-001` | Objective '[d]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-gcp-002` | Objective '[a]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-gcp-002` | Objective '[c]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-gcp-003` | Objective '[a]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-gcp-003` | Objective '[c]' not found in control CP-9 (valid: []) |
| ERROR | `cp-9-1-aws-001` | Control CP-9.1 not found in nist_800_53_controls.json |
| ERROR | `cp-9-1-azure-001` | Control CP-9.1 not found in nist_800_53_controls.json |
| ERROR | `cp-9-1-gcp-001` | Control CP-9.1 not found in nist_800_53_controls.json |
| ERROR | `cp-9-3-aws-001` | Control CP-9.3 not found in nist_800_53_controls.json |
| ERROR | `cp-9-3-azure-001` | Control CP-9.3 not found in nist_800_53_controls.json |
| ERROR | `cp-9-3-gcp-001` | Control CP-9.3 not found in nist_800_53_controls.json |
| ERROR | `cp-9-8-aws-001` | Control CP-9.8 not found in nist_800_53_controls.json |
| ERROR | `cp-9-8-aws-002` | Control CP-9.8 not found in nist_800_53_controls.json |
| ERROR | `cp-9-8-azure-001` | Control CP-9.8 not found in nist_800_53_controls.json |
| ERROR | `cp-9-8-gcp-001` | Control CP-9.8 not found in nist_800_53_controls.json |
| ERROR | `cp-10-aws-001` | Objective '[a]' not found in control CP-10 (valid: []) |
| ERROR | `cp-10-azure-001` | Objective '[a]' not found in control CP-10 (valid: []) |
| ERROR | `cp-10-gcp-001` | Objective '[a]' not found in control CP-10 (valid: []) |
| ERROR | `cp-10-2-aws-001` | Control CP-10.2 not found in nist_800_53_controls.json |
| ERROR | `cp-10-2-azure-001` | Control CP-10.2 not found in nist_800_53_controls.json |
| ERROR | `cp-10-2-gcp-001` | Control CP-10.2 not found in nist_800_53_controls.json |
| ERROR | `ia-2-aws-001` | Objective '[a]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-aws-001` | Objective '[b]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-aws-001` | Objective '[c]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-aws-002` | Objective '[a]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-aws-002` | Objective '[b]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-aws-002` | Objective '[c]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-aws-003` | Objective '[a]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-aws-003` | Objective '[b]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-aws-003` | Objective '[c]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-azure-001` | Objective '[a]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-azure-001` | Objective '[b]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-azure-001` | Objective '[c]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-azure-002` | Objective '[a]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-azure-002` | Objective '[b]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-azure-002` | Objective '[c]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-gcp-001` | Objective '[a]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-gcp-001` | Objective '[b]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-gcp-001` | Objective '[c]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-gcp-002` | Objective '[a]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-gcp-002` | Objective '[b]' not found in control IA-2 (valid: []) |
| ERROR | `ia-2-gcp-002` | Objective '[c]' not found in control IA-2 (valid: []) |
| ERROR | `ia-3-aws-001` | Objective '[a]' not found in control IA-3 (valid: []) |
| ERROR | `ia-3-aws-001` | Objective '[b]' not found in control IA-3 (valid: []) |
| ERROR | `ia-3-aws-001` | Objective '[c]' not found in control IA-3 (valid: []) |
| ERROR | `ia-3-aws-002` | Objective '[a]' not found in control IA-3 (valid: []) |
| ERROR | `ia-3-aws-002` | Objective '[b]' not found in control IA-3 (valid: []) |
| ERROR | `ia-3-aws-002` | Objective '[c]' not found in control IA-3 (valid: []) |
| ERROR | `ia-3-azure-001` | Objective '[a]' not found in control IA-3 (valid: []) |
| ERROR | `ia-3-azure-001` | Objective '[b]' not found in control IA-3 (valid: []) |
| ERROR | `ia-3-azure-001` | Objective '[c]' not found in control IA-3 (valid: []) |
| ERROR | `ia-3-azure-002` | Objective '[a]' not found in control IA-3 (valid: []) |
| ERROR | `ia-3-azure-002` | Objective '[b]' not found in control IA-3 (valid: []) |
| ERROR | `ia-3-azure-002` | Objective '[c]' not found in control IA-3 (valid: []) |
| ERROR | `ia-3-gcp-001` | Objective '[a]' not found in control IA-3 (valid: []) |
| ERROR | `ia-3-gcp-001` | Objective '[b]' not found in control IA-3 (valid: []) |
| ERROR | `ia-3-gcp-001` | Objective '[c]' not found in control IA-3 (valid: []) |
| ERROR | `ia-2-1-aws-001` | Control IA-2(1) not found in nist_800_53_controls.json |
| ERROR | `ia-2-1-aws-002` | Control IA-2(1) not found in nist_800_53_controls.json |
| ERROR | `ia-2-1-aws-003` | Control IA-2(1) not found in nist_800_53_controls.json |
| ERROR | `ia-2-1-azure-001` | Control IA-2(1) not found in nist_800_53_controls.json |
| ERROR | `ia-2-1-azure-002` | Control IA-2(1) not found in nist_800_53_controls.json |
| ERROR | `ia-2-1-gcp-001` | Control IA-2(1) not found in nist_800_53_controls.json |
| ERROR | `ia-2-1-gcp-002` | Control IA-2(1) not found in nist_800_53_controls.json |
| ERROR | `ia-2-2-aws-001` | Control IA-2(2) not found in nist_800_53_controls.json |
| ERROR | `ia-2-2-aws-002` | Control IA-2(2) not found in nist_800_53_controls.json |
| ERROR | `ia-2-2-azure-001` | Control IA-2(2) not found in nist_800_53_controls.json |
| ERROR | `ia-2-2-gcp-001` | Control IA-2(2) not found in nist_800_53_controls.json |
| ERROR | `ia-4-aws-001` | Objective '[a]' not found in control IA-4 (valid: []) |
| ERROR | `ia-4-aws-001` | Objective '[b]' not found in control IA-4 (valid: []) |
| ERROR | `ia-4-azure-001` | Objective '[a]' not found in control IA-4 (valid: []) |
| ERROR | `ia-4-azure-001` | Objective '[b]' not found in control IA-4 (valid: []) |
| ERROR | `ia-4-gcp-001` | Objective '[a]' not found in control IA-4 (valid: []) |
| ERROR | `ia-4-gcp-001` | Objective '[b]' not found in control IA-4 (valid: []) |
| ERROR | `ia-4-4-aws-001` | Control IA-4(4) not found in nist_800_53_controls.json |
| ERROR | `ia-4-4-aws-002` | Control IA-4(4) not found in nist_800_53_controls.json |
| ERROR | `ia-4-4-azure-001` | Control IA-4(4) not found in nist_800_53_controls.json |
| ERROR | `ia-4-4-gcp-001` | Control IA-4(4) not found in nist_800_53_controls.json |
| ERROR | `ia-5-aws-001` | Objective '[a]' not found in control IA-5 (valid: []) |
| ERROR | `ia-5-aws-001` | Objective '[b]' not found in control IA-5 (valid: []) |
| ERROR | `ia-5-aws-001` | Objective '[c]' not found in control IA-5 (valid: []) |
| ERROR | `ia-5-aws-001` | Objective '[d]' not found in control IA-5 (valid: []) |
| ERROR | `ia-5-azure-001` | Objective '[a]' not found in control IA-5 (valid: []) |
| ERROR | `ia-5-azure-001` | Objective '[b]' not found in control IA-5 (valid: []) |
| ERROR | `ia-5-azure-001` | Objective '[c]' not found in control IA-5 (valid: []) |
| ERROR | `ia-5-azure-001` | Objective '[d]' not found in control IA-5 (valid: []) |
| ERROR | `ia-5-gcp-001` | Objective '[a]' not found in control IA-5 (valid: []) |
| ERROR | `ia-5-gcp-001` | Objective '[b]' not found in control IA-5 (valid: []) |
| ERROR | `ia-5-gcp-001` | Objective '[c]' not found in control IA-5 (valid: []) |
| ERROR | `ia-5-gcp-001` | Objective '[d]' not found in control IA-5 (valid: []) |
| ERROR | `ia-5-1-aws-001` | Control IA-5(1) not found in nist_800_53_controls.json |
| ERROR | `ia-5-1-azure-001` | Control IA-5(1) not found in nist_800_53_controls.json |
| ERROR | `ia-5-1-gcp-001` | Control IA-5(1) not found in nist_800_53_controls.json |
| ERROR | `ia-5-2-aws-001` | Control IA-5(2) not found in nist_800_53_controls.json |
| ERROR | `ia-5-2-azure-001` | Control IA-5(2) not found in nist_800_53_controls.json |
| ERROR | `ia-5-2-gcp-001` | Control IA-5(2) not found in nist_800_53_controls.json |
| ERROR | `ia-8-aws-001` | Objective '[a]' not found in control IA-8 (valid: []) |
| ERROR | `ia-8-aws-001` | Objective '[b]' not found in control IA-8 (valid: []) |
| ERROR | `ia-8-aws-002` | Objective '[a]' not found in control IA-8 (valid: []) |
| ERROR | `ia-8-aws-002` | Objective '[b]' not found in control IA-8 (valid: []) |
| ERROR | `ia-8-azure-001` | Objective '[a]' not found in control IA-8 (valid: []) |
| ERROR | `ia-8-azure-001` | Objective '[b]' not found in control IA-8 (valid: []) |
| ERROR | `ia-8-gcp-001` | Objective '[a]' not found in control IA-8 (valid: []) |
| ERROR | `ia-8-gcp-001` | Objective '[b]' not found in control IA-8 (valid: []) |
| ERROR | `ir-2-aws-001` | Objective '[a]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-001` | Objective '[b]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-001` | Objective '[c]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-001` | Objective '[d]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-001` | Objective '[e]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-001` | Objective '[f]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-001` | Objective '[g]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-002` | Objective '[a]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-002` | Objective '[b]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-002` | Objective '[c]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-002` | Objective '[d]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-002` | Objective '[e]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-002` | Objective '[f]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-002` | Objective '[g]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-003` | Objective '[a]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-003` | Objective '[b]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-003` | Objective '[c]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-003` | Objective '[d]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-003` | Objective '[e]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-003` | Objective '[f]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-003` | Objective '[g]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-004` | Objective '[a]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-004` | Objective '[b]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-004` | Objective '[c]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-004` | Objective '[d]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-004` | Objective '[e]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-004` | Objective '[f]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-aws-004` | Objective '[g]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-001` | Objective '[a]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-001` | Objective '[b]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-001` | Objective '[c]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-001` | Objective '[d]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-001` | Objective '[e]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-001` | Objective '[f]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-001` | Objective '[g]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-002` | Objective '[a]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-002` | Objective '[b]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-002` | Objective '[c]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-002` | Objective '[d]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-002` | Objective '[e]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-002` | Objective '[f]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-002` | Objective '[g]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-003` | Objective '[a]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-003` | Objective '[b]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-003` | Objective '[c]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-003` | Objective '[d]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-003` | Objective '[e]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-003` | Objective '[f]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-azure-003` | Objective '[g]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-001` | Objective '[a]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-001` | Objective '[b]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-001` | Objective '[c]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-001` | Objective '[d]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-001` | Objective '[e]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-001` | Objective '[f]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-001` | Objective '[g]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-002` | Objective '[a]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-002` | Objective '[b]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-002` | Objective '[c]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-002` | Objective '[d]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-002` | Objective '[e]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-002` | Objective '[f]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-002` | Objective '[g]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-003` | Objective '[a]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-003` | Objective '[b]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-003` | Objective '[c]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-003` | Objective '[d]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-003` | Objective '[e]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-003` | Objective '[f]' not found in control IR-2 (valid: []) |
| ERROR | `ir-2-gcp-003` | Objective '[g]' not found in control IR-2 (valid: []) |
| ERROR | `ma-2-aws-001` | Objective '[a]' not found in control MA-2 (valid: []) |
| ERROR | `ma-2-aws-002` | Objective '[a]' not found in control MA-2 (valid: []) |
| ERROR | `ma-2-aws-003` | Objective '[a]' not found in control MA-2 (valid: []) |
| ERROR | `ma-2-azure-001` | Objective '[a]' not found in control MA-2 (valid: []) |
| ERROR | `ma-2-azure-002` | Objective '[a]' not found in control MA-2 (valid: []) |
| ERROR | `ma-2-gcp-001` | Objective '[a]' not found in control MA-2 (valid: []) |
| ERROR | `ma-2-gcp-002` | Objective '[a]' not found in control MA-2 (valid: []) |
| ERROR | `ma-4-aws-001` | Objective '[a]' not found in control MA-4 (valid: []) |
| ERROR | `ma-4-aws-001` | Objective '[b]' not found in control MA-4 (valid: []) |
| ERROR | `ma-4-aws-002` | Objective '[a]' not found in control MA-4 (valid: []) |
| ERROR | `ma-4-aws-002` | Objective '[b]' not found in control MA-4 (valid: []) |
| ERROR | `ma-4-azure-001` | Objective '[a]' not found in control MA-4 (valid: []) |
| ERROR | `ma-4-azure-001` | Objective '[b]' not found in control MA-4 (valid: []) |
| ERROR | `ma-4-gcp-001` | Objective '[a]' not found in control MA-4 (valid: []) |
| ERROR | `ma-4-gcp-001` | Objective '[b]' not found in control MA-4 (valid: []) |
| ERROR | `mp-4-aws-001` | Objective '[a]' not found in control MP-4 (valid: []) |
| ERROR | `mp-4-aws-002` | Objective '[a]' not found in control MP-4 (valid: []) |
| ERROR | `mp-4-aws-003` | Objective '[a]' not found in control MP-4 (valid: []) |
| ERROR | `mp-4-azure-001` | Objective '[a]' not found in control MP-4 (valid: []) |
| ERROR | `mp-4-azure-002` | Objective '[a]' not found in control MP-4 (valid: []) |
| ERROR | `mp-4-gcp-001` | Objective '[a]' not found in control MP-4 (valid: []) |
| ERROR | `mp-4-gcp-002` | Objective '[a]' not found in control MP-4 (valid: []) |
| ERROR | `mp-5-aws-001` | Objective '[a]' not found in control MP-5 (valid: []) |
| ERROR | `mp-5-aws-002` | Objective '[a]' not found in control MP-5 (valid: []) |
| ERROR | `mp-5-aws-003` | Objective '[a]' not found in control MP-5 (valid: []) |
| ERROR | `mp-5-azure-001` | Objective '[a]' not found in control MP-5 (valid: []) |
| ERROR | `mp-5-azure-002` | Objective '[a]' not found in control MP-5 (valid: []) |
| ERROR | `mp-5-gcp-001` | Objective '[a]' not found in control MP-5 (valid: []) |
| ERROR | `mp-5-gcp-002` | Objective '[a]' not found in control MP-5 (valid: []) |
| ERROR | `mp-4-2-aws-001` | Control MP-4(2) not found in nist_800_53_controls.json |
| ERROR | `mp-4-2-aws-002` | Control MP-4(2) not found in nist_800_53_controls.json |
| ERROR | `mp-4-2-aws-003` | Control MP-4(2) not found in nist_800_53_controls.json |
| ERROR | `mp-4-2-azure-001` | Control MP-4(2) not found in nist_800_53_controls.json |
| ERROR | `mp-4-2-azure-002` | Control MP-4(2) not found in nist_800_53_controls.json |
| ERROR | `mp-4-2-gcp-001` | Control MP-4(2) not found in nist_800_53_controls.json |
| ERROR | `pl-2-aws-001` | Objective '[a]' not found in control PL-2 (valid: []) |
| ERROR | `pl-2-azure-001` | Objective '[a]' not found in control PL-2 (valid: []) |
| ERROR | `pl-2-gcp-001` | Objective '[a]' not found in control PL-2 (valid: []) |
| ERROR | `pl-8-aws-001` | Objective '[a]' not found in control PL-8 (valid: []) |
| ERROR | `pl-8-aws-002` | Objective '[a]' not found in control PL-8 (valid: []) |
| ERROR | `pl-8-azure-001` | Objective '[a]' not found in control PL-8 (valid: []) |
| ERROR | `pl-8-azure-002` | Objective '[a]' not found in control PL-8 (valid: []) |
| ERROR | `pl-8-gcp-001` | Objective '[a]' not found in control PL-8 (valid: []) |
| ERROR | `pl-8-gcp-002` | Objective '[a]' not found in control PL-8 (valid: []) |
| ERROR | `pt-2-aws-001` | Objective '[a]' not found in control PT-2 (valid: []) |
| ERROR | `pt-2-aws-001` | Objective '[b]' not found in control PT-2 (valid: []) |
| ERROR | `pt-2-aws-002` | Objective '[a]' not found in control PT-2 (valid: []) |
| ERROR | `pt-2-aws-003` | Objective '[a]' not found in control PT-2 (valid: []) |
| ERROR | `pt-2-azure-001` | Objective '[a]' not found in control PT-2 (valid: []) |
| ERROR | `pt-2-azure-001` | Objective '[b]' not found in control PT-2 (valid: []) |
| ERROR | `pt-2-azure-002` | Objective '[a]' not found in control PT-2 (valid: []) |
| ERROR | `pt-2-azure-003` | Objective '[a]' not found in control PT-2 (valid: []) |
| ERROR | `pt-2-gcp-001` | Objective '[a]' not found in control PT-2 (valid: []) |
| ERROR | `pt-2-gcp-001` | Objective '[b]' not found in control PT-2 (valid: []) |
| ERROR | `pt-2-gcp-002` | Objective '[a]' not found in control PT-2 (valid: []) |
| ERROR | `pt-2-gcp-003` | Objective '[a]' not found in control PT-2 (valid: []) |
| ERROR | `pt-3-aws-001` | Objective '[a]' not found in control PT-3 (valid: []) |
| ERROR | `pt-3-azure-001` | Objective '[a]' not found in control PT-3 (valid: []) |
| ERROR | `pt-3-gcp-001` | Objective '[a]' not found in control PT-3 (valid: []) |
| ERROR | `pt-4-aws-001` | Objective '[a]' not found in control PT-4 (valid: []) |
| ERROR | `pt-4-azure-001` | Objective '[a]' not found in control PT-4 (valid: []) |
| ERROR | `pt-4-gcp-001` | Objective '[a]' not found in control PT-4 (valid: []) |
| ERROR | `ra-5-aws-001` | Objective '[a]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-aws-001` | Objective '[b]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-aws-001` | Objective '[c]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-aws-001` | Objective '[d]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-aws-001` | Objective '[e]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-aws-002` | Objective '[a]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-aws-002` | Objective '[b]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-aws-002` | Objective '[c]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-aws-002` | Objective '[d]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-aws-002` | Objective '[e]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-aws-003` | Objective '[a]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-aws-003` | Objective '[b]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-aws-003` | Objective '[c]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-aws-003` | Objective '[d]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-aws-003` | Objective '[e]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-001` | Objective '[a]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-001` | Objective '[b]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-001` | Objective '[c]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-001` | Objective '[d]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-001` | Objective '[e]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-002` | Objective '[a]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-002` | Objective '[b]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-002` | Objective '[c]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-002` | Objective '[d]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-002` | Objective '[e]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-003` | Objective '[a]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-003` | Objective '[b]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-003` | Objective '[c]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-003` | Objective '[d]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-azure-003` | Objective '[e]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-001` | Objective '[a]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-001` | Objective '[b]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-001` | Objective '[c]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-001` | Objective '[d]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-001` | Objective '[e]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-002` | Objective '[a]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-002` | Objective '[b]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-002` | Objective '[c]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-002` | Objective '[d]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-002` | Objective '[e]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-003` | Objective '[a]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-003` | Objective '[b]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-003` | Objective '[c]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-003` | Objective '[d]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-gcp-003` | Objective '[e]' not found in control RA-5 (valid: []) |
| ERROR | `ra-5-5-aws-001` | Control RA-5(5) not found in nist_800_53_controls.json |
| ERROR | `ra-5-5-aws-002` | Control RA-5(5) not found in nist_800_53_controls.json |
| ERROR | `ra-5-5-azure-001` | Control RA-5(5) not found in nist_800_53_controls.json |
| ERROR | `ra-5-5-azure-002` | Control RA-5(5) not found in nist_800_53_controls.json |
| ERROR | `ra-5-5-gcp-001` | Control RA-5(5) not found in nist_800_53_controls.json |
| ERROR | `ra-5-5-gcp-002` | Control RA-5(5) not found in nist_800_53_controls.json |
| ERROR | `sa-3-aws-001` | Objective '[a]' not found in control SA-3 (valid: []) |
| ERROR | `sa-3-aws-001` | Objective '[b]' not found in control SA-3 (valid: []) |
| ERROR | `sa-3-aws-002` | Objective '[a]' not found in control SA-3 (valid: []) |
| ERROR | `sa-3-aws-002` | Objective '[c]' not found in control SA-3 (valid: []) |
| ERROR | `sa-3-azure-001` | Objective '[a]' not found in control SA-3 (valid: []) |
| ERROR | `sa-3-azure-001` | Objective '[b]' not found in control SA-3 (valid: []) |
| ERROR | `sa-3-gcp-001` | Objective '[a]' not found in control SA-3 (valid: []) |
| ERROR | `sa-3-gcp-001` | Objective '[b]' not found in control SA-3 (valid: []) |
| ERROR | `sa-4-9-aws-001` | Control SA-4.9 not found in nist_800_53_controls.json |
| ERROR | `sa-4-9-azure-001` | Control SA-4.9 not found in nist_800_53_controls.json |
| ERROR | `sa-4-9-gcp-001` | Control SA-4.9 not found in nist_800_53_controls.json |
| ERROR | `sa-9-2-aws-001` | Control SA-9.2 not found in nist_800_53_controls.json |
| ERROR | `sa-9-2-azure-001` | Control SA-9.2 not found in nist_800_53_controls.json |
| ERROR | `sa-9-2-gcp-001` | Control SA-9.2 not found in nist_800_53_controls.json |
| ERROR | `sa-10-aws-001` | Objective '[a]' not found in control SA-10 (valid: []) |
| ERROR | `sa-10-aws-001` | Objective '[b]' not found in control SA-10 (valid: []) |
| ERROR | `sa-10-aws-002` | Objective '[a]' not found in control SA-10 (valid: []) |
| ERROR | `sa-10-aws-002` | Objective '[b]' not found in control SA-10 (valid: []) |
| ERROR | `sa-10-azure-001` | Objective '[a]' not found in control SA-10 (valid: []) |
| ERROR | `sa-10-azure-001` | Objective '[b]' not found in control SA-10 (valid: []) |
| ERROR | `sa-10-gcp-001` | Objective '[a]' not found in control SA-10 (valid: []) |
| ERROR | `sa-10-gcp-001` | Objective '[b]' not found in control SA-10 (valid: []) |
| ERROR | `sa-11-aws-001` | Objective '[a]' not found in control SA-11 (valid: []) |
| ERROR | `sa-11-aws-001` | Objective '[b]' not found in control SA-11 (valid: []) |
| ERROR | `sa-11-azure-001` | Objective '[a]' not found in control SA-11 (valid: []) |
| ERROR | `sa-11-azure-001` | Objective '[b]' not found in control SA-11 (valid: []) |
| ERROR | `sa-11-gcp-001` | Objective '[a]' not found in control SA-11 (valid: []) |
| ERROR | `sa-11-gcp-001` | Objective '[b]' not found in control SA-11 (valid: []) |
| ERROR | `sa-11-1-aws-001` | Control SA-11.1 not found in nist_800_53_controls.json |
| ERROR | `sa-11-1-azure-001` | Control SA-11.1 not found in nist_800_53_controls.json |
| ERROR | `sa-11-1-gcp-001` | Control SA-11.1 not found in nist_800_53_controls.json |
| ERROR | `sa-22-aws-001` | Objective '[a]' not found in control SA-22 (valid: []) |
| ERROR | `sa-22-aws-001` | Objective '[b]' not found in control SA-22 (valid: []) |
| ERROR | `sa-22-aws-002` | Objective '[a]' not found in control SA-22 (valid: []) |
| ERROR | `sa-22-aws-002` | Objective '[b]' not found in control SA-22 (valid: []) |
| ERROR | `sa-22-azure-001` | Objective '[a]' not found in control SA-22 (valid: []) |
| ERROR | `sa-22-azure-001` | Objective '[b]' not found in control SA-22 (valid: []) |
| ERROR | `sa-22-gcp-001` | Objective '[a]' not found in control SA-22 (valid: []) |
| ERROR | `sa-22-gcp-001` | Objective '[b]' not found in control SA-22 (valid: []) |
| ERROR | `sc-7-aws-001` | Objective '[a]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-001` | Objective '[b]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-001` | Objective '[c]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-001` | Objective '[d]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-001` | Objective '[e]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-001` | Objective '[f]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-001` | Objective '[g]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-001` | Objective '[h]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-002` | Objective '[a]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-002` | Objective '[b]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-002` | Objective '[c]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-002` | Objective '[d]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-002` | Objective '[e]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-002` | Objective '[f]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-002` | Objective '[g]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-002` | Objective '[h]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-003` | Objective '[a]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-003` | Objective '[b]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-003` | Objective '[c]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-003` | Objective '[d]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-003` | Objective '[e]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-003` | Objective '[f]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-003` | Objective '[g]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-003` | Objective '[h]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-004` | Objective '[a]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-004` | Objective '[b]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-004` | Objective '[c]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-004` | Objective '[d]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-004` | Objective '[e]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-004` | Objective '[f]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-004` | Objective '[g]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-aws-004` | Objective '[h]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-001` | Objective '[a]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-001` | Objective '[b]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-001` | Objective '[c]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-001` | Objective '[d]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-001` | Objective '[e]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-001` | Objective '[f]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-001` | Objective '[g]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-001` | Objective '[h]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-002` | Objective '[a]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-002` | Objective '[b]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-002` | Objective '[c]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-002` | Objective '[d]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-002` | Objective '[e]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-002` | Objective '[f]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-002` | Objective '[g]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-002` | Objective '[h]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-003` | Objective '[a]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-003` | Objective '[b]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-003` | Objective '[c]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-003` | Objective '[d]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-003` | Objective '[e]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-003` | Objective '[f]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-003` | Objective '[g]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-azure-003` | Objective '[h]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-001` | Objective '[a]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-001` | Objective '[b]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-001` | Objective '[c]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-001` | Objective '[d]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-001` | Objective '[e]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-001` | Objective '[f]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-001` | Objective '[g]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-001` | Objective '[h]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-002` | Objective '[a]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-002` | Objective '[b]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-002` | Objective '[c]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-002` | Objective '[d]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-002` | Objective '[e]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-002` | Objective '[f]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-002` | Objective '[g]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-002` | Objective '[h]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-003` | Objective '[a]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-003` | Objective '[b]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-003` | Objective '[c]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-003` | Objective '[d]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-003` | Objective '[e]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-003` | Objective '[f]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-003` | Objective '[g]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-gcp-003` | Objective '[h]' not found in control SC-7 (valid: []) |
| ERROR | `sc-7-5-aws-001` | Control SC-7(5) not found in nist_800_53_controls.json |
| ERROR | `sc-7-5-azure-001` | Control SC-7(5) not found in nist_800_53_controls.json |
| ERROR | `sc-7-5-gcp-001` | Control SC-7(5) not found in nist_800_53_controls.json |
| ERROR | `sc-7-7-aws-001` | Control SC-7(7) not found in nist_800_53_controls.json |
| ERROR | `sc-7-7-aws-002` | Control SC-7(7) not found in nist_800_53_controls.json |
| ERROR | `sc-7-7-aws-001` | Control SC-7(7) not found in nist_800_53_controls.json |
| ERROR | `sc-7-7-azure-001` | Control SC-7(7) not found in nist_800_53_controls.json |
| ERROR | `sc-7-7-azure-001` | Control SC-7(7) not found in nist_800_53_controls.json |
| ERROR | `sc-7-7-gcp-001` | Control SC-7(7) not found in nist_800_53_controls.json |
| ERROR | `sc-7-7-gcp-001` | Control SC-7(7) not found in nist_800_53_controls.json |
| ERROR | `sc-7-8-aws-001` | Control SC-7(8) not found in nist_800_53_controls.json |
| ERROR | `sc-7-8-aws-002` | Control SC-7(8) not found in nist_800_53_controls.json |
| ERROR | `sc-7-8-azure-001` | Control SC-7(8) not found in nist_800_53_controls.json |
| ERROR | `sc-7-8-gcp-001` | Control SC-7(8) not found in nist_800_53_controls.json |
| ERROR | `sc-7-4-aws-001` | Control SC-7(4) not found in nist_800_53_controls.json |
| ERROR | `sc-7-4-aws-002` | Control SC-7(4) not found in nist_800_53_controls.json |
| ERROR | `sc-7-4-azure-001` | Control SC-7(4) not found in nist_800_53_controls.json |
| ERROR | `sc-7-4-gcp-001` | Control SC-7(4) not found in nist_800_53_controls.json |
| ERROR | `sc-7-21-aws-001` | Control SC-7(21) not found in nist_800_53_controls.json |
| ERROR | `sc-7-21-aws-002` | Control SC-7(21) not found in nist_800_53_controls.json |
| ERROR | `sc-7-21-azure-001` | Control SC-7(21) not found in nist_800_53_controls.json |
| ERROR | `sc-7-21-azure-002` | Control SC-7(21) not found in nist_800_53_controls.json |
| ERROR | `sc-7-21-gcp-001` | Control SC-7(21) not found in nist_800_53_controls.json |
| ERROR | `sc-7-21-gcp-002` | Control SC-7(21) not found in nist_800_53_controls.json |
| ERROR | `sc-8-aws-001` | Objective '[a]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-aws-001` | Objective '[b]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-aws-001` | Objective '[c]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-aws-002` | Objective '[a]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-aws-002` | Objective '[b]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-aws-002` | Objective '[c]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-aws-003` | Objective '[a]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-aws-003` | Objective '[b]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-aws-003` | Objective '[c]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-azure-001` | Objective '[a]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-azure-001` | Objective '[b]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-azure-001` | Objective '[c]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-azure-002` | Objective '[a]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-azure-002` | Objective '[b]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-azure-002` | Objective '[c]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-gcp-001` | Objective '[a]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-gcp-001` | Objective '[b]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-gcp-001` | Objective '[c]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-gcp-002` | Objective '[a]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-gcp-002` | Objective '[b]' not found in control SC-8 (valid: []) |
| ERROR | `sc-8-gcp-002` | Objective '[c]' not found in control SC-8 (valid: []) |
| ERROR | `sc-10-aws-001` | Objective '[a]' not found in control SC-10 (valid: []) |
| ERROR | `sc-10-aws-001` | Objective '[b]' not found in control SC-10 (valid: []) |
| ERROR | `sc-10-aws-001` | Objective '[c]' not found in control SC-10 (valid: []) |
| ERROR | `sc-10-aws-002` | Objective '[a]' not found in control SC-10 (valid: []) |
| ERROR | `sc-10-aws-002` | Objective '[b]' not found in control SC-10 (valid: []) |
| ERROR | `sc-10-aws-002` | Objective '[c]' not found in control SC-10 (valid: []) |
| ERROR | `sc-10-azure-001` | Objective '[a]' not found in control SC-10 (valid: []) |
| ERROR | `sc-10-azure-001` | Objective '[b]' not found in control SC-10 (valid: []) |
| ERROR | `sc-10-azure-001` | Objective '[c]' not found in control SC-10 (valid: []) |
| ERROR | `sc-10-gcp-001` | Objective '[a]' not found in control SC-10 (valid: []) |
| ERROR | `sc-10-gcp-001` | Objective '[b]' not found in control SC-10 (valid: []) |
| ERROR | `sc-10-gcp-001` | Objective '[c]' not found in control SC-10 (valid: []) |
| ERROR | `sc-12-aws-001` | Objective '[a]' not found in control SC-12 (valid: []) |
| ERROR | `sc-12-aws-001` | Objective '[b]' not found in control SC-12 (valid: []) |
| ERROR | `sc-12-aws-002` | Objective '[a]' not found in control SC-12 (valid: []) |
| ERROR | `sc-12-aws-002` | Objective '[b]' not found in control SC-12 (valid: []) |
| ERROR | `sc-12-aws-003` | Objective '[a]' not found in control SC-12 (valid: []) |
| ERROR | `sc-12-aws-003` | Objective '[b]' not found in control SC-12 (valid: []) |
| ERROR | `sc-12-azure-001` | Objective '[a]' not found in control SC-12 (valid: []) |
| ERROR | `sc-12-azure-001` | Objective '[b]' not found in control SC-12 (valid: []) |
| ERROR | `sc-12-azure-002` | Objective '[a]' not found in control SC-12 (valid: []) |
| ERROR | `sc-12-azure-002` | Objective '[b]' not found in control SC-12 (valid: []) |
| ERROR | `sc-12-gcp-001` | Objective '[a]' not found in control SC-12 (valid: []) |
| ERROR | `sc-12-gcp-001` | Objective '[b]' not found in control SC-12 (valid: []) |
| ERROR | `sc-12-gcp-002` | Objective '[a]' not found in control SC-12 (valid: []) |
| ERROR | `sc-12-gcp-002` | Objective '[b]' not found in control SC-12 (valid: []) |
| ERROR | `sc-13-aws-001` | Objective '[a]' not found in control SC-13 (valid: []) |
| ERROR | `sc-13-aws-002` | Objective '[a]' not found in control SC-13 (valid: []) |
| ERROR | `sc-13-azure-001` | Objective '[a]' not found in control SC-13 (valid: []) |
| ERROR | `sc-13-gcp-001` | Objective '[a]' not found in control SC-13 (valid: []) |
| ERROR | `sc-18-aws-001` | Objective '[a]' not found in control SC-18 (valid: []) |
| ERROR | `sc-18-aws-001` | Objective '[b]' not found in control SC-18 (valid: []) |
| ERROR | `sc-18-azure-001` | Objective '[a]' not found in control SC-18 (valid: []) |
| ERROR | `sc-18-azure-001` | Objective '[b]' not found in control SC-18 (valid: []) |
| ERROR | `sc-18-gcp-001` | Objective '[a]' not found in control SC-18 (valid: []) |
| ERROR | `sc-18-gcp-001` | Objective '[b]' not found in control SC-18 (valid: []) |
| ERROR | `sc-23-aws-001` | Objective '[a]' not found in control SC-23 (valid: []) |
| ERROR | `sc-23-aws-002` | Objective '[a]' not found in control SC-23 (valid: []) |
| ERROR | `sc-23-azure-001` | Objective '[a]' not found in control SC-23 (valid: []) |
| ERROR | `sc-23-gcp-001` | Objective '[a]' not found in control SC-23 (valid: []) |
| ERROR | `sc-28-1-aws-001` | Control SC-28(1) not found in nist_800_53_controls.json |
| ERROR | `sc-28-1-aws-002` | Control SC-28(1) not found in nist_800_53_controls.json |
| ERROR | `sc-28-1-aws-003` | Control SC-28(1) not found in nist_800_53_controls.json |
| ERROR | `sc-28-1-aws-004` | Control SC-28(1) not found in nist_800_53_controls.json |
| ERROR | `sc-28-1-azure-001` | Control SC-28(1) not found in nist_800_53_controls.json |
| ERROR | `sc-28-1-azure-002` | Control SC-28(1) not found in nist_800_53_controls.json |
| ERROR | `sc-28-1-azure-003` | Control SC-28(1) not found in nist_800_53_controls.json |
| ERROR | `sc-28-1-gcp-001` | Control SC-28(1) not found in nist_800_53_controls.json |
| ERROR | `sc-28-1-gcp-002` | Control SC-28(1) not found in nist_800_53_controls.json |
| ERROR | `sc-28-1-gcp-003` | Control SC-28(1) not found in nist_800_53_controls.json |
| ERROR | `si-2-aws-001` | Objective '[a]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-001` | Objective '[b]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-001` | Objective '[c]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-001` | Objective '[d]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-001` | Objective '[e]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-001` | Objective '[f]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-002` | Objective '[a]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-002` | Objective '[b]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-002` | Objective '[c]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-002` | Objective '[d]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-002` | Objective '[e]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-002` | Objective '[f]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-003` | Objective '[a]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-003` | Objective '[b]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-003` | Objective '[c]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-003` | Objective '[d]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-003` | Objective '[e]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-003` | Objective '[f]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-004` | Objective '[a]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-004` | Objective '[b]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-004` | Objective '[c]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-004` | Objective '[d]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-004` | Objective '[e]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-aws-004` | Objective '[f]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-001` | Objective '[a]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-001` | Objective '[b]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-001` | Objective '[c]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-001` | Objective '[d]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-001` | Objective '[e]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-001` | Objective '[f]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-002` | Objective '[a]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-002` | Objective '[b]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-002` | Objective '[c]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-002` | Objective '[d]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-002` | Objective '[e]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-002` | Objective '[f]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-003` | Objective '[a]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-003` | Objective '[b]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-003` | Objective '[c]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-003` | Objective '[d]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-003` | Objective '[e]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-azure-003` | Objective '[f]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-001` | Objective '[a]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-001` | Objective '[b]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-001` | Objective '[c]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-001` | Objective '[d]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-001` | Objective '[e]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-001` | Objective '[f]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-002` | Objective '[a]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-002` | Objective '[b]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-002` | Objective '[c]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-002` | Objective '[d]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-002` | Objective '[e]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-002` | Objective '[f]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-003` | Objective '[a]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-003` | Objective '[b]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-003` | Objective '[c]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-003` | Objective '[d]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-003` | Objective '[e]' not found in control SI-2 (valid: []) |
| ERROR | `si-2-gcp-003` | Objective '[f]' not found in control SI-2 (valid: []) |
| ERROR | `si-3-aws-001` | Objective '[a]' not found in control SI-3 (valid: []) |
| ERROR | `si-3-aws-001` | Objective '[b]' not found in control SI-3 (valid: []) |
| ERROR | `si-3-aws-002` | Objective '[a]' not found in control SI-3 (valid: []) |
| ERROR | `si-3-aws-002` | Objective '[b]' not found in control SI-3 (valid: []) |
| ERROR | `si-3-aws-003` | Objective '[a]' not found in control SI-3 (valid: []) |
| ERROR | `si-3-aws-003` | Objective '[b]' not found in control SI-3 (valid: []) |
| ERROR | `si-3-azure-001` | Objective '[a]' not found in control SI-3 (valid: []) |
| ERROR | `si-3-azure-001` | Objective '[b]' not found in control SI-3 (valid: []) |
| ERROR | `si-3-azure-002` | Objective '[a]' not found in control SI-3 (valid: []) |
| ERROR | `si-3-azure-002` | Objective '[b]' not found in control SI-3 (valid: []) |
| ERROR | `si-3-gcp-001` | Objective '[a]' not found in control SI-3 (valid: []) |
| ERROR | `si-3-gcp-001` | Objective '[b]' not found in control SI-3 (valid: []) |
| ERROR | `si-3-gcp-002` | Objective '[a]' not found in control SI-3 (valid: []) |
| ERROR | `si-3-gcp-002` | Objective '[b]' not found in control SI-3 (valid: []) |
| ERROR | `si-5-aws-001` | Objective '[a]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-aws-001` | Objective '[b]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-aws-001` | Objective '[c]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-aws-002` | Objective '[a]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-aws-002` | Objective '[b]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-aws-002` | Objective '[c]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-aws-003` | Objective '[a]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-aws-003` | Objective '[b]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-aws-003` | Objective '[c]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-azure-001` | Objective '[a]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-azure-001` | Objective '[b]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-azure-001` | Objective '[c]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-azure-002` | Objective '[a]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-azure-002` | Objective '[b]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-azure-002` | Objective '[c]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-gcp-001` | Objective '[a]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-gcp-001` | Objective '[b]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-gcp-001` | Objective '[c]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-gcp-002` | Objective '[a]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-gcp-002` | Objective '[b]' not found in control SI-5 (valid: []) |
| ERROR | `si-5-gcp-002` | Objective '[c]' not found in control SI-5 (valid: []) |
| ERROR | `si-3-1-aws-001` | Control SI-3(1) not found in nist_800_53_controls.json |
| ERROR | `si-3-1-aws-002` | Control SI-3(1) not found in nist_800_53_controls.json |
| ERROR | `si-3-1-azure-001` | Control SI-3(1) not found in nist_800_53_controls.json |
| ERROR | `si-3-1-gcp-001` | Control SI-3(1) not found in nist_800_53_controls.json |
| ERROR | `si-3-2-aws-001` | Control SI-3(2) not found in nist_800_53_controls.json |
| ERROR | `si-3-2-aws-002` | Control SI-3(2) not found in nist_800_53_controls.json |
| ERROR | `si-3-2-aws-003` | Control SI-3(2) not found in nist_800_53_controls.json |
| ERROR | `si-3-2-azure-001` | Control SI-3(2) not found in nist_800_53_controls.json |
| ERROR | `si-3-2-azure-002` | Control SI-3(2) not found in nist_800_53_controls.json |
| ERROR | `si-3-2-gcp-001` | Control SI-3(2) not found in nist_800_53_controls.json |
| ERROR | `si-3-2-gcp-002` | Control SI-3(2) not found in nist_800_53_controls.json |
| ERROR | `si-4-aws-001` | Objective '[a]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-aws-001` | Objective '[b]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-aws-001` | Objective '[c]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-aws-002` | Objective '[a]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-aws-002` | Objective '[b]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-aws-002` | Objective '[c]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-aws-003` | Objective '[a]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-aws-003` | Objective '[b]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-aws-003` | Objective '[c]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-azure-001` | Objective '[a]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-azure-001` | Objective '[b]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-azure-001` | Objective '[c]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-azure-002` | Objective '[a]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-azure-002` | Objective '[b]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-azure-002` | Objective '[c]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-azure-003` | Objective '[a]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-azure-003` | Objective '[b]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-azure-003` | Objective '[c]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-gcp-001` | Objective '[a]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-gcp-001` | Objective '[b]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-gcp-001` | Objective '[c]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-gcp-002` | Objective '[a]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-gcp-002` | Objective '[b]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-gcp-002` | Objective '[c]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-gcp-003` | Objective '[a]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-gcp-003` | Objective '[b]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-gcp-003` | Objective '[c]' not found in control SI-4 (valid: []) |
| ERROR | `si-4-4-aws-001` | Control SI-4(4) not found in nist_800_53_controls.json |
| ERROR | `si-4-4-aws-002` | Control SI-4(4) not found in nist_800_53_controls.json |
| ERROR | `si-4-4-aws-003` | Control SI-4(4) not found in nist_800_53_controls.json |
| ERROR | `si-4-4-azure-001` | Control SI-4(4) not found in nist_800_53_controls.json |
| ERROR | `si-4-4-azure-002` | Control SI-4(4) not found in nist_800_53_controls.json |
| ERROR | `si-4-4-azure-003` | Control SI-4(4) not found in nist_800_53_controls.json |
| ERROR | `si-4-4-gcp-001` | Control SI-4(4) not found in nist_800_53_controls.json |
| ERROR | `si-4-4-gcp-002` | Control SI-4(4) not found in nist_800_53_controls.json |
| ERROR | `si-4-4-gcp-003` | Control SI-4(4) not found in nist_800_53_controls.json |
| ERROR | `sr-2-aws-001` | Objective '[a]' not found in control SR-2 (valid: []) |
| ERROR | `sr-2-aws-001` | Objective '[b]' not found in control SR-2 (valid: []) |
| ERROR | `sr-2-aws-002` | Objective '[a]' not found in control SR-2 (valid: []) |
| ERROR | `sr-2-azure-001` | Objective '[a]' not found in control SR-2 (valid: []) |
| ERROR | `sr-2-azure-001` | Objective '[b]' not found in control SR-2 (valid: []) |
| ERROR | `sr-2-gcp-001` | Objective '[a]' not found in control SR-2 (valid: []) |
| ERROR | `sr-2-gcp-001` | Objective '[b]' not found in control SR-2 (valid: []) |
| ERROR | `sr-3-aws-001` | Objective '[a]' not found in control SR-3 (valid: []) |
| ERROR | `sr-3-azure-001` | Objective '[a]' not found in control SR-3 (valid: []) |
| ERROR | `sr-3-gcp-001` | Objective '[a]' not found in control SR-3 (valid: []) |
| ERROR | `sr-11-aws-001` | Objective '[a]' not found in control SR-11 (valid: []) |
| ERROR | `sr-11-aws-001` | Objective '[b]' not found in control SR-11 (valid: []) |
| ERROR | `sr-11-aws-002` | Objective '[a]' not found in control SR-11 (valid: []) |
| ERROR | `sr-11-azure-001` | Objective '[a]' not found in control SR-11 (valid: []) |
| ERROR | `sr-11-azure-001` | Objective '[b]' not found in control SR-11 (valid: []) |
| ERROR | `sr-11-gcp-001` | Objective '[a]' not found in control SR-11 (valid: []) |
| ERROR | `sr-11-gcp-001` | Objective '[b]' not found in control SR-11 (valid: []) |

### Method Mapping

| Level | Check ID | Message |
|-------|----------|---------|
| WARNING | `ac-17-3-aws-001` | No entry in AWS_CHECK_METHODS — will run as 'not yet implemented' |

### Check ID Format

| Level | Check ID | Message |
|-------|----------|---------|
| ERROR | `ac-2-aws-001` | check_id 'ac-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-2-aws-002` | check_id 'ac-2-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-2-aws-003` | check_id 'ac-2-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-2-azure-001` | check_id 'ac-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-2-azure-002` | check_id 'ac-2-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-2-azure-003` | check_id 'ac-2-azure-003' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-2-gcp-001` | check_id 'ac-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-2-gcp-002` | check_id 'ac-2-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-2-gcp-003` | check_id 'ac-2-gcp-003' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-3-aws-001` | check_id 'ac-3-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-3-aws-002` | check_id 'ac-3-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-3-azure-001` | check_id 'ac-3-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-3-azure-002` | check_id 'ac-3-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-3-gcp-001` | check_id 'ac-3-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-3-gcp-002` | check_id 'ac-3-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-4-aws-001` | check_id 'ac-4-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-4-aws-002` | check_id 'ac-4-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-4-azure-001` | check_id 'ac-4-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-4-azure-002` | check_id 'ac-4-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-4-gcp-001` | check_id 'ac-4-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-4-gcp-002` | check_id 'ac-4-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-5-aws-001` | check_id 'ac-5-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-5-aws-002` | check_id 'ac-5-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-5-azure-001` | check_id 'ac-5-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-5-gcp-001` | check_id 'ac-5-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-6-aws-001` | check_id 'ac-6-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-6-aws-002` | check_id 'ac-6-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-6-aws-003` | check_id 'ac-6-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-6-azure-001` | check_id 'ac-6-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-6-azure-002` | check_id 'ac-6-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-6-gcp-001` | check_id 'ac-6-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-6-gcp-002` | check_id 'ac-6-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-6-3-aws-001` | check_id 'ac-6-3-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-6-3-azure-001` | check_id 'ac-6-3-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-6-3-gcp-001` | check_id 'ac-6-3-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-2-9-aws-001` | check_id 'ac-2-9-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-2-9-aws-002` | check_id 'ac-2-9-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-2-9-azure-001` | check_id 'ac-2-9-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-2-9-gcp-001` | check_id 'ac-2-9-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-2-9-gcp-002` | check_id 'ac-2-9-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-7-aws-001` | check_id 'ac-7-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-7-aws-002` | check_id 'ac-7-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-7-azure-001` | check_id 'ac-7-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-7-gcp-001` | check_id 'ac-7-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-11-aws-001` | check_id 'ac-11-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-11-azure-001` | check_id 'ac-11-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-11-gcp-001` | check_id 'ac-11-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-12-aws-001` | check_id 'ac-12-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-12-aws-002` | check_id 'ac-12-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-12-azure-001` | check_id 'ac-12-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-12-gcp-001` | check_id 'ac-12-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-17-1-aws-001` | check_id 'ac-17-1-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-17-1-aws-002` | check_id 'ac-17-1-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-17-1-azure-001` | check_id 'ac-17-1-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-17-1-gcp-001` | check_id 'ac-17-1-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-17-2-aws-001` | check_id 'ac-17-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-17-2-aws-002` | check_id 'ac-17-2-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-17-2-azure-001` | check_id 'ac-17-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-17-2-gcp-001` | check_id 'ac-17-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-17-3-aws-001` | check_id 'ac-17-3-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-17-3-aws-002` | check_id 'ac-17-3-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-17-3-azure-001` | check_id 'ac-17-3-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-17-3-gcp-001` | check_id 'ac-17-3-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-18-aws-001` | check_id 'ac-18-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-18-azure-001` | check_id 'ac-18-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-18-gcp-001` | check_id 'ac-18-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-19-aws-001` | check_id 'ac-19-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-19-azure-001` | check_id 'ac-19-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-19-gcp-001` | check_id 'ac-19-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-20-aws-001` | check_id 'ac-20-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-20-azure-001` | check_id 'ac-20-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-20-gcp-001` | check_id 'ac-20-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-20-1-aws-001` | check_id 'ac-20-1-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-20-1-azure-001` | check_id 'ac-20-1-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-20-1-gcp-001` | check_id 'ac-20-1-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-21-aws-001` | check_id 'ac-21-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-21-aws-002` | check_id 'ac-21-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-21-azure-001` | check_id 'ac-21-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-21-gcp-001` | check_id 'ac-21-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-3-8-aws-001` | check_id 'ac-3-8-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-3-8-azure-001` | check_id 'ac-3-8-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-3-8-gcp-001` | check_id 'ac-3-8-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-4-4-aws-001` | check_id 'ac-4-4-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-4-4-aws-002` | check_id 'ac-4-4-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-4-4-azure-001` | check_id 'ac-4-4-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `ac-4-4-gcp-001` | check_id 'ac-4-4-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ac.json) |
| ERROR | `au-2-aws-001` | check_id 'au-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-2-aws-002` | check_id 'au-2-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-2-aws-003` | check_id 'au-2-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-2-aws-004` | check_id 'au-2-aws-004' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-2-azure-001` | check_id 'au-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-2-azure-002` | check_id 'au-2-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-2-azure-003` | check_id 'au-2-azure-003' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-2-gcp-001` | check_id 'au-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-2-gcp-002` | check_id 'au-2-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-2-gcp-003` | check_id 'au-2-gcp-003' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-3-aws-001` | check_id 'au-3-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-3-aws-002` | check_id 'au-3-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-3-azure-001` | check_id 'au-3-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-3-gcp-001` | check_id 'au-3-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-5-aws-001` | check_id 'au-5-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-5-aws-002` | check_id 'au-5-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-5-azure-001` | check_id 'au-5-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-5-gcp-001` | check_id 'au-5-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-6-aws-001` | check_id 'au-6-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-6-aws-002` | check_id 'au-6-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-6-azure-001` | check_id 'au-6-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-6-gcp-001` | check_id 'au-6-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-7-aws-001` | check_id 'au-7-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-7-aws-002` | check_id 'au-7-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-7-azure-001` | check_id 'au-7-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-7-gcp-001` | check_id 'au-7-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-8-aws-001` | check_id 'au-8-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-8-azure-001` | check_id 'au-8-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-8-gcp-001` | check_id 'au-8-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-9-aws-001` | check_id 'au-9-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-9-aws-002` | check_id 'au-9-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-9-aws-003` | check_id 'au-9-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-9-azure-001` | check_id 'au-9-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-9-azure-002` | check_id 'au-9-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-9-gcp-001` | check_id 'au-9-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-9-gcp-002` | check_id 'au-9-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-9-4-aws-001` | check_id 'au-9-4-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-9-4-aws-002` | check_id 'au-9-4-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-9-4-azure-001` | check_id 'au-9-4-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `au-9-4-gcp-001` | check_id 'au-9-4-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in au.json) |
| ERROR | `ca-7-aws-001` | check_id 'ca-7-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ca.json) |
| ERROR | `ca-7-aws-002` | check_id 'ca-7-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ca.json) |
| ERROR | `ca-7-aws-003` | check_id 'ca-7-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in ca.json) |
| ERROR | `ca-7-azure-001` | check_id 'ca-7-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ca.json) |
| ERROR | `ca-7-azure-002` | check_id 'ca-7-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ca.json) |
| ERROR | `ca-7-gcp-001` | check_id 'ca-7-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ca.json) |
| ERROR | `ca-7-gcp-002` | check_id 'ca-7-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ca.json) |
| ERROR | `cm-2-aws-001` | check_id 'cm-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-2-aws-002` | check_id 'cm-2-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-2-aws-003` | check_id 'cm-2-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-2-azure-001` | check_id 'cm-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-2-azure-002` | check_id 'cm-2-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-2-gcp-001` | check_id 'cm-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-2-gcp-002` | check_id 'cm-2-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-6-aws-001` | check_id 'cm-6-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-6-aws-002` | check_id 'cm-6-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-6-azure-001` | check_id 'cm-6-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-6-azure-002` | check_id 'cm-6-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-6-gcp-001` | check_id 'cm-6-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-6-gcp-002` | check_id 'cm-6-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-3-aws-001` | check_id 'cm-3-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-3-aws-002` | check_id 'cm-3-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-3-azure-001` | check_id 'cm-3-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-3-gcp-001` | check_id 'cm-3-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-5-aws-001` | check_id 'cm-5-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-5-aws-002` | check_id 'cm-5-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-5-azure-001` | check_id 'cm-5-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-5-gcp-001` | check_id 'cm-5-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-7-aws-001` | check_id 'cm-7-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-7-aws-002` | check_id 'cm-7-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-7-azure-001` | check_id 'cm-7-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-7-gcp-001` | check_id 'cm-7-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-7-1-aws-001` | check_id 'cm-7-1-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-7-1-aws-002` | check_id 'cm-7-1-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-7-1-azure-001` | check_id 'cm-7-1-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-7-1-gcp-001` | check_id 'cm-7-1-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-7-5-aws-001` | check_id 'cm-7-5-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-7-5-azure-001` | check_id 'cm-7-5-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-7-5-gcp-001` | check_id 'cm-7-5-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-8-aws-001` | check_id 'cm-8-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-8-azure-001` | check_id 'cm-8-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cm-8-gcp-001` | check_id 'cm-8-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cm.json) |
| ERROR | `cp-2-aws-001` | check_id 'cp-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-2-azure-001` | check_id 'cp-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-2-gcp-001` | check_id 'cp-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-4-aws-001` | check_id 'cp-4-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-4-azure-001` | check_id 'cp-4-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-4-gcp-001` | check_id 'cp-4-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-6-aws-001` | check_id 'cp-6-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-6-aws-002` | check_id 'cp-6-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-6-azure-001` | check_id 'cp-6-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-6-azure-002` | check_id 'cp-6-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-6-gcp-001` | check_id 'cp-6-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-6-gcp-002` | check_id 'cp-6-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-7-aws-001` | check_id 'cp-7-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-7-aws-002` | check_id 'cp-7-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-7-azure-001` | check_id 'cp-7-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-7-azure-002` | check_id 'cp-7-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-7-gcp-001` | check_id 'cp-7-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-7-gcp-002` | check_id 'cp-7-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-aws-001` | check_id 'cp-9-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-aws-002` | check_id 'cp-9-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-aws-003` | check_id 'cp-9-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-aws-004` | check_id 'cp-9-aws-004' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-azure-001` | check_id 'cp-9-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-azure-002` | check_id 'cp-9-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-azure-003` | check_id 'cp-9-azure-003' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-gcp-001` | check_id 'cp-9-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-gcp-002` | check_id 'cp-9-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-gcp-003` | check_id 'cp-9-gcp-003' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-1-aws-001` | check_id 'cp-9-1-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-1-azure-001` | check_id 'cp-9-1-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-1-gcp-001` | check_id 'cp-9-1-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-3-aws-001` | check_id 'cp-9-3-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-3-azure-001` | check_id 'cp-9-3-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-3-gcp-001` | check_id 'cp-9-3-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-8-aws-001` | check_id 'cp-9-8-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-8-aws-002` | check_id 'cp-9-8-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-8-azure-001` | check_id 'cp-9-8-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-9-8-gcp-001` | check_id 'cp-9-8-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-10-aws-001` | check_id 'cp-10-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-10-azure-001` | check_id 'cp-10-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-10-gcp-001` | check_id 'cp-10-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-10-2-aws-001` | check_id 'cp-10-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-10-2-azure-001` | check_id 'cp-10-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `cp-10-2-gcp-001` | check_id 'cp-10-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in cp.json) |
| ERROR | `ia-2-aws-001` | check_id 'ia-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-aws-002` | check_id 'ia-2-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-aws-003` | check_id 'ia-2-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-azure-001` | check_id 'ia-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-azure-002` | check_id 'ia-2-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-gcp-001` | check_id 'ia-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-gcp-002` | check_id 'ia-2-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-3-aws-001` | check_id 'ia-3-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-3-aws-002` | check_id 'ia-3-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-3-azure-001` | check_id 'ia-3-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-3-azure-002` | check_id 'ia-3-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-3-gcp-001` | check_id 'ia-3-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-1-aws-001` | check_id 'ia-2-1-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-1-aws-002` | check_id 'ia-2-1-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-1-aws-003` | check_id 'ia-2-1-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-1-azure-001` | check_id 'ia-2-1-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-1-azure-002` | check_id 'ia-2-1-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-1-gcp-001` | check_id 'ia-2-1-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-1-gcp-002` | check_id 'ia-2-1-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-2-aws-001` | check_id 'ia-2-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-2-aws-002` | check_id 'ia-2-2-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-2-azure-001` | check_id 'ia-2-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-2-2-gcp-001` | check_id 'ia-2-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-4-aws-001` | check_id 'ia-4-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-4-azure-001` | check_id 'ia-4-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-4-gcp-001` | check_id 'ia-4-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-4-4-aws-001` | check_id 'ia-4-4-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-4-4-aws-002` | check_id 'ia-4-4-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-4-4-azure-001` | check_id 'ia-4-4-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-4-4-gcp-001` | check_id 'ia-4-4-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-5-aws-001` | check_id 'ia-5-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-5-azure-001` | check_id 'ia-5-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-5-gcp-001` | check_id 'ia-5-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-5-1-aws-001` | check_id 'ia-5-1-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-5-1-azure-001` | check_id 'ia-5-1-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-5-1-gcp-001` | check_id 'ia-5-1-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-5-2-aws-001` | check_id 'ia-5-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-5-2-azure-001` | check_id 'ia-5-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-5-2-gcp-001` | check_id 'ia-5-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-8-aws-001` | check_id 'ia-8-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-8-aws-002` | check_id 'ia-8-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-8-azure-001` | check_id 'ia-8-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ia-8-gcp-001` | check_id 'ia-8-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ia.json) |
| ERROR | `ir-2-aws-001` | check_id 'ir-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ir.json) |
| ERROR | `ir-2-aws-002` | check_id 'ir-2-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ir.json) |
| ERROR | `ir-2-aws-003` | check_id 'ir-2-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in ir.json) |
| ERROR | `ir-2-aws-004` | check_id 'ir-2-aws-004' does not match pattern {domain}-{control}-{provider}-{seq} (in ir.json) |
| ERROR | `ir-2-azure-001` | check_id 'ir-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ir.json) |
| ERROR | `ir-2-azure-002` | check_id 'ir-2-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ir.json) |
| ERROR | `ir-2-azure-003` | check_id 'ir-2-azure-003' does not match pattern {domain}-{control}-{provider}-{seq} (in ir.json) |
| ERROR | `ir-2-gcp-001` | check_id 'ir-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ir.json) |
| ERROR | `ir-2-gcp-002` | check_id 'ir-2-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ir.json) |
| ERROR | `ir-2-gcp-003` | check_id 'ir-2-gcp-003' does not match pattern {domain}-{control}-{provider}-{seq} (in ir.json) |
| ERROR | `ma-2-aws-001` | check_id 'ma-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ma.json) |
| ERROR | `ma-2-aws-002` | check_id 'ma-2-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ma.json) |
| ERROR | `ma-2-aws-003` | check_id 'ma-2-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in ma.json) |
| ERROR | `ma-2-azure-001` | check_id 'ma-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ma.json) |
| ERROR | `ma-2-azure-002` | check_id 'ma-2-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ma.json) |
| ERROR | `ma-2-gcp-001` | check_id 'ma-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ma.json) |
| ERROR | `ma-2-gcp-002` | check_id 'ma-2-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ma.json) |
| ERROR | `ma-4-aws-001` | check_id 'ma-4-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ma.json) |
| ERROR | `ma-4-aws-002` | check_id 'ma-4-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ma.json) |
| ERROR | `ma-4-azure-001` | check_id 'ma-4-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ma.json) |
| ERROR | `ma-4-gcp-001` | check_id 'ma-4-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ma.json) |
| ERROR | `mp-4-aws-001` | check_id 'mp-4-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-4-aws-002` | check_id 'mp-4-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-4-aws-003` | check_id 'mp-4-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-4-azure-001` | check_id 'mp-4-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-4-azure-002` | check_id 'mp-4-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-4-gcp-001` | check_id 'mp-4-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-4-gcp-002` | check_id 'mp-4-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-5-aws-001` | check_id 'mp-5-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-5-aws-002` | check_id 'mp-5-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-5-aws-003` | check_id 'mp-5-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-5-azure-001` | check_id 'mp-5-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-5-azure-002` | check_id 'mp-5-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-5-gcp-001` | check_id 'mp-5-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-5-gcp-002` | check_id 'mp-5-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-4-2-aws-001` | check_id 'mp-4-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-4-2-aws-002` | check_id 'mp-4-2-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-4-2-aws-003` | check_id 'mp-4-2-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-4-2-azure-001` | check_id 'mp-4-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-4-2-azure-002` | check_id 'mp-4-2-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `mp-4-2-gcp-001` | check_id 'mp-4-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in mp.json) |
| ERROR | `pl-2-aws-001` | check_id 'pl-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pl.json) |
| ERROR | `pl-2-azure-001` | check_id 'pl-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pl.json) |
| ERROR | `pl-2-gcp-001` | check_id 'pl-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pl.json) |
| ERROR | `pl-8-aws-001` | check_id 'pl-8-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pl.json) |
| ERROR | `pl-8-aws-002` | check_id 'pl-8-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in pl.json) |
| ERROR | `pl-8-azure-001` | check_id 'pl-8-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pl.json) |
| ERROR | `pl-8-azure-002` | check_id 'pl-8-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in pl.json) |
| ERROR | `pl-8-gcp-001` | check_id 'pl-8-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pl.json) |
| ERROR | `pl-8-gcp-002` | check_id 'pl-8-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in pl.json) |
| ERROR | `pt-2-aws-001` | check_id 'pt-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `pt-2-aws-002` | check_id 'pt-2-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `pt-2-aws-003` | check_id 'pt-2-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `pt-2-azure-001` | check_id 'pt-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `pt-2-azure-002` | check_id 'pt-2-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `pt-2-azure-003` | check_id 'pt-2-azure-003' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `pt-2-gcp-001` | check_id 'pt-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `pt-2-gcp-002` | check_id 'pt-2-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `pt-2-gcp-003` | check_id 'pt-2-gcp-003' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `pt-3-aws-001` | check_id 'pt-3-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `pt-3-azure-001` | check_id 'pt-3-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `pt-3-gcp-001` | check_id 'pt-3-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `pt-4-aws-001` | check_id 'pt-4-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `pt-4-azure-001` | check_id 'pt-4-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `pt-4-gcp-001` | check_id 'pt-4-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in pt.json) |
| ERROR | `ra-5-aws-001` | check_id 'ra-5-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `ra-5-aws-002` | check_id 'ra-5-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `ra-5-aws-003` | check_id 'ra-5-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `ra-5-azure-001` | check_id 'ra-5-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `ra-5-azure-002` | check_id 'ra-5-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `ra-5-azure-003` | check_id 'ra-5-azure-003' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `ra-5-gcp-001` | check_id 'ra-5-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `ra-5-gcp-002` | check_id 'ra-5-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `ra-5-gcp-003` | check_id 'ra-5-gcp-003' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `ra-5-5-aws-001` | check_id 'ra-5-5-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `ra-5-5-aws-002` | check_id 'ra-5-5-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `ra-5-5-azure-001` | check_id 'ra-5-5-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `ra-5-5-azure-002` | check_id 'ra-5-5-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `ra-5-5-gcp-001` | check_id 'ra-5-5-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `ra-5-5-gcp-002` | check_id 'ra-5-5-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in ra.json) |
| ERROR | `sa-3-aws-001` | check_id 'sa-3-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-3-aws-002` | check_id 'sa-3-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-3-azure-001` | check_id 'sa-3-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-3-gcp-001` | check_id 'sa-3-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-4-9-aws-001` | check_id 'sa-4-9-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-4-9-azure-001` | check_id 'sa-4-9-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-4-9-gcp-001` | check_id 'sa-4-9-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-9-2-aws-001` | check_id 'sa-9-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-9-2-azure-001` | check_id 'sa-9-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-9-2-gcp-001` | check_id 'sa-9-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-10-aws-001` | check_id 'sa-10-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-10-aws-002` | check_id 'sa-10-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-10-azure-001` | check_id 'sa-10-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-10-gcp-001` | check_id 'sa-10-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-11-aws-001` | check_id 'sa-11-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-11-azure-001` | check_id 'sa-11-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-11-gcp-001` | check_id 'sa-11-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-11-1-aws-001` | check_id 'sa-11-1-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-11-1-azure-001` | check_id 'sa-11-1-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-11-1-gcp-001` | check_id 'sa-11-1-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-22-aws-001` | check_id 'sa-22-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-22-aws-002` | check_id 'sa-22-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-22-azure-001` | check_id 'sa-22-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sa-22-gcp-001` | check_id 'sa-22-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sa.json) |
| ERROR | `sc-7-aws-001` | check_id 'sc-7-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-aws-002` | check_id 'sc-7-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-aws-003` | check_id 'sc-7-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-aws-004` | check_id 'sc-7-aws-004' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-azure-001` | check_id 'sc-7-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-azure-002` | check_id 'sc-7-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-azure-003` | check_id 'sc-7-azure-003' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-gcp-001` | check_id 'sc-7-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-gcp-002` | check_id 'sc-7-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-gcp-003` | check_id 'sc-7-gcp-003' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-5-aws-001` | check_id 'sc-7-5-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-5-azure-001` | check_id 'sc-7-5-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-5-gcp-001` | check_id 'sc-7-5-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-7-aws-001` | check_id 'sc-7-7-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-7-aws-002` | check_id 'sc-7-7-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-7-aws-001` | check_id 'sc-7-7-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-7-azure-001` | check_id 'sc-7-7-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-7-azure-001` | check_id 'sc-7-7-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-7-gcp-001` | check_id 'sc-7-7-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-7-gcp-001` | check_id 'sc-7-7-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-8-aws-001` | check_id 'sc-7-8-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-8-aws-002` | check_id 'sc-7-8-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-8-azure-001` | check_id 'sc-7-8-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-8-gcp-001` | check_id 'sc-7-8-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-4-aws-001` | check_id 'sc-7-4-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-4-aws-002` | check_id 'sc-7-4-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-4-azure-001` | check_id 'sc-7-4-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-4-gcp-001` | check_id 'sc-7-4-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-21-aws-001` | check_id 'sc-7-21-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-21-aws-002` | check_id 'sc-7-21-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-21-azure-001` | check_id 'sc-7-21-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-21-azure-002` | check_id 'sc-7-21-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-21-gcp-001` | check_id 'sc-7-21-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-7-21-gcp-002` | check_id 'sc-7-21-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-8-aws-001` | check_id 'sc-8-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-8-aws-002` | check_id 'sc-8-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-8-aws-003` | check_id 'sc-8-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-8-azure-001` | check_id 'sc-8-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-8-azure-002` | check_id 'sc-8-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-8-gcp-001` | check_id 'sc-8-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-8-gcp-002` | check_id 'sc-8-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-10-aws-001` | check_id 'sc-10-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-10-aws-002` | check_id 'sc-10-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-10-azure-001` | check_id 'sc-10-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-10-gcp-001` | check_id 'sc-10-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-12-aws-001` | check_id 'sc-12-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-12-aws-002` | check_id 'sc-12-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-12-aws-003` | check_id 'sc-12-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-12-azure-001` | check_id 'sc-12-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-12-azure-002` | check_id 'sc-12-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-12-gcp-001` | check_id 'sc-12-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-12-gcp-002` | check_id 'sc-12-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-13-aws-001` | check_id 'sc-13-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-13-aws-002` | check_id 'sc-13-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-13-azure-001` | check_id 'sc-13-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-13-gcp-001` | check_id 'sc-13-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-18-aws-001` | check_id 'sc-18-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-18-azure-001` | check_id 'sc-18-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-18-gcp-001` | check_id 'sc-18-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-23-aws-001` | check_id 'sc-23-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-23-aws-002` | check_id 'sc-23-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-23-azure-001` | check_id 'sc-23-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-23-gcp-001` | check_id 'sc-23-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-28-1-aws-001` | check_id 'sc-28-1-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-28-1-aws-002` | check_id 'sc-28-1-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-28-1-aws-003` | check_id 'sc-28-1-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-28-1-aws-004` | check_id 'sc-28-1-aws-004' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-28-1-azure-001` | check_id 'sc-28-1-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-28-1-azure-002` | check_id 'sc-28-1-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-28-1-azure-003` | check_id 'sc-28-1-azure-003' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-28-1-gcp-001` | check_id 'sc-28-1-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-28-1-gcp-002` | check_id 'sc-28-1-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `sc-28-1-gcp-003` | check_id 'sc-28-1-gcp-003' does not match pattern {domain}-{control}-{provider}-{seq} (in sc.json) |
| ERROR | `si-2-aws-001` | check_id 'si-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-2-aws-002` | check_id 'si-2-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-2-aws-003` | check_id 'si-2-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-2-aws-004` | check_id 'si-2-aws-004' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-2-azure-001` | check_id 'si-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-2-azure-002` | check_id 'si-2-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-2-azure-003` | check_id 'si-2-azure-003' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-2-gcp-001` | check_id 'si-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-2-gcp-002` | check_id 'si-2-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-2-gcp-003` | check_id 'si-2-gcp-003' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-aws-001` | check_id 'si-3-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-aws-002` | check_id 'si-3-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-aws-003` | check_id 'si-3-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-azure-001` | check_id 'si-3-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-azure-002` | check_id 'si-3-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-gcp-001` | check_id 'si-3-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-gcp-002` | check_id 'si-3-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-5-aws-001` | check_id 'si-5-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-5-aws-002` | check_id 'si-5-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-5-aws-003` | check_id 'si-5-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-5-azure-001` | check_id 'si-5-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-5-azure-002` | check_id 'si-5-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-5-gcp-001` | check_id 'si-5-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-5-gcp-002` | check_id 'si-5-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-1-aws-001` | check_id 'si-3-1-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-1-aws-002` | check_id 'si-3-1-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-1-azure-001` | check_id 'si-3-1-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-1-gcp-001` | check_id 'si-3-1-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-2-aws-001` | check_id 'si-3-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-2-aws-002` | check_id 'si-3-2-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-2-aws-003` | check_id 'si-3-2-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-2-azure-001` | check_id 'si-3-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-2-azure-002` | check_id 'si-3-2-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-2-gcp-001` | check_id 'si-3-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-3-2-gcp-002` | check_id 'si-3-2-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-aws-001` | check_id 'si-4-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-aws-002` | check_id 'si-4-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-aws-003` | check_id 'si-4-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-azure-001` | check_id 'si-4-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-azure-002` | check_id 'si-4-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-azure-003` | check_id 'si-4-azure-003' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-gcp-001` | check_id 'si-4-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-gcp-002` | check_id 'si-4-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-gcp-003` | check_id 'si-4-gcp-003' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-4-aws-001` | check_id 'si-4-4-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-4-aws-002` | check_id 'si-4-4-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-4-aws-003` | check_id 'si-4-4-aws-003' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-4-azure-001` | check_id 'si-4-4-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-4-azure-002` | check_id 'si-4-4-azure-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-4-azure-003` | check_id 'si-4-4-azure-003' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-4-gcp-001` | check_id 'si-4-4-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-4-gcp-002` | check_id 'si-4-4-gcp-002' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `si-4-4-gcp-003` | check_id 'si-4-4-gcp-003' does not match pattern {domain}-{control}-{provider}-{seq} (in si.json) |
| ERROR | `sr-2-aws-001` | check_id 'sr-2-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sr.json) |
| ERROR | `sr-2-aws-002` | check_id 'sr-2-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sr.json) |
| ERROR | `sr-2-azure-001` | check_id 'sr-2-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sr.json) |
| ERROR | `sr-2-gcp-001` | check_id 'sr-2-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sr.json) |
| ERROR | `sr-3-aws-001` | check_id 'sr-3-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sr.json) |
| ERROR | `sr-3-azure-001` | check_id 'sr-3-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sr.json) |
| ERROR | `sr-3-gcp-001` | check_id 'sr-3-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sr.json) |
| ERROR | `sr-11-aws-001` | check_id 'sr-11-aws-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sr.json) |
| ERROR | `sr-11-aws-002` | check_id 'sr-11-aws-002' does not match pattern {domain}-{control}-{provider}-{seq} (in sr.json) |
| ERROR | `sr-11-azure-001` | check_id 'sr-11-azure-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sr.json) |
| ERROR | `sr-11-gcp-001` | check_id 'sr-11-gcp-001' does not match pattern {domain}-{control}-{provider}-{seq} (in sr.json) |

### Control Completeness

| Level | Check ID | Message |
|-------|----------|---------|
| ERROR | `AC-1` | Control AC-1 (AC) not found in any config/checks/*.json file |
| ERROR | `AC-10` | Control AC-10 (AC) not found in any config/checks/*.json file |
| ERROR | `AC-13` | Control AC-13 (AC) not found in any config/checks/*.json file |
| ERROR | `AC-14` | Control AC-14 (AC) not found in any config/checks/*.json file |
| ERROR | `AC-15` | Control AC-15 (AC) not found in any config/checks/*.json file |
| ERROR | `AC-16` | Control AC-16 (AC) not found in any config/checks/*.json file |
| ERROR | `AC-17` | Control AC-17 (AC) not found in any config/checks/*.json file |
| ERROR | `AC-22` | Control AC-22 (AC) not found in any config/checks/*.json file |
| ERROR | `AC-23` | Control AC-23 (AC) not found in any config/checks/*.json file |
| ERROR | `AC-24` | Control AC-24 (AC) not found in any config/checks/*.json file |
| ERROR | `AC-25` | Control AC-25 (AC) not found in any config/checks/*.json file |
| ERROR | `AC-9` | Control AC-9 (AC) not found in any config/checks/*.json file |
| ERROR | `AT-1` | Control AT-1 (AT) not found in any config/checks/*.json file |
| ERROR | `AT-4` | Control AT-4 (AT) not found in any config/checks/*.json file |
| ERROR | `AT-5` | Control AT-5 (AT) not found in any config/checks/*.json file |
| ERROR | `AT-6` | Control AT-6 (AT) not found in any config/checks/*.json file |
| ERROR | `AU-1` | Control AU-1 (AU) not found in any config/checks/*.json file |
| ERROR | `AU-10` | Control AU-10 (AU) not found in any config/checks/*.json file |
| ERROR | `AU-11` | Control AU-11 (AU) not found in any config/checks/*.json file |
| ERROR | `AU-12` | Control AU-12 (AU) not found in any config/checks/*.json file |
| ERROR | `AU-13` | Control AU-13 (AU) not found in any config/checks/*.json file |
| ERROR | `AU-14` | Control AU-14 (AU) not found in any config/checks/*.json file |
| ERROR | `AU-15` | Control AU-15 (AU) not found in any config/checks/*.json file |
| ERROR | `AU-16` | Control AU-16 (AU) not found in any config/checks/*.json file |
| ERROR | `AU-4` | Control AU-4 (AU) not found in any config/checks/*.json file |
| ERROR | `CA-1` | Control CA-1 (CA) not found in any config/checks/*.json file |
| ERROR | `CA-3` | Control CA-3 (CA) not found in any config/checks/*.json file |
| ERROR | `CA-4` | Control CA-4 (CA) not found in any config/checks/*.json file |
| ERROR | `CA-6` | Control CA-6 (CA) not found in any config/checks/*.json file |
| ERROR | `CA-8` | Control CA-8 (CA) not found in any config/checks/*.json file |
| ERROR | `CA-9` | Control CA-9 (CA) not found in any config/checks/*.json file |
| ERROR | `CM-1` | Control CM-1 (CM) not found in any config/checks/*.json file |
| ERROR | `CM-10` | Control CM-10 (CM) not found in any config/checks/*.json file |
| ERROR | `CM-11` | Control CM-11 (CM) not found in any config/checks/*.json file |
| ERROR | `CM-12` | Control CM-12 (CM) not found in any config/checks/*.json file |
| ERROR | `CM-13` | Control CM-13 (CM) not found in any config/checks/*.json file |
| ERROR | `CM-14` | Control CM-14 (CM) not found in any config/checks/*.json file |
| ERROR | `CM-4` | Control CM-4 (CM) not found in any config/checks/*.json file |
| ERROR | `CM-9` | Control CM-9 (CM) not found in any config/checks/*.json file |
| ERROR | `CP-1` | Control CP-1 (CP) not found in any config/checks/*.json file |
| ERROR | `CP-11` | Control CP-11 (CP) not found in any config/checks/*.json file |
| ERROR | `CP-12` | Control CP-12 (CP) not found in any config/checks/*.json file |
| ERROR | `CP-13` | Control CP-13 (CP) not found in any config/checks/*.json file |
| ERROR | `CP-3` | Control CP-3 (CP) not found in any config/checks/*.json file |
| ERROR | `CP-5` | Control CP-5 (CP) not found in any config/checks/*.json file |
| ERROR | `CP-8` | Control CP-8 (CP) not found in any config/checks/*.json file |
| ERROR | `IA-1` | Control IA-1 (IA) not found in any config/checks/*.json file |
| ERROR | `IA-10` | Control IA-10 (IA) not found in any config/checks/*.json file |
| ERROR | `IA-12` | Control IA-12 (IA) not found in any config/checks/*.json file |
| ERROR | `IA-13` | Control IA-13 (IA) not found in any config/checks/*.json file |
| ERROR | `IA-6` | Control IA-6 (IA) not found in any config/checks/*.json file |
| ERROR | `IA-7` | Control IA-7 (IA) not found in any config/checks/*.json file |
| ERROR | `IA-9` | Control IA-9 (IA) not found in any config/checks/*.json file |
| ERROR | `IR-1` | Control IR-1 (IR) not found in any config/checks/*.json file |
| ERROR | `IR-10` | Control IR-10 (IR) not found in any config/checks/*.json file |
| ERROR | `IR-3` | Control IR-3 (IR) not found in any config/checks/*.json file |
| ERROR | `IR-6` | Control IR-6 (IR) not found in any config/checks/*.json file |
| ERROR | `IR-7` | Control IR-7 (IR) not found in any config/checks/*.json file |
| ERROR | `IR-8` | Control IR-8 (IR) not found in any config/checks/*.json file |
| ERROR | `IR-9` | Control IR-9 (IR) not found in any config/checks/*.json file |
| ERROR | `MA-1` | Control MA-1 (MA) not found in any config/checks/*.json file |
| ERROR | `MA-6` | Control MA-6 (MA) not found in any config/checks/*.json file |
| ERROR | `MA-7` | Control MA-7 (MA) not found in any config/checks/*.json file |
| ERROR | `MP-1` | Control MP-1 (MP) not found in any config/checks/*.json file |
| ERROR | `MP-8` | Control MP-8 (MP) not found in any config/checks/*.json file |
| ERROR | `PE-1` | Control PE-1 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-10` | Control PE-10 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-11` | Control PE-11 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-12` | Control PE-12 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-13` | Control PE-13 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-14` | Control PE-14 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-15` | Control PE-15 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-16` | Control PE-16 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-18` | Control PE-18 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-19` | Control PE-19 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-20` | Control PE-20 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-21` | Control PE-21 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-22` | Control PE-22 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-23` | Control PE-23 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-4` | Control PE-4 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-7` | Control PE-7 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-8` | Control PE-8 (PE) not found in any config/checks/*.json file |
| ERROR | `PE-9` | Control PE-9 (PE) not found in any config/checks/*.json file |
| ERROR | `PL-1` | Control PL-1 (PL) not found in any config/checks/*.json file |
| ERROR | `PL-10` | Control PL-10 (PL) not found in any config/checks/*.json file |
| ERROR | `PL-11` | Control PL-11 (PL) not found in any config/checks/*.json file |
| ERROR | `PL-3` | Control PL-3 (PL) not found in any config/checks/*.json file |
| ERROR | `PL-4` | Control PL-4 (PL) not found in any config/checks/*.json file |
| ERROR | `PL-5` | Control PL-5 (PL) not found in any config/checks/*.json file |
| ERROR | `PL-6` | Control PL-6 (PL) not found in any config/checks/*.json file |
| ERROR | `PL-7` | Control PL-7 (PL) not found in any config/checks/*.json file |
| ERROR | `PL-9` | Control PL-9 (PL) not found in any config/checks/*.json file |
| ERROR | `PM-1` | Control PM-1 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-10` | Control PM-10 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-11` | Control PM-11 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-12` | Control PM-12 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-13` | Control PM-13 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-14` | Control PM-14 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-15` | Control PM-15 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-16` | Control PM-16 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-17` | Control PM-17 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-18` | Control PM-18 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-19` | Control PM-19 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-2` | Control PM-2 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-20` | Control PM-20 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-21` | Control PM-21 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-22` | Control PM-22 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-23` | Control PM-23 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-24` | Control PM-24 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-25` | Control PM-25 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-26` | Control PM-26 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-27` | Control PM-27 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-28` | Control PM-28 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-29` | Control PM-29 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-3` | Control PM-3 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-30` | Control PM-30 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-31` | Control PM-31 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-32` | Control PM-32 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-4` | Control PM-4 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-5` | Control PM-5 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-6` | Control PM-6 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-7` | Control PM-7 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-8` | Control PM-8 (PM) not found in any config/checks/*.json file |
| ERROR | `PM-9` | Control PM-9 (PM) not found in any config/checks/*.json file |
| ERROR | `PS-1` | Control PS-1 (PS) not found in any config/checks/*.json file |
| ERROR | `PS-2` | Control PS-2 (PS) not found in any config/checks/*.json file |
| ERROR | `PS-5` | Control PS-5 (PS) not found in any config/checks/*.json file |
| ERROR | `PS-6` | Control PS-6 (PS) not found in any config/checks/*.json file |
| ERROR | `PS-7` | Control PS-7 (PS) not found in any config/checks/*.json file |
| ERROR | `PS-8` | Control PS-8 (PS) not found in any config/checks/*.json file |
| ERROR | `PS-9` | Control PS-9 (PS) not found in any config/checks/*.json file |
| ERROR | `PT-1` | Control PT-1 (PT) not found in any config/checks/*.json file |
| ERROR | `PT-5` | Control PT-5 (PT) not found in any config/checks/*.json file |
| ERROR | `PT-6` | Control PT-6 (PT) not found in any config/checks/*.json file |
| ERROR | `PT-7` | Control PT-7 (PT) not found in any config/checks/*.json file |
| ERROR | `PT-8` | Control PT-8 (PT) not found in any config/checks/*.json file |
| ERROR | `RA-1` | Control RA-1 (RA) not found in any config/checks/*.json file |
| ERROR | `RA-10` | Control RA-10 (RA) not found in any config/checks/*.json file |
| ERROR | `RA-2` | Control RA-2 (RA) not found in any config/checks/*.json file |
| ERROR | `RA-4` | Control RA-4 (RA) not found in any config/checks/*.json file |
| ERROR | `RA-6` | Control RA-6 (RA) not found in any config/checks/*.json file |
| ERROR | `RA-7` | Control RA-7 (RA) not found in any config/checks/*.json file |
| ERROR | `RA-8` | Control RA-8 (RA) not found in any config/checks/*.json file |
| ERROR | `RA-9` | Control RA-9 (RA) not found in any config/checks/*.json file |
| ERROR | `SA-1` | Control SA-1 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-12` | Control SA-12 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-13` | Control SA-13 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-14` | Control SA-14 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-15` | Control SA-15 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-16` | Control SA-16 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-17` | Control SA-17 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-18` | Control SA-18 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-19` | Control SA-19 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-2` | Control SA-2 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-20` | Control SA-20 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-21` | Control SA-21 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-23` | Control SA-23 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-24` | Control SA-24 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-4` | Control SA-4 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-5` | Control SA-5 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-6` | Control SA-6 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-7` | Control SA-7 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-8` | Control SA-8 (SA) not found in any config/checks/*.json file |
| ERROR | `SA-9` | Control SA-9 (SA) not found in any config/checks/*.json file |
| ERROR | `SC-1` | Control SC-1 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-11` | Control SC-11 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-14` | Control SC-14 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-16` | Control SC-16 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-17` | Control SC-17 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-19` | Control SC-19 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-2` | Control SC-2 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-20` | Control SC-20 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-21` | Control SC-21 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-22` | Control SC-22 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-24` | Control SC-24 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-25` | Control SC-25 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-26` | Control SC-26 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-27` | Control SC-27 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-29` | Control SC-29 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-3` | Control SC-3 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-30` | Control SC-30 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-31` | Control SC-31 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-32` | Control SC-32 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-33` | Control SC-33 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-34` | Control SC-34 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-35` | Control SC-35 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-36` | Control SC-36 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-37` | Control SC-37 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-38` | Control SC-38 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-39` | Control SC-39 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-4` | Control SC-4 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-40` | Control SC-40 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-41` | Control SC-41 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-42` | Control SC-42 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-43` | Control SC-43 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-44` | Control SC-44 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-45` | Control SC-45 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-46` | Control SC-46 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-47` | Control SC-47 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-48` | Control SC-48 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-49` | Control SC-49 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-5` | Control SC-5 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-50` | Control SC-50 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-51` | Control SC-51 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-6` | Control SC-6 (SC) not found in any config/checks/*.json file |
| ERROR | `SC-9` | Control SC-9 (SC) not found in any config/checks/*.json file |
| ERROR | `SI-1` | Control SI-1 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-10` | Control SI-10 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-11` | Control SI-11 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-12` | Control SI-12 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-13` | Control SI-13 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-14` | Control SI-14 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-15` | Control SI-15 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-16` | Control SI-16 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-17` | Control SI-17 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-18` | Control SI-18 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-19` | Control SI-19 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-20` | Control SI-20 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-21` | Control SI-21 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-22` | Control SI-22 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-23` | Control SI-23 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-6` | Control SI-6 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-7` | Control SI-7 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-8` | Control SI-8 (SI) not found in any config/checks/*.json file |
| ERROR | `SI-9` | Control SI-9 (SI) not found in any config/checks/*.json file |
| ERROR | `SR-1` | Control SR-1 (SR) not found in any config/checks/*.json file |
| ERROR | `SR-10` | Control SR-10 (SR) not found in any config/checks/*.json file |
| ERROR | `SR-12` | Control SR-12 (SR) not found in any config/checks/*.json file |
| ERROR | `SR-4` | Control SR-4 (SR) not found in any config/checks/*.json file |
| ERROR | `SR-5` | Control SR-5 (SR) not found in any config/checks/*.json file |
| ERROR | `SR-6` | Control SR-6 (SR) not found in any config/checks/*.json file |
| ERROR | `SR-7` | Control SR-7 (SR) not found in any config/checks/*.json file |
| ERROR | `SR-8` | Control SR-8 (SR) not found in any config/checks/*.json file |
| ERROR | `SR-9` | Control SR-9 (SR) not found in any config/checks/*.json file |

### API Call Match

| Level | Check ID | Message |
|-------|----------|---------|
| ERROR | `cm-7-5-azure-001` | API mismatch: config says 'security.adaptive_application_controls.list' but code uses: ['helper:_get_security_client'] |
| ERROR | `cp-2-aws-001` | API mismatch: config says 'resourcegroupstaggingapi.get_resources' but code uses: ['ec2.describe_instances', 'rds.describe_db_instances', 'rds.list_tags_for_resource'] |
| ERROR | `cp-2-gcp-001` | API mismatch: config says 'cloudresourcemanager.projects.list' but code uses: [] |
| ERROR | `cp-4-azure-001` | API mismatch: config says 'RecoveryServicesClient.replication_protected_items.list' but code uses: ['backup_jobs.list'] |
| ERROR | `cp-6-azure-002` | API mismatch: config says 'SqlManagementClient.databases.list' but code uses: ['helper:_get_sql_client'] |
| ERROR | `cp-7-aws-001` | API mismatch: config says 'elbv2.describe_load_balancers' but code uses: ['ec2.describe_regions', 'client.describe_instances'] |
| ERROR | `cp-7-azure-001` | API mismatch: config says 'NetworkManagementClient.load_balancers.list_all' but code uses: ['virtual_machines.list_all'] |
| ERROR | `cp-9-azure-002` | API mismatch: config says 'SqlManagementClient.databases.list' but code uses: ['helper:_get_sql_client'] |
| ERROR | `cp-9-1-gcp-001` | API mismatch: config says 'logging.entries.list' but code uses: [] |
| ERROR | `cp-9-8-azure-001` | API mismatch: config says 'RecoveryServicesClient.vaults.list_by_subscription_id' but code uses: ['helper:_get_recovery_client'] |
| ERROR | `cp-10-aws-001` | API mismatch: config says 'ssm.list_documents' but code uses: ['ec2.describe_instances', 'rds.describe_db_instances', 'rds.list_tags_for_resource'] |
| ERROR | `cp-10-gcp-001` | API mismatch: config says 'logging.entries.list' but code uses: [] |
| ERROR | `pl-2-azure-001` | API mismatch: config says 'BlueprintManagementClient.blueprints.list' but code uses: [] |
| ERROR | `pl-2-gcp-001` | API mismatch: config says 'orgpolicy.organizations.policies.list' but code uses: [] |
| ERROR | `pl-8-aws-001` | API mismatch: config says 'resourcegroupstaggingapi.get_resources' but code uses: ['ec2.describe_instances', 'rds.describe_db_instances', 'rds.list_tags_for_resource'] |
| ERROR | `pl-8-gcp-001` | API mismatch: config says 'cloudresourcemanager.projects.list' but code uses: [] |
| ERROR | `pt-2-azure-001` | API mismatch: config says 'PurviewManagementClient.accounts.list_by_subscription' but code uses: ['resources.list'] |
| ERROR | `pt-2-azure-003` | API mismatch: config says 'SqlManagementClient.databases.list' but code uses: ['helper:_get_sql_client'] |
| ERROR | `pt-3-aws-001` | API mismatch: config says 'resourcegroupstaggingapi.get_resources' but code uses: ['ec2.describe_instances', 'rds.describe_db_instances', 'rds.list_tags_for_resource'] |
| ERROR | `pt-3-gcp-001` | API mismatch: config says 'cloudresourcemanager.projects.list' but code uses: [] |
| ERROR | `pt-4-azure-001` | API mismatch: config says 'ApiManagementClient.api.list_by_service' but code uses: ['resources.list'] |
| ERROR | `pt-4-gcp-001` | API mismatch: config says 'apigateway.projects.locations.apis.list' but code uses: [] |
| ERROR | `sa-3-azure-001` | API mismatch: config says 'azure_devops.pipelines.list' but code uses: ['resources.list'] |
| ERROR | `sa-9-2-azure-001` | API mismatch: config says 'ApiManagementClient.api_management_service.list' but code uses: ['resources.list'] |
| ERROR | `sa-10-azure-001` | API mismatch: config says 'azure_devops.git.get_repositories' but code uses: [] |
| ERROR | `sa-11-azure-001` | API mismatch: config says 'azure_devops.pipelines.list' but code uses: [] |
| ERROR | `sa-11-1-azure-001` | API mismatch: config says 'azure_devops.extensions.list_installed' but code uses: [] |
| ERROR | `sr-2-aws-001` | API mismatch: config says 'ecr.describe_image_scan_findings' but code uses: ['ecr.describe_repositories', 'ecr.get_registry_scanning_configuration'] |
| ERROR | `sr-2-azure-001` | API mismatch: config says 'ContainerRegistryManagementClient.registries.list' but code uses: ['resources.list'] |
| ERROR | `sr-3-azure-001` | API mismatch: config says 'azure_devops.pipelines.list' but code uses: [] |
| ERROR | `sr-11-aws-001` | API mismatch: config says 'signer.list_signing_jobs' but code uses: ['ecr.get_registry_policy', 'ecr.describe_repositories'] |
| ERROR | `sr-11-aws-002` | API mismatch: config says 'lambda.list_code_signing_configs' but code uses: ['lambda_client.list_functions', 'client.list_functions'] |
| ERROR | `sr-11-azure-001` | API mismatch: config says 'ContainerRegistryManagementClient.registries.list' but code uses: ['resources.list'] |

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
| AC-12 | AC | 2 | 1 | 1 |
| AC-6 | AC | 3 | 2 | 2 |
| AC-7 | AC | 2 | 1 | 1 |
| AU-5 | AU | 2 | 1 | 1 |
| AU-6 | AU | 2 | 1 | 1 |
| AU-9 | AU | 3 | 2 | 2 |
| IA-5 | IA | 1 | 1 | 1 |
| SI-3 | SI | 3 | 2 | 2 |

## Objective Coverage Gaps

Automatable objectives not covered by any check or documentation requirement.

| Control | Domain | Objective | Text |
|----------|--------|-----------|------|
| — | — | — | No gaps found |

**Total objective gaps:** 0

---
*Report generated by `scripts/qa_traceability.py` on 2026-03-10 22:37 UTC*
