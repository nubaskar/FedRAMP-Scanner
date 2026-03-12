# FedRAMP Cloud Compliance Scanner — Assessment Methodology

**Document Classification:** For Official Use — Assessment Staff Only

**Version:** 1.0 | **Date:** March 12, 2026 | **Author:** Securitybricks (3PAO, powered by Aprio)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Purpose and Audience](#2-purpose-and-audience)
3. [Authoritative Sources and Traceability](#3-authoritative-sources-and-traceability)
4. [Assessment Architecture](#4-assessment-architecture)
   - 4.1 [Check-to-Objective Mapping](#41-check-to-objective-mapping)
   - 4.2 [Three-Tier Evaluation Model](#42-three-tier-evaluation-model)
   - 4.3 [Cloud Provider API Baselines](#43-cloud-provider-api-baselines)
   - 4.4 [Why Only 93 of 324 Controls Are Automated](#44-why-only-93-of-324-controls-are-automated)
5. [Coverage Matrix Summary](#5-coverage-matrix-summary)
   - 5.1 [Overall Statistics](#51-overall-statistics)
   - 5.2 [Domain-Level Coverage](#52-domain-level-coverage)
   - 5.3 [Objective Automatable Classification](#53-objective-automatable-classification)
6. [Complete Control Reference](#6-complete-control-reference)
   - 6.1 [AC — Access Control](#ac--access-control)
   - 6.2 [AT — Awareness and Training](#at--awareness-and-training)
   - 6.3 [AU — Audit and Accountability](#au--audit-and-accountability)
   - 6.4 [CA — Assessment, Authorization, and Monitoring](#ca--assessment,-authorization,-and-monitoring)
   - 6.5 [CM — Configuration Management](#cm--configuration-management)
   - 6.6 [CP — Contingency Planning](#cp--contingency-planning)
   - 6.7 [IA — Identification and Authentication](#ia--identification-and-authentication)
   - 6.8 [IR — Incident Response](#ir--incident-response)
   - 6.9 [MA — Maintenance](#ma--maintenance)
   - 6.10 [MP — Media Protection](#mp--media-protection)
   - 6.11 [PE — Physical and Environmental Protection](#pe--physical-and-environmental-protection)
   - 6.12 [PL — Planning](#pl--planning)
   - 6.13 [PM — Program Management](#pm--program-management)
   - 6.14 [PS — Personnel Security](#ps--personnel-security)
   - 6.15 [PT — Personally Identifiable Information Processing and Transparency](#pt--personally-identifiable-information-processing-and-transparency)
   - 6.16 [RA — Risk Assessment](#ra--risk-assessment)
   - 6.17 [SA — System and Services Acquisition](#sa--system-and-services-acquisition)
   - 6.18 [SC — System and Communications Protection](#sc--system-and-communications-protection)
   - 6.19 [SI — System and Information Integrity](#si--system-and-information-integrity)
   - 6.20 [SR — Supply Chain Risk Management](#sr--supply-chain-risk-management)
7. [3PAO Manual Assessment Guide](#7-cca-manual-assessment-guide)
   - 7.1 [How to Use This Guide](#71-how-to-use-this-guide)
   - 7.2 [Manual Control Reference](#72-manual-control-reference)
8. [Appendix A — API Call Reference](#8-appendix-a--api-call-reference)
9. [Appendix B — Glossary](#9-appendix-b--glossary)

---

## 1. Executive Summary

The FedRAMP Cloud Compliance Scanner is an automated assessment tool built by Securitybricks, a FedRAMP Third-Party Assessment Organization (3PAO) powered by Aprio. It evaluates Defense Industrial Base (DIB) contractor cloud environments against FedRAMP requirements by querying cloud service provider (CSP) APIs and comparing configuration states to NIST SP 800-53 Rev 5 security controls.

This document serves as the **authoritative methodology reference** for FedRAMP Assessors (3PAOs) using the scanner. It explains:

- **How** each of the 324 NIST 800-53 Rev 5 controls is evaluated
- **Which** cloud APIs are queried and what constitutes a passing or failing check
- **Why** each check maps to specific NIST SP 800-53A assessment objectives
- **What** 3PAOs must do for the 231 controls that require manual assessment
- **Where** the authoritative sources and traceability chain originates

The scanner implements **496 cloud-specific technical checks** across AWS (203), Azure (147), and GCP (146), mapped to **254 NIST SP 800-53A assessment objectives** across all 324 controls and 20 FedRAMP control families.

---

## 2. Purpose and Audience

### Who Should Read This Document

| Role | How to Use This Document |
|------|------------------------|
| **Lead 3PAO** | Validate the scanner's methodology against 800-53A before accepting automated results |
| **3PAO (Technical)** | Reference during assessment to understand what each check evaluates and which API responses constitute evidence |
| **3PAO (Policy/Process)** | Use Section 7 as a structured guide for manual control assessments — interview questions, evidence artifacts, and determination criteria |
| **Assessment Team Lead** | Review coverage matrix to understand which objectives are automated vs. manual |
| **Quality Assurance** | Verify traceability from check results back to 800-53A objectives |

### How This Document Builds Trust

For a 3PAO to rely on automated tool results in a FedRAMP assessment, they need to verify:

1. **Traceability** — Every automated check traces back to a specific NIST SP 800-53A assessment objective
2. **Completeness** — The tool identifies which objectives it covers and which require manual assessment
3. **Accuracy** — Checks query the correct cloud APIs and evaluate the right configuration properties
4. **Transparency** — The methodology is fully documented, not a black box

This document satisfies all four requirements.

---

## 3. Authoritative Sources and Traceability

The scanner's check library is derived from and traceable to the following authoritative sources:

| Source | Version | Purpose | Reference |
|--------|---------|---------|-----------|
| **NIST SP 800-53 Rev 5** | Sep 2020 | 324 security controls across 20 families | [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) |
| **NIST SP 800-53A Rev 5** | Jan 2022 | 254 assessment objectives ("determine if" statements) | [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-53a/rev-5/final) |
| **NIST SP 800-172** | Feb 2021 | Enhanced security controls for Level 3 | [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-172/final) |
| **FAR 52.204-21** | 2016 | 17 basic safeguarding controls for Level 1 | [acquisition.gov](https://www.acquisition.gov/far/52.204-21) |
| **FedRAMP Model** | Dec 2021 | Three-level certification model | [dodcio.defense.gov](https://dodcio.defense.gov/FedRAMP/) |
| **AWS Config Rules** | Current | ~200 rules mapped to NIST 800-53 Rev 5 | [docs.aws.amazon.com](https://docs.aws.amazon.com/config/latest/developerguide/operational-best-controls-for-nist_800-53 Rev 5.html) |
| **Azure Policy** | Current | ~200 policy definitions for NIST 800-53 Rev 5 R2 | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/governance/policy/samples/nist-sp-800-53 Rev 5-r2) |
| **GCP CIS Benchmark** | Current | GCP security controls aligned to NIST controls | [cloud.google.com](https://cloud.google.com/security/compliance/cis-benchmarks) |

### Traceability Chain

Every check in the scanner traces back through the following chain:

| Step | Stage | Description |
|------|-------|-------------|
| 1 | **FedRAMP Level** | L1 / L2 / L3 certification tier |
| 2 | **NIST SP 800-53 Rev 5 Control** | One of 324 security requirements |
| 3 | **800-53A Assessment Objective** | Specific "determine if" statement |
| 4 | **Scanner Check** | Cloud-specific configuration test |
| 5 | **Cloud API Call** | Read-only query to AWS, Azure, or GCP |
| 6 | **Compliance Determination** | Met / Not Met / Manual Review |

Every finding in the scanner report traces back through this chain to the authoritative NIST standard.

---

## 4. Assessment Architecture

### 4.1 Check-to-Objective Mapping

NIST SP 800-53A defines **254 assessment objectives** across the 324 NIST SP 800-53 Rev 5 controls. Each objective is a discrete "determine if" statement that an assessor must evaluate.

The scanner maps every automated check to the specific 800-53A objectives it supports via the `supports_objectives` field. For example:

```json
{
  "check_id": "ac-3.1.1-aws-001",
  "name": "Root account access keys disabled",
  "supports_objectives": ["[d]"],
  "service": "IAM",
  "api_call": "iam.get_account_summary",
  "severity": "critical"
}

```

**Objective [d]** for control 3.1.1 states: *"system access is limited to authorized users."* Disabling root account access keys directly enforces this by preventing the most privileged account from using long-term credentials.

This mapping enables:
- **Per-objective coverage scoring** — the report shows which objectives are covered by automated checks, which require documentation, and which are not tested
- **Gap identification** — 3PAOs can immediately see which objectives need manual verification
- **Audit traceability** — every Met/Not Met determination links to specific 800-53A language

### 4.2 Three-Tier Evaluation Model

The scanner classifies every 800-53A assessment objective into one of three tiers:

| Tier | Classification | Count | Description |
|------|---------------|-------|-------------|
| **Tier 1** | Fully Automatable | 180 | Cloud API configuration check provides a definitive Met/Not Met determination |
| **Tier 2** | Partially Automatable | 0 | Cloud API provides supporting evidence, but 3PAO must verify organizational context |
| **Tier 3** | Not Automatable | 74 | Requires documentation review, interviews, or physical inspection |

**Tier 1 — Fully Automatable:** The API response alone determines compliance. Example: *"MFA is enabled for all console users"* — the credential report provides a binary yes/no.

**Tier 2 — Partially Automatable:** The API response provides evidence that supports a determination, but the 3PAO must also verify organizational context. Example: *"Authorized users are identified"* — IAM user lists show WHO has access, but the 3PAO must verify this matches the organization's authorized user roster.

**Tier 3 — Not Automatable:** No cloud API can evaluate this objective. Example: *"Visitors are escorted"* (physical security) or *"Security awareness training is provided"* (organizational process).

### 4.3 Cloud Provider API Baselines

The scanner uses read-only API calls across three cloud service providers. All access is via read-only IAM roles — **no configuration changes are ever made** to the client's environment.

| Provider | Access Method | Permissions Required | Checks |
|----------|--------------|---------------------|--------|
| **AWS** | STS AssumeRole (cross-account) | `SecurityAudit` + `ViewOnlyAccess` managed policies | 203 |
| **Azure** | Service Principal (ClientSecretCredential) | `Reader` + `Security Reader` roles + Microsoft Graph API | 147 |
| **GCP** | Service Account (JSON key) | `Viewer` + `Security Reviewer` + `Security Center Admin` roles | 146 |

**Key AWS Services Queried:** IAM, STS, EC2, VPC, S3, CloudTrail, CloudWatch, Config, GuardDuty, Security Hub, KMS, SSM, Inspector, WAFv2, ELB, CloudFront, RDS, Organizations, ACM, Route 53, Network Firewall, DynamoDB, API Gateway, CodePipeline, Athena, SNS, ECR, Health

**Key Azure Services Queried:** Entra ID (Graph API), Network, Compute, Storage, Key Vault, Security Center, Monitor, Policy, Authorization, SQL, App Service, Sentinel, Advisor, Automation, Resource Graph, Guest Configuration

**Key GCP Services Queried:** IAM, Cloud Resource Manager, Compute, VPC, Storage, Cloud KMS, Cloud Logging, Cloud Monitoring, Security Command Center, OS Config, Binary Authorization, Container Analysis, Web Security Scanner, Cloud SQL, BigQuery, Cloud DNS, Recommender, Cloud IDS, Cloud Armor, BeyondCorp, Organization Policy

### 4.4 Why Only 93 of 324 Controls Are Automated

NIST SP 800-53 Rev 5 defines 324 security controls, but only 93 (28%) can be meaningfully evaluated through cloud API queries. This is not a gap in scanner coverage — it reflects the fundamental nature of the controls themselves. The remaining 231 controls govern activities that occur outside of cloud infrastructure and cannot be observed through any API.

**Controls That Cannot Be Automated:**

| Category | Families | Controls | Why Not Automatable |
|----------|----------|----------|---------------------|
| Physical & Environmental | PE (23 controls) | 23 | Facility access, environmental protections, fire suppression — no API can verify a locked door |
| Organizational Governance | PM (32 controls) | 32 | Risk strategy, authorization processes, insider threat programs — organizational policies, not cloud configs |
| Personnel Security | PS (9 controls) | 9 | Background checks, screening, access agreements, termination — HR processes requiring human verification |
| Awareness & Training | AT (6 controls) | 6 | Security training programs, role-based training — requires review of materials and completion records |
| **Subtotal** | **4 families (0% automation)** | **70** | **21% of the framework** |

**Policy & Procedure Objectives Within Automated Families:**

Even in families with automated checks, many controls ask: *"Does the organization define and document a policy/procedure for X?"* These Tier 3 objectives require a 3PAO to review written policies and standard operating procedures — artifacts that exist as documents, not as cloud API states. This is why families like Access Control (AC) show only 13/25 automation: the automated controls check *configuration states* (MFA, least-privilege roles, session timeouts), while the manual controls verify that policies, procedures, and approval workflows exist and are followed.

**What *Can* Be Automated:**

The 93 automated controls share a common trait: their compliance state is observable through cloud provider APIs as a **configuration property** that is either present or absent. Examples:

- **AC-6(3):** *Is privileged access restricted to specific accounts?* → Check IAM policies for least-privilege roles (API-verifiable)
- **AU-6:** *Are audit records reviewed and analyzed?* → Check CloudTrail/Activity Log enabled and forwarded (API-verifiable)
- **SC-8:** *Is transmitted information protected?* → Check TLS/SSL configuration on load balancers (API-verifiable)
- **PE-3:** *Is physical access controlled?* → Requires on-site inspection of badge readers and guard stations (not API-verifiable)

> **Bottom line:** The 93/324 automation ratio is inherent to the NIST 800-53 framework, which intentionally covers physical, procedural, and organizational security alongside technical controls. A scanner claiming 100% automation of 800-53 would be misrepresenting what the framework requires.

---

## 5. Coverage Matrix Summary

### 5.1 Overall Statistics

| Metric | Value |
|--------|-------|
| NIST 800-53 Rev 5 Controls | 324 |
| NIST 800-53A Assessment Objectives | 254 |
| Controls with Automated Checks | 93 (28%) |
| Controls Requiring Manual Assessment | 231 (71%) |
| Total Cloud-Specific Technical Checks | 496 |
| AWS Checks | 203 |
| Azure Checks | 147 |
| GCP Checks | 146 |
| Documentation Evidence Requirements | 104 |

### 5.2 Domain-Level Coverage

The table below shows the scanner's coverage across all 20 FedRAMP control families. Each domain is broken down by the number of NIST 800-53 Rev 5 controls, how many are automated vs. manual, the total 800-53A assessment objectives, and the cloud-specific checks implemented for each provider. The **Automation Rate** shows the percentage of controls in each domain that are fully automated by the scanner.

| Domain | Name | Controls | Automated | Manual | Objectives | AWS | Azure | GCP | Automation Rate |
|--------|------|-----------|-----------|--------|------------|-----|-------|-----|-----------------|
| AC | Access Control | 25 | 14 | 11 | 44 | 35 | 25 | 26 | 56% |
| AT | Awareness and Training | 6 | 2 | 4 | 7 | 0 | 0 | 0 | 33% |
| AU | Audit and Accountability | 16 | 7 | 9 | 24 | 18 | 11 | 11 | 44% |
| CA | Assessment, Authorization, and Monitoring | 9 | 3 | 6 | 10 | 3 | 2 | 2 | 33% |
| CM | Configuration Management | 14 | 6 | 8 | 25 | 15 | 10 | 10 | 43% |
| CP | Contingency Planning | 13 | 6 | 7 | 13 | 16 | 14 | 14 | 46% |
| IA | Identification and Authentication | 13 | 6 | 7 | 15 | 18 | 13 | 12 | 46% |
| IR | Incident Response | 10 | 3 | 7 | 14 | 4 | 3 | 3 | 30% |
| MA | Maintenance | 7 | 4 | 3 | 8 | 5 | 3 | 3 | 57% |
| MP | Media Protection | 8 | 6 | 2 | 11 | 9 | 6 | 5 | 75% |
| PE | Physical and Environmental Protection | 23 | 5 | 18 | 13 | 0 | 0 | 0 | 22% |
| PL | Planning | 11 | 2 | 9 | 2 | 3 | 3 | 3 | 18% |
| PM | Program Management | 32 | 0 | 32 | 0 | 0 | 0 | 0 | 0% |
| PS | Personnel Security | 9 | 2 | 7 | 4 | 0 | 0 | 0 | 22% |
| PT | Personally Identifiable Information Processing and Transparency | 8 | 3 | 5 | 4 | 5 | 5 | 5 | 38% |
| RA | Risk Assessment | 10 | 2 | 8 | 7 | 5 | 5 | 5 | 20% |
| SA | System and Services Acquisition | 24 | 6 | 18 | 9 | 10 | 7 | 7 | 25% |
| SC | System and Communications Protection | 51 | 9 | 42 | 25 | 31 | 21 | 21 | 18% |
| SI | System and Information Integrity | 23 | 4 | 19 | 14 | 21 | 16 | 16 | 17% |
| SR | Supply Chain Risk Management | 12 | 3 | 9 | 5 | 5 | 3 | 3 | 25% |
| **Total** | | **324** | **93** | **231** | **254** | **203** | **147** | **146** | **29%** |

### 5.3 Objective Automatable Classification

| Classification | Count | Percentage | Scanner Handling |
|---------------|-------|------------|-----------------|
| Fully Automatable | 180 | 70% | Automated check provides Met/Not Met determination |
| Partially Automatable | 0 | 0% | Automated check provides evidence; 3PAO verifies context |
| Not Automatable | 74 | 29% | Flagged as Documentation Required; 3PAO assesses manually |

---

## 6. Complete Control Reference

This section provides the complete technical reference for every NIST SP 800-53 Rev 5 control, organized by FedRAMP family. For each control, it shows:

- The requirement text and FedRAMP baseline
- All NIST SP 800-53A assessment objectives
- Cloud-specific automated checks with API calls, services, and severity
- Objective mapping (which checks support which objectives)
- Documentation requirements for non-automatable objectives

### AC — Access Control

**Controls:** 25 | **Automated:** 14 | **Manual:** 11 | **Objectives:** 44 | **Checks:** AWS 35, Azure 25, GCP 26

#### AC-1 — Develop, document, and disseminate to {{ insert: param, ac-1_prm_1 }}: {{ insert: param, ac-01_odp.03 }} access control policy that: Addresses purpose, scope, roles, responsibilities, management commi

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### AC-2 — Define and document the types of accounts allowed and specifically prohibited for use within the system; Assign account managers; Require {{ insert: param, ac-02_odp.01 }} for group and role membershi

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 6

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-2[a] | Define and document the types of accounts allowed and specifically prohibited for use within the system | Yes |
| AC-2[b] | Assign account managers | Yes |
| AC-2[c] | Require {{ insert: param, ac-02_odp.01 }} for group and role membership | Yes |
| AC-2[d] | Specify: Authorized users of the system | Yes |
| AC-2[e] | Group and role membership | Yes |
| AC-2[f] | Access authorizations (i.e., privileges) and {{ insert: param, ac-02_odp.02 }} for each account | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-2-aws-001` | AWS | Root account access keys disabled | IAM | `iam.get_account_summary` | critical | [d] |
| `ac-2-aws-002` | AWS | IAM users have active credentials reviewed | IAM | `iam.generate_credential_report` | high | [a], [d] |
| `ac-2-aws-003` | AWS | IAM password policy enforced | IAM | `iam.get_account_password_policy` | high | [a], [d] |
| `ac-2-azure-001` | AZURE | Conditional Access policies configured | Authorization | `AuthorizationManagementClient.role_assignments.list_for_scope` | high | [a], [d], [f] |
| `ac-2-azure-002` | AZURE | Guest user access restricted | Azure AD | `graph.authorization_policy.get` | medium | [a], [d] |
| `ac-2-azure-003` | AZURE | Security defaults or Conditional Access enabled | Azure AD | `graph.identity_security_defaults_enforcement_policy.get` | high | [a], [d], [f] |
| `ac-2-gcp-001` | GCP | Organization-level IAM bindings reviewed | IAM | `cloudresourcemanager.projects.getIamPolicy` | critical | [a], [c] |
| `ac-2-gcp-002` | GCP | Service account keys rotated | IAM | `iam.projects.serviceAccounts.keys.list` | high | [b], [e] |
| `ac-2-gcp-003` | GCP | Default service account not used | IAM | `compute.instances.list` | high | [b], [e] |


#### AC-2(9) (Enhancement) — Only permit the use of shared and group accounts that meet {{ insert: param, ac-02.09_odp }}. Before permitting the use of shared or group accounts, organizations consider the increased risk due to th

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-2(9)[a] | Only permit the use of shared and group accounts that meet {{ insert: param, ac-02.09_odp }}. Before permitting the use  | Yes |
| AC-2(9)[b] | Only permit the use of shared and group accounts that meet {{ insert: param, ac-02.09_odp }}. Before permitting the use  | Yes |
| AC-2(9)[c] | Only permit the use of shared and group accounts that meet {{ insert: param, ac-02.09_odp }}. Before permitting the use  | Yes |
| AC-2(9)[d] | Only permit the use of shared and group accounts that meet {{ insert: param, ac-02.09_odp }}. Before permitting the use  | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-2-9-aws-001` | AWS | CloudTrail logging enabled for all management events | CloudTrail | `cloudtrail.describe_trails` | critical | [a], [c], [d] |
| `ac-2-9-aws-002` | AWS | SCP prevents disabling CloudTrail | Organizations | `organizations.list_policies` | high | [b], [c], [d] |
| `ac-2-9-azure-001` | AZURE | Activity Log alerts for privilege escalation | Monitor | `monitor.activity_log_alerts.list` | high | [a], [b], [c], [d] |
| `ac-2-9-gcp-001` | GCP | Admin Activity audit logs enabled | Logging | `logging.projects.logs.list` | high | [c], [d] |
| `ac-2-9-gcp-002` | GCP | Log-based metrics and alerts for IAM changes | Monitoring | `monitoring.projects.alertPolicies.list` | high | [b], [c], [d] |


#### AC-3 — Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies. Access control policies control access between active enti

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-3[a] | Enforce approved authorizations for logical access to information and system resources in accordance with applicable acc | Yes |
| AC-3[b] | Enforce approved authorizations for logical access to information and system resources in accordance with applicable acc | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3-aws-001` | AWS | IAM policies follow least privilege | IAM | `iam.list_policies` | high | [b] |
| `ac-3-aws-002` | AWS | IAM permission boundaries configured for delegated admin | IAM | `iam.list_users` | medium | [a], [b] |
| `ac-3-azure-001` | AZURE | Custom RBAC roles use least privilege | Authorization | `authorization.role_definitions.list` | high | [a], [b] |
| `ac-3-azure-002` | AZURE | PIM enabled for privileged roles | Azure AD | `graph/roleManagement/directory/roleAssignmentScheduleInstances` | high | [a], [b] |
| `ac-3-gcp-001` | GCP | Custom IAM roles scoped appropriately | IAM | `iam.projects.roles.list` | high | [a], [b] |
| `ac-3-gcp-002` | GCP | Primitive roles not assigned to users | IAM | `cloudresourcemanager.projects.getIamPolicy` | high | [a], [b] |


#### AC-3(8) (Enhancement) — Enforce the revocation of access authorizations resulting from changes to the security attributes of subjects and objects based on {{ insert: param, ac-03.08_odp }}. Revocation of access rules may dif

**Baseline:** N/A | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-3(8)[a] | Enforce the revocation of access authorizations resulting from changes to the security attributes of subjects and object | No |
| AC-3(8)[b] | revocation of access authorizations is enforced resulting from changes to the security attributes of objects based on {{ | No |
| AC-3(8)[c] | revocation of access authorizations is enforced resulting from changes to the security attributes of objects based on {{ | No |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3-8-aws-001` | AWS | S3 Block Public Access enabled at account level | S3 | `s3control.get_public_access_block` | high |  |
| `ac-3-8-azure-001` | AZURE | Storage accounts block public blob access | Storage | `storage.storage_accounts.list` | high |  |
| `ac-3-8-gcp-001` | GCP | Uniform bucket-level access org policy enforced | OrgPolicy | `orgpolicy.projects.policies.get` | high |  |

**Documentation Requirements:**

- **AC-3(8)[a]**: use of organizational portable storage devices containing CUI on external systems is identified and documented. — *Provide documentation showing that use of organizational portable storage devices containing cui on external systems are identified and documented.*
- **AC-3(8)[b]**: limits on the use of organizational portable storage devices containing CUI on external systems are defined. — *Provide documentation showing that limits on the use of organizational portable storage devices containing cui on external systems are defined.*
- **AC-3(8)[c]**: use of organizational portable storage devices containing CUI on external systems is limited as defined. — *Provide documentation or process evidence: use of organizational portable storage devices containing CUI on external systems is limited as defined.*


#### AC-4 — Enforce approved authorizations for controlling the flow of information within the system and between connected systems based on {{ insert: param, ac-04_odp }}. Information flow control regulates wher

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 5

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-4[a] | Enforce approved authorizations for controlling the flow of information within the system and between connected systems  | Yes |
| AC-4[b] | Enforce approved authorizations for controlling the flow of information within the system and between connected systems  | Yes |
| AC-4[c] | Enforce approved authorizations for controlling the flow of information within the system and between connected systems  | No |
| AC-4[d] | Enforce approved authorizations for controlling the flow of information within the system and between connected systems  | Yes |
| AC-4[e] | Enforce approved authorizations for controlling the flow of information within the system and between connected systems  | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-4-aws-001` | AWS | VPC Flow Logs enabled | VPC | `ec2.describe_flow_logs` | high | [a], [b], [d], [e] |
| `ac-4-aws-002` | AWS | S3 Block Public Access enabled at account level | S3 | `s3control.get_public_access_block` | critical | [a], [b], [d], [e] |
| `ac-4-azure-001` | AZURE | NSG flow logs enabled | Network | `network_watchers.list_all + nsgs.list_all` | high | [a], [b], [d], [e] |
| `ac-4-azure-002` | AZURE | Azure Firewall or Network Virtual Appliance deployed | Network | `network.azure_firewalls.list` | high | [a], [b], [d], [e] |
| `ac-4-gcp-001` | GCP | VPC Flow Logs enabled | VPC | `compute.subnetworks.list` | high | [a], [b], [d], [e] |
| `ac-4-gcp-002` | GCP | Firewall rules reviewed for least privilege | VPC | `compute.firewalls.list` | critical | [a], [b], [d], [e] |

**Documentation Requirements:**

- **AC-4[c]**: designated sources and destinations (e.g., networks, individuals, and devices) for CUI within systems and between interconnected systems are identified. — *Provide documentation showing that designated sources and destinations (e.g., networks, individuals, and devices) for cui within systems and between interconnected systems are identified and documented.*


#### AC-4(4) (Enhancement) — Prevent encrypted information from bypassing {{ insert: param, ac-04.04_odp.01 }} by {{ insert: param, ac-04.04_odp.02 }}. Flow control mechanisms include content checking, security policy filters, an

**Baseline:** High | **Type:** Automated | **Objectives:** 5

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-4(4)[a] | Prevent encrypted information from bypassing {{ insert: param, ac-04.04_odp.01 }} by {{ insert: param, ac-04.04_odp.02 } | Yes |
| AC-4(4)[b] | Prevent encrypted information from bypassing {{ insert: param, ac-04.04_odp.01 }} by {{ insert: param, ac-04.04_odp.02 } | Yes |
| AC-4(4)[c] | Prevent encrypted information from bypassing {{ insert: param, ac-04.04_odp.01 }} by {{ insert: param, ac-04.04_odp.02 } | Yes |
| AC-4(4)[d] | Prevent encrypted information from bypassing {{ insert: param, ac-04.04_odp.01 }} by {{ insert: param, ac-04.04_odp.02 } | Yes |
| AC-4(4)[e] | Prevent encrypted information from bypassing {{ insert: param, ac-04.04_odp.01 }} by {{ insert: param, ac-04.04_odp.02 } | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-4-4-aws-001` | AWS | No S3 buckets publicly accessible | S3 | `s3.get_bucket_policy_status` | critical | [a], [b], [c], [d], [e] |
| `ac-4-4-aws-002` | AWS | No EC2 instances with public IPs in CUI subnets | EC2 | `ec2.describe_instances` | high | [a], [b], [c], [d], [e] |
| `ac-4-4-azure-001` | AZURE | No storage accounts with public blob access | Storage | `storage.storage_accounts.list` | critical | [a], [b], [c], [d], [e] |
| `ac-4-4-gcp-001` | GCP | No Cloud Storage buckets publicly accessible | Storage | `storage.buckets.getIamPolicy` | critical | [a], [b], [c], [d], [e] |


#### AC-5 — Identify and document {{ insert: param, ac-05_odp }} ; and Define system access authorizations to support separation of duties. Separation of duties addresses the potential for abuse of authorized pri

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-5[a] | Identify and document {{ insert: param, ac-05_odp }} | Yes |
| AC-5[b] | Define system access authorizations to support separation of duties. Separation of duties addresses the potential for ab | Yes |
| AC-5[c] | system access authorizations to support separation of duties are defined. Access control policy

procedures addressing d | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-5-aws-001` | AWS | Separate IAM roles for admin and operational tasks | IAM | `iam.list_roles` | medium | [a], [b], [c] |
| `ac-5-aws-002` | AWS | No single user has both deploy and approve permissions | IAM | `iam.get_policy_version` | high | [a], [b], [c] |
| `ac-5-azure-001` | AZURE | Separation of duties for subscription management | Authorization | `authorization.role_assignments.list` | medium | [a], [b], [c] |
| `ac-5-gcp-001` | GCP | Separation of duties for project management | IAM | `cloudresourcemanager.projects.getIamPolicy` | medium | [a], [b], [c] |


#### AC-6 — Employ the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of users) that are necessary to accomplish assigned organizational tasks. Organizati

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-6[a] | Employ the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of u | Yes |
| AC-6[b] | Employ the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of u | Yes |
| AC-6[c] | Employ the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of u | Yes |
| AC-6[d] | Employ the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of u | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-6-aws-001` | AWS | No inline IAM policies with wildcard permissions | IAM | `iam.list_user_policies` | high | [b] |
| `ac-6-aws-002` | AWS | IAM Access Analyzer enabled | IAM | `accessanalyzer.list_analyzers` | medium | [a], [b] |
| `ac-6-aws-003` | AWS | No IAM users with AdministratorAccess policy | IAM | `iam.list_entities_for_policy` | high | [a], [b], [c], [d] |
| `ac-6-azure-001` | AZURE | Global Administrator role limited | Azure AD | `graph.directory_roles.members.list` | high | [a], [b], [c], [d] |
| `ac-6-azure-002` | AZURE | JIT VM access configured | Security Center | `security.jit_network_access_policies.list` | medium | [a], [b], [d] |
| `ac-6-gcp-001` | GCP | No user has Owner role on multiple projects | IAM | `cloudresourcemanager.projects.getIamPolicy` | high | [a], [d] |
| `ac-6-gcp-002` | GCP | IAM recommender reviewed | IAM | `recommender.projects.locations.recommenders.recommendations.list` | medium | [b] |


#### AC-6(3) (Enhancement) — Authorize network access to {{ insert: param, ac-06.03_odp.01 }} only for {{ insert: param, ac-06.03_odp.02 }} and document the rationale for such access in the security plan for the system. Network a

**Baseline:** High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-6(3)[a] | Authorize network access to {{ insert: param, ac-06.03_odp.01 }} only for {{ insert: param, ac-06.03_odp.02 }} and docum | Yes |
| AC-6(3)[b] | the rationale for authorizing network access to privileged commands is documented in the security plan for the system. A | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-6-3-aws-001` | AWS | Separate admin and standard user roles defined | IAM | `iam.list_roles` | medium | [a], [b] |
| `ac-6-3-azure-001` | AZURE | Admin accounts separate from daily-use accounts | Azure AD | `graph/directoryRoles/*/members` | medium | [a], [b] |
| `ac-6-3-gcp-001` | GCP | Admin and user roles separated | IAM | `cloudresourcemanager.projects.getIamPolicy` | medium | [a], [b] |


#### AC-7 — Enforce a limit of {{ insert: param, ac-07_odp.01 }} consecutive invalid logon attempts by a user during a {{ insert: param, ac-07_odp.02 }} ; and Automatically {{ insert: param, ac-07_odp.03 }} when 

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-7[a] | Enforce a limit of {{ insert: param, ac-07_odp.01 }} consecutive invalid logon attempts by a user during a {{ insert: pa | Yes |
| AC-7[b] | Automatically {{ insert: param, ac-07_odp.03 }} when the maximum number of unsuccessful attempts is exceeded. The need t | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-7-aws-001` | AWS | Account lockout policy configured in IAM Identity Center | IAM Identity Center | `sso-admin.list_instances()` | high | [a], [b] |
| `ac-7-aws-002` | AWS | GuardDuty brute force finding type enabled | GuardDuty | `guardduty.list_detectors` | medium | [a], [b] |
| `ac-7-azure-001` | AZURE | Smart lockout configured in Azure AD | Azure AD | `graph.settings.list` | high | [a], [b] |
| `ac-7-gcp-001` | GCP | Google Workspace login challenge enabled | Workspace Admin | `admin.directory.users.list` | medium | [a], [b] |


#### AC-8 — Display {{ insert: param, ac-08_odp.01 }} to users before granting access to the system that provides privacy and security notices consistent with applicable laws, executive orders, directives, regula

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-8[a] | Display {{ insert: param, ac-08_odp.01 }} to users before granting access to the system that provides privacy and securi | No |
| AC-8[b] | System usage may be monitored, recorded, and subject to audit | No |

**Documentation Requirements:**

- **AC-8[a]**: privacy and security notices required by CUI-specified rules are identified, consistent, and associated with the specific CUI category — *Provide documentation showing that privacy and security notices required by cui-specified rules are identified and documented.*
- **AC-8[b]**: privacy and security notices are displayed. — *Provide documentation or process evidence: privacy and security notices are displayed.*


#### AC-9 — Notify the user, upon successful logon to the system, of the date and time of the last logon. Previous logon notification is applicable to system access via human user interfaces and access to systems

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### AC-10 — Limit the number of concurrent sessions for each {{ insert: param, ac-10_odp.01 }} to {{ insert: param, ac-10_odp.02 }}. Organizations may define the maximum number of concurrent sessions for system a

**Baseline:** High | **Type:** Manual | **Objectives:** 0


#### AC-11 — Prevent further access to the system by {{ insert: param, ac-11_odp.01 }} ; and Retain the device lock until the user reestablishes access using established identification and authentication procedure

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-11[a] | Prevent further access to the system by {{ insert: param, ac-11_odp.01 }} | Yes |
| AC-11[b] | Retain the device lock until the user reestablishes access using established identification and authentication procedure | Yes |
| AC-11[c] | device lock is retained until the user re-establishes access using established identification and authentication procedu | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-11-aws-001` | AWS | Console session timeout configured | IAM | `iam.get_role` | medium | [a], [b], [c] |
| `ac-11-azure-001` | AZURE | Conditional Access session controls configured | Azure AD | `graph.conditional_access_policies.list` | medium | [a], [b], [c] |
| `ac-11-gcp-001` | GCP | Session control policy configured | OrgPolicy | `BeyondCorp / session management` | medium | [a], [b], [c] |


#### AC-12 — Automatically terminate a user session after {{ insert: param, ac-12_odp }}. Session termination addresses the termination of user-initiated logical sessions (in contrast to [SC-10](#sc-10) , which ad

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-12[a] | Automatically terminate a user session after {{ insert: param, ac-12_odp }}. Session termination addresses the terminati | Yes |
| AC-12[b] | Automatically terminate a user session after {{ insert: param, ac-12_odp }}. Session termination addresses the terminati | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-12-aws-001` | AWS | IAM role session duration limited | IAM | `iam.list_roles` | medium | [a], [b] |
| `ac-12-aws-002` | AWS | SSO session timeout configured | IAM Identity Center | `sso-admin.describe_instance` | medium | [a], [b] |
| `ac-12-azure-001` | AZURE | Token lifetime policy configured | Azure AD | `graph.token_lifetime_policies.list` | medium | [a], [b] |
| `ac-12-gcp-001` | GCP | OAuth token expiration configured | IAM | `iam.projects.serviceAccounts.list` | medium | [a], [b] |


#### AC-13

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### AC-14 — Identify {{ insert: param, ac-14_odp }} that can be performed on the system without identification or authentication consistent with organizational mission and business functions; and Document and pro

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### AC-15

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### AC-16 — Provide the means to associate {{ insert: param, ac-16_prm_1 }} with {{ insert: param, ac-16_prm_2 }} for information in storage, in process, and/or in transmission; Ensure that the attribute associat

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### AC-17 — Establish and document usage restrictions, configuration/connection requirements, and implementation guidance for each type of remote access allowed; and Authorize each type of remote access to the sy

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### AC-17(1) (Enhancement) — Employ automated mechanisms to monitor and control remote access methods. Monitoring and control of remote access methods allows organizations to detect attacks and help ensure compliance with remote 

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-17(1)[a] | Employ automated mechanisms to monitor and control remote access methods. Monitoring and control of remote access method | Yes |
| AC-17(1)[b] | automated mechanisms are employed to control remote access methods. Access control policy

procedures addressing remote  | Yes |
| AC-17(1)[c] | automated mechanisms are employed to control remote access methods. Access control policy

procedures addressing remote  | Yes |
| AC-17(1)[d] | automated mechanisms are employed to control remote access methods. Access control policy

procedures addressing remote  | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-17-1-aws-001` | AWS | VPN connections use CloudWatch monitoring | VPC | `ec2.describe_vpn_connections` | high | [a], [b], [c], [d] |
| `ac-17-1-aws-002` | AWS | Systems Manager Session Manager logging enabled | SSM | `ssm.describe_document` | high | [a], [b], [c], [d] |
| `ac-17-1-azure-001` | AZURE | Azure Bastion deployed for remote access | Network | `network.bastion_hosts.list` | high | [a], [b], [c], [d] |
| `ac-17-1-gcp-001` | GCP | IAP for TCP forwarding enabled | Compute | `compute.firewalls.list` | high | [a], [b], [c], [d] |


#### AC-17(2) (Enhancement) — Implement cryptographic mechanisms to protect the confidentiality and integrity of remote access sessions. Virtual private networks can be used to protect the confidentiality and integrity of remote a

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-17(2)[a] | Implement cryptographic mechanisms to protect the confidentiality and integrity of remote access sessions. Virtual priva | Yes |
| AC-17(2)[b] | Implement cryptographic mechanisms to protect the confidentiality and integrity of remote access sessions. Virtual priva | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-17-2-aws-001` | AWS | VPN uses approved encryption | VPC | `ec2.describe_vpn_connections` | high | [a], [b] |
| `ac-17-2-aws-002` | AWS | TLS 1.2+ enforced on all load balancers | ELB | `elbv2.describe_load_balancers() + describe_listeners()` | high | [a], [b] |
| `ac-17-2-azure-001` | AZURE | VPN Gateway uses IKEv2 with strong encryption | Network | `network.virtual_network_gateway_connections.list` | high | [a], [b] |
| `ac-17-2-gcp-001` | GCP | Cloud VPN uses IKEv2 with strong ciphers | VPN | `compute.vpnTunnels.list` | high | [a], [b] |


#### AC-17(3) (Enhancement) — Route remote accesses through authorized and managed network access control points. Organizations consider the Trusted Internet Connections (TIC) initiative [DHS TIC](#4f42ee6e-86cc-403b-a51f-76c2b4f8

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-17(3)[a] | Route remote accesses through authorized and managed network access control points. Organizations consider the Trusted I | Yes |
| AC-17(3)[b] | Route remote accesses through authorized and managed network access control points. Organizations consider the Trusted I | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-17-3-aws-001` | AWS | Client VPN endpoint configured | VPC | `ec2.describe_client_vpn_endpoints` | high | [a], [b] |
| `ac-17-3-aws-002` | AWS | No direct SSH/RDP access from internet | EC2 | `ec2.describe_security_groups` | critical | [a], [b] |
| `ac-17-3-azure-001` | AZURE | No direct RDP/SSH from internet | Network | `network.network_security_groups.list` | critical | [a], [b] |
| `ac-17-3-gcp-001` | GCP | No direct SSH from internet via firewall rules | VPC | `compute.firewalls.list` | critical | [a], [b] |


#### AC-18 — Establish configuration requirements, connection requirements, and implementation guidance for each type of wireless access; and Authorize each type of wireless access to the system prior to allowing 

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-18[a] | Establish configuration requirements, connection requirements, and implementation guidance for each type of wireless acc | Yes |
| AC-18[b] | Authorize each type of wireless access to the system prior to allowing such connections. Wireless technologies include m | Yes |
| AC-18[c] | connection requirements are established for each type of wireless access | Yes |
| AC-18[d] | implementation guidance is established for each type of wireless access | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-18-aws-001` | AWS | Session Manager used for privileged remote access | SSM | `ssm.describe_instance_information` | high | [a], [b], [c], [d] |
| `ac-18-azure-001` | AZURE | Privileged Access Workstation policy enforced | Azure AD | `graph.conditional_access_policies.list` | high | [a], [b], [c], [d] |
| `ac-18-gcp-001` | GCP | OS Login enabled for privileged access | Compute | `compute.projects.get` | high | [a], [b], [c], [d] |


#### AC-19 — Establish configuration requirements, connection requirements, and implementation guidance for organization-controlled mobile devices, to include when such devices are outside of controlled areas; and

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-19[a] | Establish configuration requirements, connection requirements, and implementation guidance for organization-controlled m | No |
| AC-19[b] | Authorize the connection of mobile devices to organizational systems. A mobile device is a computing device that has a s | No |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-19-aws-001` | AWS | VPN infrastructure for remote access authorization | VPC | `ec2.describe_vpn_connections/describe_client_vpn_endpoints` | high |  |
| `ac-19-azure-001` | AZURE | VPN gateway for remote access authorization | Network | `network.virtual_network_gateways.list` | high |  |
| `ac-19-gcp-001` | GCP | Cloud VPN for remote access authorization | VPN | `compute.vpnGateways.list/vpnTunnels.list` | high |  |

**Documentation Requirements:**

- **AC-19[a]**: wireless access points are identified. — *Provide documentation showing that wireless access points are identified and documented.*
- **AC-19[b]**: wireless access is authorized prior to allowing such connections. — *Provide documentation or process evidence: wireless access is authorized prior to allowing such connections.*


#### AC-19(5) (Enhancement) — Employ {{ insert: param, ac-19.05_odp.01 }} to protect the confidentiality and integrity of information on {{ insert: param, ac-19.05_odp.02 }}. Container-based encryption provides a more fine-grained

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-19(5)[a] | Employ {{ insert: param, ac-19.05_odp.01 }} to protect the confidentiality and integrity of information on {{ insert: pa | No |
| AC-19(5)[b] | Employ {{ insert: param, ac-19.05_odp.01 }} to protect the confidentiality and integrity of information on {{ insert: pa | No |

**Documentation Requirements:**

- **AC-19(5)[a]**: wireless access to the system is protected using encryption. — *Provide documentation or process evidence: wireless access to the system is protected using encryption.*
- **AC-19(5)[b]**: wireless access to the system is protected using authentication. — *Provide documentation or process evidence: wireless access to the system is protected using authentication.*


#### AC-20 — {{ insert: param, ac-20_odp.01 }} , consistent with the trust relationships established with other organizations owning, operating, and/or maintaining external systems, allowing authorized individuals

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-20[a] | {{ insert: param, ac-20_odp.01 }} , consistent with the trust relationships established with other organizations owning, | No |
| AC-20[b] | Process, store, or transmit organization-controlled information using external systems | No |
| AC-20[c] | Prohibit the use of {{ insert: param, ac-20_odp.04 }}. External systems are systems that are used by but not part of org | No |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-20-aws-001` | AWS | Centralized identity providers for device control | IAM | `iam.list_saml_providers/list_open_id_connect_providers` | high |  |
| `ac-20-azure-001` | AZURE | Defender for Cloud and managed identity for device control | Security/Authorization | `resource_client.providers.get/auth_client.role_assignments.list` | high |  |
| `ac-20-gcp-001` | GCP | OS Login and device security org policies | OrgPolicy | `orgpolicy.projects.policies.get` | high |  |

**Documentation Requirements:**

- **AC-20[a]**: mobile devices that process, store, or transmit CUI are identified. — *Provide documentation showing that mobile devices that process, store, or transmit cui are identified and documented.*
- **AC-20[b]**: the connection of mobile devices is authorized. — *Provide documentation or process evidence: the connection of mobile devices is authorized.*
- **AC-20[c]**: mobile device connections are monitored and logged. — *Provide documentation or process evidence: mobile device connections are monitored and logged.*


#### AC-20(1) (Enhancement) — Permit authorized individuals to use an external system to access the system or to process, store, or transmit organization-controlled information only after: Verification of the implementation of con

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-20(1)[a] | Permit authorized individuals to use an external system to access the system or to process, store, or transmit organizat | No |
| AC-20(1)[b] | or Retention of approved system connection or processing agreements with the organizational entity hosting the external  | No |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-20-1-aws-001` | AWS | EBS default encryption enabled for compute platforms | EC2 | `ec2.get_ebs_encryption_by_default` | high |  |
| `ac-20-1-azure-001` | AZURE | All managed disks encrypted | Compute | `compute.disks.list` | high |  |
| `ac-20-1-gcp-001` | GCP | CMEK org policy or disk-level CMEK enforced | OrgPolicy/Compute | `orgpolicy/compute.disks.list` | high |  |

**Documentation Requirements:**

- **AC-20(1)[a]**: mobile devices and mobile computing platforms that process, store, or transmit CUI are identified. — *Provide documentation showing that mobile devices and mobile computing platforms that process, store, or transmit cui are identified and documented.*
- **AC-20(1)[b]**: encryption is employed to protect CUI on identified mobile devices and mobile computing platforms. — *Provide documentation or process evidence: encryption is employed to protect CUI on identified mobile devices and mobile computing platforms.*


#### AC-21 — Enable authorized users to determine whether access authorizations assigned to a sharing partner match the information’s access and use restrictions for {{ insert: param, ac-21_odp.01 }} ; and Employ 

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 6

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AC-21[a] | Enable authorized users to determine whether access authorizations assigned to a sharing partner match the information’s | Yes |
| AC-21[b] | Employ {{ insert: param, ac-21_odp.02 }} to assist users in making information sharing and collaboration decisions. Info | Yes |
| AC-21[c] | {{ insert: param, ac-21_odp.02 }} are employed to assist users in making information-sharing and collaboration decisions | Yes |
| AC-21[d] | {{ insert: param, ac-21_odp.02 }} are employed to assist users in making information-sharing and collaboration decisions | Yes |
| AC-21[e] | {{ insert: param, ac-21_odp.02 }} are employed to assist users in making information-sharing and collaboration decisions | Yes |
| AC-21[f] | {{ insert: param, ac-21_odp.02 }} are employed to assist users in making information-sharing and collaboration decisions | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-21-aws-001` | AWS | VPC peering connections reviewed | VPC | `ec2.describe_vpc_peering_connections` | medium | [a], [b], [c], [d], [e], [f] |
| `ac-21-aws-002` | AWS | Transit Gateway attachments reviewed | VPC | `ec2.describe_transit_gateway_attachments` | medium | [a], [b], [c], [d], [e], [f] |
| `ac-21-azure-001` | AZURE | VNet peering connections reviewed | Network | `network.virtual_network_peerings.list` | medium | [a], [b], [c], [d], [e], [f] |
| `ac-21-gcp-001` | GCP | VPC peering connections reviewed | VPC | `compute.networks.listPeering` | medium | [a], [b], [c], [d], [e], [f] |


#### AC-22 — Designate individuals authorized to make information publicly accessible; Train authorized individuals to ensure that publicly accessible information does not contain nonpublic information; Review the

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### AC-23 — Employ {{ insert: param, ac-23_odp.01 }} for {{ insert: param, ac-23_odp.02 }} to detect and protect against unauthorized data mining. Data mining is an analytical process that attempts to find correl

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### AC-24 — {{ insert: param, ac-24_odp.01 }} to ensure {{ insert: param, ac-24_odp.02 }} are applied to each access request prior to access enforcement. Access control decisions (also known as authorization deci

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### AC-25 — Implement a reference monitor for {{ insert: param, ac-25_odp }} that is tamperproof, always invoked, and small enough to be subject to analysis and testing, the completeness of which can be assured. 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### AT — Awareness and Training

**Controls:** 6 | **Automated:** 2 | **Manual:** 4 | **Objectives:** 7 | **Checks:** AWS 0, Azure 0, GCP 0

#### AT-1 — Develop, document, and disseminate to {{ insert: param, at-1_prm_1 }}: {{ insert: param, at-01_odp.03 }} awareness and training policy that: Addresses purpose, scope, roles, responsibilities, manageme

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### AT-2 — Provide security and privacy literacy training to system users (including managers, senior executives, and contractors): As part of initial training for new users and {{ insert: param, at-2_prm_1 }} t

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AT-2[a] | Provide security and privacy literacy training to system users (including managers, senior executives, and contractors): | No |
| AT-2[b] | When required by system changes or following {{ insert: param, at-2_prm_2 }} | No |
| AT-2[c] | Employ the following techniques to increase the security and privacy awareness of system users {{ insert: param, at-02_o | No |
| AT-2[d] | Update literacy training and awareness content {{ insert: param, at-02_odp.06 }} and following {{ insert: param, at-02_o | No |

**Documentation Requirements:**

- **AT-2[a]**: security risks associated with organizational activities involving CUI are identified. — *Provide documentation showing that security risks associated with organizational activities involving cui are identified and documented.*
- **AT-2[b]**: policies, standards, and procedures related to the security of the system are identified. — *Provide documentation showing that policies, standards, and procedures related to the security of the system are identified and documented.*
- **AT-2[c]**: managers, systems administrators, and users of the system are made aware of the security risks associated with their activities. — *Provide documentation or process evidence: managers, systems administrators, and users of the system are made aware of the security risks associated with their activities.*
- **AT-2[d]**: managers, systems administrators, and users of the system are made aware of the applicable policies, standards, and procedures related to the security of the system. — *Provide documentation or process evidence: managers, systems administrators, and users of the system are made aware of the applicable policies, standards, and procedures related to the security of the system.*


#### AT-2(2) (Enhancement) — Provide literacy training on recognizing and reporting potential indicators of insider threat. Potential indicators and possible precursors of insider threat can include behaviors such as inordinate, 

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AT-2(2)[a] | Provide literacy training on recognizing and reporting potential indicators of insider threat. Potential indicators and  | No |
| AT-2(2)[b] | attempts to gain access to information not required for job performance | No |

**Documentation Requirements:**

- **AT-2(2)[a]**: potential indicators associated with insider threats are identified. — *Provide documentation showing that potential indicators associated with insider threats are identified and documented.*
- **AT-2(2)[b]**: security awareness training on recognizing and reporting potential indicators of insider threat is provided to managers and employees. — *Provide training records: security awareness training on recognizing and reporting potential indicators of insider threat is provided to managers and employees.*


#### AT-3 — Provide role-based security and privacy training to personnel with the following roles and responsibilities: {{ insert: param, at-3_prm_1 }}: Before authorizing access to the system, information, or p

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AT-3[a] | Provide role-based security and privacy training to personnel with the following roles and responsibilities: {{ insert:  | No |
| AT-3[b] | When required by system changes | No |
| AT-3[c] | Update role-based training content {{ insert: param, at-03_odp.04 }} and following {{ insert: param, at-03_odp.05 }} | No |

**Documentation Requirements:**

- **AT-3[a]**: information security-related duties, roles, and responsibilities are defined. — *Provide documentation showing that information security-related duties, roles, and responsibilities are defined.*
- **AT-3[b]**: information security-related duties, roles, and responsibilities are assigned to designated personnel. — *Provide personnel records: information security-related duties, roles, and responsibilities are assigned to designated personnel.*
- **AT-3[c]**: personnel are adequately trained to carry out their assigned information security-related duties, roles, and responsibilities. — *Provide personnel records: personnel are adequately trained to carry out their assigned information security-related duties, roles, and responsibilities.*


#### AT-4 — Document and monitor information security and privacy training activities, including security and privacy awareness training and specific role-based security and privacy training; and Retain individua

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### AT-5

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### AT-6 — Provide feedback on organizational training results to the following personnel {{ insert: param, at-06_odp.01 }}: {{ insert: param, at-06_odp.02 }}. Training feedback includes awareness training resul

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### AU — Audit and Accountability

**Controls:** 16 | **Automated:** 7 | **Manual:** 9 | **Objectives:** 24 | **Checks:** AWS 18, Azure 11, GCP 11

#### AU-1 — Develop, document, and disseminate to {{ insert: param, au-1_prm_1 }}: {{ insert: param, au-01_odp.03 }} audit and accountability policy that: Addresses purpose, scope, roles, responsibilities, manage

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### AU-2 — Identify the types of events that the system is capable of logging in support of the audit function: {{ insert: param, au-02_odp.01 }}; Coordinate the event logging function with other organizational 

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 6

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AU-2[a] | Identify the types of events that the system is capable of logging in support of the audit function: {{ insert: param, a | Yes |
| AU-2[b] | Coordinate the event logging function with other organizational entities requiring audit-related information to guide an | Yes |
| AU-2[c] | Specify the following event types for logging within the system: {{ insert: param, au-2_prm_2 }} | Yes |
| AU-2[d] | Provide a rationale for why the event types selected for logging are deemed to be adequate to support after-the-fact inv | Yes |
| AU-2[e] | Review and update the event types selected for logging {{ insert: param, au-02_odp.04 }}. An event is an observable occu | Yes |
| AU-2[f] | the event logging function is coordinated with other organizational entities requiring audit-related information to guid | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-2-aws-001` | AWS | CloudTrail enabled in all regions | CloudTrail | `cloudtrail.describe_trails` | critical | [a], [b], [c], [d], [e], [f] |
| `au-2-aws-002` | AWS | CloudTrail log file validation enabled | CloudTrail | `cloudtrail.describe_trails` | high | [a], [b], [c], [d], [e], [f] |
| `au-2-aws-003` | AWS | CloudTrail logs retained for at least 365 days | S3 | `s3.get_bucket_lifecycle_configuration` | high | [a], [b], [c], [d], [e], [f] |
| `au-2-aws-004` | AWS | CloudTrail data events enabled for S3 and Lambda | CloudTrail | `cloudtrail.get_event_selectors` | medium | [a], [b], [c], [d], [e], [f] |
| `au-2-azure-001` | AZURE | Azure Activity Log retention configured | Monitor | `MonitorManagementClient.activity_log_alerts.list_by_subscription_id` | critical | [a], [b], [c], [d], [e], [f] |
| `au-2-azure-002` | AZURE | Azure AD audit logs retained | Azure AD | `NetworkManagementClient.network_watchers.list_all + resources.list` | high | [a], [b], [c], [d], [e], [f] |
| `au-2-azure-003` | AZURE | Resource diagnostic settings enabled | Monitor | `monitor.diagnostic_settings.list` | high | [a], [b], [c], [d], [e], [f] |
| `au-2-gcp-001` | GCP | Admin Activity audit logs active | Logging | `logging.projects.logs.list` | critical | [a], [b], [c], [d], [e], [f] |
| `au-2-gcp-002` | GCP | Data Access audit logs enabled | Logging | `cloudresourcemanager.projects.getIamPolicy` | high | [a], [b], [c], [d], [e], [f] |
| `au-2-gcp-003` | GCP | Audit log sink to long-term storage | Logging | `logging.projects.sinks.list` | high | [a], [b], [c], [d], [e], [f] |


#### AU-3 — Ensure that audit records contain information that establishes the following: What type of event occurred; When the event occurred; Where the event occurred; Source of the event; Outcome of the event;

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AU-3[a] | Ensure that audit records contain information that establishes the following: What type of event occurred | Yes |
| AU-3[b] | When the event occurred | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-3-aws-001` | AWS | CloudTrail records user identity | CloudTrail | `cloudtrail.describe_trails` | high | [a], [b] |
| `au-3-aws-002` | AWS | No shared IAM user accounts | IAM | `iam.list_users()` | high | [a], [b] |
| `au-3-azure-001` | AZURE | Azure AD sign-in logs available | Azure AD | `graph.sign_in_logs.list` | high | [a], [b] |
| `au-3-gcp-001` | GCP | Audit logs include principal identity | Logging | `logging.entries.list` | high | [a], [b] |


#### AU-3(1) (Enhancement) — Generate audit records containing the following additional information: {{ insert: param, au-03.01_odp }}. The ability to add information generated in audit records is dependent on system functionalit

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AU-3(1)[a] | Generate audit records containing the following additional information: {{ insert: param, au-03.01_odp }}. The ability t | No |
| AU-3(1)[b] | Generate audit records containing the following additional information: {{ insert: param, au-03.01_odp }}. The ability t | No |
| AU-3(1)[c] | Generate audit records containing the following additional information: {{ insert: param, au-03.01_odp }}. The ability t | No |

**Documentation Requirements:**

- **AU-3(1)[a]**: a process for determining when to review logged events is defined. — *Provide documentation showing that a process for determining when to review logged events are defined.*
- **AU-3(1)[b]**: event types being logged are reviewed in accordance with the defined review process. — *Provide evidence of periodic review: event types being logged are reviewed in accordance with the defined review process.*
- **AU-3(1)[c]**: event types being logged are updated based on the review. — *Provide documentation or process evidence: event types being logged are updated based on the review.*


#### AU-4 — Allocate audit log storage capacity to accommodate {{ insert: param, au-04_odp }}. Organizations consider the types of audit logging to be performed and the audit log processing requirements when allo

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### AU-5 — Alert {{ insert: param, au-05_odp.01 }} within {{ insert: param, au-05_odp.02 }} in the event of an audit logging process failure; and Take the following additional actions: {{ insert: param, au-05_od

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AU-5[a] | Alert {{ insert: param, au-05_odp.01 }} within {{ insert: param, au-05_odp.02 }} in the event of an audit logging proces | Yes |
| AU-5[b] | Take the following additional actions: {{ insert: param, au-05_odp.03 }}. Audit logging process failures include softwar | Yes |
| AU-5[c] | {{ insert: param, au-05_odp.03 }} are taken in the event of an audit logging process failure. Audit and accountability p | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-5-aws-001` | AWS | CloudWatch alarm for CloudTrail logging changes | CloudWatch | `cloudwatch.describe_alarms` | high | [a], [b], [c] |
| `au-5-aws-002` | AWS | SNS topic configured for audit failure notifications | SNS | `sns.list_topics()` | medium | [a], [b], [c] |
| `au-5-azure-001` | AZURE | Activity log alert for diagnostic settings changes | Monitor | `monitor.activity_log_alerts.list` | high | [a], [b], [c] |
| `au-5-gcp-001` | GCP | Alert policy for log sink changes | Monitoring | `monitoring.projects.alertPolicies.list` | high | [a], [b], [c] |


#### AU-6 — Review and analyze system audit records {{ insert: param, au-06_odp.01 }} for indications of {{ insert: param, au-06_odp.02 }} and the potential impact of the inappropriate or unusual activity; Report

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AU-6[a] | Review and analyze system audit records {{ insert: param, au-06_odp.01 }} for indications of {{ insert: param, au-06_odp | Yes |
| AU-6[b] | Report findings to {{ insert: param, au-06_odp.03 }} | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-6-aws-001` | AWS | AWS Security Hub enabled | Security Hub | `securityhub.describe_hub` | high | [a], [b] |
| `au-6-aws-002` | AWS | CloudTrail integrated with CloudWatch Logs | CloudTrail | `cloudtrail.describe_trails` | high | [a], [b] |
| `au-6-azure-001` | AZURE | Microsoft Sentinel enabled | Sentinel | `securityinsight.sentinel_onboarding_states.list` | high | [a], [b] |
| `au-6-gcp-001` | GCP | Security Command Center enabled | SCC | `securitycenter.securityHealthAnalyticsSettings` | high | [a], [b] |


#### AU-7 — Provide and implement an audit record reduction and report generation capability that: Supports on-demand audit record review, analysis, and reporting requirements and after-the-fact investigations of

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AU-7[a] | Provide and implement an audit record reduction and report generation capability that: Supports on-demand audit record r | Yes |
| AU-7[b] | Does not alter the original content or time ordering of audit records. Audit record reduction is a process that manipula | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-7-aws-001` | AWS | CloudWatch Logs Insights available | CloudWatch | `logs.describe_log_groups` | medium | [a], [b] |
| `au-7-aws-002` | AWS | Athena table configured for CloudTrail analysis | Athena | `athena.list_named_queries` | low | [a], [b] |
| `au-7-azure-001` | AZURE | Log Analytics workspace configured | Monitor | `operationalinsights.workspaces.list` | medium | [a], [b] |
| `au-7-gcp-001` | GCP | Log Analytics enabled in Cloud Logging | Logging | `logging.projects.locations.buckets.list` | medium | [a], [b] |


#### AU-8 — Use internal system clocks to generate time stamps for audit records; and Record time stamps for audit records that meet {{ insert: param, au-08_odp }} and that use Coordinated Universal Time, have a 

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AU-8[a] | Use internal system clocks to generate time stamps for audit records | Yes |
| AU-8[b] | Record time stamps for audit records that meet {{ insert: param, au-08_odp }} and that use Coordinated Universal Time, h | Yes |
| AU-8[c] | timestamps are recorded for audit records that meet {{ insert: param, au-08_odp }} and that use Coordinated Universal Ti | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-8-aws-001` | AWS | NTP configured on EC2 instances | EC2 | `ec2.describe_instances()` | medium | [a], [b], [c] |
| `au-8-azure-001` | AZURE | Azure VMs use platform time sync | Compute | `compute.virtual_machines.list` | medium | [a], [b], [c] |
| `au-8-gcp-001` | GCP | GCE instances use Google NTP | Compute | `compute.instances.list` | medium | [a], [b], [c] |


#### AU-9 — Protect audit information and audit logging tools from unauthorized access, modification, and deletion; and Alert {{ insert: param, au-09_odp }} upon detection of unauthorized access, modification, or

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 6

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AU-9[a] | Protect audit information and audit logging tools from unauthorized access, modification, and deletion | Yes |
| AU-9[b] | Alert {{ insert: param, au-09_odp }} upon detection of unauthorized access, modification, or deletion of audit informati | Yes |
| AU-9[c] | {{ insert: param, au-09_odp }} are alerted upon detection of unauthorized access, modification, or deletion of audit inf | Yes |
| AU-9[d] | {{ insert: param, au-09_odp }} are alerted upon detection of unauthorized access, modification, or deletion of audit inf | Yes |
| AU-9[e] | {{ insert: param, au-09_odp }} are alerted upon detection of unauthorized access, modification, or deletion of audit inf | Yes |
| AU-9[f] | {{ insert: param, au-09_odp }} are alerted upon detection of unauthorized access, modification, or deletion of audit inf | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-9-aws-001` | AWS | CloudTrail S3 bucket has access logging | S3 | `s3.get_bucket_logging` | high | [a], [b], [c], [d], [e], [f] |
| `au-9-aws-002` | AWS | CloudTrail S3 bucket encrypted | S3 | `s3.get_bucket_encryption` | high | [a], [b], [c], [d], [e], [f] |
| `au-9-aws-003` | AWS | CloudTrail S3 bucket MFA Delete enabled | S3 | `s3.get_bucket_versioning` | medium | [a], [b], [c], [d], [e], [f] |
| `au-9-azure-001` | AZURE | Log Analytics workspace access controlled | Monitor | `operationalinsights.workspaces.list` | high | [a], [b], [c], [d], [e], [f] |
| `au-9-azure-002` | AZURE | Audit log storage uses immutable blobs | Storage | `storage_accounts.list` | high | [a], [b], [c], [d], [e], [f] |
| `au-9-gcp-001` | GCP | Audit log bucket has retention policy | Storage | `storage.buckets.get` | high | [a], [b], [c], [d], [e], [f] |
| `au-9-gcp-002` | GCP | Audit log bucket access restricted | Storage | `storage.buckets.getIamPolicy` | high | [a], [b], [c], [d], [e], [f] |


#### AU-9(4) (Enhancement) — Authorize access to management of audit logging functionality to only {{ insert: param, au-09.04_odp }}. Individuals or roles with privileged access to a system and who are also the subject of an audi

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| AU-9(4)[a] | Authorize access to management of audit logging functionality to only {{ insert: param, au-09.04_odp }}. Individuals or  | Yes |
| AU-9(4)[b] | Authorize access to management of audit logging functionality to only {{ insert: param, au-09.04_odp }}. Individuals or  | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-9-4-aws-001` | AWS | CloudTrail management restricted to security team | IAM | `iam.list_entities_for_policy` | high | [a], [b] |
| `au-9-4-aws-002` | AWS | SCP prevents non-security users from modifying audit config | Organizations | `organizations.list_policies` | high | [a], [b] |
| `au-9-4-azure-001` | AZURE | Diagnostic settings management restricted | Authorization | `authorization.role_assignments.list` | high | [a], [b] |
| `au-9-4-gcp-001` | GCP | Logging admin role restricted | IAM | `cloudresourcemanager.projects.getIamPolicy` | high | [a], [b] |


#### AU-10 — Provide irrefutable evidence that an individual (or process acting on behalf of an individual) has performed {{ insert: param, au-10_odp }}. Types of individual actions covered by non-repudiation incl

**Baseline:** High | **Type:** Manual | **Objectives:** 0


#### AU-11 — Retain audit records for {{ insert: param, au-11_odp }} to provide support for after-the-fact investigations of incidents and to meet regulatory and organizational information retention requirements. 

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### AU-12 — Provide audit record generation capability for the event types the system is capable of auditing as defined in [AU-2a](#au-2_smt.a) on {{ insert: param, au-12_odp.01 }}; Allow {{ insert: param, au-12_

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### AU-13 — Monitor {{ insert: param, au-13_odp.01 }} {{ insert: param, au-13_odp.02 }} for evidence of unauthorized disclosure of organizational information; and If an information disclosure is discovered: Notif

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### AU-14 — Provide and implement the capability for {{ insert: param, au-14_odp.01 }} to {{ insert: param, au-14_odp.02 }} the content of a user session under {{ insert: param, au-14_odp.03 }} ; and Develop, int

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### AU-15

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### AU-16 — Employ {{ insert: param, au-16_odp.01 }} for coordinating {{ insert: param, au-16_odp.02 }} among external organizations when audit information is transmitted across organizational boundaries. When or

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### CA — Assessment, Authorization, and Monitoring

**Controls:** 9 | **Automated:** 3 | **Manual:** 6 | **Objectives:** 10 | **Checks:** AWS 3, Azure 2, GCP 2

#### CA-1 — Develop, document, and disseminate to {{ insert: param, ca-1_prm_1 }}: {{ insert: param, ca-01_odp.03 }} assessment, authorization, and monitoring policy that: Addresses purpose, scope, roles, respons

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### CA-2 — Select the appropriate assessor or assessment team for the type of assessment to be conducted; Develop a control assessment plan that describes the scope of the assessment including: Controls and cont

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CA-2[a] | Select the appropriate assessor or assessment team for the type of assessment to be conducted | No |
| CA-2[b] | Develop a control assessment plan that describes the scope of the assessment including: Controls and control enhancement | No |

**Documentation Requirements:**

- **CA-2[a]**: the frequency of security control assessments is defined. — *Provide documentation showing that the frequency of security control assessments are defined.*
- **CA-2[b]**: security controls are assessed with the defined frequency to determine if the controls are effective in their application. — *Provide documentation or process evidence: security controls are assessed with the defined frequency to determine if the controls are effective in their application.*


#### CA-3 — Approve and manage the exchange of information between the system and other systems using {{ insert: param, ca-03_odp.01 }}; Document, as part of each exchange agreement, the interface characteristics

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### CA-4

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### CA-5 — Develop a plan of action and milestones for the system to document the planned remediation actions of the organization to correct weaknesses or deficiencies noted during the assessment of the controls

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 7

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CA-5[a] | Develop a plan of action and milestones for the system to document the planned remediation actions of the organization t | No |
| CA-5[b] | Update existing plan of action and milestones {{ insert: param, ca-05_odp }} based on the findings from control assessme | No |
| CA-5[c] | existing plan of action and milestones are updated {{ insert: param, ca-05_odp }} based on the findings from control ass | No |
| CA-5[d] | existing plan of action and milestones are updated {{ insert: param, ca-05_odp }} based on the findings from control ass | No |
| CA-5[e] | existing plan of action and milestones are updated {{ insert: param, ca-05_odp }} based on the findings from control ass | No |
| CA-5[f] | existing plan of action and milestones are updated {{ insert: param, ca-05_odp }} based on the findings from control ass | No |
| CA-5[g] | existing plan of action and milestones are updated {{ insert: param, ca-05_odp }} based on the findings from control ass | No |

**Documentation Requirements:**

- **CA-5[a]**: deficiencies and vulnerabilities to be addressed by the plan of action are identified. — *Provide documentation showing that deficiencies and vulnerabilities to be addressed by the plan of action are identified and documented.*
- **CA-5[b]**: a plan of action is developed to correct identified deficiencies and reduce or eliminate identified vulnerabilities. — *Provide documentation or process evidence: a plan of action is developed to correct identified deficiencies and reduce or eliminate identified vulnerabilities.*
- **CA-5[c]**: the plan of action is implemented to correct identified deficiencies and reduce or eliminate identified vulnerabilities. — *Provide documentation or process evidence: the plan of action is implemented to correct identified deficiencies and reduce or eliminate identified vulnerabilities.*
- **CA-5[a]**: a system security plan is developed. — *Provide documentation or process evidence: a system security plan is developed.*
- **CA-5[b]**: the system boundary is described and documented in the system security plan. — *Provide documentation or process evidence: the system boundary is described and documented in the system security plan.*
- **CA-5[c]**: the system environment of operation is described and documented in the system security plan. — *Provide documentation or process evidence: the system environment of operation is described and documented in the system security plan.*
- **CA-5[d]**: the security requirements identified and approved by the designated authority as non-applicable are identified. — *Provide documentation showing that the security requirements identified and approved by the designated authority as non-applicable are identified and documented.*
- **CA-5[e]**: the method of security requirement implementation is described and documented in the system security plan. — *Provide documentation or process evidence: the method of security requirement implementation is described and documented in the system security plan.*
- **CA-5[f]**: the relationship with or connection to other systems is described and documented in the system security plan. — *Provide documentation or process evidence: the relationship with or connection to other systems is described and documented in the system security plan.*
- **CA-5[g]**: the frequency to update the system security plan is defined. — *Provide documentation showing that the frequency to update the system security plan are defined.*


#### CA-6 — Assign a senior official as the authorizing official for the system; Assign a senior official as the authorizing official for common controls available for inheritance by organizational systems; Ensur

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### CA-7 — Develop a system-level continuous monitoring strategy and implement continuous monitoring in accordance with the organization-level continuous monitoring strategy that includes: Establishing the follo

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CA-7[a] | Develop a system-level continuous monitoring strategy and implement continuous monitoring in accordance with the organiz | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ca-7-aws-001` | AWS | Security Hub continuous monitoring active | Security Hub | `securityhub.describe_hub` | high | [a] |
| `ca-7-aws-002` | AWS | Config rules continuously evaluating | Config | `config.describe_compliance_by_config_rule` | high | [a] |
| `ca-7-aws-003` | AWS | GuardDuty continuous threat monitoring | GuardDuty | `guardduty.get_detector` | high | [a] |
| `ca-7-azure-001` | AZURE | Defender for Cloud continuous assessment | Security Center | `security.assessments.list` | high | [a] |
| `ca-7-azure-002` | AZURE | Azure Policy compliance continuously monitored | Policy | `policy.policy_states.list` | high | [a] |
| `ca-7-gcp-001` | GCP | Security Command Center continuous monitoring | SCC | `securitycenter.organizations.getOrganizationSettings` | high | [a] |
| `ca-7-gcp-002` | GCP | Organization policy compliance monitored | Organization Policy | `orgpolicy.projects.policies.list` | high | [a] |


#### CA-8 — Conduct penetration testing {{ insert: param, ca-08_odp.01 }} on {{ insert: param, ca-08_odp.02 }}. Penetration testing is a specialized type of assessment conducted on systems or individual system co

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### CA-9 — Authorize internal connections of {{ insert: param, ca-09_odp.01 }} to the system; Document, for each internal connection, the interface characteristics, security and privacy requirements, and the nat

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


### CM — Configuration Management

**Controls:** 14 | **Automated:** 6 | **Manual:** 8 | **Objectives:** 25 | **Checks:** AWS 15, Azure 10, GCP 10

#### CM-1 — Develop, document, and disseminate to {{ insert: param, cm-1_prm_1 }}: {{ insert: param, cm-01_odp.03 }} configuration management policy that: Addresses purpose, scope, roles, responsibilities, manage

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### CM-2 — Develop, document, and maintain under configuration control, a current baseline configuration of the system; and Review and update the baseline configuration of the system: {{ insert: param, cm-02_odp

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 6

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CM-2[a] | Develop, document, and maintain under configuration control, a current baseline configuration of the system | Yes |
| CM-2[b] | Review and update the baseline configuration of the system: {{ insert: param, cm-02_odp.01 }} | No |
| CM-2[c] | When required due to {{ insert: param, cm-02_odp.02 }} | Yes |
| CM-2[d] | When system components are installed or upgraded. Baseline configurations for systems and system components include conn | Yes |
| CM-2[e] | a current baseline configuration of the system is maintained under configuration control | No |
| CM-2[f] | the baseline configuration of the system is reviewed and updated {{ insert: param, cm-02_odp.01 }} | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-2-aws-001` | AWS | AWS Config enabled in all regions | Config | `config.describe_configuration_recorders` | critical | [a], [c], [d], [f] |
| `cm-2-aws-002` | AWS | Systems Manager Inventory enabled | SSM | `ssm.describe_instance_information` | high | [a], [c], [d], [f] |
| `cm-2-aws-003` | AWS | AMI baseline documented and maintained | EC2 | `ec2.describe_images` | medium | [a], [c], [d], [f] |
| `cm-2-azure-001` | AZURE | Azure Resource Graph inventory available | Resource Graph | `resourcegraph.resources` | high | [a], [c], [d], [f] |
| `cm-2-azure-002` | AZURE | Azure Policy Guest Configuration enabled | Policy | `policy_assignments.list` | high | [a], [c], [d], [f] |
| `cm-2-gcp-001` | GCP | Cloud Asset Inventory enabled | Asset Inventory | `cloudasset.assets.list` | high | [a], [c], [d], [f] |
| `cm-2-gcp-002` | GCP | OS Config inventory management enabled | OS Config | `compute.instances.aggregatedList` | medium | [a], [c], [d], [f] |

**Documentation Requirements:**

- **CM-2[b]**: the baseline configuration includes hardware, software, firmware, and documentation. — *Provide documentation or process evidence: the baseline configuration includes hardware, software, firmware, and documentation.*
- **CM-2[e]**: the system inventory includes hardware, software, firmware, and documentation. — *Provide documentation or process evidence: the system inventory includes hardware, software, firmware, and documentation.*


#### CM-3 — Determine and document the types of changes to the system that are configuration-controlled; Review proposed configuration-controlled changes to the system and approve or disapprove such changes with 

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CM-3[a] | Determine and document the types of changes to the system that are configuration-controlled | Yes |
| CM-3[b] | Review proposed configuration-controlled changes to the system and approve or disapprove such changes with explicit cons | Yes |
| CM-3[c] | Document configuration change decisions associated with the system | Yes |
| CM-3[d] | Implement approved configuration-controlled changes to the system | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-3-aws-001` | AWS | AWS Config configuration history enabled | Config | `config.describe_delivery_channels` | high | [a], [b], [c], [d] |
| `cm-3-aws-002` | AWS | CloudTrail captures config changes | CloudTrail | `cloudtrail.describe_trails` | high | [a], [b], [c], [d] |
| `cm-3-azure-001` | AZURE | Activity Log captures resource changes | Monitor | `diagnostic_settings.list` | high | [a], [b], [c], [d] |
| `cm-3-gcp-001` | GCP | Admin Activity logs capture changes | Logging | `logging.entries.list` | high | [a], [b], [c], [d] |


#### CM-3(4) (Enhancement) — Require {{ insert: param, cm-3.4_prm_1 }} to be members of the {{ insert: param, cm-03.04_odp.03 }}. Information security and privacy representatives include system security officers, senior agency in

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CM-3(4)[a] | Require {{ insert: param, cm-3.4_prm_1 }} to be members of the {{ insert: param, cm-03.04_odp.03 }}. Information securit | No |

**Documentation Requirements:**

- **CM-3(4)[a]**: the security impact of changes to each organizational system is analyzed prior to implementation. — *Provide documentation or process evidence: the security impact of changes to each organizational system is analyzed prior to implementation.*


#### CM-4 — Analyze changes to the system to determine potential security and privacy impacts prior to change implementation. Organizational personnel with security or privacy responsibilities conduct impact anal

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### CM-5 — Define, document, approve, and enforce physical and logical access restrictions associated with changes to the system. Changes to the hardware, software, or firmware components of systems or the opera

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 8

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CM-5[a] | Define, document, approve, and enforce physical and logical access restrictions associated with changes to the system. C | Yes |
| CM-5[b] | physical access restrictions associated with changes to the system are approved | No |
| CM-5[c] | physical access restrictions associated with changes to the system are enforced | Yes |
| CM-5[d] | logical access restrictions associated with changes to the system are defined and documented | Yes |
| CM-5[e] | logical access restrictions associated with changes to the system are approved | Yes |
| CM-5[f] | logical access restrictions associated with changes to the system are enforced. Configuration management policy

procedu | No |
| CM-5[g] | logical access restrictions associated with changes to the system are enforced. Configuration management policy

procedu | Yes |
| CM-5[h] | logical access restrictions associated with changes to the system are enforced. Configuration management policy

procedu | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-5-aws-001` | AWS | CI/CD pipeline has approval gates | CodePipeline | `codepipeline.list_pipelines` | high | [a], [c], [d], [e], [g], [h] |
| `cm-5-aws-002` | AWS | IAM roles for deployment are scoped | IAM | `iam.list_roles` | high | [a], [c], [d], [e], [g], [h] |
| `cm-5-azure-001` | AZURE | Resource locks on critical resources | Resources | `resources.management_locks.list` | medium | [a], [c], [d], [e], [g], [h] |
| `cm-5-gcp-001` | GCP | Project lien configured for critical projects | Resource Manager | `cloudresourcemanager.liens.list` | medium | [a], [c], [d], [e], [g], [h] |

**Documentation Requirements:**

- **CM-5[b]**: physical access restrictions associated with changes to the system are documented. — *Provide physical security evidence: physical access restrictions associated with changes to the system are documented.*
- **CM-5[f]**: logical access restrictions associated with changes to the system are documented. — *Provide documentation or process evidence: logical access restrictions associated with changes to the system are documented.*


#### CM-6 — Establish and document configuration settings for components employed within the system that reflect the most restrictive mode consistent with operational requirements using {{ insert: param, cm-06_od

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CM-6[a] | Establish and document configuration settings for components employed within the system that reflect the most restrictiv | Yes |
| CM-6[b] | Implement the configuration settings | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-6-aws-001` | AWS | AWS Config rules for CIS Benchmark | Config | `config.describe_config_rules` | high | [a], [b] |
| `cm-6-aws-002` | AWS | Security Hub CIS standard enabled | Security Hub | `securityhub.describe_standards_subscriptions` | high | [a], [b] |
| `cm-6-azure-001` | AZURE | Azure Policy assignments for security baseline | Policy | `policy.policy_assignments.list` | high | [a], [b] |
| `cm-6-azure-002` | AZURE | Defender for Cloud secure score reviewed | Security Center | `security.secure_scores.list` | medium | [a], [b] |
| `cm-6-gcp-001` | GCP | Organization policies configured | Organization Policy | `orgpolicy.projects.policies.list` | high | [a], [b] |
| `cm-6-gcp-002` | GCP | SCC findings for CIS compliance | SCC | `securitycenter.securityHealthAnalyticsSettings` | high | [a], [b] |


#### CM-7 — Configure the system to provide only {{ insert: param, cm-07_odp.01 }} ; and Prohibit or restrict the use of the following functions, ports, protocols, software, and/or services: {{ insert: param, cm-

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CM-7[a] | Configure the system to provide only {{ insert: param, cm-07_odp.01 }} | Yes |
| CM-7[b] | Prohibit or restrict the use of the following functions, ports, protocols, software, and/or services: {{ insert: param,  | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-7-aws-001` | AWS | Unused security groups identified | EC2 | `ec2.describe_security_groups` | medium | [a], [b] |
| `cm-7-aws-002` | AWS | Unused IAM roles identified | IAM | `iam.list_roles` | medium | [a], [b] |
| `cm-7-azure-001` | AZURE | Unused resources identified | Advisor | `advisor.recommendations.list` | medium | [a], [b] |
| `cm-7-gcp-001` | GCP | Unused firewall rules identified | VPC | `compute.firewalls.list` | medium | [a], [b] |


#### CM-7(1) (Enhancement) — Review the system {{ insert: param, cm-07.01_odp.01 }} to identify unnecessary and/or nonsecure functions, ports, protocols, software, and services; and Disable or remove {{ insert: param, cm-7.1_prm_

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 15

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CM-7(1)[a] | Review the system {{ insert: param, cm-07.01_odp.01 }} to identify unnecessary and/or nonsecure functions, ports, protoc | Yes |
| CM-7(1)[b] | and Disable or remove {{ insert: param, cm-7.1_prm_2 }}. Organizations review functions, ports, protocols, and services  | Yes |
| CM-7(1)[c] | {{ insert: param, cm-07.01_odp.03 }} deemed to be unnecessary and/or non-secure are disabled or removed | Yes |
| CM-7(1)[d] | {{ insert: param, cm-07.01_odp.04 }} deemed to be unnecessary and/or non-secure are disabled or removed | Yes |
| CM-7(1)[e] | {{ insert: param, cm-07.01_odp.05 }} deemed to be unnecessary and/or non-secure is disabled or removed | Yes |
| CM-7(1)[f] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure are disabled or removed. Configuration m | Yes |
| CM-7(1)[g] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure are disabled or removed. Configuration m | Yes |
| CM-7(1)[h] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure are disabled or removed. Configuration m | Yes |
| CM-7(1)[i] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure are disabled or removed. Configuration m | Yes |
| CM-7(1)[j] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure are disabled or removed. Configuration m | Yes |
| CM-7(1)[k] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure are disabled or removed. Configuration m | Yes |
| CM-7(1)[l] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure are disabled or removed. Configuration m | Yes |
| CM-7(1)[m] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure are disabled or removed. Configuration m | Yes |
| CM-7(1)[n] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure are disabled or removed. Configuration m | Yes |
| CM-7(1)[o] | {{ insert: param, cm-07.01_odp.06 }} deemed to be unnecessary and/or non-secure are disabled or removed. Configuration m | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-7-1-aws-001` | AWS | Security groups restrict unnecessary ports | EC2 | `ec2.describe_security_groups` | high | [a], [b], [c], [d], [e], [f], [g], [h], [i], [j], [k], [l], [m], [n], [o] |
| `cm-7-1-aws-002` | AWS | Unnecessary AWS services restricted via SCP | Organizations | `organizations.list_policies` | medium | [a], [b], [c], [d], [e], [f], [g], [h], [i], [j], [k], [l], [m], [n], [o] |
| `cm-7-1-azure-001` | AZURE | NSG rules restrict unnecessary ports | Network | `network.network_security_groups.list` | high | [a], [b], [c], [d], [e], [f], [g], [h], [i], [j], [k], [l], [m], [n], [o] |
| `cm-7-1-gcp-001` | GCP | Firewall rules restrict unnecessary ports | VPC | `compute.firewalls.list` | high | [a], [b], [c], [d], [e], [f], [g], [h], [i], [j], [k], [l], [m], [n], [o] |


#### CM-7(5) (Enhancement) — Identify {{ insert: param, cm-07.05_odp.01 }}; Employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs on the system; and Review and update the list of aut

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CM-7(5)[a] | Identify {{ insert: param, cm-07.05_odp.01 }} | Yes |
| CM-7(5)[b] | Employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs on the system | Yes |
| CM-7(5)[c] | and Review and update the list of authorized software programs {{ insert: param, cm-07.05_odp.02 }}. Authorized software | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-7-5-aws-001` | AWS | SSM AppManager or application control configured | SSM | `ssm.list_documents` | medium | [a], [b], [c] |
| `cm-7-5-azure-001` | AZURE | Adaptive application controls enabled | Security Center | `security.assessments.list` | medium | [a], [b], [c] |
| `cm-7-5-gcp-001` | GCP | Binary Authorization enabled | Binary Authorization | `binaryauthorization.projects.getPolicy` | medium | [a], [b], [c] |


#### CM-8 — Develop and document an inventory of system components that: Accurately reflects the system; Includes all components within the system; Does not include duplicate accounting of components or component

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CM-8[a] | Develop and document an inventory of system components that: Accurately reflects the system | Yes |
| CM-8[b] | Includes all components within the system | Yes |
| CM-8[c] | Does not include duplicate accounting of components or components assigned to any other system | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-8-aws-001` | AWS | SSM software inventory collected | SSM | `ssm.describe_instance_information()` | medium | [a], [b], [c] |
| `cm-8-azure-001` | AZURE | Change Tracking and Inventory enabled | Automation | `automation.automation_accounts.list` | medium | [a], [b], [c] |
| `cm-8-gcp-001` | GCP | OS Config patch and inventory management | OS Config | `osconfig.patchDeployments.list` | medium | [a], [b], [c] |


#### CM-9 — Develop, document, and implement a configuration management plan for the system that: Addresses roles, responsibilities, and configuration management processes and procedures; Establishes a process fo

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### CM-10 — Use software and associated documentation in accordance with contract agreements and copyright laws; Track the use of software and associated documentation protected by quantity licenses to control co

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### CM-11 — Establish {{ insert: param, cm-11_odp.01 }} governing the installation of software by users; Enforce software installation policies through the following methods: {{ insert: param, cm-11_odp.02 }} ; a

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### CM-12 — Identify and document the location of {{ insert: param, cm-12_odp }} and the specific system components on which the information is processed and stored; Identify and document the users who have acces

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### CM-13 — Develop and document a map of system data actions. Data actions are system operations that process personally identifiable information. The processing of such information encompasses the full informat

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### CM-14 — Prevent the installation of {{ insert: param, cm-14_prm_1 }} without verification that the component has been digitally signed using a certificate that is recognized and approved by the organization. 

**Baseline:** High | **Type:** Manual | **Objectives:** 0


### CP — Contingency Planning

**Controls:** 13 | **Automated:** 6 | **Manual:** 7 | **Objectives:** 13 | **Checks:** AWS 16, Azure 14, GCP 14

#### CP-1 — Develop, document, and disseminate to {{ insert: param, cp-1_prm_1 }}: {{ insert: param, cp-01_odp.03 }} contingency planning policy that: Addresses purpose, scope, roles, responsibilities, management

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### CP-2 — Develop a contingency plan for the system that: Identifies essential mission and business functions and associated contingency requirements; Provides recovery objectives, restoration priorities, and m

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CP-2[a] | Develop a contingency plan for the system that: Identifies essential mission and business functions and associated conti | Yes |
| CP-2[c] | Provides recovery objectives, restoration priorities, and metrics | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cp-2-aws-001` | AWS | Resources tagged with DR plan metadata | EC2 + RDS | `ec2.describe_instances + rds.describe_db_instances` | medium | [a], [c] |
| `cp-2-azure-001` | AZURE | Resources tagged with DR plan metadata | Resources | `ResourceManagementClient.resources.list` | medium | [a], [c] |
| `cp-2-gcp-001` | GCP | Resources labeled with DR plan metadata | Compute Engine | `compute.instances.aggregatedList` | medium | [a], [c] |


#### CP-3 — Provide contingency training to system users consistent with assigned roles and responsibilities: Within {{ insert: param, cp-03_odp.01 }} of assuming a contingency role or responsibility; When requir

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### CP-4 — Test the contingency plan for the system {{ insert: param, cp-04_odp.01 }} using the following tests to determine the effectiveness of the plan and the readiness to execute the plan: {{ insert: param,

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CP-4[a] | Test the contingency plan for the system {{ insert: param, cp-04_odp.01 }} using the following tests to determine the ef | Yes |
| CP-4[b] | Initiate corrective actions, if needed. Methods for testing contingency plans to determine the effectiveness of the plan | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cp-4-aws-001` | AWS | AWS Resilience Hub assessments completed | ResilienceHub | `resiliencehub.list_app_assessments` | medium | [a], [b] |
| `cp-4-azure-001` | AZURE | Azure Site Recovery test failover documented | Recovery Services | `backup.backup_jobs.list` | medium | [a], [b] |
| `cp-4-gcp-001` | GCP | Disaster recovery test documented in Cloud Logging | Logging | `logging.entries.list` | medium | [a], [b] |


#### CP-5

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### CP-6 — Establish an alternate storage site, including necessary agreements to permit the storage and retrieval of system backup information; and Ensure that the alternate storage site provides controls equiv

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CP-6[a] | Establish an alternate storage site, including necessary agreements to permit the storage and retrieval of system backup | Yes |
| CP-6[b] | Ensure that the alternate storage site provides controls equivalent to that of the primary site. Alternate storage sites | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cp-6-aws-001` | AWS | S3 buckets have cross-region replication enabled | S3 | `s3.get_bucket_replication` | high | [a], [b] |
| `cp-6-aws-002` | AWS | RDS databases have cross-region read replicas | RDS | `rds.describe_db_instances` | high | [a], [b] |
| `cp-6-azure-001` | AZURE | Storage accounts have geo-redundant replication | Storage | `StorageManagementClient.storage_accounts.list` | high | [a], [b] |
| `cp-6-azure-002` | AZURE | SQL databases have geo-replication configured | SQL | `sql.servers.list + sql.replication_links.list_by_database` | high | [a], [b] |
| `cp-6-gcp-001` | GCP | Cloud Storage buckets use multi-region or dual-region | Storage | `storage.buckets.list` | high | [a], [b] |
| `cp-6-gcp-002` | GCP | Cloud SQL instances have HA and cross-region replicas | Cloud SQL | `sqladmin.instances.list` | high | [a], [b] |


#### CP-7 — Establish an alternate processing site, including necessary agreements to permit the transfer and resumption of {{ insert: param, cp-07_odp.01 }} for essential mission and business functions within {{

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CP-7[a] | Establish an alternate processing site, including necessary agreements to permit the transfer and resumption of {{ inser | Yes |
| CP-7[b] | Make available at the alternate processing site, the equipment and supplies required to transfer and resume operations o | Yes |
| CP-7[d] | Provide controls at the alternate processing site that are equivalent to those at the primary site. Alternate processing | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cp-7-aws-001` | AWS | Application deployed to multiple regions | EC2 | `ec2.describe_regions + ec2.describe_instances` | high | [a], [b], [d] |
| `cp-7-aws-002` | AWS | Route 53 health checks configured for failover | Route53 | `route53.list_health_checks` | high | [a], [d] |
| `cp-7-azure-001` | AZURE | Application deployed to multiple regions | Compute | `compute.virtual_machines.list_all` | high | [a], [b], [d] |
| `cp-7-azure-002` | AZURE | Traffic Manager or Front Door configured for failover | Resources | `resource.resources.list` | high | [a], [d] |
| `cp-7-gcp-001` | GCP | Application deployed to multiple regions | Compute Engine | `compute.instanceGroupManagers.aggregatedList` | high | [a], [b], [d] |
| `cp-7-gcp-002` | GCP | Cloud Load Balancing configured with multi-region backends | Compute Engine | `compute.backendServices.list` | high | [a], [d] |


#### CP-8 — Establish alternate telecommunications services, including necessary agreements to permit the resumption of {{ insert: param, cp-08_odp.01 }} for essential mission and business functions within {{ ins

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### CP-9 — Conduct backups of user-level information contained in {{ insert: param, cp-09_odp.01 }} {{ insert: param, cp-09_odp.02 }}; Conduct backups of system-level information contained in the system {{ inser

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CP-9[a] | Conduct backups of user-level information contained in {{ insert: param, cp-09_odp.01 }} {{ insert: param, cp-09_odp.02  | Yes |
| CP-9[c] | Conduct backups of system-level information contained in the system {{ insert: param, cp-09_odp.03 }} | Yes |
| CP-9[d] | Conduct backups of system documentation, including security- and privacy-related documentation {{ insert: param, cp-09_o | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cp-9-aws-001` | AWS | AWS Backup vaults configured with backup plans | Backup | `backup.list_backup_vaults` | critical | [a], [c], [d] |
| `cp-9-aws-002` | AWS | RDS automated backups enabled | RDS | `rds.describe_db_instances` | critical | [a], [c] |
| `cp-9-aws-003` | AWS | EBS snapshots scheduled for volumes | EC2 | `ec2.describe_snapshots` | high | [a], [c] |
| `cp-9-aws-004` | AWS | DynamoDB point-in-time recovery enabled | DynamoDB | `dynamodb.describe_continuous_backups` | high | [a], [c] |
| `cp-9-azure-001` | AZURE | Azure Backup configured for VMs | Recovery Services | `RecoveryServicesBackupClient.backup_protected_items.list` | critical | [a], [c], [d] |
| `cp-9-azure-002` | AZURE | SQL Database automated backups configured | SQL | `sql.servers.list + sql.backup_short_term_retention_policies.get` | critical | [a], [c] |
| `cp-9-azure-003` | AZURE | Storage account soft delete enabled | Storage | `StorageManagementClient.blob_services.get_service_properties` | high | [a], [c] |
| `cp-9-gcp-001` | GCP | Compute Engine persistent disk snapshots scheduled | Compute Engine | `compute.resourcePolicies.list` | critical | [a], [c], [d] |
| `cp-9-gcp-002` | GCP | Cloud SQL automated backups enabled | Cloud SQL | `sqladmin.instances.list` | critical | [a], [c] |
| `cp-9-gcp-003` | GCP | Cloud Storage bucket versioning enabled | Storage | `storage.buckets.get` | high | [a], [c] |


#### CP-9(1) (Enhancement) — Test backup information {{ insert: param, cp-9.1_prm_1 }} to verify media reliability and information integrity. Organizations need assurance that backup information can be reliably retrieved. Reliabi

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CP-9(1)[a] | Test backup information {{ insert: param, cp-9.1_prm_1 }} to verify media reliability and information integrity. Organiz | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cp-9-1-aws-001` | AWS | AWS Backup restore jobs completed successfully | Backup | `backup.list_restore_jobs` | high | [a] |
| `cp-9-1-azure-001` | AZURE | Azure Backup restore jobs tested | Recovery Services | `RecoveryServicesBackupClient.restore_jobs.list` | high | [a] |
| `cp-9-1-gcp-001` | GCP | Snapshot restore operations logged and verified | Compute Engine | `compute.snapshots.list` | high | [a] |


#### CP-9(3) (Enhancement) — Store backup copies of {{ insert: param, cp-09.03_odp }} in a separate facility or in a fire rated container that is not collocated with the operational system. Separate storage for critical informati

**Baseline:** High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CP-9(3)[a] | Store backup copies of {{ insert: param, cp-09.03_odp }} in a separate facility or in a fire rated container that is not | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cp-9-3-aws-001` | AWS | Backups replicated to alternate region | Backup | `backup.list_backup_vaults` | high | [a] |
| `cp-9-3-azure-001` | AZURE | Backup data replicated to separate region | Recovery Services | `RecoveryServicesClient.vaults.list_by_subscription_id` | high | [a] |
| `cp-9-3-gcp-001` | GCP | Snapshots stored in separate region | Compute Engine | `compute.snapshots.list` | high | [a] |


#### CP-9(8) (Enhancement) — Implement cryptographic mechanisms to prevent unauthorized disclosure and modification of {{ insert: param, cp-09.08_odp }}. The selection of cryptographic mechanisms is based on the need to protect t

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CP-9(8)[a] | Implement cryptographic mechanisms to prevent unauthorized disclosure and modification of {{ insert: param, cp-09.08_odp | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cp-9-8-aws-001` | AWS | AWS Backup vault encryption enabled | Backup | `backup.describe_backup_vault` | high | [a] |
| `cp-9-8-aws-002` | AWS | RDS backup encryption enabled | RDS | `rds.describe_db_snapshots` | high | [a] |
| `cp-9-8-azure-001` | AZURE | Recovery Services vault encryption configured | Recovery Services | `recoveryservices.vaults.list` | high | [a] |
| `cp-9-8-gcp-001` | GCP | Snapshots encrypted with Cloud KMS | Compute Engine | `compute.snapshots.list` | high | [a] |


#### CP-10 — Provide for the recovery and reconstitution of the system to a known state within {{ insert: param, cp-10_prm_1 }} after a disruption, compromise, or failure. Recovery is executing contingency plan ac

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CP-10[a] | Provide for the recovery and reconstitution of the system to a known state within {{ insert: param, cp-10_prm_1 }} after | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cp-10-aws-001` | AWS | System recovery procedures documented in Systems Manager | EC2 + RDS | `ec2.describe_instances + rds.describe_db_instances` | medium | [a] |
| `cp-10-azure-001` | AZURE | Azure Site Recovery configured for critical VMs | Recovery Services | `RecoveryServicesClient.replication_protected_items.list` | medium | [a] |
| `cp-10-gcp-001` | GCP | Recovery procedures documented in Cloud Operations | Compute Engine | `compute.instances.aggregatedList` | medium | [a] |


#### CP-10(2) (Enhancement) — Implement transaction recovery for systems that are transaction-based. Transaction-based systems include database management systems and transaction processing systems. Mechanisms supporting transacti

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| CP-10(2)[a] | Implement transaction recovery for systems that are transaction-based. Transaction-based systems include database manage | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cp-10-2-aws-001` | AWS | RDS point-in-time recovery enabled | RDS | `rds.describe_db_instances` | high | [a] |
| `cp-10-2-azure-001` | AZURE | SQL Database point-in-time restore available | SQL | `SqlManagementClient.restorable_dropped_databases.list` | high | [a] |
| `cp-10-2-gcp-001` | GCP | Cloud SQL point-in-time recovery enabled | Cloud SQL | `sqladmin.instances.list` | high | [a] |


#### CP-11 — Provide the capability to employ {{ insert: param, cp-11_odp }} in support of maintaining continuity of operations. Contingency plans and the contingency training or testing associated with those plan

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### CP-12 — When {{ insert: param, cp-12_odp.02 }} are detected, enter a safe mode of operation with {{ insert: param, cp-12_odp.01 }}. For systems that support critical mission and business functions—including m

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### CP-13 — Employ {{ insert: param, cp-13_odp.01 }} for satisfying {{ insert: param, cp-13_odp.02 }} when the primary means of implementing the security function is unavailable or compromised. Use of alternative

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### IA — Identification and Authentication

**Controls:** 13 | **Automated:** 6 | **Manual:** 7 | **Objectives:** 15 | **Checks:** AWS 18, Azure 13, GCP 12

#### IA-1 — Develop, document, and disseminate to {{ insert: param, ia-1_prm_1 }}: {{ insert: param, ia-01_odp.03 }} identification and authentication policy that: Addresses purpose, scope, roles, responsibilitie

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### IA-2 — Uniquely identify and authenticate organizational users and associate that unique identification with processes acting on behalf of those users. Organizations can satisfy the identification and authen

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| IA-2[a] | Uniquely identify and authenticate organizational users and associate that unique identification with processes acting o | Yes |
| IA-2[b] | the unique identification of authenticated organizational users is associated with processes acting on behalf of those u | Yes |
| IA-2[c] | the unique identification of authenticated organizational users is associated with processes acting on behalf of those u | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-2-aws-001` | AWS | All IAM users uniquely identified | IAM | `iam.list_users` | high | [a], [b], [c] |
| `ia-2-aws-002` | AWS | Service accounts have descriptive names | IAM | `iam.list_roles` | medium | [a], [b], [c] |
| `ia-2-aws-003` | AWS | EC2 instances use instance profiles | EC2 | `ec2.describe_instances` | high | [a], [b], [c] |
| `ia-2-azure-001` | AZURE | All Azure AD users uniquely identified | Azure AD | `graph.users.list` | high | [a], [b], [c] |
| `ia-2-azure-002` | AZURE | Managed identities used for service authentication | Compute | `compute.virtual_machines.list` | high | [a], [b], [c] |
| `ia-2-gcp-001` | GCP | All users identified via Google Cloud Identity | IAM | `cloudresourcemanager.projects.getIamPolicy` | high | [a], [b], [c] |
| `ia-2-gcp-002` | GCP | Service accounts clearly identified | IAM | `iam.projects.serviceAccounts.list` | medium | [a], [b], [c] |


#### IA-2(1) (Enhancement) — Implement multi-factor authentication for access to privileged accounts. Multi-factor authentication requires the use of two or more different factors to achieve authentication. The authentication fac

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| IA-2(1)[a] | Implement multi-factor authentication for access to privileged accounts. Multi-factor authentication requires the use of | Yes |
| IA-2(1)[b] | Implement multi-factor authentication for access to privileged accounts. Multi-factor authentication requires the use of | Yes |
| IA-2(1)[c] | Implement multi-factor authentication for access to privileged accounts. Multi-factor authentication requires the use of | Yes |
| IA-2(1)[d] | Implement multi-factor authentication for access to privileged accounts. Multi-factor authentication requires the use of | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-2-1-aws-001` | AWS | MFA enforced for all console access | IAM | `iam.generate_credential_report` | critical | [a], [b], [c], [d] |
| `ia-2-1-aws-002` | AWS | MFA required for privileged API actions | IAM | `iam.get_policy_version` | high | [a], [b], [c], [d] |
| `ia-2-1-aws-003` | AWS | Hardware MFA used for root account | IAM | `iam.list_virtual_mfa_devices` | high | [a], [b], [c], [d] |
| `ia-2-1-azure-001` | AZURE | MFA required via Conditional Access | Azure AD | `graph.conditional_access_policies.list` | critical | [a], [b], [c], [d] |
| `ia-2-1-azure-002` | AZURE | MFA required for Azure management | Azure AD | `graph.conditional_access_policies.list` | critical | [a], [b], [c], [d] |
| `ia-2-1-gcp-001` | GCP | 2-Step Verification enforced organization-wide | Workspace Admin | `admin.directory.users.list` | critical | [a], [b], [c], [d] |
| `ia-2-1-gcp-002` | GCP | Security key required for admin accounts | Workspace Admin | `admin.directory.users.list` | high | [a], [b], [c], [d] |


#### IA-2(2) (Enhancement) — Implement multi-factor authentication for access to non-privileged accounts. Multi-factor authentication requires the use of two or more different factors to achieve authentication. The authentication

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| IA-2(2)[a] | Implement multi-factor authentication for access to non-privileged accounts. Multi-factor authentication requires the us | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-2-2-aws-001` | AWS | FIDO2/WebAuthn supported for MFA | IAM | `iam.list_mfa_devices` | medium | [a] |
| `ia-2-2-aws-002` | AWS | STS tokens are time-limited | STS | `iam.list_roles` | medium | [a] |
| `ia-2-2-azure-001` | AZURE | FIDO2 authentication method enabled | Azure AD | `graph.authentication_method_configurations.get` | medium | [a] |
| `ia-2-2-gcp-001` | GCP | Security key enforcement available | Workspace Admin | `admin.directory.users.list` | medium | [a] |


#### IA-3 — Uniquely identify and authenticate {{ insert: param, ia-03_odp.01 }} before establishing a {{ insert: param, ia-03_odp.02 }} connection. Devices that require unique device-to-device identification and

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| IA-3[a] | Uniquely identify and authenticate {{ insert: param, ia-03_odp.01 }} before establishing a {{ insert: param, ia-03_odp.0 | Yes |
| IA-3[b] | Uniquely identify and authenticate {{ insert: param, ia-03_odp.01 }} before establishing a {{ insert: param, ia-03_odp.0 | Yes |
| IA-3[c] | Uniquely identify and authenticate {{ insert: param, ia-03_odp.01 }} before establishing a {{ insert: param, ia-03_odp.0 | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-3-aws-001` | AWS | Root account has MFA enabled | IAM | `iam.get_account_summary` | critical | [a], [b], [c] |
| `ia-3-aws-002` | AWS | All IAM users with console access have MFA | IAM | `iam.generate_credential_report` | critical | [a], [b], [c] |
| `ia-3-azure-001` | AZURE | MFA registration required for all users | Azure AD | `graph.reports.credential_user_registration_details.list` | critical | [a], [b], [c] |
| `ia-3-azure-002` | AZURE | Legacy authentication blocked | Azure AD | `graph.conditional_access_policies.list` | high | [a], [b], [c] |
| `ia-3-gcp-001` | GCP | 2-Step Verification enforced | Workspace Admin | `admin.directory.users.list` | critical | [a], [b], [c] |


#### IA-4 — Manage system identifiers by: Receiving authorization from {{ insert: param, ia-04_odp.01 }} to assign an individual, group, role, service, or device identifier; Selecting an identifier that identifie

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| IA-4[a] | Manage system identifiers by: Receiving authorization from {{ insert: param, ia-04_odp.01 }} to assign an individual, gr | Yes |
| IA-4[b] | Selecting an identifier that identifies an individual, group, role, service, or device | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-4-aws-001` | AWS | Deleted IAM user names not reused within 90 days | IAM | `iam.list_users` | medium | [a], [b] |
| `ia-4-azure-001` | AZURE | Soft-deleted user accounts not reused | Azure AD | `graph.deleted_users.list` | medium | [a], [b] |
| `ia-4-gcp-001` | GCP | User account identifiers not reused | Workspace Admin | `admin.directory.users.list` | medium | [a], [b] |


#### IA-4(4) (Enhancement) — Manage individual identifiers by uniquely identifying each individual as {{ insert: param, ia-04.04_odp }}. Characteristics that identify the status of individuals include contractors, foreign nationa

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| IA-4(4)[a] | Manage individual identifiers by uniquely identifying each individual as {{ insert: param, ia-04.04_odp }}. Characterist | Yes |
| IA-4(4)[b] | Manage individual identifiers by uniquely identifying each individual as {{ insert: param, ia-04.04_odp }}. Characterist | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-4-4-aws-001` | AWS | IAM users inactive for 90 days identified | IAM | `iam.generate_credential_report` | high | [a], [b] |
| `ia-4-4-aws-002` | AWS | Access keys inactive for 90 days identified | IAM | `iam.generate_credential_report` | high | [a], [b] |
| `ia-4-4-azure-001` | AZURE | Inactive Azure AD accounts identified | Azure AD | `graph.users.list` | high | [a], [b] |
| `ia-4-4-gcp-001` | GCP | Inactive service account keys identified | IAM | `iam.projects.serviceAccounts.keys.list` | high | [a], [b] |


#### IA-5 — Manage system authenticators by: Verifying, as part of the initial authenticator distribution, the identity of the individual, group, role, service, or device receiving the authenticator; Establishing

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| IA-5[a] | Manage system authenticators by: Verifying, as part of the initial authenticator distribution, the identity of the indiv | Yes |
| IA-5[b] | Establishing initial authenticator content for any authenticators issued by the organization | Yes |
| IA-5[c] | Ensuring that authenticators have sufficient strength of mechanism for their intended use | Yes |
| IA-5[d] | Establishing and implementing administrative procedures for initial authenticator distribution, for lost or compromised  | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-5-aws-001` | AWS | IAM password policy enforces complexity | IAM | `iam.get_account_password_policy` | high | [a], [b], [c], [d] |
| `ia-5-azure-001` | AZURE | Azure AD password protection enabled | Azure AD | `graph.settings.list` | high | [a], [b], [c], [d] |
| `ia-5-gcp-001` | GCP | Password policy enforced in Workspace | Workspace Admin | `admin.directory.users.list` | high | [a], [b], [c], [d] |


#### IA-5(1) (Enhancement) — For password-based authentication: Maintain a list of commonly-used, expected, or compromised passwords and update the list {{ insert: param, ia-05.01_odp.01 }} and when organizational passwords are s

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| IA-5(1)[a] | For password-based authentication: Maintain a list of commonly-used, expected, or compromised passwords and update the l | Yes |
| IA-5(1)[b] | Verify, when users create or update passwords, that the passwords are not found on the list of commonly-used, expected,  | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-5-1-aws-001` | AWS | Password reuse prevention configured | IAM | `iam.get_account_password_policy` | high | [a], [b] |
| `ia-5-1-azure-001` | AZURE | Password history enforced | Azure AD | `graph.settings.list` | high | [a], [b] |
| `ia-5-1-gcp-001` | GCP | Password reuse restricted in Workspace | Workspace Admin | `admin.directory.users.list` | high | [a], [b] |


#### IA-5(2) (Enhancement) — For public key-based authentication: Enforce authorized access to the corresponding private key; and Map the authenticated identity to the account of the individual or group; and When public key infra

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| IA-5(2)[a] | For public key-based authentication: Enforce authorized access to the corresponding private key | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-5-2-aws-001` | AWS | IAM Identity Center force password change on first login | IAM Identity Center | `sso-admin.list_instances()` | medium | [a] |
| `ia-5-2-azure-001` | AZURE | Force password change on new accounts | Azure AD | `graph.users.list` | medium | [a] |
| `ia-5-2-gcp-001` | GCP | Force password change for new users | Workspace Admin | `admin.directory.users.list` | medium | [a] |


#### IA-6 — Obscure feedback of authentication information during the authentication process to protect the information from possible exploitation and use by unauthorized individuals. Authentication feedback from

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### IA-7 — Implement mechanisms for authentication to a cryptographic module that meet the requirements of applicable laws, executive orders, directives, policies, regulations, standards, and guidelines for such

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### IA-8 — Uniquely identify and authenticate non-organizational users or processes acting on behalf of non-organizational users. Non-organizational users include system users other than organizational users exp

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| IA-8[a] | Uniquely identify and authenticate non-organizational users or processes acting on behalf of non-organizational users. N | Yes |
| IA-8[b] | Uniquely identify and authenticate non-organizational users or processes acting on behalf of non-organizational users. N | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-8-aws-001` | AWS | TLS enforced for all API communication | IAM | `iam.get_credential_report()` | high | [a], [b] |
| `ia-8-aws-002` | AWS | Database passwords encrypted in transit | RDS | `rds.describe_db_instances` | high | [a], [b] |
| `ia-8-azure-001` | AZURE | HTTPS-only access enforced | App Service | `web.web_apps.list` | high | [a], [b] |
| `ia-8-gcp-001` | GCP | SSL enforced on Cloud SQL instances | Cloud SQL | `sqladmin.instances.list` | high | [a], [b] |


#### IA-9 — Uniquely identify and authenticate {{ insert: param, ia-09_odp }} before establishing communications with devices, users, or other services or applications. Services that may require identification an

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### IA-10 — Require individuals accessing the system to employ {{ insert: param, ia-10_odp.01 }} under specific {{ insert: param, ia-10_odp.02 }}. Adversaries may compromise individual authentication mechanisms e

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### IA-11 — Require users to re-authenticate when {{ insert: param, ia-11_odp }}. In addition to the re-authentication requirements associated with device locks, organizations may require re-authentication of ind

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| IA-11[a] | Require users to re-authenticate when {{ insert: param, ia-11_odp }}. In addition to the re-authentication requirements  | No |

**Documentation Requirements:**

- **IA-11[a]**: authentication information is obscured during the authentication process. — *Provide documentation or process evidence: authentication information is obscured during the authentication process.*


#### IA-12 — Identity proof users that require accounts for logical access to systems based on appropriate identity assurance level requirements as specified in applicable standards and guidelines; Resolve user id

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### IA-13 — Employ identity providers and authorization servers to manage user, device, and non-person entity (NPE) identities, attributes, and access rights supporting authentication and authorization decisions 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### IR — Incident Response

**Controls:** 10 | **Automated:** 3 | **Manual:** 7 | **Objectives:** 14 | **Checks:** AWS 4, Azure 3, GCP 3

#### IR-1 — Develop, document, and disseminate to {{ insert: param, ir-1_prm_1 }}: {{ insert: param, ir-01_odp.03 }} incident response policy that: Addresses purpose, scope, roles, responsibilities, management co

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### IR-2 — Provide incident response training to system users consistent with assigned roles and responsibilities: Within {{ insert: param, ir-02_odp.01 }} of assuming an incident response role or responsibility

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 7

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| IR-2[a] | Provide incident response training to system users consistent with assigned roles and responsibilities: Within {{ insert | Yes |
| IR-2[b] | When required by system changes | Yes |
| IR-2[c] | {{ insert: param, ir-02_odp.02 }} thereafter | Yes |
| IR-2[d] | Review and update incident response training content {{ insert: param, ir-02_odp.03 }} and following {{ insert: param, i | Yes |
| IR-2[e] | system administrators may require additional training on how to handle incidents | Yes |
| IR-2[f] | incident responders may receive more specific training on forensics, data collection techniques, reporting, system recov | Yes |
| IR-2[g] | incident response training is provided to system users consistent with assigned roles and responsibilities when required | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ir-2-aws-001` | AWS | GuardDuty enabled in all regions | GuardDuty | `guardduty.list_detectors` | critical | [a], [b], [c], [d], [e], [f], [g] |
| `ir-2-aws-002` | AWS | Security Hub enabled with automated findings | Security Hub | `securityhub.describe_hub` | high | [a], [b], [c], [d], [e], [f], [g] |
| `ir-2-aws-003` | AWS | EventBridge rules for security events | EventBridge | `events.list_rules` | high | [a], [b], [c], [d], [e], [f], [g] |
| `ir-2-aws-004` | AWS | IR playbooks documented in SSM Automation | SSM | `ssm.list_documents` | medium | [a], [b], [c], [d], [e], [f], [g] |
| `ir-2-azure-001` | AZURE | Microsoft Defender for Cloud enabled | Security Center | `security.pricings.list` | critical | [a], [b], [c], [d], [e], [f], [g] |
| `ir-2-azure-002` | AZURE | Microsoft Sentinel deployed | Sentinel | `securityinsight.sentinel_onboarding_states.list` | high | [a], [b], [c], [d], [e], [f], [g] |
| `ir-2-azure-003` | AZURE | Sentinel automation rules configured | Sentinel | `securityinsight.automation_rules.list` | medium | [a], [b], [c], [d], [e], [f], [g] |
| `ir-2-gcp-001` | GCP | Security Command Center Premium enabled | SCC | `securitycenter.organizations.getOrganizationSettings` | critical | [a], [b], [c], [d], [e], [f], [g] |
| `ir-2-gcp-002` | GCP | Event Threat Detection enabled | SCC | `securitycenter.securityHealthAnalyticsSettings` | high | [a], [b], [c], [d], [e], [f], [g] |
| `ir-2-gcp-003` | GCP | Pub/Sub notifications for SCC findings | SCC | `securitycenter.organizations.notificationConfigs.list` | high | [a], [b], [c], [d], [e], [f], [g] |


#### IR-3 — Test the effectiveness of the incident response capability for the system {{ insert: param, ir-03_odp.01 }} using the following tests: {{ insert: param, ir-03_odp.02 }}. Organizations test incident re

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### IR-4 — Implement an incident handling capability for incidents that is consistent with the incident response plan and includes preparation, detection and analysis, containment, eradication, and recovery; Coo

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 6

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| IR-4[a] | Implement an incident handling capability for incidents that is consistent with the incident response plan and includes  | No |
| IR-4[b] | Coordinate incident handling activities with contingency planning activities | No |
| IR-4[c] | Incorporate lessons learned from ongoing incident handling activities into incident response procedures, training, and t | No |
| IR-4[d] | Ensure the rigor, intensity, scope, and results of incident handling activities are comparable and predictable across th | No |
| IR-4[e] | user or administrator reports | No |
| IR-4[f] | reported supply chain events. An effective incident handling capability includes coordination among many organizational  | No |

**Documentation Requirements:**

- **IR-4[a]**: incidents are tracked. — *Provide documentation or process evidence: incidents are tracked.*
- **IR-4[b]**: incidents are documented. — *Provide documentation or process evidence: incidents are documented.*
- **IR-4[c]**: authorities to whom incidents are to be reported are identified. — *Provide documentation showing that authorities to whom incidents are to be reported are identified and documented.*
- **IR-4[d]**: organizational officials to whom incidents are to be reported are identified. — *Provide documentation showing that organizational officials to whom incidents are to be reported are identified and documented.*
- **IR-4[e]**: identified authorities are notified of incidents. — *Provide documentation or process evidence: identified authorities are notified of incidents.*
- **IR-4[f]**: identified organizational officials are notified of incidents. — *Provide documentation or process evidence: identified organizational officials are notified of incidents.*


#### IR-5 — Track and document incidents. Documenting incidents includes maintaining records about each incident, the status of the incident, and other pertinent information necessary for forensics as well as eva

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| IR-5[a] | Track and document incidents. Documenting incidents includes maintaining records about each incident, the status of the  | No |

**Documentation Requirements:**

- **IR-5[a]**: the incident response capability is tested. — *Provide documentation or process evidence: the incident response capability is tested.*


#### IR-6 — Require personnel to report suspected incidents to the organizational incident response capability within {{ insert: param, ir-06_odp.01 }} ; and Report incident information to {{ insert: param, ir-06

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### IR-7 — Provide an incident response support resource, integral to the organizational incident response capability, that offers advice and assistance to users of the system for the handling and reporting of i

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### IR-8 — Develop an incident response plan that: Provides the organization with a roadmap for implementing its incident response capability; Describes the structure and organization of the incident response ca

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### IR-9 — Respond to information spills by: Assigning {{ insert: param, ir-09_odp.01 }} with responsibility for responding to information spills; Identifying the specific information involved in the system cont

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### IR-10

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### MA — Maintenance

**Controls:** 7 | **Automated:** 4 | **Manual:** 3 | **Objectives:** 8 | **Checks:** AWS 5, Azure 3, GCP 3

#### MA-1 — Develop, document, and disseminate to {{ insert: param, ma-1_prm_1 }}: {{ insert: param, ma-01_odp.03 }} maintenance policy that: Addresses purpose, scope, roles, responsibilities, management commitme

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### MA-2 — Schedule, document, and review records of maintenance, repair, and replacement on system components in accordance with manufacturer or vendor specifications and/or organizational requirements; Approve

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MA-2[a] | Schedule, document, and review records of maintenance, repair, and replacement on system components in accordance with m | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ma-2-aws-001` | AWS | SSM Patch Manager configured | SSM | `ssm.describe_patch_baselines` | high | [a] |
| `ma-2-aws-002` | AWS | Patch compliance monitored | SSM | `ssm.describe_instance_patch_states` | high | [a] |
| `ma-2-aws-003` | AWS | RDS automatic minor version upgrade enabled | RDS | `rds.describe_db_instances` | medium | [a] |
| `ma-2-azure-001` | AZURE | Azure Update Management configured | Automation | `automation_account.list` | high | [a] |
| `ma-2-azure-002` | AZURE | VM patch assessment enabled | Compute | `compute.virtual_machines.list` | high | [a] |
| `ma-2-gcp-001` | GCP | OS Config patch management configured | OS Config | `osconfig.projects.patchDeployments.list` | high | [a] |
| `ma-2-gcp-002` | GCP | Container image vulnerability scanning | Artifact Registry | `containeranalysis.projects.occurrences.list` | high | [a] |


#### MA-3 — Approve, control, and monitor the use of system maintenance tools; and Review previously approved system maintenance tools {{ insert: param, ma-03_odp }}. Approving, controlling, monitoring, and revie

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MA-3[a] | Approve, control, and monitor the use of system maintenance tools | No |
| MA-3[b] | Review previously approved system maintenance tools {{ insert: param, ma-03_odp }}. Approving, controlling, monitoring,  | No |
| MA-3[c] | the use of system maintenance tools is controlled | No |
| MA-3[d] | the use of system maintenance tools is monitored | No |

**Documentation Requirements:**

- **MA-3[a]**: tools used to conduct system maintenance are controlled. — *Provide documentation or process evidence: tools used to conduct system maintenance are controlled.*
- **MA-3[b]**: techniques used to conduct system maintenance are controlled. — *Provide documentation or process evidence: techniques used to conduct system maintenance are controlled.*
- **MA-3[c]**: mechanisms used to conduct system maintenance are controlled. — *Provide documentation or process evidence: mechanisms used to conduct system maintenance are controlled.*
- **MA-3[d]**: personnel used to conduct system maintenance are controlled. — *Provide personnel records: personnel used to conduct system maintenance are controlled.*


#### MA-3(1) (Enhancement) — Inspect the maintenance tools used by maintenance personnel for improper or unauthorized modifications. Maintenance tools can be directly brought into a facility by maintenance personnel or downloaded

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MA-3(1)[a] | Inspect the maintenance tools used by maintenance personnel for improper or unauthorized modifications. Maintenance tool | No |

**Documentation Requirements:**

- **MA-3(1)[a]**: equipment to be removed from organizational spaces for off-site maintenance is sanitized of any CUI. — *Provide documentation or process evidence: equipment to be removed from organizational spaces for off-site maintenance is sanitized of any CUI.*


#### MA-3(2) (Enhancement) — Check media containing diagnostic and test programs for malicious code before the media are used in the system. If, upon inspection of media containing maintenance, diagnostic, and test programs, orga

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MA-3(2)[a] | Check media containing diagnostic and test programs for malicious code before the media are used in the system. If, upon | No |

**Documentation Requirements:**

- **MA-3(2)[a]**: media containing diagnostic and test programs are checked for malicious code before being used in organizational systems that process, store, or transmit CUI. — *Provide documentation or process evidence: media containing diagnostic and test programs are checked for malicious code before being used in organizational systems that process, store, or transmit CUI.*


#### MA-4 — Approve and monitor nonlocal maintenance and diagnostic activities; Allow the use of nonlocal maintenance and diagnostic tools only as consistent with organizational policy and documented in the secur

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MA-4[a] | Approve and monitor nonlocal maintenance and diagnostic activities | Yes |
| MA-4[b] | Allow the use of nonlocal maintenance and diagnostic tools only as consistent with organizational policy and documented  | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ma-4-aws-001` | AWS | Session Manager requires MFA for remote maintenance | SSM | `iam.get_policy_version` | high | [a], [b] |
| `ma-4-aws-002` | AWS | VPN connections require MFA | VPC | `ec2.describe_client_vpn_endpoints` | high | [a], [b] |
| `ma-4-azure-001` | AZURE | MFA required for Azure Bastion access | Azure AD | `graph.conditional_access_policies.list` | high | [a], [b] |
| `ma-4-gcp-001` | GCP | 2SV required for admin console access | Workspace Admin | `admin.directory.users.list` | high | [a], [b] |


#### MA-5 — Establish a process for maintenance personnel authorization and maintain a list of authorized maintenance organizations or personnel; Verify that non-escorted personnel performing maintenance on the s

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MA-5[a] | Establish a process for maintenance personnel authorization and maintain a list of authorized maintenance organizations  | No |

**Documentation Requirements:**

- **MA-5[a]**: maintenance personnel without required access authorization are supervised during maintenance activities. — *Provide personnel records: maintenance personnel without required access authorization are supervised during maintenance activities.*


#### MA-6 — Obtain maintenance support and/or spare parts for {{ insert: param, ma-06_odp.01 }} within {{ insert: param, ma-06_odp.02 }} of failure. Organizations specify the system components that result in incr

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### MA-7 — Restrict or prohibit field maintenance on {{ insert: param, ma-07_odp.01 }} to {{ insert: param, ma-07_odp.02 }}. Field maintenance is the type of maintenance conducted on a system or system component

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### MP — Media Protection

**Controls:** 8 | **Automated:** 6 | **Manual:** 2 | **Objectives:** 11 | **Checks:** AWS 9, Azure 6, GCP 5

#### MP-1 — Develop, document, and disseminate to {{ insert: param, mp-1_prm_1 }}: {{ insert: param, mp-01_odp.03 }} media protection policy that: Addresses purpose, scope, roles, responsibilities, management com

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### MP-2 — Restrict access to {{ insert: param, mp-2_prm_1 }} to {{ insert: param, mp-2_prm_2 }}. System media includes digital and non-digital media. Digital media includes flash drives, diskettes, magnetic tap

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MP-2[a] | Restrict access to {{ insert: param, mp-2_prm_1 }} to {{ insert: param, mp-2_prm_2 }}. System media includes digital and | No |
| MP-2[b] | access to {{ insert: param, mp-02_odp.03 }} is restricted to {{ insert: param, mp-02_odp.04 }}. System media protection  | No |
| MP-2[c] | access to {{ insert: param, mp-02_odp.03 }} is restricted to {{ insert: param, mp-02_odp.04 }}. System media protection  | No |
| MP-2[d] | access to {{ insert: param, mp-02_odp.03 }} is restricted to {{ insert: param, mp-02_odp.04 }}. System media protection  | No |

**Documentation Requirements:**

- **MP-2[a]**: paper media containing CUI is physically controlled. — *Provide physical security evidence: paper media containing CUI is physically controlled.*
- **MP-2[b]**: digital media containing CUI is physically controlled. — *Provide physical security evidence: digital media containing CUI is physically controlled.*
- **MP-2[c]**: paper media containing CUI is securely stored. — *Provide documentation or process evidence: paper media containing CUI is securely stored.*
- **MP-2[d]**: digital media containing CUI is securely stored. — *Provide documentation or process evidence: digital media containing CUI is securely stored.*


#### MP-3 — Mark system media indicating the distribution limitations, handling caveats, and applicable security markings (if any) of the information; and Exempt {{ insert: param, mp-03_odp.01 }} from marking if 

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MP-3[a] | Mark system media indicating the distribution limitations, handling caveats, and applicable security markings (if any) o | No |
| MP-3[b] | Exempt {{ insert: param, mp-03_odp.01 }} from marking if the media remain within {{ insert: param, mp-03_odp.02 }}. Secu | No |

**Documentation Requirements:**

- **MP-3[a]**: access to media containing CUI is controlled. — *Provide documentation or process evidence: access to media containing CUI is controlled.*
- **MP-3[b]**: accountability for media containing CUI is maintained during transport outside of controlled areas. — *Provide documentation or process evidence: accountability for media containing CUI is maintained during transport outside of controlled areas.*


#### MP-4 — Physically control and securely store {{ insert: param, mp-4_prm_1 }} within {{ insert: param, mp-4_prm_2 }} ; and Protect system media types defined in MP-4a until the media are destroyed or sanitize

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MP-4[a] | Physically control and securely store {{ insert: param, mp-4_prm_1 }} within {{ insert: param, mp-4_prm_2 }} | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `mp-4-aws-001` | AWS | S3 bucket policies restrict CUI access | S3 | `s3.get_bucket_policy` | high | [a] |
| `mp-4-aws-002` | AWS | EBS volumes encrypted | EC2 | `ec2.describe_volumes` | high | [a] |
| `mp-4-aws-003` | AWS | EBS default encryption enabled | EC2 | `ec2.get_ebs_encryption_by_default` | high | [a] |
| `mp-4-azure-001` | AZURE | Storage account access restricted | Storage | `storage.storage_accounts.list` | high | [a] |
| `mp-4-azure-002` | AZURE | Managed disk encryption enabled | Compute | `compute.disks.list` | high | [a] |
| `mp-4-gcp-001` | GCP | Cloud Storage bucket access restricted | Storage | `storage.buckets.getIamPolicy` | high | [a] |
| `mp-4-gcp-002` | GCP | Persistent disk encryption with CMEK | Compute | `compute.disks.list` | high | [a] |


#### MP-4(2) (Enhancement) — Restrict access to media storage areas and log access attempts and access granted using {{ insert: param, mp-4.2_prm_1 }}. Automated mechanisms include keypads, biometric readers, or card readers on t

**Baseline:** N/A | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MP-4(2)[a] | Restrict access to media storage areas and log access attempts and access granted using {{ insert: param, mp-4.2_prm_1 } | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `mp-4-2-aws-001` | AWS | Backup vault encrypted with KMS | Backup | `backup.list_backup_vaults` | high | [a] |
| `mp-4-2-aws-002` | AWS | Backup vault access policy restricts access | Backup | `backup.get_backup_vault_access_policy` | high | [a] |
| `mp-4-2-aws-003` | AWS | S3 cross-region replication encrypted | S3 | `s3.get_bucket_replication` | medium | [a] |
| `mp-4-2-azure-001` | AZURE | Recovery Services vault encrypted | Recovery Services | `recoveryservices.vaults.list` | high | [a] |
| `mp-4-2-azure-002` | AZURE | Backup vault soft delete enabled | Recovery Services | `recoveryservices.vaults.list` | medium | [a] |
| `mp-4-2-gcp-001` | GCP | Backup encrypted with CMEK | Backup and DR | `backupdr.projects.locations.backupVaults.list` | high | [a] |


#### MP-5 — Protect and control {{ insert: param, mp-05_odp.01 }} during transport outside of controlled areas using {{ insert: param, mp-5_prm_2 }}; Maintain accountability for system media during transport outs

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MP-5[a] | Protect and control {{ insert: param, mp-05_odp.01 }} during transport outside of controlled areas using {{ insert: para | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `mp-5-aws-001` | AWS | S3 buckets encrypted with KMS | S3 | `s3.get_bucket_encryption` | high | [a] |
| `mp-5-aws-002` | AWS | RDS instances encrypted | RDS | `rds.describe_db_instances` | high | [a] |
| `mp-5-aws-003` | AWS | EFS file systems encrypted | EFS | `efs.describe_file_systems` | high | [a] |
| `mp-5-azure-001` | AZURE | Storage accounts enforce encryption | Storage | `storage.storage_accounts.list` | high | [a] |
| `mp-5-azure-002` | AZURE | SQL Database TDE enabled | SQL | `sql.transparent_data_encryptions.get` | high | [a] |
| `mp-5-gcp-001` | GCP | Cloud Storage buckets use CMEK | Storage | `storage.buckets.get` | high | [a] |
| `mp-5-gcp-002` | GCP | Cloud SQL instances encrypted | Cloud SQL | `sqladmin.instances.list` | high | [a] |


#### MP-6 — Sanitize {{ insert: param, mp-6_prm_1 }} prior to disposal, release out of organizational control, or release for reuse using {{ insert: param, mp-6_prm_2 }} ; and Employ sanitization mechanisms with 

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MP-6[a] | Sanitize {{ insert: param, mp-6_prm_1 }} prior to disposal, release out of organizational control, or release for reuse  | No |
| MP-6[b] | Employ sanitization mechanisms with the strength and integrity commensurate with the security category or classification | No |

**Documentation Requirements:**

- **MP-6[a]**: system media containing CUI is sanitized or destroyed before disposal. — *Provide documentation or process evidence: system media containing CUI is sanitized or destroyed before disposal.*
- **MP-6[b]**: system media containing CUI is sanitized before it is released for reuse. — *Provide documentation or process evidence: system media containing CUI is sanitized before it is released for reuse.*


#### MP-6(1) (Enhancement) — Review, approve, track, document, and verify media sanitization and disposal actions. Organizations review and approve media to be sanitized to ensure compliance with records retention policies. Track

**Baseline:** High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MP-6(1)[a] | Review, approve, track, document, and verify media sanitization and disposal actions. Organizations review and approve m | No |
| MP-6(1)[b] | media sanitization and disposal actions are approved | No |

**Documentation Requirements:**

- **MP-6(1)[a]**: media containing CUI is marked with applicable CUI markings. — *Provide documentation or process evidence: media containing CUI is marked with applicable CUI markings.*
- **MP-6(1)[b]**: media containing CUI is marked with distribution limitations. — *Provide documentation or process evidence: media containing CUI is marked with distribution limitations.*


#### MP-7 — {{ insert: param, mp-07_odp.02 }} the use of {{ insert: param, mp-07_odp.01 }} on {{ insert: param, mp-07_odp.03 }} using {{ insert: param, mp-07_odp.04 }} ; and Prohibit the use of portable storage d

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MP-7[a] | {{ insert: param, mp-07_odp.02 }} the use of {{ insert: param, mp-07_odp.01 }} on {{ insert: param, mp-07_odp.03 }} usin | No |

**Documentation Requirements:**

- **MP-7[a]**: the use of removable media on system components containing CUI is controlled. — *Provide documentation or process evidence: the use of removable media on system components containing CUI is controlled.*


#### MP-7(1) (Enhancement)

**Baseline:** N/A | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| MP-7(1)[a] | Organization-defined requirement | No |

**Documentation Requirements:**

- **MP-7(1)[a]**: the use of portable storage devices is prohibited when such devices have no identifiable owner. — *Provide documentation or process evidence: the use of portable storage devices is prohibited when such devices have no identifiable owner.*


#### MP-8 — Establish {{ insert: param, mp-08_odp.01 }} that includes employing downgrading mechanisms with strength and integrity commensurate with the security category or classification of the information; Ver

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### PE — Physical and Environmental Protection

**Controls:** 23 | **Automated:** 5 | **Manual:** 18 | **Objectives:** 13 | **Checks:** AWS 0, Azure 0, GCP 0

#### PE-1 — Develop, document, and disseminate to {{ insert: param, pe-1_prm_1 }}: {{ insert: param, pe-01_odp.03 }} physical and environmental protection policy that: Addresses purpose, scope, roles, responsibil

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PE-2 — Develop, approve, and maintain a list of individuals with authorized access to the facility where the system resides; Issue authorization credentials for facility access; Review the access list detail

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| PE-2[a] | Develop, approve, and maintain a list of individuals with authorized access to the facility where the system resides | No |
| PE-2[b] | Issue authorization credentials for facility access | No |
| PE-2[c] | Review the access list detailing authorized facility access by individuals {{ insert: param, pe-02_odp }} | No |
| PE-2[d] | Remove individuals from the facility access list when access is no longer required. Physical access authorizations apply | No |

**Documentation Requirements:**

- **PE-2[a]**: authorized individuals allowed physical access are identified. — *Provide documentation showing that authorized individuals allowed physical access are identified and documented.*
- **PE-2[b]**: physical access to organizational systems is limited to authorized individuals. — *Provide physical security evidence: physical access to organizational systems is limited to authorized individuals.*
- **PE-2[c]**: physical access to equipment is limited to authorized individuals. — *Provide physical security evidence: physical access to equipment is limited to authorized individuals.*
- **PE-2[d]**: physical access to operating environments is limited to authorized individuals. — *Provide physical security evidence: physical access to operating environments is limited to authorized individuals.*


#### PE-3 — Enforce physical access authorizations at {{ insert: param, pe-03_odp.01 }} by: Verifying individual access authorizations before granting access to the facility; and Controlling ingress and egress to

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| PE-3[a] | Enforce physical access authorizations at {{ insert: param, pe-03_odp.01 }} by: Verifying individual access authorizatio | No |
| PE-3[b] | Controlling ingress and egress to the facility using {{ insert: param, pe-03_odp.02 }} | No |

**Documentation Requirements:**

- **PE-3[a]**: visitors are escorted. — *Provide documentation or process evidence: visitors are escorted.*
- **PE-3[b]**: visitor activity is monitored. — *Provide documentation or process evidence: visitor activity is monitored.*


#### PE-4 — Control physical access to {{ insert: param, pe-04_odp.01 }} within organizational facilities using {{ insert: param, pe-04_odp.02 }}. Security controls applied to system distribution and transmission

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### PE-5 — Control physical access to output from {{ insert: param, pe-05_odp }} to prevent unauthorized individuals from obtaining the output. Controlling physical access to output devices includes placing outp

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| PE-5[a] | Control physical access to output from {{ insert: param, pe-05_odp }} to prevent unauthorized individuals from obtaining | No |

**Documentation Requirements:**

- **PE-5[a]**: audit logs of physical access are maintained. — *Provide physical security evidence: audit logs of physical access are maintained.*


#### PE-6 — Monitor physical access to the facility where the system resides to detect and respond to physical security incidents; Review physical access logs {{ insert: param, pe-06_odp.01 }} and upon occurrence

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| PE-6[a] | Monitor physical access to the facility where the system resides to detect and respond to physical security incidents | No |
| PE-6[b] | Review physical access logs {{ insert: param, pe-06_odp.01 }} and upon occurrence of {{ insert: param, pe-06_odp.02 }} | No |
| PE-6[c] | Coordinate results of reviews and investigations with the organizational incident response capability. Physical access m | No |
| PE-6[d] | physical access logs are reviewed {{ insert: param, pe-06_odp.01 }} | No |

**Documentation Requirements:**

- **PE-6[a]**: the physical facility where that system resides is protected. — *Provide physical security evidence: the physical facility where that system resides is protected.*
- **PE-6[b]**: the support infrastructure for that system is protected. — *Provide documentation or process evidence: the support infrastructure for that system is protected.*
- **PE-6[c]**: the physical facility where that system resides is monitored. — *Provide physical security evidence: the physical facility where that system resides is monitored.*
- **PE-6[d]**: the support infrastructure for that system is monitored. — *Provide documentation or process evidence: the support infrastructure for that system is monitored.*


#### PE-6(1) (Enhancement) — Monitor physical access to the facility where the system resides using physical intrusion alarms and surveillance equipment. Physical intrusion alarms can be employed to alert security personnel when 

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| PE-6(1)[a] | Monitor physical access to the facility where the system resides using physical intrusion alarms and surveillance equipm | No |
| PE-6(1)[b] | physical access to the facility where the system resides is monitored using physical surveillance equipment. Physical an | No |
| PE-6(1)[c] | physical access to the facility where the system resides is monitored using physical surveillance equipment. Physical an | No |

**Documentation Requirements:**

- **PE-6(1)[a]**: physical access devices are identified. — *Provide documentation showing that physical access devices are identified and documented.*
- **PE-6(1)[b]**: physical access devices are controlled. — *Provide physical security evidence: physical access devices are controlled.*
- **PE-6(1)[c]**: physical access devices are managed. — *Provide physical security evidence: physical access devices are managed.*


#### PE-7

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PE-8 — Maintain visitor access records to the facility where the system resides for {{ insert: param, pe-08_odp.01 }}; Review visitor access records {{ insert: param, pe-08_odp.02 }} ; and Report anomalies i

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PE-9 — Protect power equipment and power cabling for the system from damage and destruction. Organizations determine the types of protection necessary for the power equipment and cabling employed at differen

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### PE-10 — Provide the capability of shutting off power to {{ insert: param, pe-10_odp.01 }} in emergency situations; Place emergency shutoff switches or devices in {{ insert: param, pe-10_odp.02 }} to facilitat

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### PE-11 — Provide an uninterruptible power supply to facilitate {{ insert: param, pe-11_odp }} in the event of a primary power source loss. An uninterruptible power supply (UPS) is an electrical system or mecha

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### PE-12 — Employ and maintain automatic emergency lighting for the system that activates in the event of a power outage or disruption and that covers emergency exits and evacuation routes within the facility. T

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PE-13 — Employ and maintain fire detection and suppression systems that are supported by an independent energy source. The provision of fire detection and suppression systems applies primarily to organization

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PE-14 — Maintain {{ insert: param, pe-14_odp.01 }} levels within the facility where the system resides at {{ insert: param, pe-14_odp.03 }} ; and Monitor environmental control levels {{ insert: param, pe-14_o

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PE-15 — Protect the system from damage resulting from water leakage by providing master shutoff or isolation valves that are accessible, working properly, and known to key personnel. The provision of water da

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PE-16 — Authorize and control {{ insert: param, pe-16_prm_1 }} entering and exiting the facility; and Maintain records of the system components. Enforcing authorizations for entry and exit of system component

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PE-17 — Determine and document the {{ insert: param, pe-17_odp.01 }} allowed for use by employees; Employ the following controls at alternate work sites: {{ insert: param, pe-17_odp.02 }}; Assess the effectiv

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| PE-17[a] | Determine and document the {{ insert: param, pe-17_odp.01 }} allowed for use by employees | No |
| PE-17[b] | Employ the following controls at alternate work sites: {{ insert: param, pe-17_odp.02 }} | No |

**Documentation Requirements:**

- **PE-17[a]**: safeguarding measures for CUI are defined for alternate work sites. — *Provide documentation showing that safeguarding measures for cui are defined.*
- **PE-17[b]**: safeguarding measures for CUI are enforced for alternate work sites. — *Provide documentation or process evidence: safeguarding measures for CUI are enforced for alternate work sites.*


#### PE-18 — Position system components within the facility to minimize potential damage from {{ insert: param, pe-18_odp }} and to minimize the opportunity for unauthorized access. Physical and environmental haza

**Baseline:** High | **Type:** Manual | **Objectives:** 0


#### PE-19 — Protect the system from information leakage due to electromagnetic signals emanations. Information leakage is the intentional or unintentional release of data or information to an untrusted environmen

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PE-20 — Employ {{ insert: param, pe-20_odp.01 }} to track and monitor the location and movement of {{ insert: param, pe-20_odp.02 }} within {{ insert: param, pe-20_odp.03 }}. Asset location technologies can h

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PE-21 — Employ {{ insert: param, pe-21_odp.01 }} against electromagnetic pulse damage for {{ insert: param, pe-21_odp.02 }}. An electromagnetic pulse (EMP) is a short burst of electromagnetic energy that is s

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PE-22 — Mark {{ insert: param, pe-22_odp }} indicating the impact level or classification level of the information permitted to be processed, stored, or transmitted by the hardware component. Hardware compone

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PE-23 — Plan the location or site of the facility where the system resides considering physical and environmental hazards; and For existing facilities, consider the physical and environmental hazards in the o

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### PL — Planning

**Controls:** 11 | **Automated:** 2 | **Manual:** 9 | **Objectives:** 2 | **Checks:** AWS 3, Azure 3, GCP 3

#### PL-1 — Develop, document, and disseminate to {{ insert: param, pl-1_prm_1 }}: {{ insert: param, pl-01_odp.03 }} planning policy that: Addresses purpose, scope, roles, responsibilities, management commitment,

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PL-2 — Develop security and privacy plans for the system that: Are consistent with the organization’s enterprise architecture; Explicitly define the constituent system components; Describe the operational co

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| PL-2[a] | Develop security and privacy plans for the system that: Are consistent with the organization’s enterprise architecture | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `pl-2-aws-001` | AWS | Systems Manager documents for security plans exist | SSM | `ssm.list_documents` | medium | [a] |
| `pl-2-azure-001` | AZURE | Blueprints or Policy definitions for security plans exist | Policy | `policy.policy_assignments.list` | medium | [a] |
| `pl-2-gcp-001` | GCP | Organization policies document security requirements | Organization Policy | `cloudresourcemanager.projects.getEffectiveOrgPolicy` | medium | [a] |


#### PL-3

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PL-4 — Establish and provide to individuals requiring access to the system, the rules that describe their responsibilities and expected behavior for information and system usage, security, and privacy; Recei

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PL-5

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PL-6

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PL-7 — Develop a Concept of Operations (CONOPS) for the system describing how the organization intends to operate the system from the perspective of information security and privacy; and Review and update th

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PL-8 — Develop security and privacy architectures for the system that: Describe the requirements and approach to be taken for protecting the confidentiality, integrity, and availability of organizational inf

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| PL-8[a] | Develop security and privacy architectures for the system that: Describe the requirements and approach to be taken for p | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `pl-8-aws-001` | AWS | Resources tagged with architecture metadata | EC2 + RDS | `ec2.describe_instances + rds.describe_db_instances` | medium | [a] |
| `pl-8-aws-002` | AWS | VPC architecture documented with flow logs | EC2 | `ec2.describe_flow_logs` | medium | [a] |
| `pl-8-azure-001` | AZURE | Resources tagged with architecture metadata | Resources | `ResourceManagementClient.resources.list` | medium | [a] |
| `pl-8-azure-002` | AZURE | Network architecture documented with NSG flow logs | Network | `NetworkManagementClient.flow_logs.list` | medium | [a] |
| `pl-8-gcp-001` | GCP | Resources labeled with architecture metadata | Compute Engine | `compute.instances.aggregatedList` | medium | [a] |
| `pl-8-gcp-002` | GCP | VPC architecture documented with flow logs | Compute Engine | `compute.subnetworks.list` | medium | [a] |


#### PL-9 — Centrally manage {{ insert: param, pl-09_odp }}. Central management refers to organization-wide management and implementation of selected controls and processes. This includes planning, implementing, 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PL-10 — Select a control baseline for the system. Control baselines are predefined sets of controls specifically assembled to address the protection needs of a group, organization, or community of interest. C

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PL-11 — Tailor the selected control baseline by applying specified tailoring actions. The concept of tailoring allows organizations to specialize or customize a set of baseline controls by applying a defined 

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


### PM — Program Management

**Controls:** 32 | **Automated:** 0 | **Manual:** 32 | **Objectives:** 0 | **Checks:** AWS 0, Azure 0, GCP 0

#### PM-1 — Develop and disseminate an organization-wide information security program plan that: Provides an overview of the requirements for the security program and a description of the security program managem

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-2 — Appoint a senior agency information security officer with the mission and resources to coordinate, develop, implement, and maintain an organization-wide information security program. The senior agency

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-3 — Include the resources needed to implement the information security and privacy programs in capital planning and investment requests and document all exceptions to this requirement; Prepare documentati

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-4 — Implement a process to ensure that plans of action and milestones for the information security, privacy, and supply chain risk management programs and associated organizational systems: Are developed 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-5 — Develop and update {{ insert: param, pm-05_odp }} an inventory of organizational systems. [OMB A-130](#27847491-5ce1-4f6a-a1e4-9e483782f0ef) provides guidance on developing systems inventories and ass

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-6 — Develop, monitor, and report on the results of information security and privacy measures of performance. Measures of performance are outcome-based metrics used by an organization to measure the effect

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-7 — Develop and maintain an enterprise architecture with consideration for information security, privacy, and the resulting risk to organizational operations and assets, individuals, other organizations, 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-8 — Address information security and privacy issues in the development, documentation, and updating of a critical infrastructure and key resources protection plan. Protection strategies are based on the p

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-9 — Develops a comprehensive strategy to manage: Security risk to organizational operations and assets, individuals, other organizations, and the Nation associated with the operation and use of organizati

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-10 — Manage the security and privacy state of organizational systems and the environments in which those systems operate through authorization processes; Designate individuals to fulfill specific roles and

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-11 — Define organizational mission and business processes with consideration for information security and privacy and the resulting risk to organizational operations, organizational assets, individuals, ot

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-12 — Implement an insider threat program that includes a cross-discipline insider threat incident handling team. Organizations that handle classified information are required, under Executive Order 13587 [

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-13 — Establish a security and privacy workforce development and improvement program. Security and privacy workforce development and improvement programs include defining the knowledge, skills, and abilitie

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-14 — Implement a process for ensuring that organizational plans for conducting security and privacy testing, training, and monitoring activities associated with organizational systems: Are developed and ma

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-15 — Establish and institutionalize contact with selected groups and associations within the security and privacy communities: To facilitate ongoing security and privacy education and training for organiza

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-16 — Implement a threat awareness program that includes a cross-organization information-sharing capability for threat intelligence. Because of the constantly changing and increasing sophistication of adve

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-17 — Establish policy and procedures to ensure that requirements for the protection of controlled unclassified information that is processed, stored or transmitted on external systems, are implemented in a

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-18 — Develop and disseminate an organization-wide privacy program plan that provides an overview of the agency’s privacy program, and: Includes a description of the structure of the privacy program and the

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-19 — Appoint a senior agency official for privacy with the authority, mission, accountability, and resources to coordinate, develop, and implement, applicable privacy requirements and manage privacy risks 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-20 — Maintain a central resource webpage on the organization’s principal public website that serves as a central source of information about the organization’s privacy program and that: Ensures that the pu

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-21 — Develop and maintain an accurate accounting of disclosures of personally identifiable information, including: Date, nature, and purpose of each disclosure; and Name and address, or other contact infor

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-22 — Develop and document organization-wide policies and procedures for: Reviewing for the accuracy, relevance, timeliness, and completeness of personally identifiable information across the information li

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-23 — Establish a Data Governance Body consisting of {{ insert: param, pm-23_odp.01 }} with {{ insert: param, pm-23_odp.02 }}. A Data Governance Body can help ensure that the organization has coherent polic

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-24 — Establish a Data Integrity Board to: Review proposals to conduct or participate in a matching program; and Conduct an annual review of all matching programs in which the agency has participated. A Dat

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-25 — Develop, document, and implement policies and procedures that address the use of personally identifiable information for internal testing, training, and research; Limit or minimize the amount of perso

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-26 — Implement a process for receiving and responding to complaints, concerns, or questions from individuals about the organizational security and privacy practices that includes: Mechanisms that are easy 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-27 — Develop {{ insert: param, pm-27_odp.01 }} and disseminate to: {{ insert: param, pm-27_odp.02 }} to demonstrate accountability with statutory, regulatory, and policy privacy mandates; and {{ insert: pa

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-28 — Identify and document: Assumptions affecting risk assessments, risk responses, and risk monitoring; Constraints affecting risk assessments, risk responses, and risk monitoring; Priorities and trade-of

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-29 — Appoint a Senior Accountable Official for Risk Management to align organizational information security and privacy management processes with strategic, operational, and budgetary planning processes; a

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-30 — Develop an organization-wide strategy for managing supply chain risks associated with the development, acquisition, maintenance, and disposal of systems, system components, and system services; Implem

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-31 — Develop an organization-wide continuous monitoring strategy and implement continuous monitoring programs that include: Establishing the following organization-wide metrics to be monitored: {{ insert: 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PM-32 — Analyze {{ insert: param, pm-32_odp }} supporting mission essential services or functions to ensure that the information resources are being used consistent with their intended purpose. Systems are de

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### PS — Personnel Security

**Controls:** 9 | **Automated:** 2 | **Manual:** 7 | **Objectives:** 4 | **Checks:** AWS 0, Azure 0, GCP 0

#### PS-1 — Develop, document, and disseminate to {{ insert: param, ps-1_prm_1 }}: {{ insert: param, ps-01_odp.03 }} personnel security policy that: Addresses purpose, scope, roles, responsibilities, management c

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PS-2 — Assign a risk designation to all organizational positions; Establish screening criteria for individuals filling those positions; and Review and update position risk designations {{ insert: param, ps-0

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PS-3 — Screen individuals prior to authorizing access to the system; and Rescreen individuals in accordance with {{ insert: param, ps-3_prm_1 }}. Personnel screening and rescreening activities reflect applic

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| PS-3[a] | Screen individuals prior to authorizing access to the system | No |

**Documentation Requirements:**

- **PS-3[a]**: individuals are screened prior to authorizing access to organizational systems. — *Provide documentation or process evidence: individuals are screened prior to authorizing access to organizational systems.*


#### PS-4 — Upon termination of individual employment: Disable system access within {{ insert: param, ps-04_odp.01 }}; Terminate or revoke any authenticators and credentials associated with the individual; Conduc

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| PS-4[a] | Upon termination of individual employment: Disable system access within {{ insert: param, ps-04_odp.01 }} | No |
| PS-4[b] | Terminate or revoke any authenticators and credentials associated with the individual | No |
| PS-4[c] | Conduct exit interviews that include a discussion of {{ insert: param, ps-04_odp.02 }} | No |

**Documentation Requirements:**

- **PS-4[a]**: a policy and/or process for terminating system access authorization and any credentials coincident with personnel actions is established. — *Provide personnel records: a policy and/or process for terminating system access authorization and any credentials coincident with personnel actions is established.*
- **PS-4[b]**: system access and credentials are terminated consistent with personnel actions such as termination or transfer. — *Provide personnel records: system access and credentials are terminated consistent with personnel actions such as termination or transfer.*
- **PS-4[c]**: the system is protected during and after personnel transfer actions. — *Provide personnel records: the system is protected during and after personnel transfer actions.*


#### PS-5 — Review and confirm ongoing operational need for current logical and physical access authorizations to systems and facilities when individuals are reassigned or transferred to other positions within th

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PS-6 — Develop and document access agreements for organizational systems; Review and update the access agreements {{ insert: param, ps-06_odp.01 }} ; and Verify that individuals requiring access to organizat

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PS-7 — Establish personnel security requirements, including security roles and responsibilities for external providers; Require external providers to comply with personnel security policies and procedures es

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PS-8 — Employ a formal sanctions process for individuals failing to comply with established information security and privacy policies and procedures; and Notify {{ insert: param, ps-08_odp.01 }} within {{ in

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### PS-9 — Incorporate security and privacy roles and responsibilities into organizational position descriptions. Specification of security and privacy roles in individual organizational position descriptions fa

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


### PT — Personally Identifiable Information Processing and Transparency

**Controls:** 8 | **Automated:** 3 | **Manual:** 5 | **Objectives:** 4 | **Checks:** AWS 5, Azure 5, GCP 5

#### PT-1 — Develop, document, and disseminate to {{ insert: param, pt-1_prm_1 }}: {{ insert: param, pt-01_odp.03 }} personally identifiable information processing and transparency policy that: Addresses purpose,

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PT-2 — Determine and document the {{ insert: param, pt-02_odp.01 }} that permits the {{ insert: param, pt-02_odp.02 }} of personally identifiable information; and Restrict the {{ insert: param, pt-02_odp.03 

**Baseline:** N/A | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| PT-2[a] | Determine and document the {{ insert: param, pt-02_odp.01 }} that permits the {{ insert: param, pt-02_odp.02 }} of perso | Yes |
| PT-2[b] | Restrict the {{ insert: param, pt-02_odp.03 }} of personally identifiable information to only that which is authorized.  | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `pt-2-aws-001` | AWS | Macie enabled for PII data discovery | Macie2 | `macie2.get_macie_session` | high | [a], [b] |
| `pt-2-aws-002` | AWS | S3 buckets tagged with data classification | S3 | `s3.get_bucket_tagging` | high | [a] |
| `pt-2-aws-003` | AWS | RDS databases tagged with data classification | RDS | `rds.list_tags_for_resource` | high | [a] |
| `pt-2-azure-001` | AZURE | Microsoft Purview enabled for data discovery | Resources | `resource.resources.list` | high | [a], [b] |
| `pt-2-azure-002` | AZURE | Storage accounts tagged with data classification | Storage | `StorageManagementClient.storage_accounts.list` | high | [a] |
| `pt-2-azure-003` | AZURE | SQL databases tagged with data classification | SQL | `sql.servers.list` | high | [a] |
| `pt-2-gcp-001` | GCP | Cloud DLP enabled for PII discovery | DLP | `dlp.projects.dlpJobs.list` | high | [a], [b] |
| `pt-2-gcp-002` | GCP | Storage buckets labeled with data classification | Storage | `storage.buckets.get` | high | [a] |
| `pt-2-gcp-003` | GCP | BigQuery datasets labeled with data classification | BigQuery | `bigquery.datasets.list` | high | [a] |


#### PT-3 — Identify and document the {{ insert: param, pt-03_odp.01 }} for processing personally identifiable information; Describe the purpose(s) in the public privacy notices and policies of the organization; 

**Baseline:** N/A | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| PT-3[a] | Identify and document the {{ insert: param, pt-03_odp.01 }} for processing personally identifiable information | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `pt-3-aws-001` | AWS | Resources tagged with data processing purpose | EC2 + RDS | `ec2.describe_instances + rds.describe_db_instances` | medium | [a] |
| `pt-3-azure-001` | AZURE | Resources tagged with data processing purpose | Resources | `ResourceManagementClient.resources.list` | medium | [a] |
| `pt-3-gcp-001` | GCP | Resources labeled with data processing purpose | Compute Engine | `compute.instances.aggregatedList + storage.buckets.list` | medium | [a] |


#### PT-4 — Implement {{ insert: param, pt-04_odp }} for individuals to consent to the processing of their personally identifiable information prior to its collection that facilitate individuals’ informed decisio

**Baseline:** N/A | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| PT-4[a] | Implement {{ insert: param, pt-04_odp }} for individuals to consent to the processing of their personally identifiable i | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `pt-4-aws-001` | AWS | API Gateway includes consent mechanism documentation | API Gateway | `apigateway.get_rest_apis` | medium | [a] |
| `pt-4-azure-001` | AZURE | API Management includes consent documentation | Resources | `resource.resources.list` | medium | [a] |
| `pt-4-gcp-001` | GCP | API Gateway includes consent mechanism documentation | Service Usage | `serviceusage.services.list` | medium | [a] |


#### PT-5 — Provide notice to individuals about the processing of personally identifiable information that: Is available to individuals upon first interacting with an organization, and subsequently at {{ insert: 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PT-6 — For systems that process information that will be maintained in a Privacy Act system of records: Draft system of records notices in accordance with OMB guidance and submit new and significantly modifi

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PT-7 — Apply {{ insert: param, pt-07_odp }} for specific categories of personally identifiable information. Organizations apply any conditions or protections that may be necessary for specific categories of 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### PT-8 — When a system or organization processes information for the purpose of conducting a matching program: Obtain approval from the Data Integrity Board to conduct the matching program; Develop and enter i

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### RA — Risk Assessment

**Controls:** 10 | **Automated:** 2 | **Manual:** 8 | **Objectives:** 7 | **Checks:** AWS 5, Azure 5, GCP 5

#### RA-1 — Develop, document, and disseminate to {{ insert: param, ra-1_prm_1 }}: {{ insert: param, ra-01_odp.03 }} risk assessment policy that: Addresses purpose, scope, roles, responsibilities, management comm

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### RA-2 — Categorize the system and information it processes, stores, and transmits; Document the security categorization results, including supporting rationale, in the security plan for the system; and Verify

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### RA-3 — Conduct a risk assessment, including: Identifying threats to and vulnerabilities in the system; Determining the likelihood and magnitude of harm from unauthorized access, use, disclosure, disruption, 

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| RA-3[a] | Conduct a risk assessment, including: Identifying threats to and vulnerabilities in the system | No |
| RA-3[b] | Determining the likelihood and magnitude of harm from unauthorized access, use, disclosure, disruption, modification, or | No |

**Documentation Requirements:**

- **RA-3[a]**: the frequency to assess risk to organizational operations, organizational assets, and individuals is defined. — *Provide documentation showing that the frequency to assess risk to organizational operations, organizational assets, and individuals are defined.*
- **RA-3[b]**: risk to organizational operations, organizational assets, and individuals resulting from the operation of an organizational system that processes, stores, or transmits CUI is assessed with the defined frequency. — *Provide documentation or process evidence: risk to organizational operations, organizational assets, and individuals resulting from the operation of an organizational system that processes, stores, or transmits CUI is assessed with the defined frequency.*


#### RA-4

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### RA-5 — Monitor and scan for vulnerabilities in the system and hosted applications {{ insert: param, ra-5_prm_1 }} and when new vulnerabilities potentially affecting the system are identified and reported; Em

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 5

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| RA-5[a] | Monitor and scan for vulnerabilities in the system and hosted applications {{ insert: param, ra-5_prm_1 }} and when new  | Yes |
| RA-5[b] | Employ vulnerability monitoring tools and techniques that facilitate interoperability among tools and automate parts of  | Yes |
| RA-5[c] | Formatting checklists and test procedures | Yes |
| RA-5[d] | Measuring vulnerability impact | Yes |
| RA-5[e] | Analyze vulnerability scan reports and results from vulnerability monitoring | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ra-5-aws-001` | AWS | Amazon Inspector enabled | Inspector | `inspector2.list_account_permissions` | high | [a], [b], [c], [d], [e] |
| `ra-5-aws-002` | AWS | ECR image scanning enabled | ECR | `ecr.describe_repositories` | high | [a], [b], [c], [d], [e] |
| `ra-5-aws-003` | AWS | Vulnerability findings reviewed regularly | Inspector | `inspector2.list_findings` | high | [a], [b], [c], [d], [e] |
| `ra-5-azure-001` | AZURE | Defender for Cloud vulnerability assessment enabled | Security Center | `security.sub_assessments.list` | high | [a], [b], [c], [d], [e] |
| `ra-5-azure-002` | AZURE | Container vulnerability scanning enabled | Security Center | `security.pricings.get` | high | [a], [b], [c], [d], [e] |
| `ra-5-azure-003` | AZURE | SQL vulnerability assessment enabled | SQL | `sql.server_vulnerability_assessments.get` | high | [a], [b], [c], [d], [e] |
| `ra-5-gcp-001` | GCP | Web Security Scanner enabled | SCC | `websecurityscanner.projects.scanConfigs.list` | high | [a], [b], [c], [d], [e] |
| `ra-5-gcp-002` | GCP | Container Analysis vulnerability scanning | Container Analysis | `containeranalysis.projects.occurrences.list` | high | [a], [b], [c], [d], [e] |
| `ra-5-gcp-003` | GCP | Security Health Analytics enabled | SCC | `securitycenter.securityHealthAnalyticsSettings` | high | [a], [b], [c], [d], [e] |


#### RA-5(5) (Enhancement) — Implement privileged access authorization to {{ insert: param, ra-05.05_odp.01 }} for {{ insert: param, ra-05.05_odp.02 }}. In certain situations, the nature of the vulnerability scanning may be more 

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| RA-5(5)[a] | Implement privileged access authorization to {{ insert: param, ra-05.05_odp.01 }} for {{ insert: param, ra-05.05_odp.02  | Yes |
| RA-5(5)[b] | Implement privileged access authorization to {{ insert: param, ra-05.05_odp.01 }} for {{ insert: param, ra-05.05_odp.02  | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ra-5-5-aws-001` | AWS | SSM Patch Manager compliance monitored | SSM | `ssm.describe_instance_patch_states` | high | [a], [b] |
| `ra-5-5-aws-002` | AWS | Inspector critical findings remediated | Inspector | `inspector2.list_findings` | high | [a], [b] |
| `ra-5-5-azure-001` | AZURE | Update Management compliance tracked | Automation | `automation_account.list` | high | [a], [b] |
| `ra-5-5-azure-002` | AZURE | Defender recommendations addressed | Security Center | `security.assessments.list` | high | [a], [b] |
| `ra-5-5-gcp-001` | GCP | OS Config patch compliance monitored | OS Config | `osconfig.patchDeployments.list` | high | [a], [b] |
| `ra-5-5-gcp-002` | GCP | SCC critical findings remediated | SCC | `securitycenter.securityHealthAnalyticsSettings` | high | [a], [b] |


#### RA-6 — Employ a technical surveillance countermeasures survey at {{ insert: param, ra-06_odp.01 }} {{ insert: param, ra-06_odp.02 }}. A technical surveillance countermeasures survey is a service provided by 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### RA-7 — Respond to findings from security and privacy assessments, monitoring, and audits in accordance with organizational risk tolerance. Organizations have many options for responding to risk including mit

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### RA-8 — Conduct privacy impact assessments for systems, programs, or other activities before: Developing or procuring information technology that processes personally identifiable information; and Initiating 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### RA-9 — Identify critical system components and functions by performing a criticality analysis for {{ insert: param, ra-09_odp.01 }} at {{ insert: param, ra-09_odp.02 }}. Not all system components, functions,

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### RA-10 — Establish and maintain a cyber threat hunting capability to: Search for indicators of compromise in organizational systems; and Detect, track, and disrupt threats that evade existing controls; and Emp

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### SA — System and Services Acquisition

**Controls:** 24 | **Automated:** 6 | **Manual:** 18 | **Objectives:** 9 | **Checks:** AWS 10, Azure 7, GCP 7

#### SA-1 — Develop, document, and disseminate to {{ insert: param, sa-1_prm_1 }}: {{ insert: param, sa-01_odp.03 }} system and services acquisition policy that: Addresses purpose, scope, roles, responsibilities,

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SA-2 — Determine the high-level information security and privacy requirements for the system or system service in mission and business process planning; Determine, document, and allocate the resources requir

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SA-3 — Acquire, develop, and manage the system using {{ insert: param, sa-03_odp }} that incorporates information security and privacy considerations; Define and document information security and privacy rol

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SA-3[a] | Acquire, develop, and manage the system using {{ insert: param, sa-03_odp }} that incorporates information security and  | Yes |
| SA-3[b] | Define and document information security and privacy roles and responsibilities throughout the system development life c | Yes |
| SA-3[c] | Identify individuals having information security and privacy roles and responsibilities | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sa-3-aws-001` | AWS | CodePipeline configured for CI/CD | CodePipeline | `codepipeline.list_pipelines` | medium | [a], [b] |
| `sa-3-aws-002` | AWS | CodeBuild projects configured with security scanning | CodeBuild | `codebuild.list_projects` | medium | [a], [c] |
| `sa-3-azure-001` | AZURE | Azure DevOps pipelines configured | Resources | `resource.resources.list` | medium | [a], [b] |
| `sa-3-gcp-001` | GCP | Cloud Build triggers configured | Cloud Build | `cloudbuild.projects.triggers.list` | medium | [a], [b] |


#### SA-4 — Include the following requirements, descriptions, and criteria, explicitly or by reference, using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or sys

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SA-4(9) (Enhancement) — Require the developer of the system, system component, or system service to identify the functions, ports, protocols, and services intended for organizational use. The identification of functions, por

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SA-4(9)[a] | Require the developer of the system, system component, or system service to identify the functions, ports, protocols, an | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sa-4-9-aws-001` | AWS | Security groups restrict unused ports | EC2 | `ec2.describe_security_groups` | high | [a] |
| `sa-4-9-azure-001` | AZURE | Network Security Groups restrict unused ports | Network | `NetworkManagementClient.network_security_groups.list_all` | high | [a] |
| `sa-4-9-gcp-001` | GCP | VPC firewall rules restrict unused ports | Compute Engine | `compute.firewalls.list` | high | [a] |


#### SA-5 — Obtain or develop administrator documentation for the system, system component, or system service that describes: Secure configuration, installation, and operation of the system, component, or service

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SA-6

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SA-7

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SA-8 — Apply the following systems security and privacy engineering principles in the specification, design, development, implementation, and modification of the system and system components: {{ insert: para

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SA-9 — Require that providers of external system services comply with organizational security and privacy requirements and employ the following controls: {{ insert: param, sa-09_odp.01 }}; Define and documen

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SA-9(2) (Enhancement) — Require providers of the following external system services to identify the functions, ports, protocols, and other services required for the use of such services: {{ insert: param, sa-09.02_odp }}. In

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SA-9(2)[a] | Require providers of the following external system services to identify the functions, ports, protocols, and other servi | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sa-9-2-aws-001` | AWS | API Gateway endpoints documented | API Gateway | `apigateway.get_rest_apis` | medium | [a] |
| `sa-9-2-azure-001` | AZURE | API Management services documented | Resources | `resource.resources.list` | medium | [a] |
| `sa-9-2-gcp-001` | GCP | API Gateway configurations documented | API Gateway | `apigateway.projects.locations.apis.list` | medium | [a] |


#### SA-10 — Require the developer of the system, system component, or system service to: Perform configuration management during system, component, or service {{ insert: param, sa-10_odp.01 }}; Document, manage, 

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SA-10[a] | Require the developer of the system, system component, or system service to: Perform configuration management during sys | Yes |
| SA-10[b] | Document, manage, and control the integrity of changes to {{ insert: param, sa-10_odp.02 }} | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sa-10-aws-001` | AWS | CodeCommit repositories configured with version control | CodeCommit | `codecommit.list_repositories` | high | [a], [b] |
| `sa-10-aws-002` | AWS | Infrastructure as Code stored in version control | CloudFormation | `cloudformation.list_stacks` | high | [a], [b] |
| `sa-10-azure-001` | AZURE | Azure Repos configured with branch policies | Policy | `policy.policy_assignments.list` | high | [a], [b] |
| `sa-10-gcp-001` | GCP | Cloud Source Repositories configured | Cloud Source Repositories | `sourcerepo.projects.repos.list` | high | [a], [b] |


#### SA-11 — Require the developer of the system, system component, or system service, at all post-design stages of the system development life cycle, to: Develop and implement a plan for ongoing security and priv

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SA-11[a] | Require the developer of the system, system component, or system service, at all post-design stages of the system develo | Yes |
| SA-11[b] | Perform {{ insert: param, sa-11_odp.01 }} testing/evaluation {{ insert: param, sa-11_odp.02 }} at {{ insert: param, sa-1 | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sa-11-aws-001` | AWS | CodeBuild projects include test stages | CodeBuild | `codebuild.batch_get_projects` | high | [a], [b] |
| `sa-11-azure-001` | AZURE | Azure Pipelines include test stages | Automation | `automation.automation_account.list + automation.runbook.list_by_automation_account` | high | [a], [b] |
| `sa-11-gcp-001` | GCP | Cloud Build includes test steps | Cloud Build | `cloudbuild.projects.builds.list` | high | [a], [b] |


#### SA-11(1) (Enhancement) — Require the developer of the system, system component, or system service to employ static code analysis tools to identify common flaws and document the results of the analysis. Static code analysis pr

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SA-11(1)[a] | Require the developer of the system, system component, or system service to employ static code analysis tools to identif | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sa-11-1-aws-001` | AWS | CodeGuru or third-party SAST integrated | CodeGuru | `codeguru-reviewer.list_repository_associations` | high | [a] |
| `sa-11-1-azure-001` | AZURE | Security DevOps extension configured for SAST | Security Center | `security.dev_ops_configurations.list` | high | [a] |
| `sa-11-1-gcp-001` | GCP | Cloud Build integrated with SAST tools | Cloud Build | `cloudbuild.projects.builds.list` | high | [a] |


#### SA-12

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SA-13

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SA-14

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SA-15 — Require the developer of the system, system component, or system service to follow a documented development process that: Explicitly addresses security and privacy requirements; Identifies the standar

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### SA-16 — Require the developer of the system, system component, or system service to provide the following training on the correct use and operation of the implemented security and privacy functions, controls,

**Baseline:** High | **Type:** Manual | **Objectives:** 0


#### SA-17 — Require the developer of the system, system component, or system service to produce a design specification and security and privacy architecture that: Is consistent with the organization’s security an

**Baseline:** High | **Type:** Manual | **Objectives:** 0


#### SA-18

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SA-19

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SA-20 — Reimplement or custom develop the following critical system components: {{ insert: param, sa-20_odp }}. Organizations determine that certain system components likely cannot be trusted due to specific 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SA-21 — Require that the developer of {{ insert: param, sa-21_odp.01 }}: Has appropriate access authorizations as determined by assigned {{ insert: param, sa-21_odp.02 }} ; and Satisfies the following additio

**Baseline:** High | **Type:** Manual | **Objectives:** 0


#### SA-22 — Replace system components when support for the components is no longer available from the developer, vendor, or manufacturer; or Provide the following options for alternative sources for continued sup

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SA-22[a] | Replace system components when support for the components is no longer available from the developer, vendor, or manufact | Yes |
| SA-22[b] | Provide the following options for alternative sources for continued support for unsupported components {{ insert: param, | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sa-22-aws-001` | AWS | Systems Manager inventory tracks software versions | SSM | `ssm.get_inventory` | high | [a], [b] |
| `sa-22-aws-002` | AWS | Inspector scans for EOL software packages | Inspector2 | `inspector2.list_findings` | high | [a], [b] |
| `sa-22-azure-001` | AZURE | Microsoft Defender for Cloud detects EOL software | Security Center | `SecurityCenter.assessments.list` | high | [a], [b] |
| `sa-22-gcp-001` | GCP | Security Command Center detects EOL software | Security Command Center | `securitycenter.organizations.findings.list` | high | [a], [b] |


#### SA-23 — Employ {{ insert: param, sa-23_odp.01 }} on {{ insert: param, sa-23_odp.02 }} supporting mission essential services or functions to increase the trustworthiness in those systems or components. It is o

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SA-24 — Design organizational systems, system components, or system services to achieve cyber resiliency by: Defining the following cyber resiliency goals: {{ insert: param, sa-24_odp.01 }}. Defining the foll

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### SC — System and Communications Protection

**Controls:** 51 | **Automated:** 9 | **Manual:** 42 | **Objectives:** 25 | **Checks:** AWS 31, Azure 21, GCP 21

#### SC-1 — Develop, document, and disseminate to {{ insert: param, sc-1_prm_1 }}: {{ insert: param, sc-01_odp.03 }} system and communications protection policy that: Addresses purpose, scope, roles, responsibili

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SC-2 — Separate user functionality, including user interface services, from system management functionality. System management functionality includes functions that are necessary to administer databases, net

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### SC-3 — Isolate security functions from nonsecurity functions. Security functions are isolated from nonsecurity functions by means of an isolation boundary implemented within a system via partitions and domai

**Baseline:** High | **Type:** Manual | **Objectives:** 0


#### SC-4 — Prevent unauthorized and unintended information transfer via shared system resources. Preventing unauthorized and unintended information transfer via shared system resources stops information produced

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### SC-5 — {{ insert: param, sc-05_odp.02 }} the effects of the following types of denial-of-service events: {{ insert: param, sc-05_odp.01 }} ; and Employ the following controls to achieve the denial-of-service

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SC-6 — Protect the availability of resources by allocating {{ insert: param, sc-06_odp.01 }} by {{ insert: param, sc-06_odp.02 }}. Priority protection prevents lower-priority processes from delaying or inter

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-7 — Monitor and control communications at the external managed interfaces to the system and at key internal managed interfaces within the system; Implement subnetworks for publicly accessible system compo

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 8

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-7[a] | Monitor and control communications at the external managed interfaces to the system and at key internal managed interfac | Yes |
| SC-7[b] | Implement subnetworks for publicly accessible system components that are {{ insert: param, sc-07_odp }} separated from i | Yes |
| SC-7[c] | Connect to external networks or systems only through managed interfaces consisting of boundary protection devices arrang | Yes |
| SC-7[d] | communications at external managed interfaces to the system are controlled | Yes |
| SC-7[e] | communications at key internal managed interfaces within the system are monitored | Yes |
| SC-7[f] | communications at key internal managed interfaces within the system are controlled | Yes |
| SC-7[g] | subnetworks for publicly accessible system components are {{ insert: param, sc-07_odp }} separated from internal organiz | Yes |
| SC-7[h] | external networks or systems are only connected to through managed interfaces consisting of boundary protection devices  | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-7-aws-001` | AWS | WAF deployed on internet-facing resources | WAFv2 | `wafv2.list_web_acls` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-7-aws-002` | AWS | VPC Flow Logs enabled for all VPCs | VPC | `ec2.describe_flow_logs` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-7-aws-003` | AWS | Network Firewall deployed for CUI VPCs | Network Firewall | `network-firewall.list_firewalls` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-7-aws-004` | AWS | GuardDuty monitors network anomalies | GuardDuty | `guardduty.get_detector` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-7-azure-001` | AZURE | Azure Firewall or NVA deployed | Network | `network.azure_firewalls.list` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-7-azure-002` | AZURE | NSG flow logs enabled | Network | `network_watchers.list_all + nsgs.list_all` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-7-azure-003` | AZURE | Azure WAF deployed | Network | `network.web_application_firewall_policies.list` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-7-gcp-001` | GCP | Cloud Armor WAF deployed | Cloud Armor | `compute.securityPolicies.list` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-7-gcp-002` | GCP | VPC Flow Logs enabled | VPC | `compute.subnetworks.list` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-7-gcp-003` | GCP | Packet Mirroring or IDS configured | VPC | `compute.packetMirrorings.list` | medium | [a], [b], [c], [d], [e], [f], [g], [h] |


#### SC-7(4) (Enhancement) — Implement a managed interface for each external telecommunication service; Establish a traffic flow policy for each managed interface; Protect the confidentiality and integrity of the information bein

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-7(4)[a] | Implement a managed interface for each external telecommunication service | Yes |
| SC-7(4)[b] | Establish a traffic flow policy for each managed interface | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-7-4-aws-001` | AWS | Public subnets isolated from private subnets | VPC | `ec2.describe_subnets` | high | [a], [b] |
| `sc-7-4-aws-002` | AWS | NAT Gateway used for private subnet outbound | VPC | `ec2.describe_nat_gateways` | high | [a], [b] |
| `sc-7-4-azure-001` | AZURE | DMZ subnet implemented | Network | `network.virtual_networks.list` | high | [a], [b] |
| `sc-7-4-gcp-001` | GCP | Public-facing resources in dedicated subnets | VPC | `compute.subnetworks.list` | high | [a], [b] |


#### SC-7(5) (Enhancement) — Deny network communications traffic by default and allow network communications traffic by exception {{ insert: param, sc-07.05_odp.01 }}. Denying by default and allowing by exception applies to inbou

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 6

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-7(5)[a] | Deny network communications traffic by default and allow network communications traffic by exception {{ insert: param, s | No |
| SC-7(5)[b] | network communications traffic is allowed by exception {{ insert: param, sc-07.05_odp.01 }}. System and communications p | No |
| SC-7(5)[c] | network communications traffic is allowed by exception {{ insert: param, sc-07.05_odp.01 }}. System and communications p | No |
| SC-7(5)[d] | network communications traffic is allowed by exception {{ insert: param, sc-07.05_odp.01 }}. System and communications p | No |
| SC-7(5)[e] | network communications traffic is allowed by exception {{ insert: param, sc-07.05_odp.01 }}. System and communications p | No |
| SC-7(5)[f] | network communications traffic is allowed by exception {{ insert: param, sc-07.05_odp.01 }}. System and communications p | No |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-7-5-aws-001` | AWS | Defense-in-depth architecture layers present | Multiple | `ec2/guardduty/cloudtrail/kms` | high |  |
| `sc-7-5-azure-001` | AZURE | Defense-in-depth architecture layers present | Multiple | `network/keyvault/monitor/security` | high |  |
| `sc-7-5-gcp-001` | GCP | Defense-in-depth architecture layers present | Multiple | `compute/kms/logging/orgpolicy` | high |  |

**Documentation Requirements:**

- **SC-7(5)[a]**: architectural designs that promote effective information security are identified. — *Provide documentation showing that architectural designs that promote effective information security are identified and documented.*
- **SC-7(5)[b]**: software development techniques that promote effective information security are identified. — *Provide documentation showing that software development techniques that promote effective information security are identified and documented.*
- **SC-7(5)[c]**: systems engineering principles that promote effective information security are identified. — *Provide documentation showing that systems engineering principles that promote effective information security are identified and documented.*
- **SC-7(5)[d]**: identified architectural designs that promote effective information security are employed. — *Provide documentation or process evidence: identified architectural designs that promote effective information security are employed.*
- **SC-7(5)[e]**: identified software development techniques that promote effective information security are employed. — *Provide documentation or process evidence: identified software development techniques that promote effective information security are employed.*
- **SC-7(5)[f]**: identified systems engineering principles that promote effective information security are employed. — *Provide documentation or process evidence: identified systems engineering principles that promote effective information security are employed.*


#### SC-7(7) (Enhancement) — Prevent split tunneling for remote devices connecting to organizational systems unless the split tunnel is securely provisioned using {{ insert: param, sc-07.07_odp }}. Split tunneling is the process 

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-7(7)[a] | Prevent split tunneling for remote devices connecting to organizational systems unless the split tunnel is securely prov | Yes |
| SC-7(7)[b] | Prevent split tunneling for remote devices connecting to organizational systems unless the split tunnel is securely prov | Yes |
| SC-7(7)[c] | Prevent split tunneling for remote devices connecting to organizational systems unless the split tunnel is securely prov | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-7-7-aws-001` | AWS | Management and data plane separated | VPC | `ec2.describe_subnets` | high | [a], [b], [c] |
| `sc-7-7-aws-002` | AWS | Systems Manager for management access | SSM | `ssm.describe_instance_information` | high | [a], [b], [c] |
| `sc-7-7-aws-001` | AWS | Client VPN full tunnel enforced | VPC | `ec2.describe_client_vpn_endpoints` | high | [a] |
| `sc-7-7-azure-001` | AZURE | Management network isolated | Network | `network.virtual_networks.list` | high | [a], [b], [c] |
| `sc-7-7-azure-001` | AZURE | VPN forced tunneling configured | Network | `network.virtual_network_gateways.list` | high | [a] |
| `sc-7-7-gcp-001` | GCP | Management network segmented | VPC | `compute.subnetworks.list` | high | [a], [b], [c] |
| `sc-7-7-gcp-001` | GCP | VPN full tunnel policy enforced | VPN | `compute.vpnTunnels.list` | high | [a] |


#### SC-7(8) (Enhancement) — Route {{ insert: param, sc-07.08_odp.01 }} to {{ insert: param, sc-07.08_odp.02 }} through authenticated proxy servers at managed interfaces. External networks are networks outside of organizational c

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-7(8)[a] | Route {{ insert: param, sc-07.08_odp.01 }} to {{ insert: param, sc-07.08_odp.02 }} through authenticated proxy servers a | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-7-8-aws-001` | AWS | EBS volumes not shared across accounts | EC2 | `ec2.describe_snapshot_attribute` | high | [a] |
| `sc-7-8-aws-002` | AWS | AMIs not publicly shared | EC2 | `ec2.describe_images()` | high | [a] |
| `sc-7-8-azure-001` | AZURE | Shared disks restricted | Compute | `compute.disks.list` | medium | [a] |
| `sc-7-8-gcp-001` | GCP | Images not publicly shared | Compute | `compute.images.getIamPolicy` | high | [a] |


#### SC-7(21) (Enhancement) — Employ boundary protection mechanisms to isolate {{ insert: param, sc-07.21_odp.01 }} supporting {{ insert: param, sc-07.21_odp.02 }}. Organizations can isolate system components that perform differen

**Baseline:** High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-7(21)[a] | Employ boundary protection mechanisms to isolate {{ insert: param, sc-07.21_odp.01 }} supporting {{ insert: param, sc-07 | Yes |
| SC-7(21)[b] | cross-domain devices that separate subnetworks | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-7-21-aws-001` | AWS | Default security group restricts all traffic | EC2 | `ec2.describe_security_groups` | high | [a], [b] |
| `sc-7-21-aws-002` | AWS | NACLs implement deny-by-default | VPC | `ec2.describe_network_acls` | medium | [a], [b] |
| `sc-7-21-azure-001` | AZURE | NSG default deny rules active | Network | `network.network_security_groups.list` | high | [a], [b] |
| `sc-7-21-azure-002` | AZURE | Azure Firewall default deny configured | Network | `network.azure_firewalls.list` | high | [a], [b] |
| `sc-7-21-gcp-001` | GCP | Default deny ingress firewall rule | VPC | `compute.firewalls.list` | high | [a], [b] |
| `sc-7-21-gcp-002` | GCP | Default allow egress reviewed | VPC | `compute.firewalls.list` | medium | [a], [b] |


#### SC-8 — Protect the {{ insert: param, sc-08_odp }} of transmitted information. Protecting the confidentiality and integrity of transmitted information applies to internal and external networks as well as any 

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-8[a] | Protect the {{ insert: param, sc-08_odp }} of transmitted information. Protecting the confidentiality and integrity of t | Yes |
| SC-8[b] | Protect the {{ insert: param, sc-08_odp }} of transmitted information. Protecting the confidentiality and integrity of t | Yes |
| SC-8[c] | Protect the {{ insert: param, sc-08_odp }} of transmitted information. Protecting the confidentiality and integrity of t | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-8-aws-001` | AWS | ALB/NLB listeners use TLS 1.2+ | ELB | `elbv2.describe_listeners` | high | [a], [b], [c] |
| `sc-8-aws-002` | AWS | CloudFront uses TLS 1.2+ | CloudFront | `cloudfront.list_distributions` | high | [a], [b], [c] |
| `sc-8-aws-003` | AWS | S3 bucket policy enforces TLS | S3 | `s3.get_bucket_policy` | high | [a], [b], [c] |
| `sc-8-azure-001` | AZURE | Minimum TLS 1.2 enforced on App Services | App Service | `web.web_apps.list` | high | [a], [b], [c] |
| `sc-8-azure-002` | AZURE | Storage accounts enforce TLS 1.2+ | Storage | `storage.storage_accounts.list` | high | [a], [b], [c] |
| `sc-8-gcp-001` | GCP | SSL policies enforce TLS 1.2+ | Compute | `compute.sslPolicies.list` | high | [a], [b], [c] |
| `sc-8-gcp-002` | GCP | Cloud SQL requires SSL | Cloud SQL | `sqladmin.instances.list` | high | [a], [b], [c] |


#### SC-9

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-10 — Terminate the network connection associated with a communications session at the end of the session or after {{ insert: param, sc-10_odp }} of inactivity. Network disconnect applies to internal and ex

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-10[a] | Terminate the network connection associated with a communications session at the end of the session or after {{ insert:  | Yes |
| SC-10[b] | Terminate the network connection associated with a communications session at the end of the session or after {{ insert:  | Yes |
| SC-10[c] | Terminate the network connection associated with a communications session at the end of the session or after {{ insert:  | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-10-aws-001` | AWS | ALB idle timeout configured | ELB | `elbv2.describe_load_balancer_attributes` | medium | [a], [b], [c] |
| `sc-10-aws-002` | AWS | API Gateway timeout configured | API Gateway | `apigateway.get_rest_apis` | medium | [a], [b], [c] |
| `sc-10-azure-001` | AZURE | Application Gateway idle timeout configured | Network | `network.application_gateways.list` | medium | [a], [b], [c] |
| `sc-10-gcp-001` | GCP | Load balancer timeout configured | Compute | `compute.backendServices.list` | medium | [a], [b], [c] |


#### SC-11 — Provide a {{ insert: param, sc-11_odp.01 }} isolated trusted communications path for communications between the user and the trusted components of the system; and Permit users to invoke the trusted co

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-12 — Establish and manage cryptographic keys when cryptography is employed within the system in accordance with the following key management requirements: {{ insert: param, sc-12_odp }}. Cryptographic key 

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-12[a] | Establish and manage cryptographic keys when cryptography is employed within the system in accordance with the following | Yes |
| SC-12[b] | cryptographic keys are managed when cryptography is employed within the system in accordance with {{ insert: param, sc-1 | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-12-aws-001` | AWS | KMS key rotation enabled | KMS | `kms.get_key_rotation_status` | high | [a], [b] |
| `sc-12-aws-002` | AWS | KMS key policies restrict access | KMS | `kms.get_key_policy` | high | [a], [b] |
| `sc-12-aws-003` | AWS | ACM certificates managed and auto-renewed | ACM | `acm.list_certificates` | medium | [a], [b] |
| `sc-12-azure-001` | AZURE | Key Vault key rotation configured | Key Vault | `KeyVaultManagementClient.vaults.list + get` | high | [a], [b] |
| `sc-12-azure-002` | AZURE | Key Vault access policies follow least privilege | Key Vault | `keyvault.vaults.list` | high | [a], [b] |
| `sc-12-gcp-001` | GCP | Cloud KMS key rotation configured | KMS | `kms_v1.KeyManagementServiceClient.list_key_rings` | high | [a], [b] |
| `sc-12-gcp-002` | GCP | Cloud KMS IAM bindings restricted | KMS | `cloudkms.projects.locations.keyRings.getIamPolicy` | high | [a], [b] |


#### SC-13 — Determine the {{ insert: param, sc-13_odp.01 }} ; and Implement the following types of cryptography required for each specified cryptographic use: {{ insert: param, sc-13_odp.02 }}. Cryptography can b

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-13[a] | Determine the {{ insert: param, sc-13_odp.01 }} | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-13-aws-001` | AWS | FIPS endpoints used in GovCloud | IAM | `sts.get_caller_identity` | high | [a] |
| `sc-13-aws-002` | AWS | S3 uses FIPS-validated encryption | S3 | `s3.get_bucket_encryption` | high | [a] |
| `sc-13-azure-001` | AZURE | Azure Government FIPS-validated services used | Compute | `StorageManagementClient.storage_accounts.list` | high | [a] |
| `sc-13-gcp-001` | GCP | CMEK uses FIPS-validated Cloud KMS | KMS | `cloudkms.projects.locations.keyRings.cryptoKeys.list` | high | [a] |


#### SC-14

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-15 — Prohibit remote activation of collaborative computing devices and applications with the following exceptions: {{ insert: param, sc-15_odp }} ; and Provide an explicit indication of use to users physic

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-15[a] | Prohibit remote activation of collaborative computing devices and applications with the following exceptions: {{ insert: | No |
| SC-15[b] | Provide an explicit indication of use to users physically present at the devices. Collaborative computing devices and ap | No |
| SC-15[c] | an explicit indication of use is provided to users physically present at the devices. System and communications protecti | No |

**Documentation Requirements:**

- **SC-15[a]**: collaborative computing devices are identified. — *Provide documentation showing that collaborative computing devices are identified and documented.*
- **SC-15[b]**: collaborative computing devices provide indication to users of devices in use. — *Provide documentation or process evidence: collaborative computing devices provide indication to users of devices in use.*
- **SC-15[c]**: remote activation of collaborative computing devices is prohibited. — *Provide documentation or process evidence: remote activation of collaborative computing devices is prohibited.*


#### SC-16 — Associate {{ insert: param, sc-16_prm_1 }} with information exchanged between systems and between system components. Security and privacy attributes can be explicitly or implicitly associated with the

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-17 — Issue public key certificates under an {{ insert: param, sc-17_odp }} or obtain public key certificates from an approved service provider; and Include only approved trust anchors in trust stores or ce

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### SC-18 — Define acceptable and unacceptable mobile code and mobile code technologies; and Authorize, monitor, and control the use of mobile code within the system. Mobile code includes any program, application

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-18[a] | Define acceptable and unacceptable mobile code and mobile code technologies | Yes |
| SC-18[b] | Authorize, monitor, and control the use of mobile code within the system. Mobile code includes any program, application, | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-18-aws-001` | AWS | WAF rules block malicious scripts | WAFv2 | `wafv2.list_web_acls` | high | [a], [b] |
| `sc-18-azure-001` | AZURE | WAF OWASP rules enabled | Network | `network.web_application_firewall_policies.list` | high | [a], [b] |
| `sc-18-gcp-001` | GCP | Cloud Armor preconfigured WAF rules | Cloud Armor | `compute.securityPolicies.list` | high | [a], [b] |


#### SC-19 — Technology-specific; addressed as any other technology or protocol.

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-20 — Provide additional data origin authentication and integrity verification artifacts along with the authoritative name resolution data the system returns in response to external name/address resolution 

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SC-21 — Request and perform data origin authentication and data integrity verification on the name/address resolution responses the system receives from authoritative sources. Each client of name resolution s

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SC-22 — Ensure the systems that collectively provide name/address resolution service for an organization are fault-tolerant and implement internal and external role separation. Systems that provide name and a

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SC-23 — Protect the authenticity of communications sessions. Protecting session authenticity addresses communications protection at the session level, not at the packet level. Such protection establishes grou

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-23[a] | Protect the authenticity of communications sessions. Protecting session authenticity addresses communications protection | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-23-aws-001` | AWS | ACM certificates valid and not expired | ACM | `acm.list_certificates` | high | [a] |
| `sc-23-aws-002` | AWS | DNSSEC enabled on Route 53 hosted zones | Route 53 | `route53.list_hosted_zones` | medium | [a] |
| `sc-23-azure-001` | AZURE | App Service certificates valid | App Service | `web.certificates.list` | high | [a] |
| `sc-23-gcp-001` | GCP | Managed SSL certificates valid | Compute | `compute.sslCertificates.list` | high | [a] |


#### SC-24 — Fail to a {{ insert: param, sc-24_odp.02 }} for the following failures on the indicated components while preserving {{ insert: param, sc-24_odp.03 }} in failure: {{ insert: param, sc-24_odp.01 }}. Fai

**Baseline:** High | **Type:** Manual | **Objectives:** 0


#### SC-25 — Employ minimal functionality and information storage on the following system components: {{ insert: param, sc-25_odp }}. The deployment of system components with minimal functionality reduces the need

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-26 — Include components within organizational systems specifically designed to be the target of malicious attacks for detecting, deflecting, and analyzing such attacks. Decoys (i.e., honeypots, honeynets, 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-27 — Include within organizational systems the following platform independent applications: {{ insert: param, sc-27_odp }}. Platforms are combinations of hardware, firmware, and software components used to

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-28 — Protect the {{ insert: param, sc-28_odp.01 }} of the following information at rest: {{ insert: param, sc-28_odp.02 }}. Information at rest refers to the state of information when it is not in process 

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-28[a] | Protect the {{ insert: param, sc-28_odp.01 }} of the following information at rest: {{ insert: param, sc-28_odp.02 }}. I | No |
| SC-28[b] | Protect the {{ insert: param, sc-28_odp.01 }} of the following information at rest: {{ insert: param, sc-28_odp.02 }}. I | No |

**Documentation Requirements:**

- **SC-28[a]**: use of Voice over Internet Protocol (VoIP) technologies is controlled. — *Provide documentation or process evidence: use of Voice over Internet Protocol (VoIP) technologies is controlled.*
- **SC-28[b]**: use of Voice over Internet Protocol (VoIP) technologies is monitored. — *Provide documentation or process evidence: use of Voice over Internet Protocol (VoIP) technologies is monitored.*


#### SC-28(1) (Enhancement) — Implement cryptographic mechanisms to prevent unauthorized disclosure and modification of the following information at rest on {{ insert: param, sc-28.01_odp.02 }}: {{ insert: param, sc-28.01_odp.01 }

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SC-28(1)[a] | Implement cryptographic mechanisms to prevent unauthorized disclosure and modification of the following information at r | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-28-1-aws-001` | AWS | S3 default encryption enabled | S3 | `s3.get_bucket_encryption` | high | [a] |
| `sc-28-1-aws-002` | AWS | RDS encryption at rest enabled | RDS | `rds.describe_db_instances` | high | [a] |
| `sc-28-1-aws-003` | AWS | DynamoDB encryption enabled | DynamoDB | `dynamodb.describe_table` | high | [a] |
| `sc-28-1-aws-004` | AWS | EBS encryption by default enabled | EC2 | `ec2.get_ebs_encryption_by_default` | high | [a] |
| `sc-28-1-azure-001` | AZURE | Storage account encryption with CMK | Storage | `storage.storage_accounts.list` | high | [a] |
| `sc-28-1-azure-002` | AZURE | Azure SQL TDE with CMK | SQL | `sql.encryption_protectors.get` | high | [a] |
| `sc-28-1-azure-003` | AZURE | VM disk encryption enabled | Compute | `compute.disks.list` | high | [a] |
| `sc-28-1-gcp-001` | GCP | Cloud Storage CMEK encryption | Storage | `storage.buckets.get` | high | [a] |
| `sc-28-1-gcp-002` | GCP | Cloud SQL CMEK encryption | Cloud SQL | `sqladmin.instances.list` | high | [a] |
| `sc-28-1-gcp-003` | GCP | BigQuery CMEK encryption | BigQuery | `bigquery.datasets.list` | high | [a] |


#### SC-29 — Employ a diverse set of information technologies for the following system components in the implementation of the system: {{ insert: param, sc-29_odp }}. Increasing the diversity of information techno

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-30 — Employ the following concealment and misdirection techniques for {{ insert: param, sc-30_odp.02 }} at {{ insert: param, sc-30_odp.03 }} to confuse and mislead adversaries: {{ insert: param, sc-30_odp.

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-31 — Perform a covert channel analysis to identify those aspects of communications within the system that are potential avenues for covert {{ insert: param, sc-31_odp }} channels; and Estimate the maximum 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-32 — Partition the system into {{ insert: param, sc-32_odp.01 }} residing in separate {{ insert: param, sc-32_odp.02 }} domains or environments based on {{ insert: param, sc-32_odp.03 }}. System partitioni

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-33

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-34 — For {{ insert: param, sc-34_odp.01 }} , load and execute: The operating environment from hardware-enforced, read-only media; and The following applications from hardware-enforced, read-only media: {{ 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-35 — Include system components that proactively seek to identify network-based malicious code or malicious websites. External malicious code identification differs from decoys in [SC-26](#sc-26) in that th

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-36 — Distribute the following processing and storage components across multiple {{ insert: param, sc-36_prm_1 }}: {{ insert: param, sc-36_prm_2 }}. Distributing processing and storage across multiple physi

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-37 — Employ the following out-of-band channels for the physical delivery or electronic transmission of {{ insert: param, sc-37_odp.02 }} to {{ insert: param, sc-37_odp.03 }}: {{ insert: param, sc-37_odp.01

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-38 — Employ the following operations security controls to protect key organizational information throughout the system development life cycle: {{ insert: param, sc-38_odp }}. Operations security (OPSEC) is

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-39 — Maintain a separate execution domain for each executing system process. Systems can maintain separate execution domains for each executing process by assigning each process a separate address space. E

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SC-40 — Protect external and internal {{ insert: param, sc-40_prm_1 }} from the following signal parameter attacks: {{ insert: param, sc-40_prm_2 }}. Wireless link protection applies to internal and external 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-41 — {{ insert: param, sc-41_odp.02 }} disable or remove {{ insert: param, sc-41_odp.01 }} on the following systems or system components: {{ insert: param, sc-41_odp.03 }}. Connection ports include Univers

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-42 — Prohibit {{ insert: param, sc-42_odp.01 }} ; and Provide an explicit indication of sensor use to {{ insert: param, sc-42_odp.05 }}. Sensor capability and data applies to types of systems or system com

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-43 — Establish usage restrictions and implementation guidelines for the following system components: {{ insert: param, sc-43_odp }} ; and Authorize, monitor, and control the use of such components within t

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-44 — Employ a detonation chamber capability within {{ insert: param, sc-44_odp }}. Detonation chambers, also known as dynamic execution environments, allow organizations to open email attachments, execute 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-45 — Synchronize system clocks within and between systems and system components. Time synchronization of system clocks is essential for the correct execution of many system services, including identificati

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### SC-46 — Implement a policy enforcement mechanism {{ insert: param, sc-46_odp }} between the physical and/or network interfaces for the connecting security domains. For logical policy enforcement mechanisms, o

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-47 — Establish {{ insert: param, sc-47_odp }} for system operations organizational command and control. An incident, whether adversarial- or nonadversarial-based, can disrupt established communications pat

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-48 — Relocate {{ insert: param, sc-48_odp.01 }} to {{ insert: param, sc-48_odp.02 }} under the following conditions or circumstances: {{ insert: param, sc-48_odp.03 }}. Adversaries may take various paths a

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-49 — Implement hardware-enforced separation and policy enforcement mechanisms between {{ insert: param, sc-49_odp }}. System owners may require additional strength of mechanism and robustness to ensure dom

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-50 — Implement software-enforced separation and policy enforcement mechanisms between {{ insert: param, sc-50_odp }}. System owners may require additional strength of mechanism to ensure domain separation 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SC-51 — Employ hardware-based, write-protect for {{ insert: param, sc-51_odp.01 }} ; and Implement specific procedures for {{ insert: param, sc-51_odp.02 }} to manually disable hardware write-protect for firm

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### SI — System and Information Integrity

**Controls:** 23 | **Automated:** 4 | **Manual:** 19 | **Objectives:** 14 | **Checks:** AWS 21, Azure 16, GCP 16

#### SI-1 — Develop, document, and disseminate to {{ insert: param, si-1_prm_1 }}: {{ insert: param, si-01_odp.03 }} system and information integrity policy that: Addresses purpose, scope, roles, responsibilities

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SI-2 — Identify, report, and correct system flaws; Test software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation; Install security-relevant s

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 6

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SI-2[a] | Identify, report, and correct system flaws | Yes |
| SI-2[b] | Test software and firmware updates related to flaw remediation for effectiveness and potential side effects before insta | Yes |
| SI-2[c] | Install security-relevant software and firmware updates within {{ insert: param, si-02_odp }} of the release of the upda | Yes |
| SI-2[d] | Incorporate flaw remediation into the organizational configuration management process. The need to remediate system flaw | Yes |
| SI-2[e] | system flaws are reported | Yes |
| SI-2[f] | system flaws are corrected | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `si-2-aws-001` | AWS | SSM Patch Manager deployed | SSM | `ssm.describe_patch_baselines` | high | [a], [b], [c], [d], [e], [f] |
| `si-2-aws-002` | AWS | Patch compliance within SLA | SSM | `ssm.describe_instance_patch_states` | high | [a], [b], [c], [d], [e], [f] |
| `si-2-aws-003` | AWS | Amazon Inspector vulnerability findings addressed | Inspector | `inspector2.list_findings` | high | [a], [b], [c], [d], [e], [f] |
| `si-2-aws-004` | AWS | RDS automatic minor version upgrade enabled | RDS | `rds.describe_db_instances` | medium | [a], [b], [c], [d], [e], [f] |
| `si-2-azure-001` | AZURE | Azure Update Manager configured | Compute | `compute.virtual_machines.list` | high | [a], [b], [c], [d], [e], [f] |
| `si-2-azure-002` | AZURE | Defender vulnerability assessment findings addressed | Security Center | `security.sub_assessments.list` | high | [a], [b], [c], [d], [e], [f] |
| `si-2-azure-003` | AZURE | App Service platform version current | App Service | `web.web_apps.list` | medium | [a], [b], [c], [d], [e], [f] |
| `si-2-gcp-001` | GCP | OS Config patch management active | OS Config | `osconfig.projects.patchDeployments.list` | high | [a], [b], [c], [d], [e], [f] |
| `si-2-gcp-002` | GCP | GKE cluster auto-upgrade enabled | GKE | `container.projects.locations.clusters.list` | high | [a], [b], [c], [d], [e], [f] |
| `si-2-gcp-003` | GCP | Container vulnerability findings addressed | Container Analysis | `containeranalysis.projects.occurrences.list` | high | [a], [b], [c], [d], [e], [f] |


#### SI-3 — Implement {{ insert: param, si-03_odp.01 }} malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code; Automatically update malicious code protection 

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SI-3[a] | Implement {{ insert: param, si-03_odp.01 }} malicious code protection mechanisms at system entry and exit points to dete | Yes |
| SI-3[b] | Automatically update malicious code protection mechanisms as new releases are available in accordance with organizationa | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `si-3-aws-001` | AWS | GuardDuty malware protection enabled | GuardDuty | `guardduty.get_detector` | high | [a], [b] |
| `si-3-aws-002` | AWS | EC2 instances have endpoint protection | SSM | `ssm.list_inventory_entries` | high | [a], [b] |
| `si-3-aws-003` | AWS | S3 Malware Scanning configured | GuardDuty | `guardduty.get_detector()` | medium | [a], [b] |
| `si-3-azure-001` | AZURE | Defender for Endpoint deployed | Security Center | `security.pricings.get` | high | [a], [b] |
| `si-3-azure-002` | AZURE | Microsoft Antimalware extension deployed | Compute | `compute.virtual_machine_extensions.list` | high | [a], [b] |
| `si-3-gcp-001` | GCP | Endpoint protection deployed on GCE instances | Compute | `compute.instances.list` | high | [a], [b] |
| `si-3-gcp-002` | GCP | Malware scanning enabled for Cloud Storage | Storage | `storage.buckets.list` | medium | [a], [b] |


#### SI-3(1) (Enhancement)

**Baseline:** N/A | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SI-3(1)[a] | Organization-defined requirement | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `si-3-1-aws-001` | AWS | Endpoint protection auto-update enabled | SSM | `ssm.describe_instance_information()` | high | [a] |
| `si-3-1-aws-002` | AWS | GuardDuty threat intelligence auto-updated | GuardDuty | `guardduty.get_detector` | medium | [a] |
| `si-3-1-azure-001` | AZURE | Defender for Endpoint signature updates current | Security Center | `security.pricings.get` | high | [a] |
| `si-3-1-gcp-001` | GCP | Endpoint protection auto-update configured | Compute | `compute.instances.list` | high | [a] |


#### SI-3(2) (Enhancement)

**Baseline:** N/A | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SI-3(2)[a] | Organization-defined requirement | Yes |
| SI-3(2)[b] | Organization-defined requirement | Yes |
| SI-3(2)[c] | Organization-defined requirement | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `si-3-2-aws-001` | AWS | Periodic vulnerability scanning configured | Inspector | `inspector2.list_account_permissions` | high | [a], [b], [c] |
| `si-3-2-aws-002` | AWS | GuardDuty real-time malware scanning | GuardDuty | `guardduty.get_detector` | high | [a], [b], [c] |
| `si-3-2-aws-003` | AWS | S3 object scanning for uploads | GuardDuty | `guardduty.get_detector()` | medium | [a], [b], [c] |
| `si-3-2-azure-001` | AZURE | Scheduled VM vulnerability scans configured | Security Center | `assessments.list` | high | [a], [b], [c] |
| `si-3-2-azure-002` | AZURE | Real-time protection enabled on endpoints | Compute | `compute.virtual_machine_extensions.list` | high | [a], [b], [c] |
| `si-3-2-gcp-001` | GCP | Container vulnerability scanning continuous | Container Analysis | `containeranalysis.projects.occurrences.list` | high | [a], [b], [c] |
| `si-3-2-gcp-002` | GCP | Web Security Scanner periodic scans | SCC | `websecurityscanner.projects.scanConfigs.list` | medium | [a], [b], [c] |


#### SI-4 — Monitor the system to detect: Attacks and indicators of potential attacks in accordance with the following monitoring objectives: {{ insert: param, si-04_odp.01 }} ; and Unauthorized local, network, a

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SI-4[a] | Monitor the system to detect: Attacks and indicators of potential attacks in accordance with the following monitoring ob | Yes |
| SI-4[b] | Unauthorized local, network, and remote connections | Yes |
| SI-4[c] | Identify unauthorized use of the system through the following techniques and methods: {{ insert: param, si-04_odp.02 }} | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `si-4-aws-001` | AWS | GuardDuty monitors network traffic | GuardDuty | `guardduty.get_detector` | high | [a], [b], [c] |
| `si-4-aws-002` | AWS | VPC Flow Logs analyzed for anomalies | VPC | `ec2.describe_flow_logs` | high | [a], [b], [c] |
| `si-4-aws-003` | AWS | Network Firewall IDS/IPS rules configured | Network Firewall | `network-firewall.list_firewall_policies` | high | [a], [b], [c] |
| `si-4-azure-001` | AZURE | Defender for Network deployed | Security Center | `ResourceManagementClient.providers.get('Microsoft.Security')` | high | [a], [b], [c] |
| `si-4-azure-002` | AZURE | Azure Firewall IDPS enabled | Network | `network.azure_firewalls.list` | high | [a], [b], [c] |
| `si-4-azure-003` | AZURE | NSG flow log analytics enabled | Network | `network_watchers.list_all + nsgs.list_all` | high | [a], [b], [c] |
| `si-4-gcp-001` | GCP | Cloud IDS deployed for network monitoring | Cloud IDS | `ids.projects.locations.endpoints.list` | high | [a], [b], [c] |
| `si-4-gcp-002` | GCP | VPC Flow Logs analyzed | VPC | `compute.subnetworks.list` | high | [a], [b], [c] |
| `si-4-gcp-003` | GCP | Event Threat Detection monitors for attacks | SCC | `securitycenter.securityHealthAnalyticsSettings` | high | [a], [b], [c] |


#### SI-4(4) (Enhancement) — Determine criteria for unusual or unauthorized activities or conditions for inbound and outbound communications traffic; Monitor inbound and outbound communications traffic {{ insert: param, si-4.4_pr

**Baseline:** Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SI-4(4)[a] | Determine criteria for unusual or unauthorized activities or conditions for inbound and outbound communications traffic | Yes |
| SI-4(4)[b] | Monitor inbound and outbound communications traffic {{ insert: param, si-4.4_prm_1 }} for {{ insert: param, si-4.4_prm_2 | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `si-4-4-aws-001` | AWS | GuardDuty UnauthorizedAccess findings monitored | GuardDuty | `guardduty.list_findings` | high | [a], [b] |
| `si-4-4-aws-002` | AWS | CloudWatch anomaly detection configured | CloudWatch | `cloudwatch.describe_anomaly_detectors` | medium | [a], [b] |
| `si-4-4-aws-003` | AWS | CloudTrail Insights enabled | CloudTrail | `cloudtrail.get_insight_selectors` | medium | [a], [b] |
| `si-4-4-azure-001` | AZURE | Azure AD Identity Protection configured | Azure AD | `graph.identity_protection.risk_detections.list` | high | [a], [b] |
| `si-4-4-azure-002` | AZURE | Sentinel UEBA enabled | Sentinel | `sentinel_onboarding_states.list` | medium | [a], [b] |
| `si-4-4-azure-003` | AZURE | Anomalous login alerts configured | Azure AD | `graph.identity_protection.risky_users.list` | high | [a], [b] |
| `si-4-4-gcp-001` | GCP | Event Threat Detection for unauthorized access | SCC | `securitycenter.securityHealthAnalyticsSettings` | high | [a], [b] |
| `si-4-4-gcp-002` | GCP | Anomaly detection alerts configured | Monitoring | `monitoring.projects.alertPolicies.list` | medium | [a], [b] |
| `si-4-4-gcp-003` | GCP | Access Transparency logs monitored | Logging | `logging.entries.list` | medium | [a], [b] |


#### SI-5 — Receive system security alerts, advisories, and directives from {{ insert: param, si-05_odp.01 }} on an ongoing basis; Generate internal security alerts, advisories, and directives as deemed necessary

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SI-5[a] | Receive system security alerts, advisories, and directives from {{ insert: param, si-05_odp.01 }} on an ongoing basis | Yes |
| SI-5[b] | Generate internal security alerts, advisories, and directives as deemed necessary | Yes |
| SI-5[c] | Disseminate security alerts, advisories, and directives to: {{ insert: param, si-05_odp.02 }} | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `si-5-aws-001` | AWS | Security Hub findings notifications configured | Security Hub | `events.list_rules()` | high | [a], [b], [c] |
| `si-5-aws-002` | AWS | GuardDuty findings alerting configured | GuardDuty | `events.list_rules()` | high | [a], [b], [c] |
| `si-5-aws-003` | AWS | AWS Health Dashboard alerts configured | Health | `health.describe_events` | medium | [a], [b], [c] |
| `si-5-azure-001` | AZURE | Defender for Cloud email notifications | Security Center | `security.security_contacts.list` | high | [a], [b], [c] |
| `si-5-azure-002` | AZURE | Service Health alerts configured | Monitor | `monitor.activity_log_alerts.list` | medium | [a], [b], [c] |
| `si-5-gcp-001` | GCP | SCC notification config for critical findings | SCC | `securitycenter.organizations.notificationConfigs.list` | high | [a], [b], [c] |
| `si-5-gcp-002` | GCP | Cloud Monitoring alerting for security events | Monitoring | `monitoring.projects.alertPolicies.list` | high | [a], [b], [c] |


#### SI-6 — Verify the correct operation of {{ insert: param, si-6_prm_1 }}; Perform the verification of the functions specified in SI-6a {{ insert: param, si-06_odp.03 }}; Alert {{ insert: param, si-06_odp.06 }}

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### SI-7 — Employ integrity verification tools to detect unauthorized changes to the following software, firmware, and information: {{ insert: param, si-7_prm_1 }} ; and Take the following actions when unauthori

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### SI-8 — Employ spam protection mechanisms at system entry and exit points to detect and act on unsolicited messages; and Update spam protection mechanisms when new releases are available in accordance with or

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### SI-9

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SI-10 — Check the validity of the following information inputs: {{ insert: param, si-10_odp }}. Checking the valid syntax and semantics of system inputs—including character set, length, numerical range, and a

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### SI-11 — Generate error messages that provide information necessary for corrective actions without revealing information that could be exploited; and Reveal error messages only to {{ insert: param, si-11_odp }

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### SI-12 — Manage and retain information within the system and information output from the system in accordance with applicable laws, executive orders, directives, regulations, policies, standards, guidelines an

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SI-13 — Determine mean time to failure (MTTF) for the following system components in specific environments of operation: {{ insert: param, si-13_odp.01 }} ; and Provide substitute system components and a mean

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SI-14 — Implement non-persistent {{ insert: param, si-14_odp.01 }} that are initiated in a known state and terminated {{ insert: param, si-14_odp.02 }}. Implementation of non-persistent components and service

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SI-15 — Validate information output from the following software programs and/or applications to ensure that the information is consistent with the expected content: {{ insert: param, si-15_odp }}. Certain typ

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SI-16 — Implement the following controls to protect the system memory from unauthorized code execution: {{ insert: param, si-16_odp }}. Some adversaries launch attacks with the intent of executing code in non

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### SI-17 — Implement the indicated fail-safe procedures when the indicated failures occur: {{ insert: param, si-17_prm_1 }}. Failure conditions include the loss of communications among critical system components

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SI-18 — Check the accuracy, relevance, timeliness, and completeness of personally identifiable information across the information life cycle {{ insert: param, si-18_prm_1 }} ; and Correct or delete inaccurate

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SI-19 — Remove the following elements of personally identifiable information from datasets: {{ insert: param, si-19_odp.01 }} ; and Evaluate {{ insert: param, si-19_odp.02 }} for effectiveness of de-identific

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SI-20 — Embed data or capabilities in the following systems or system components to determine if organizational data has been exfiltrated or improperly removed from the organization: {{ insert: param, si-20_o

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SI-21 — Refresh {{ insert: param, si-21_odp.01 }} at {{ insert: param, si-21_odp.02 }} or generate the information on demand and delete the information when no longer needed. Retaining information for longer 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SI-22 — Identify the following alternative sources of information for {{ insert: param, si-22_odp.02 }}: {{ insert: param, si-22_odp.01 }} ; and Use an alternative information source for the execution of esse

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SI-23 — Based on {{ insert: param, si-23_odp.01 }}: Fragment the following information: {{ insert: param, si-23_odp.02 }} ; and Distribute the fragmented information across the following systems or system com

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


### SR — Supply Chain Risk Management

**Controls:** 12 | **Automated:** 3 | **Manual:** 9 | **Objectives:** 5 | **Checks:** AWS 5, Azure 3, GCP 3

#### SR-1 — Develop, document, and disseminate to {{ insert: param, sr-1_prm_1 }}: {{ insert: param, sr-01_odp.03 }} supply chain risk management policy that: Addresses purpose, scope, roles, responsibilities, ma

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SR-2 — Develop a plan for managing supply chain risks associated with the research and development, design, manufacturing, acquisition, delivery, integration, operations and maintenance, and disposal of the 

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SR-2[a] | Develop a plan for managing supply chain risks associated with the research and development, design, manufacturing, acqu | Yes |
| SR-2[b] | Review and update the supply chain risk management plan {{ insert: param, sr-02_odp.02 }} or as required, to address thr | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sr-2-aws-001` | AWS | ECR images scanned for vulnerabilities | ECR | `ecr.describe_repositories + ecr.get_registry_scanning_configuration` | high | [a], [b] |
| `sr-2-aws-002` | AWS | Inspector scans for software bill of materials | Inspector2 | `inspector2.list_coverage` | medium | [a] |
| `sr-2-azure-001` | AZURE | Container Registry images scanned | Resources | `resource.resources.list` | high | [a], [b] |
| `sr-2-gcp-001` | GCP | Artifact Registry images scanned | Artifact Registry | `artifactregistry.projects.locations.repositories.list` | high | [a], [b] |


#### SR-3 — Establish a process or processes to identify and address weaknesses or deficiencies in the supply chain elements and processes of {{ insert: param, sr-03_odp.01 }} in coordination with {{ insert: para

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SR-3[a] | Establish a process or processes to identify and address weaknesses or deficiencies in the supply chain elements and pro | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sr-3-aws-001` | AWS | CodeBuild includes dependency scanning | CodeBuild | `codebuild.batch_get_projects` | high | [a] |
| `sr-3-azure-001` | AZURE | Azure Pipelines include dependency scanning | Security Center | `security.assessments.list` | high | [a] |
| `sr-3-gcp-001` | GCP | Cloud Build includes dependency scanning | Cloud Build | `cloudbuild.projects.builds.list` | high | [a] |


#### SR-4 — Document, monitor, and maintain valid provenance of the following systems, system components, and associated data: {{ insert: param, sr-04_odp }}. Every system and system component has a point of orig

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SR-5 — Employ the following acquisition strategies, contract tools, and procurement methods to protect against, identify, and mitigate supply chain risks: {{ insert: param, sr-05_odp }}. The use of the acqui

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SR-6 — Assess and review the supply chain-related risks associated with suppliers or contractors and the system, system component, or system service they provide {{ insert: param, sr-06_odp }}. An assessment

**Baseline:** Moderate/High | **Type:** Manual | **Objectives:** 0


#### SR-7 — Employ the following Operations Security (OPSEC) controls to protect supply chain-related information for the system, system component, or system service: {{ insert: param, sr-07_odp }}. Supply chain 

**Baseline:** N/A | **Type:** Manual | **Objectives:** 0


#### SR-8 — Establish agreements and procedures with entities involved in the supply chain for the system, system component, or system service for the {{ insert: param, sr-08_odp.01 }}. The establishment of agree

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SR-9 — Implement a tamper protection program for the system, system component, or system service. Anti-tamper technologies, tools, and techniques provide a level of protection for systems, system components,

**Baseline:** High | **Type:** Manual | **Objectives:** 0


#### SR-10 — Inspect the following systems or system components {{ insert: param, sr-10_odp.02 }} to detect tampering: {{ insert: param, sr-10_odp.01 }}. The inspection of systems or systems components for tamper 

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


#### SR-11 — Develop and implement anti-counterfeit policy and procedures that include the means to detect and prevent counterfeit components from entering the system; and Report counterfeit system components to {

**Baseline:** Low/Moderate/High | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| SR-11[a] | Develop and implement anti-counterfeit policy and procedures that include the means to detect and prevent counterfeit co | Yes |
| SR-11[b] | Report counterfeit system components to {{ insert: param, sr-11_odp.01 }}. Sources of counterfeit components include man | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sr-11-aws-001` | AWS | ECR images signed with AWS Signer | ECR | `ecr.get_registry_policy + ecr.describe_repositories` | high | [a], [b] |
| `sr-11-aws-002` | AWS | Lambda code signing configured | Lambda | `lambda.list_functions` | high | [a] |
| `sr-11-azure-001` | AZURE | Container Registry content trust enabled | Resources | `resource.resources.list` | high | [a], [b] |
| `sr-11-gcp-001` | GCP | Binary Authorization enforced | Binary Authorization | `binaryauthorization.projects.policy.get` | high | [a], [b] |


#### SR-12 — Dispose of {{ insert: param, sr-12_odp.01 }} using the following techniques and methods: {{ insert: param, sr-12_odp.02 }}. Data, documentation, tools, or system components can be disposed of at any t

**Baseline:** Low/Moderate/High | **Type:** Manual | **Objectives:** 0


---

## 7. 3PAO Manual Assessment Guide

### 7.1 How to Use This Guide

For the 231 controls classified as **Manual Review Required**, the scanner cannot make an automated determination. The 3PAO must independently assess these controls using the guidance below.

For each manual control, this guide provides:

1. **Assessment Objectives** — The exact 800-53A "determine if" statements the 3PAO must evaluate
2. **Assessment Guidance** — Specific steps, interview topics, and configuration areas to examine
3. **Evidence Artifacts** — Documents, records, and artifacts the 3PAO should request from the OSC
4. **Determination Criteria** — What constitutes a Met vs. Not Met finding

**Note:** Some "manual" controls have automated checks that provide *supporting evidence* (e.g., cloud configurations). These checks do not determine compliance but give the 3PAO baseline data to inform their manual assessment.

### 7.2 Manual Control Reference

#### AC — Access Control (Manual Controls)

##### Control AC-1: Develop, document, and disseminate to {{ insert: param, ac-1_prm_1 }}: {{ insert: param, ac-01_odp.03 }} access control policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the access control policy and the associated access controls; Designate an {{ insert: param, ac-01_odp.04 }} to manage the development, documentation, and dissemination of the access control policy and procedures; and Review and update the current access control: Policy {{ insert: param, ac-01_odp.05 }} and following {{ insert: param, ac-01_odp.06 }} ; and Procedures {{ insert: param, ac-01_odp.07 }} and following {{ insert: param, ac-01_odp.08 }}. Access control policy and procedures address the controls in the AC family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of access control policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies reflecting the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to access control policy and procedures include assessment or audit findings, security incidents or breaches, or changes in laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. an access control policy is developed and documented; the access control policy is disseminated to {{ insert: param, ac-01_odp.01 }}; access control procedures to facilitate the implementation of the access control policy and associated controls are developed and documented; the access control procedures are disseminated to {{ insert: param, ac-01_odp.02 }}; the {{ insert: param, ac-01_odp.03 }} access control policy addresses purpose; the {{ insert: param, ac-01_odp.03 }} access control policy addresses scope; the {{ insert: param, ac-01_odp.03 }} access control policy addresses roles; the {{ insert: param, ac-01_odp.03 }} access control policy addresses responsibilities; the {{ insert: param, ac-01_odp.03 }} access control policy addresses management commitment; the {{ insert: param, ac-01_odp.03 }} access control policy addresses coordination among organizational entities; the {{ insert: param, ac-01_odp.03 }} access control policy addresses compliance; the {{ insert: param, ac-01_odp.03 }} access control policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, ac-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the access control policy and procedures; the current access control policy is reviewed and updated {{ insert: param, ac-01_odp.05 }}; the current access control policy is reviewed and updated following {{ insert: param, ac-01_odp.06 }}; the current access control procedures are reviewed and updated {{ insert: param, ac-01_odp.07 }}; the current access control procedures are reviewed and updated following {{ insert: param, ac-01_odp.08 }}. Access control policy and procedures

system security plan

privacy plan

other relevant documents or records Organizational personnel with access control responsibilities

organizational personnel with information security with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** AC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AC-9: Notify the user, upon successful logon to the system, of the date and time of the last logon. Previous logon notification is applicable to system access via human user interfaces and access to systems that occurs in other types of architectures. Information about the last successful logon allows the user to recognize if the date and time provided is not consistent with the user’s last access. the user is notified, upon successful logon to the system, of the date and time of the last logon. Access control policy

procedures addressing previous logon notification

system design documentation

system configuration settings and associated documentation

system notification messages

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

system developers Mechanisms implementing access control policy for previous logon notification

**FedRAMP Baseline:** L2 | **Domain:** AC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AC-10: Limit the number of concurrent sessions for each {{ insert: param, ac-10_odp.01 }} to {{ insert: param, ac-10_odp.02 }}. Organizations may define the maximum number of concurrent sessions for system accounts globally, by account type, by account, or any combination thereof. For example, organizations may limit the number of concurrent sessions for system administrators or other individuals working in particularly sensitive domains or mission-critical applications. Concurrent session control addresses concurrent sessions for system accounts. It does not, however, address concurrent sessions by single users via multiple system accounts. the number of concurrent sessions for each {{ insert: param, ac-10_odp.01 }} is limited to {{ insert: param, ac-10_odp.02 }}. Access control policy

procedures addressing concurrent session control

system design documentation

system configuration settings and associated documentation

security plan

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

system developers Mechanisms implementing access control policy for concurrent session control

**FedRAMP Baseline:** L2 | **Domain:** AC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AC-13: 

**FedRAMP Baseline:** L2 | **Domain:** AC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AC-14: Identify {{ insert: param, ac-14_odp }} that can be performed on the system without identification or authentication consistent with organizational mission and business functions; and Document and provide supporting rationale in the security plan for the system, user actions not requiring identification or authentication. Specific user actions may be permitted without identification or authentication if organizations determine that identification and authentication are not required for the specified user actions. Organizations may allow a limited number of user actions without identification or authentication, including when individuals access public websites or other publicly accessible federal systems, when individuals use mobile phones to receive calls, or when facsimiles are received. Organizations identify actions that normally require identification or authentication but may, under certain circumstances, allow identification or authentication mechanisms to be bypassed. Such bypasses may occur, for example, via a software-readable physical switch that commands bypass of the logon functionality and is protected from accidental or unmonitored use. Permitting actions without identification or authentication does not apply to situations where identification and authentication have already occurred and are not repeated but rather to situations where identification and authentication have not yet occurred. Organizations may decide that there are no user actions that can be performed on organizational systems without identification and authentication, and therefore, the value for the assignment operation can be "none."  {{ insert: param, ac-14_odp }} that can be performed on the system without identification or authentication consistent with organizational mission and business functions are identified; user actions not requiring identification or authentication are documented in the security plan for the system; a rationale for user actions not requiring identification or authentication is provided in the security plan for the system. Access control policy

procedures addressing permitted actions without identification or authentication

system configuration settings and associated documentation

security plan

list of user actions that can be performed without identification or authentication

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

**FedRAMP Baseline:** L2 | **Domain:** AC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AC-15: 

**FedRAMP Baseline:** L2 | **Domain:** AC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AC-16: Provide the means to associate {{ insert: param, ac-16_prm_1 }} with {{ insert: param, ac-16_prm_2 }} for information in storage, in process, and/or in transmission; Ensure that the attribute associations are made and retained with the information; Establish the following permitted security and privacy attributes from the attributes defined in [AC-16a](#ac-16_smt.a) for {{ insert: param, ac-16_prm_3 }}: {{ insert: param, ac-16_prm_4 }}; Determine the following permitted attribute values or ranges for each of the established attributes: {{ insert: param, ac-16_odp.09 }}; Audit changes to attributes; and Review {{ insert: param, ac-16_prm_6 }} for applicability {{ insert: param, ac-16_prm_7 }}. Information is represented internally within systems using abstractions known as data structures. Internal data structures can represent different types of entities, both active and passive. Active entities, also known as subjects, are typically associated with individuals, devices, or processes acting on behalf of individuals. Passive entities, also known as objects, are typically associated with data structures, such as records, buffers, tables, files, inter-process pipes, and communications ports. Security attributes, a form of metadata, are abstractions that represent the basic properties or characteristics of active and passive entities with respect to safeguarding information. Privacy attributes, which may be used independently or in conjunction with security attributes, represent the basic properties or characteristics of active or passive entities with respect to the management of personally identifiable information. Attributes can be either explicitly or implicitly associated with the information contained in organizational systems or system components.

Attributes may be associated with active entities (i.e., subjects) that have the potential to send or receive information, cause information to flow among objects, or change the system state. These attributes may also be associated with passive entities (i.e., objects) that contain or receive information. The association of attributes to subjects and objects by a system is referred to as binding and is inclusive of setting the attribute value and the attribute type. Attributes, when bound to data or information, permit the enforcement of security and privacy policies for access control and information flow control, including data retention limits, permitted uses of personally identifiable information, and identification of personal information within data objects. Such enforcement occurs through organizational processes or system functions or mechanisms. The binding techniques implemented by systems affect the strength of attribute binding to information. Binding strength and the assurance associated with binding techniques play important parts in the trust that organizations have in the information flow enforcement process. The binding techniques affect the number and degree of additional reviews required by organizations. The content or assigned values of attributes can directly affect the ability of individuals to access organizational information.

Organizations can define the types of attributes needed for systems to support missions or business functions. There are many values that can be assigned to a security attribute. By specifying the permitted attribute ranges and values, organizations ensure that attribute values are meaningful and relevant. Labeling refers to the association of attributes with the subjects and objects represented by the internal data structures within systems. This facilitates system-based enforcement of information security and privacy policies. Labels include classification of information in accordance with legal and compliance requirements (e.g., top secret, secret, confidential, controlled unclassified), information impact level; high value asset information, access authorizations, nationality; data life cycle protection (i.e., encryption and data expiration), personally identifiable information processing permissions, including individual consent to personally identifiable information processing, and contractor affiliation. A related term to labeling is marking. Marking refers to the association of attributes with objects in a human-readable form and displayed on system media. Marking enables manual, procedural, or process-based enforcement of information security and privacy policies. Security and privacy labels may have the same value as media markings (e.g., top secret, secret, confidential). See [MP-3](#mp-3) (Media Marking). the means to associate {{ insert: param, ac-16_odp.01 }} with {{ insert: param, ac-16_odp.03 }} for information in storage, in process, and/or in transmission are provided; the means to associate {{ insert: param, ac-16_odp.02 }} with {{ insert: param, ac-16_odp.04 }} for information in storage, in process, and/or in transmission are provided; attribute associations are made; attribute associations are retained with the information; the following permitted security attributes are established from the attributes defined in AC-16_ODP[01] for {{ insert: param, ac-16_odp.05 }}: {{ insert: param, ac-16_odp.07 }}; the following permitted privacy attributes are established from the attributes defined in AC-16_ODP[02] for {{ insert: param, ac-16_odp.06 }}: {{ insert: param, ac-16_odp.08 }}; the following permitted attribute values or ranges for each of the established attributes are determined: {{ insert: param, ac-16_odp.09 }}; changes to attributes are audited; {{ insert: param, ac-16_odp.07 }} are reviewed for applicability {{ insert: param, ac-16_odp.10 }}; {{ insert: param, ac-16_odp.08 }} are reviewed for applicability {{ insert: param, ac-16_odp.11 }}. Access control policy

procedures addressing the association of security and privacy attributes to information in storage, in process, and in transmission

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

privacy plan

other relevant documents or records System/network administrators

organizational personnel with information security and privacy responsibilities

system developers Organizational capability supporting and maintaining the association of security and privacy attributes to information in storage, in process, and in transmission

**FedRAMP Baseline:** L2 | **Domain:** AC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AC-17: Establish and document usage restrictions, configuration/connection requirements, and implementation guidance for each type of remote access allowed; and Authorize each type of remote access to the system prior to allowing such connections. Remote access is access to organizational systems (or processes acting on behalf of users) that communicate through external networks such as the Internet. Types of remote access include dial-up, broadband, and wireless. Organizations use encrypted virtual private networks (VPNs) to enhance confidentiality and integrity for remote connections. The use of encrypted VPNs provides sufficient assurance to the organization that it can effectively treat such connections as internal networks if the cryptographic mechanisms used are implemented in accordance with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Still, VPN connections traverse external networks, and the encrypted VPN does not enhance the availability of remote connections. VPNs with encrypted tunnels can also affect the ability to adequately monitor network communications traffic for malicious code. Remote access controls apply to systems other than public web servers or systems designed for public access. Authorization of each remote access type addresses authorization prior to allowing remote access without specifying the specific formats for such authorization. While organizations may use information exchange and system connection security agreements to manage remote access connections to other systems, such agreements are addressed as part of [CA-3](#ca-3) . Enforcing access restrictions for remote access is addressed via [AC-3](#ac-3). usage restrictions are established and documented for each type of remote access allowed; configuration/connection requirements are established and documented for each type of remote access allowed; implementation guidance is established and documented for each type of remote access allowed; each type of remote access to the system is authorized prior to allowing such connections. Access control policy

procedures addressing remote access implementation and usage (including restrictions)

configuration management plan

system configuration settings and associated documentation

remote access authorizations

system audit records

system security plan

other relevant documents or records Organizational personnel with responsibilities for managing remote access connections

system/network administrators

organizational personnel with information security responsibilities Remote access management capability for the system

**FedRAMP Baseline:** L2 | **Domain:** AC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AC-22: Designate individuals authorized to make information publicly accessible; Train authorized individuals to ensure that publicly accessible information does not contain nonpublic information; Review the proposed content of information prior to posting onto the publicly accessible system to ensure that nonpublic information is not included; and Review the content on the publicly accessible system for nonpublic information {{ insert: param, ac-22_odp }} and remove such information, if discovered. In accordance with applicable laws, executive orders, directives, policies, regulations, standards, and guidelines, the public is not authorized to have access to nonpublic information, including information protected under the [PRIVACT](#18e71fec-c6fd-475a-925a-5d8495cf8455) and proprietary information. Publicly accessible content addresses systems that are controlled by the organization and accessible to the public, typically without identification or authentication. Posting information on non-organizational systems (e.g., non-organizational public websites, forums, and social media) is covered by organizational policy. While organizations may have individuals who are responsible for developing and implementing policies about the information that can be made publicly accessible, publicly accessible content addresses the management of the individuals who make such information publicly accessible. designated individuals are authorized to make information publicly accessible; authorized individuals are trained to ensure that publicly accessible information does not contain non-public information; the proposed content of information is reviewed prior to posting onto the publicly accessible system to ensure that non-public information is not included; the content on the publicly accessible system is reviewed for non-public information {{ insert: param, ac-22_odp }}; non-public information is removed from the publicly accessible system, if discovered. Access control policy

procedures addressing publicly accessible content

list of users authorized to post publicly accessible content on organizational systems

training materials and/or records

records of publicly accessible information reviews

records of response to non-public information on public websites

system audit logs

security awareness training records

system security plan

other relevant documents or records Organizational personnel with responsibilities for managing publicly accessible information posted on organizational systems

organizational personnel with information security responsibilities Mechanisms implementing management of publicly accessible content

**FedRAMP Baseline:** L2 | **Domain:** AC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AC-23: Employ {{ insert: param, ac-23_odp.01 }} for {{ insert: param, ac-23_odp.02 }} to detect and protect against unauthorized data mining. Data mining is an analytical process that attempts to find correlations or patterns in large data sets for the purpose of data or knowledge discovery. Data storage objects include database records and database fields. Sensitive information can be extracted from data mining operations. When information is personally identifiable information, it may lead to unanticipated revelations about individuals and give rise to privacy risks. Prior to performing data mining activities, organizations determine whether such activities are authorized. Organizations may be subject to applicable laws, executive orders, directives, regulations, or policies that address data mining requirements. Organizational personnel consult with the senior agency official for privacy and legal counsel regarding such requirements.

Data mining prevention and detection techniques include limiting the number and frequency of database queries to increase the work factor needed to determine the contents of databases, limiting types of responses provided to database queries, applying differential privacy techniques or homomorphic encryption, and notifying personnel when atypical database queries or accesses occur. Data mining protection focuses on protecting information from data mining while such information resides in organizational data stores. In contrast, [AU-13](#au-13) focuses on monitoring for organizational information that may have been mined or otherwise obtained from data stores and is available as open-source information residing on external sites, such as social networking or social media websites.

[EO 13587](#0af071a6-cf8e-48ee-8c82-fe91efa20f94) requires the establishment of an insider threat program for deterring, detecting, and mitigating insider threats, including the safeguarding of sensitive information from exploitation, compromise, or other unauthorized disclosure. Data mining protection requires organizations to identify appropriate techniques to prevent and detect unnecessary or unauthorized data mining. Data mining can be used by an insider to collect organizational information for the purpose of exfiltration. {{ insert: param, ac-23_odp.01 }} are employed for {{ insert: param, ac-23_odp.02 }} to detect and protect against unauthorized data mining. Access control policy

procedures for preventing and detecting data mining

policies and procedures addressing authorized data mining techniques

procedures addressing protection of data storage objects against data mining

system design documentation

system configuration settings and associated documentation

system audit logs

system audit records

procedures addressing differential privacy techniques

notifications of atypical database queries or accesses

documentation or reports of insider threat program

system security plan

privacy plan

other relevant documents or records Organizational personnel with responsibilities for implementing data mining detection and prevention techniques for data storage objects

legal counsel

organizational personnel with information security and privacy responsibilities

system developers Mechanisms implementing data mining prevention and detection

**FedRAMP Baseline:** L2 | **Domain:** AC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AC-24: {{ insert: param, ac-24_odp.01 }} to ensure {{ insert: param, ac-24_odp.02 }} are applied to each access request prior to access enforcement. Access control decisions (also known as authorization decisions) occur when authorization information is applied to specific accesses. In contrast, access enforcement occurs when systems enforce access control decisions. While it is common to have access control decisions and access enforcement implemented by the same entity, it is not required, and it is not always an optimal implementation choice. For some architectures and distributed systems, different entities may make access control decisions and enforce access. {{ insert: param, ac-24_odp.01 }} are taken to ensure that {{ insert: param, ac-24_odp.02 }} are applied to each access request prior to access enforcement. Access control policy

procedures addressing access control decisions

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records Organizational personnel with responsibilities for establishing procedures regarding access control decisions to the system

organizational personnel with information security responsibilities Mechanisms applying established access control decisions and procedures

**FedRAMP Baseline:** L2 | **Domain:** AC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AC-25: Implement a reference monitor for {{ insert: param, ac-25_odp }} that is tamperproof, always invoked, and small enough to be subject to analysis and testing, the completeness of which can be assured. A reference monitor is a set of design requirements on a reference validation mechanism that, as a key component of an operating system, enforces an access control policy over all subjects and objects. A reference validation mechanism is always invoked, tamper-proof, and small enough to be subject to analysis and tests, the completeness of which can be assured (i.e., verifiable). Information is represented internally within systems using abstractions known as data structures. Internal data structures can represent different types of entities, both active and passive. Active entities, also known as subjects, are associated with individuals, devices, or processes acting on behalf of individuals. Passive entities, also known as objects, are associated with data structures, such as records, buffers, communications ports, tables, files, and inter-process pipes. Reference monitors enforce access control policies that restrict access to objects based on the identity of subjects or groups to which the subjects belong. The system enforces the access control policy based on the rule set established by the policy. The tamper-proof property of the reference monitor prevents determined adversaries from compromising the functioning of the reference validation mechanism. The always invoked property prevents adversaries from bypassing the mechanism and violating the security policy. The smallness property helps to ensure completeness in the analysis and testing of the mechanism to detect any weaknesses or deficiencies (i.e., latent flaws) that would prevent the enforcement of the security policy. a reference monitor is implemented for {{ insert: param, ac-25_odp }} that is tamper-proof, always invoked, and small enough to be subject to analysis and testing, the completeness of which can be assured. Access control policy

procedures addressing access enforcement

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records Organizational personnel with access enforcement responsibilities

system/network administrators

organizational personnel with information security responsibilities

system developers Mechanisms implementing access enforcement functions

**FedRAMP Baseline:** L2 | **Domain:** AC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### AT — Awareness and Training (Manual Controls)

##### Control AT-1: Develop, document, and disseminate to {{ insert: param, at-1_prm_1 }}: {{ insert: param, at-01_odp.03 }} awareness and training policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the awareness and training policy and the associated awareness and training controls; Designate an {{ insert: param, at-01_odp.04 }} to manage the development, documentation, and dissemination of the awareness and training policy and procedures; and Review and update the current awareness and training: Policy {{ insert: param, at-01_odp.05 }} and following {{ insert: param, at-01_odp.06 }} ; and Procedures {{ insert: param, at-01_odp.07 }} and following {{ insert: param, at-01_odp.08 }}. Awareness and training policy and procedures address the controls in the AT family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of awareness and training policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to awareness and training policy and procedures include assessment or audit findings, security incidents or breaches, or changes in applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. an awareness and training policy is developed and documented;  the awareness and training policy is disseminated to {{ insert: param, at-01_odp.01 }}; awareness and training procedures to facilitate the implementation of the awareness and training policy and associated access controls are developed and documented; the awareness and training procedures are disseminated to {{ insert: param, at-01_odp.02 }}. the {{ insert: param, at-01_odp.03 }} awareness and training policy addresses purpose; the {{ insert: param, at-01_odp.03 }} awareness and training policy addresses scope; the {{ insert: param, at-01_odp.03 }} awareness and training policy addresses roles; the {{ insert: param, at-01_odp.03 }} awareness and training policy addresses responsibilities; the {{ insert: param, at-01_odp.03 }} awareness and training policy addresses management commitment; the {{ insert: param, at-01_odp.03 }} awareness and training policy addresses coordination among organizational entities; the {{ insert: param, at-01_odp.03 }} awareness and training policy addresses compliance; and the {{ insert: param, at-01_odp.03 }} awareness and training policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; and the {{ insert: param, at-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the awareness and training policy and procedures; the current awareness and training policy is reviewed and updated {{ insert: param, at-01_odp.05 }};  the current awareness and training policy is reviewed and updated following {{ insert: param, at-01_odp.06 }}; the current awareness and training procedures are reviewed and updated {{ insert: param, at-01_odp.07 }}; the current awareness and training procedures are reviewed and updated following {{ insert: param, at-01_odp.08 }}. System security plan

privacy plan

awareness and training policy and procedures

other relevant documents or records Organizational personnel with awareness and training responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** AT

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AT-4: Document and monitor information security and privacy training activities, including security and privacy awareness training and specific role-based security and privacy training; and Retain individual training records for {{ insert: param, at-04_odp }}. Documentation for specialized training may be maintained by individual supervisors at the discretion of the organization. The National Archives and Records Administration provides guidance on records retention for federal agencies. information security and privacy training activities, including security and privacy awareness training and specific role-based security and privacy training, are documented; information security and privacy training activities, including security and privacy awareness training and specific role-based security and privacy training, are monitored; individual training records are retained for {{ insert: param, at-04_odp }}. Security and privacy awareness and training policy

procedures addressing security and privacy training records

security and privacy awareness and training records

system security plan

privacy plan

other relevant documents or records Organizational personnel with information security and privacy training record retention responsibilities Mechanisms supporting the management of security and privacy training records

**FedRAMP Baseline:** L2 | **Domain:** AT

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AT-5: 

**FedRAMP Baseline:** L2 | **Domain:** AT

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AT-6: Provide feedback on organizational training results to the following personnel {{ insert: param, at-06_odp.01 }}: {{ insert: param, at-06_odp.02 }}. Training feedback includes awareness training results and role-based training results. Training results, especially failures of personnel in critical roles, can be indicative of a potentially serious problem. Therefore, it is important that senior managers are made aware of such situations so that they can take appropriate response actions. Training feedback supports the evaluation and update of organizational training described in [AT-2b](#at-2_smt.b) and [AT-3b](#at-3_smt.b). feedback on organizational training results is provided {{ insert: param, at-06_odp.01 }} to {{ insert: param, at-06_odp.02 }}. Security awareness and training policy

procedures addressing security training records

security awareness and training records

security plan

other relevant documents or records Organizational personnel with information security training record retention responsibilities Mechanisms supporting the management of security training records

**FedRAMP Baseline:** L2 | **Domain:** AT

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### AU — Audit and Accountability (Manual Controls)

##### Control AU-1: Develop, document, and disseminate to {{ insert: param, au-1_prm_1 }}: {{ insert: param, au-01_odp.03 }} audit and accountability policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the audit and accountability policy and the associated audit and accountability controls; Designate an {{ insert: param, au-01_odp.04 }} to manage the development, documentation, and dissemination of the audit and accountability policy and procedures; and Review and update the current audit and accountability: Policy {{ insert: param, au-01_odp.05 }} and following {{ insert: param, au-01_odp.06 }} ; and Procedures {{ insert: param, au-01_odp.07 }} and following {{ insert: param, au-01_odp.08 }}. Audit and accountability policy and procedures address the controls in the AU family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of audit and accountability policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to audit and accountability policy and procedures include assessment or audit findings, security incidents or breaches, or changes in applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. an audit and accountability policy is developed and documented; the audit and accountability policy is disseminated to {{ insert: param, au-01_odp.01 }}; audit and accountability procedures to facilitate the implementation of the audit and accountability policy and associated audit and accountability controls are developed and documented; the audit and accountability procedures are disseminated to {{ insert: param, au-01_odp.02 }}; the {{ insert: param, au-01_odp.03 }} of the audit and accountability policy addresses purpose; the {{ insert: param, au-01_odp.03 }} of the audit and accountability policy addresses scope; the {{ insert: param, au-01_odp.03 }} of the audit and accountability policy addresses roles; the {{ insert: param, au-01_odp.03 }} of the audit and accountability policy addresses responsibilities; the {{ insert: param, au-01_odp.03 }} of the audit and accountability policy addresses management commitment; the {{ insert: param, au-01_odp.03 }} of the audit and accountability policy addresses coordination among organizational entities; the {{ insert: param, au-01_odp.03 }} of the audit and accountability policy addresses compliance; the {{ insert: param, au-01_odp.03 }} of the audit and accountability policy is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, au-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the audit and accountability policy and procedures; the current audit and accountability policy is reviewed and updated {{ insert: param, au-01_odp.05 }}; the current audit and accountability policy is reviewed and updated following {{ insert: param, au-01_odp.06 }}; the current audit and accountability procedures are reviewed and updated {{ insert: param, au-01_odp.07 }}; the current audit and accountability procedures are reviewed and updated following {{ insert: param, au-01_odp.08 }}. Audit and accountability policy and procedures

system security plan

privacy plan

other relevant documents or records Organizational personnel with audit and accountability responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** AU

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AU-4: Allocate audit log storage capacity to accommodate {{ insert: param, au-04_odp }}. Organizations consider the types of audit logging to be performed and the audit log processing requirements when allocating audit log storage capacity. Allocating sufficient audit log storage capacity reduces the likelihood of such capacity being exceeded and resulting in the potential loss or reduction of audit logging capability. audit log storage capacity is allocated to accommodate {{ insert: param, au-04_odp }}. Audit and accountability policy

procedures addressing audit storage capacity

system security plan

privacy plan

system design documentation

system configuration settings and associated documentation

audit record storage requirements

audit record storage capability for system components

system audit records

other relevant documents or records Organizational personnel with audit and accountability responsibilities

organizational personnel with information security and privacy responsibilities

system/network administrators

system developers Audit record storage capacity and related configuration settings

**FedRAMP Baseline:** L2 | **Domain:** AU

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AU-10: Provide irrefutable evidence that an individual (or process acting on behalf of an individual) has performed {{ insert: param, au-10_odp }}. Types of individual actions covered by non-repudiation include creating information, sending and receiving messages, and approving information. Non-repudiation protects against claims by authors of not having authored certain documents, senders of not having transmitted messages, receivers of not having received messages, and signatories of not having signed documents. Non-repudiation services can be used to determine if information originated from an individual or if an individual took specific actions (e.g., sending an email, signing a contract, approving a procurement request, or receiving specific information). Organizations obtain non-repudiation services by employing various techniques or mechanisms, including digital signatures and digital message receipts. irrefutable evidence is provided that an individual (or process acting on behalf of an individual) has performed {{ insert: param, au-10_odp }}. Audit and accountability policy

system security plan

privacy plan

procedures addressing non-repudiation

system design documentation

system configuration settings and associated documentation

system audit records

other relevant documents or records Organizational personnel with information security and privacy responsibilities

system/network administrators

system developers Mechanisms implementing non-repudiation capability

**FedRAMP Baseline:** L2 | **Domain:** AU

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AU-11: Retain audit records for {{ insert: param, au-11_odp }} to provide support for after-the-fact investigations of incidents and to meet regulatory and organizational information retention requirements. Organizations retain audit records until it is determined that the records are no longer needed for administrative, legal, audit, or other operational purposes. This includes the retention and availability of audit records relative to Freedom of Information Act (FOIA) requests, subpoenas, and law enforcement actions. Organizations develop standard categories of audit records relative to such types of actions and standard response processes for each type of action. The National Archives and Records Administration (NARA) General Records Schedules provide federal policy on records retention. audit records are retained for {{ insert: param, au-11_odp }} to provide support for after-the-fact investigations of incidents and to meet regulatory and organizational information retention requirements. Audit and accountability policy

system security plan

privacy plan

audit record retention policy and procedures

security plan

organization-defined retention period for audit records

audit record archives

audit logs

audit records

other relevant documents or records Organizational personnel with audit record retention responsibilities

organizational personnel with information security and privacy responsibilities

system/network administrators

**FedRAMP Baseline:** L2 | **Domain:** AU

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AU-12: Provide audit record generation capability for the event types the system is capable of auditing as defined in [AU-2a](#au-2_smt.a) on {{ insert: param, au-12_odp.01 }}; Allow {{ insert: param, au-12_odp.02 }} to select the event types that are to be logged by specific components of the system; and Generate audit records for the event types defined in [AU-2c](#au-2_smt.c) that include the audit record content defined in [AU-3](#au-3). Audit records can be generated from many different system components. The event types specified in [AU-2d](#au-2_smt.d) are the event types for which audit logs are to be generated and are a subset of all event types for which the system can generate audit records. audit record generation capability for the event types the system is capable of auditing (defined in AU-02_ODP[01]) is provided by {{ insert: param, au-12_odp.01 }}; {{ insert: param, au-12_odp.02 }} is/are allowed to select the event types that are to be logged by specific components of the system; audit records for the event types defined in AU-02_ODP[02] that include the audit record content defined in AU-03 are generated. Audit and accountability policy

procedures addressing audit record generation

system security plan

privacy plan

system design documentation

system configuration settings and associated documentation

list of auditable events

system audit records

other relevant documents or records Organizational personnel with audit record generation responsibilities

organizational personnel with information security and privacy responsibilities

system/network administrators

system developers Mechanisms implementing audit record generation capability

**FedRAMP Baseline:** L2 | **Domain:** AU

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AU-13: Monitor {{ insert: param, au-13_odp.01 }} {{ insert: param, au-13_odp.02 }} for evidence of unauthorized disclosure of organizational information; and If an information disclosure is discovered: Notify {{ insert: param, au-13_odp.03 }} ; and Take the following additional actions: {{ insert: param, au-13_odp.04 }}. Unauthorized disclosure of information is a form of data leakage. Open-source information includes social networking sites and code-sharing platforms and repositories. Examples of organizational information include personally identifiable information retained by the organization or proprietary information generated by the organization. {{ insert: param, au-13_odp.01 }} is/are monitored {{ insert: param, au-13_odp.02 }} for evidence of unauthorized disclosure of organizational information; {{ insert: param, au-13_odp.03 }} are notified if an information disclosure is discovered; {{ insert: param, au-13_odp.04 }} are taken if an information disclosure is discovered. Audit and accountability policy

system security plan

privacy plan

procedures addressing information disclosure monitoring

system design documentation

system configuration settings and associated documentation

monitoring records

system audit records

other relevant documents or records Organizational personnel with responsibilities for monitoring open-source information and/or information sites

organizational personnel with security and privacy responsibilities Mechanisms implementing monitoring for information disclosure

**FedRAMP Baseline:** L2 | **Domain:** AU

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AU-14: Provide and implement the capability for {{ insert: param, au-14_odp.01 }} to {{ insert: param, au-14_odp.02 }} the content of a user session under {{ insert: param, au-14_odp.03 }} ; and Develop, integrate, and use session auditing activities in consultation with legal counsel and in accordance with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Session audits can include monitoring keystrokes, tracking websites visited, and recording information and/or file transfers. Session audit capability is implemented in addition to event logging and may involve implementation of specialized session capture technology. Organizations consider how session auditing can reveal information about individuals that may give rise to privacy risk as well as how to mitigate those risks. Because session auditing can impact system and network performance, organizations activate the capability under well-defined situations (e.g., the organization is suspicious of a specific individual). Organizations consult with legal counsel, civil liberties officials, and privacy officials to ensure that any legal, privacy, civil rights, or civil liberties issues, including the use of personally identifiable information, are appropriately addressed. {{ insert: param, au-14_odp.01 }} are provided with the capability to {{ insert: param, au-14_odp.02 }} the content of a user session under {{ insert: param, au-14_odp.03 }}; the capability for {{ insert: param, au-14_odp.01 }} to {{ insert: param, au-14_odp.02 }} the content of a user session under {{ insert: param, au-14_odp.03 }} is implemented; session auditing activities are developed in consultation with legal counsel and in accordance with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; session auditing activities are integrated in consultation with legal counsel and in accordance with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; session auditing activities are used in consultation with legal counsel and in accordance with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; Audit and accountability policy

system security plan

privacy plan

procedures addressing user session auditing

system design documentation

system configuration settings and associated documentation

system audit records

other relevant documents or records Organizational personnel with information security and privacy responsibilities

system/network administrators

system developers

legal counsel

personnel with civil liberties responsibilities Mechanisms implementing user session auditing capability

**FedRAMP Baseline:** L2 | **Domain:** AU

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AU-15: 

**FedRAMP Baseline:** L2 | **Domain:** AU

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control AU-16: Employ {{ insert: param, au-16_odp.01 }} for coordinating {{ insert: param, au-16_odp.02 }} among external organizations when audit information is transmitted across organizational boundaries. When organizations use systems or services of external organizations, the audit logging capability necessitates a coordinated, cross-organization approach. For example, maintaining the identity of individuals who request specific services across organizational boundaries may often be difficult, and doing so may prove to have significant performance and privacy ramifications. Therefore, it is often the case that cross-organizational audit logging simply captures the identity of individuals who issue requests at the initial system, and subsequent systems record that the requests originated from authorized individuals. Organizations consider including processes for coordinating audit information requirements and protection of audit information in information exchange agreements. {{ insert: param, au-16_odp.01 }} for coordinating {{ insert: param, au-16_odp.02 }} among external organizations when audit information is transmitted across organizational boundaries are employed. Audit and accountability policy

system security plan

privacy plan

procedures addressing methods for coordinating audit information among external organizations

system design documentation

system configuration settings and associated documentation

system audit records

other relevant documents or records Organizational personnel with responsibilities for coordinating audit information among external organizations

organizational personnel with information security and privacy responsibilities Mechanisms implementing cross-organizational auditing

**FedRAMP Baseline:** L2 | **Domain:** AU

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### CA — Assessment, Authorization, and Monitoring (Manual Controls)

##### Control CA-1: Develop, document, and disseminate to {{ insert: param, ca-1_prm_1 }}: {{ insert: param, ca-01_odp.03 }} assessment, authorization, and monitoring policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the assessment, authorization, and monitoring policy and the associated assessment, authorization, and monitoring controls; Designate an {{ insert: param, ca-01_odp.04 }} to manage the development, documentation, and dissemination of the assessment, authorization, and monitoring policy and procedures; and Review and update the current assessment, authorization, and monitoring: Policy {{ insert: param, ca-01_odp.05 }} and following {{ insert: param, ca-01_odp.06 }} ; and Procedures {{ insert: param, ca-01_odp.07 }} and following {{ insert: param, ca-01_odp.08 }}. Assessment, authorization, and monitoring policy and procedures address the controls in the CA family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of assessment, authorization, and monitoring policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to assessment, authorization, and monitoring policy and procedures include assessment or audit findings, security incidents or breaches, or changes in applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. an assessment, authorization, and monitoring policy is developed and documented; the assessment, authorization, and monitoring policy is disseminated to {{ insert: param, ca-01_odp.01 }}; assessment, authorization, and monitoring procedures to facilitate the implementation of the assessment, authorization, and monitoring policy and associated assessment, authorization, and monitoring controls are developed and documented; the assessment, authorization, and monitoring procedures are disseminated to {{ insert: param, ca-01_odp.02 }}; the {{ insert: param, ca-01_odp.03 }} assessment, authorization, and monitoring policy addresses purpose; the {{ insert: param, ca-01_odp.03 }} assessment, authorization, and monitoring policy addresses scope; the {{ insert: param, ca-01_odp.03 }} assessment, authorization, and monitoring policy addresses roles; the {{ insert: param, ca-01_odp.03 }} assessment, authorization, and monitoring policy addresses responsibilities; the {{ insert: param, ca-01_odp.03 }} assessment, authorization, and monitoring policy addresses management commitment; the {{ insert: param, ca-01_odp.03 }} assessment, authorization, and monitoring policy addresses coordination among organizational entities; the {{ insert: param, ca-01_odp.03 }} assessment, authorization, and monitoring policy addresses compliance; the {{ insert: param, ca-01_odp.03 }} assessment, authorization, and monitoring policy is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, ca-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the assessment, authorization, and monitoring policy and procedures; the current assessment, authorization, and monitoring policy is reviewed and updated {{ insert: param, ca-01_odp.05 }};  the current assessment, authorization, and monitoring policy is reviewed and updated following {{ insert: param, ca-01_odp.06 }}; the current assessment, authorization, and monitoring procedures are reviewed and updated {{ insert: param, ca-01_odp.07 }};  the current assessment, authorization, and monitoring procedures are reviewed and updated following {{ insert: param, ca-01_odp.08 }}. Assessment, authorization, and monitoring policy and procedures

system security plan

privacy plan

other relevant documents or records Organizational personnel with assessment, authorization, and monitoring policy responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** CA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CA-3: Approve and manage the exchange of information between the system and other systems using {{ insert: param, ca-03_odp.01 }}; Document, as part of each exchange agreement, the interface characteristics, security and privacy requirements, controls, and responsibilities for each system, and the impact level of the information communicated; and Review and update the agreements {{ insert: param, ca-03_odp.03 }}. System information exchange requirements apply to information exchanges between two or more systems. System information exchanges include connections via leased lines or virtual private networks, connections to internet service providers, database sharing or exchanges of database transaction information, connections and exchanges with cloud services, exchanges via web-based services, or exchanges of files via file transfer protocols, network protocols (e.g., IPv4, IPv6), email, or other organization-to-organization communications. Organizations consider the risk related to new or increased threats that may be introduced when systems exchange information with other systems that may have different security and privacy requirements and controls. This includes systems within the same organization and systems that are external to the organization. A joint authorization of the systems exchanging information, as described in [CA-6(1)](#ca-6.1) or [CA-6(2)](#ca-6.2) , may help to communicate and reduce risk.

Authorizing officials determine the risk associated with system information exchange and the controls needed for appropriate risk mitigation. The types of agreements selected are based on factors such as the impact level of the information being exchanged, the relationship between the organizations exchanging information (e.g., government to government, government to business, business to business, government or business to service provider, government or business to individual), or the level of access to the organizational system by users of the other system. If systems that exchange information have the same authorizing official, organizations need not develop agreements. Instead, the interface characteristics between the systems (e.g., how the information is being exchanged. how the information is protected) are described in the respective security and privacy plans. If the systems that exchange information have different authorizing officials within the same organization, the organizations can develop agreements or provide the same information that would be provided in the appropriate agreement type from [CA-3a](#ca-3_smt.a) in the respective security and privacy plans for the systems. Organizations may incorporate agreement information into formal contracts, especially for information exchanges established between federal agencies and nonfederal organizations (including service providers, contractors, system developers, and system integrators). Risk considerations include systems that share the same networks. the exchange of information between the system and other systems is approved and managed using {{ insert: param, ca-03_odp.01 }}; the interface characteristics are documented as part of each exchange agreement; security requirements are documented as part of each exchange agreement; privacy requirements are documented as part of each exchange agreement; controls are documented as part of each exchange agreement; responsibilities for each system are documented as part of each exchange agreement; the impact level of the information communicated is documented as part of each exchange agreement; agreements are reviewed and updated {{ insert: param, ca-03_odp.03 }}. Access control policy

procedures addressing system connections

system and communications protection policy

system interconnection security agreements

information exchange security agreements

memoranda of understanding or agreements

service level agreements

non-disclosure agreements

system design documentation

enterprise architecture

system architecture

system configuration settings and associated documentation

system security plan

privacy plan

other relevant documents or records Organizational personnel with responsibilities for developing, implementing, or approving system interconnection agreements

organizational personnel with information security and privacy responsibilities

personnel managing the system(s) to which the interconnection security agreement applies

**FedRAMP Baseline:** L2 | **Domain:** CA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CA-4: 

**FedRAMP Baseline:** L2 | **Domain:** CA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CA-6: Assign a senior official as the authorizing official for the system; Assign a senior official as the authorizing official for common controls available for inheritance by organizational systems; Ensure that the authorizing official for the system, before commencing operations: Accepts the use of common controls inherited by the system; and Authorizes the system to operate; Ensure that the authorizing official for common controls authorizes the use of those controls for inheritance by organizational systems; Update the authorizations {{ insert: param, ca-06_odp }}. Authorizations are official management decisions by senior officials to authorize operation of systems, authorize the use of common controls for inheritance by organizational systems, and explicitly accept the risk to organizational operations and assets, individuals, other organizations, and the Nation based on the implementation of agreed-upon controls. Authorizing officials provide budgetary oversight for organizational systems and common controls or assume responsibility for the mission and business functions supported by those systems or common controls. The authorization process is a federal responsibility, and therefore, authorizing officials must be federal employees. Authorizing officials are both responsible and accountable for security and privacy risks associated with the operation and use of organizational systems. Nonfederal organizations may have similar processes to authorize systems and senior officials that assume the authorization role and associated responsibilities.

Authorizing officials issue ongoing authorizations of systems based on evidence produced from implemented continuous monitoring programs. Robust continuous monitoring programs reduce the need for separate reauthorization processes. Through the employment of comprehensive continuous monitoring processes, the information contained in authorization packages (i.e., security and privacy plans, assessment reports, and plans of action and milestones) is updated on an ongoing basis. This provides authorizing officials, common control providers, and system owners with an up-to-date status of the security and privacy posture of their systems, controls, and operating environments. To reduce the cost of reauthorization, authorizing officials can leverage the results of continuous monitoring processes to the maximum extent possible as the basis for rendering reauthorization decisions. a senior official is assigned as the authorizing official for the system; a senior official is assigned as the authorizing official for common controls available for inheritance by organizational systems; before commencing operations, the authorizing official for the system accepts the use of common controls inherited by the system; before commencing operations, the authorizing official for the system authorizes the system to operate; the authorizing official for common controls authorizes the use of those controls for inheritance by organizational systems; the authorizations are updated {{ insert: param, ca-06_odp }}. Assessment, authorization, and monitoring policy

procedures addressing authorization

system security plan, privacy plan, assessment report, plan of action and milestones

authorization statement

other relevant documents or records Organizational personnel with authorization responsibilities

organizational personnel with information security and privacy responsibilities Mechanisms that facilitate authorizations and updates

**FedRAMP Baseline:** L2 | **Domain:** CA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CA-8: Conduct penetration testing {{ insert: param, ca-08_odp.01 }} on {{ insert: param, ca-08_odp.02 }}. Penetration testing is a specialized type of assessment conducted on systems or individual system components to identify vulnerabilities that could be exploited by adversaries. Penetration testing goes beyond automated vulnerability scanning and is conducted by agents and teams with demonstrable skills and experience that include technical expertise in network, operating system, and/or application level security. Penetration testing can be used to validate vulnerabilities or determine the degree of penetration resistance of systems to adversaries within specified constraints. Such constraints include time, resources, and skills. Penetration testing attempts to duplicate the actions of adversaries and provides a more in-depth analysis of security- and privacy-related weaknesses or deficiencies. Penetration testing is especially important when organizations are transitioning from older technologies to newer technologies (e.g., transitioning from IPv4 to IPv6 network protocols).

Organizations can use the results of vulnerability analyses to support penetration testing activities. Penetration testing can be conducted internally or externally on the hardware, software, or firmware components of a system and can exercise both physical and technical controls. A standard method for penetration testing includes a pretest analysis based on full knowledge of the system, pretest identification of potential vulnerabilities based on the pretest analysis, and testing designed to determine the exploitability of vulnerabilities. All parties agree to the rules of engagement before commencing penetration testing scenarios. Organizations correlate the rules of engagement for the penetration tests with the tools, techniques, and procedures that are anticipated to be employed by adversaries. Penetration testing may result in the exposure of information that is protected by laws or regulations, to individuals conducting the testing. Rules of engagement, contracts, or other appropriate mechanisms can be used to communicate expectations for how to protect this information. Risk assessments guide the decisions on the level of independence required for the personnel conducting penetration testing. penetration testing is conducted {{ insert: param, ca-08_odp.01 }} on {{ insert: param, ca-08_odp.02 }}. Assessment, authorization, and monitoring policy

procedures addressing penetration testing

assessment plan

penetration test report

assessment report

assessment evidence

system security plan

privacy plan

other relevant documents or records Organizational personnel with control assessment responsibilities

organizational personnel with information security and privacy responsibilities

system/network administrators Mechanisms supporting penetration testing

**FedRAMP Baseline:** L2 | **Domain:** CA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CA-9: Authorize internal connections of {{ insert: param, ca-09_odp.01 }} to the system; Document, for each internal connection, the interface characteristics, security and privacy requirements, and the nature of the information communicated; Terminate internal system connections after {{ insert: param, ca-09_odp.02 }} ; and Review {{ insert: param, ca-09_odp.03 }} the continued need for each internal connection. Internal system connections are connections between organizational systems and separate constituent system components (i.e., connections between components that are part of the same system) including components used for system development. Intra-system connections include connections with mobile devices, notebook and desktop computers, tablets, printers, copiers, facsimile machines, scanners, sensors, and servers. Instead of authorizing each internal system connection individually, organizations can authorize internal connections for a class of system components with common characteristics and/or configurations, including printers, scanners, and copiers with a specified processing, transmission, and storage capability or smart phones and tablets with a specific baseline configuration. The continued need for an internal system connection is reviewed from the perspective of whether it provides support for organizational missions or business functions. internal connections of {{ insert: param, ca-09_odp.01 }} to the system are authorized; for each internal connection, the interface characteristics are documented; for each internal connection, the security requirements are documented; for each internal connection, the privacy requirements are documented; for each internal connection, the nature of the information communicated is documented; internal system connections are terminated after {{ insert: param, ca-09_odp.02 }}; the continued need for each internal connection is reviewed {{ insert: param, ca-09_odp.03 }}. Assessment, authorization, and monitoring policy

access control policy

procedures addressing system connections

system and communications protection policy

system design documentation

system configuration settings and associated documentation

list of components or classes of components authorized as internal system connections

assessment report

system audit records

system security plan

privacy plan

other relevant documents or records Organizational personnel with responsibilities for developing, implementing, or authorizing internal system connections

organizational personnel with information security and privacy responsibilities Mechanisms supporting internal system connections

**FedRAMP Baseline:** L2 | **Domain:** CA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### CM — Configuration Management (Manual Controls)

##### Control CM-1: Develop, document, and disseminate to {{ insert: param, cm-1_prm_1 }}: {{ insert: param, cm-01_odp.03 }} configuration management policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the configuration management policy and the associated configuration management controls; Designate an {{ insert: param, cm-01_odp.04 }} to manage the development, documentation, and dissemination of the configuration management policy and procedures; and Review and update the current configuration management: Policy {{ insert: param, cm-01_odp.05 }} and following {{ insert: param, cm-01_odp.06 }} ; and Procedures {{ insert: param, cm-01_odp.07 }} and following {{ insert: param, cm-01_odp.08 }}. Configuration management policy and procedures address the controls in the CM family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of configuration management policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission/business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to configuration management policy and procedures include, but are not limited to, assessment or audit findings, security incidents or breaches, or changes in applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. a configuration management policy is developed and documented; the configuration management policy is disseminated to {{ insert: param, cm-01_odp.01 }}; configuration management procedures to facilitate the implementation of the configuration management policy and associated configuration management controls are developed and documented; the configuration management procedures are disseminated to {{ insert: param, cm-01_odp.02 }}; the {{ insert: param, cm-01_odp.03 }} of the configuration management policy addresses purpose; the {{ insert: param, cm-01_odp.03 }} of the configuration management policy addresses scope; the {{ insert: param, cm-01_odp.03 }} of the configuration management policy addresses roles; the {{ insert: param, cm-01_odp.03 }} of the configuration management policy addresses responsibilities; the {{ insert: param, cm-01_odp.03 }} of the configuration management policy addresses management commitment; the {{ insert: param, cm-01_odp.03 }} of the configuration management policy addresses coordination among organizational entities; the {{ insert: param, cm-01_odp.03 }} of the configuration management policy addresses compliance; the configuration management policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, cm-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the configuration management policy and procedures; the current configuration management policy is reviewed and updated {{ insert: param, cm-01_odp.05 }};  the current configuration management policy is reviewed and updated following {{ insert: param, cm-01_odp.06 }}; the current configuration management procedures are reviewed and updated {{ insert: param, cm-01_odp.07 }};  the current configuration management procedures are reviewed and updated following {{ insert: param, cm-01_odp.08 }}. Configuration management policy and procedures

security and privacy program policies and procedures

assessment or audit findings

documentation of security incidents or breaches

system security plan

privacy plan

risk management strategy

other relevant artifacts, documents, or records Organizational personnel with configuration management responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** CM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CM-4: Analyze changes to the system to determine potential security and privacy impacts prior to change implementation. Organizational personnel with security or privacy responsibilities conduct impact analyses. Individuals conducting impact analyses possess the necessary skills and technical expertise to analyze the changes to systems as well as the security or privacy ramifications. Impact analyses include reviewing security and privacy plans, policies, and procedures to understand control requirements; reviewing system design documentation and operational procedures to understand control implementation and how specific system changes might affect the controls; reviewing the impact of changes on organizational supply chain partners with stakeholders; and determining how potential changes to a system create new risks to the privacy of individuals and the ability of implemented controls to mitigate those risks. Impact analyses also include risk assessments to understand the impact of the changes and determine if additional controls are required. changes to the system are analyzed to determine potential security impacts prior to change implementation; changes to the system are analyzed to determine potential privacy impacts prior to change implementation. Configuration management policy

procedures addressing security impact analyses for changes to the system

procedures addressing privacy impact analyses for changes to the system

configuration management plan

security impact analysis documentation

privacy impact analysis documentation

privacy impact assessment

privacy risk assessment documentation, system design documentation

analysis tools and associated outputs

change control records

system audit records

system security plan

privacy plan

other relevant documents or records Organizational personnel with responsibility for conducting security impact analyses

organizational personnel with responsibility for conducting privacy impact analyses

organizational personnel with information security and privacy responsibilities

system developer

system/network administrators

members of change control board or similar Organizational processes for security impact analyses

organizational processes for privacy impact analyses

**FedRAMP Baseline:** L2 | **Domain:** CM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CM-9: Develop, document, and implement a configuration management plan for the system that: Addresses roles, responsibilities, and configuration management processes and procedures; Establishes a process for identifying configuration items throughout the system development life cycle and for managing the configuration of the configuration items; Defines the configuration items for the system and places the configuration items under configuration management; Is reviewed and approved by {{ insert: param, cm-09_odp }} ; and Protects the configuration management plan from unauthorized disclosure and modification. Configuration management activities occur throughout the system development life cycle. As such, there are developmental configuration management activities (e.g., the control of code and software libraries) and operational configuration management activities (e.g., control of installed components and how the components are configured). Configuration management plans satisfy the requirements in configuration management policies while being tailored to individual systems. Configuration management plans define processes and procedures for how configuration management is used to support system development life cycle activities.

Configuration management plans are generated during the development and acquisition stage of the system development life cycle. The plans describe how to advance changes through change management processes; update configuration settings and baselines; maintain component inventories; control development, test, and operational environments; and develop, release, and update key documents.

Organizations can employ templates to help ensure the consistent and timely development and implementation of configuration management plans. Templates can represent a configuration management plan for the organization with subsets of the plan implemented on a system by system basis. Configuration management approval processes include the designation of key stakeholders responsible for reviewing and approving proposed changes to systems, and personnel who conduct security and privacy impact analyses prior to the implementation of changes to the systems. Configuration items are the system components, such as the hardware, software, firmware, and documentation to be configuration-managed. As systems continue through the system development life cycle, new configuration items may be identified, and some existing configuration items may no longer need to be under configuration control. a configuration management plan for the system is developed and documented; a configuration management plan for the system is implemented; the configuration management plan addresses roles; the configuration management plan addresses responsibilities; the configuration management plan addresses configuration management processes and procedures; the configuration management plan establishes a process for identifying configuration items throughout the system development life cycle; the configuration management plan establishes a process for managing the configuration of the configuration items; the configuration management plan defines the configuration items for the system; the configuration management plan places the configuration items under configuration management; the configuration management plan is reviewed and approved by {{ insert: param, cm-09_odp }}; the configuration management plan is protected from unauthorized disclosure; the configuration management plan is protected from unauthorized modification. Configuration management policy

procedures addressing configuration management planning

configuration management plan

system design documentation

system security plan

privacy plan

other relevant documents or records Organizational personnel with responsibilities for developing the configuration management plan

organizational personnel with responsibilities for implementing and managing processes defined in the configuration management plan

organizational personnel with responsibilities for protecting the configuration management plan

organizational personnel with information security and privacy responsibilities

system/network administrators Organizational processes for developing and documenting the configuration management plan

organizational processes for identifying and managing configuration items

organizational processes for protecting the configuration management plan

mechanisms implementing the configuration management plan

mechanisms for managing configuration items

mechanisms for protecting the configuration management plan

**FedRAMP Baseline:** L2 | **Domain:** CM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CM-10: Use software and associated documentation in accordance with contract agreements and copyright laws; Track the use of software and associated documentation protected by quantity licenses to control copying and distribution; and Control and document the use of peer-to-peer file sharing technology to ensure that this capability is not used for the unauthorized distribution, display, performance, or reproduction of copyrighted work. Software license tracking can be accomplished by manual or automated methods, depending on organizational needs. Examples of contract agreements include software license agreements and non-disclosure agreements. software and associated documentation are used in accordance with contract agreements and copyright laws; the use of software and associated documentation protected by quantity licenses is tracked to control copying and distribution; the use of peer-to-peer file sharing technology is controlled and documented to ensure that peer-to-peer file sharing is not used for the unauthorized distribution, display, performance, or reproduction of copyrighted work. Configuration management policy

software usage restrictions

software contract agreements and copyright laws

site license documentation

list of software usage restrictions

software license tracking reports

configuration management plan

system security plan

system security plan

other relevant documents or records Organizational personnel operating, using, and/or maintaining the system

organizational personnel with software license management responsibilities

organizational personnel with information security responsibilities

system/network administrators Organizational processes for tracking the use of software protected by quantity licenses

organizational processes for controlling/documenting the use of peer-to-peer file sharing technology

mechanisms implementing software license tracking

mechanisms implementing and controlling the use of peer-to-peer files sharing technology

**FedRAMP Baseline:** L2 | **Domain:** CM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CM-11: Establish {{ insert: param, cm-11_odp.01 }} governing the installation of software by users; Enforce software installation policies through the following methods: {{ insert: param, cm-11_odp.02 }} ; and Monitor policy compliance {{ insert: param, cm-11_odp.03 }}. If provided the necessary privileges, users can install software in organizational systems. To maintain control over the software installed, organizations identify permitted and prohibited actions regarding software installation. Permitted software installations include updates and security patches to existing software and downloading new applications from organization-approved "app stores." Prohibited software installations include software with unknown or suspect pedigrees or software that organizations consider potentially malicious. Policies selected for governing user-installed software are organization-developed or provided by some external entity. Policy enforcement methods can include procedural methods and automated methods. {{ insert: param, cm-11_odp.01 }} governing the installation of software by users are established; software installation policies are enforced through {{ insert: param, cm-11_odp.02 }}; compliance with {{ insert: param, cm-11_odp.01 }} is monitored {{ insert: param, cm-11_odp.03 }}. Configuration management policy

procedures addressing user-installed software

configuration management plan

system security plan

system design documentation

system configuration settings and associated documentation

list of rules governing user installed software

system monitoring records

system audit records

continuous monitoring strategy

system security plan

other relevant documents or records Organizational personnel with responsibilities for governing user-installed software

organizational personnel operating, using, and/or maintaining the system

organizational personnel monitoring compliance with user-installed software policy

organizational personnel with information security responsibilities

system/network administrators Organizational processes governing user-installed software on the system

mechanisms enforcing policies and methods for governing the installation of software by users

mechanisms monitoring policy compliance

**FedRAMP Baseline:** L2 | **Domain:** CM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CM-12: Identify and document the location of {{ insert: param, cm-12_odp }} and the specific system components on which the information is processed and stored; Identify and document the users who have access to the system and system components where the information is processed and stored; and Document changes to the location (i.e., system or system components) where the information is processed and stored. Information location addresses the need to understand where information is being processed and stored. Information location includes identifying where specific information types and information reside in system components and how information is being processed so that information flow can be understood and adequate protection and policy management provided for such information and system components. The security category of the information is also a factor in determining the controls necessary to protect the information and the system component where the information resides (see [FIPS 199](#628d22a1-6a11-4784-bc59-5cd9497b5445) ). The location of the information and system components is also a factor in the architecture and design of the system (see [SA-4](#sa-4), [SA-8](#sa-8), [SA-17](#sa-17)). the location of {{ insert: param, cm-12_odp }} is identified and documented; the specific system components on which {{ insert: param, cm-12_odp }} is processed are identified and documented; the specific system components on which {{ insert: param, cm-12_odp }} is stored are identified and documented; the users who have access to the system and system components where {{ insert: param, cm-12_odp }} is processed are identified and documented; the users who have access to the system and system components where {{ insert: param, cm-12_odp }} is stored are identified and documented; changes to the location (i.e., system or system components) where {{ insert: param, cm-12_odp }} is processed are documented; changes to the location (i.e., system or system components) where {{ insert: param, cm-12_odp }} is stored are documented. Configuration management policy

procedures addressing identification and documentation of information location

configuration management plan

system design documentation

system architecture documentation

PII inventory documentation

data mapping documentation

audit records

list of users with system and system component access

change control records

system component inventory

system security plan

privacy plan

other relevant documents or records Organizational personnel with responsibilities for managing information location and user access to information

organizational personnel with responsibilities for operating, using, and/or maintaining the system

organizational personnel with information security and privacy responsibilities

system/network administrators

system developers Organizational processes governing information location

mechanisms enforcing policies and methods for governing information location

**FedRAMP Baseline:** L2 | **Domain:** CM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CM-13: Develop and document a map of system data actions. Data actions are system operations that process personally identifiable information. The processing of such information encompasses the full information life cycle, which includes collection, generation, transformation, use, disclosure, retention, and disposal. A map of system data actions includes discrete data actions, elements of personally identifiable information being processed in the data actions, system components involved in the data actions, and the owners or operators of the system components. Understanding what personally identifiable information is being processed (e.g., the sensitivity of the personally identifiable information), how personally identifiable information is being processed (e.g., if the data action is visible to the individual or is processed in another part of the system), and by whom (e.g., individuals may have different privacy perceptions based on the entity that is processing the personally identifiable information) provides a number of contextual factors that are important to assessing the degree of privacy risk created by the system. Data maps can be illustrated in different ways, and the level of detail may vary based on the mission and business needs of the organization. The data map may be an overlay of any system design artifact that the organization is using. The development of this map may necessitate coordination between the privacy and security programs regarding the covered data actions and the components that are identified as part of the system. a map of system data actions is developed and documented. Configuration management policy

procedures for identification and documentation of information location

procedures for mapping data actions

configuration management plan

system security plan

privacy plan

system design documentation

PII inventory documentation

data mapping documentation

change control records

system component inventory

other relevant documents or records Organizational personnel with responsibilities for managing information location

organizational personnel responsible for data action mapping

organizational personnel with information security and privacy responsibilities

system/network administrators

system developers Organizational processes governing information location

mechanisms supporting or implementing data action mapping

**FedRAMP Baseline:** L2 | **Domain:** CM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CM-14: Prevent the installation of {{ insert: param, cm-14_prm_1 }} without verification that the component has been digitally signed using a certificate that is recognized and approved by the organization. Software and firmware components prevented from installation unless signed with recognized and approved certificates include software and firmware version updates, patches, service packs, device drivers, and basic input/output system updates. Organizations can identify applicable software and firmware components by type, by specific items, or a combination of both. Digital signatures and organizational verification of such signatures is a method of code authentication. the installation of {{ insert: param, cm-14_odp.01 }} is prevented unless it is verified that the software has been digitally signed using a certificate recognized and approved by the organization; the installation of {{ insert: param, cm-14_odp.02 }} is prevented unless it is verified that the firmware has been digitally signed using a certificate recognized and approved by the organization. Configuration management policy

procedures addressing digitally signed certificates for software and firmware components

configuration management plan

system security plan

system design documentation

change control records

system component inventory

system security plan

other relevant documents or records Organizational personnel with responsibilities for verifying digitally signed certificates for software and firmware component installation

organizational personnel with information security responsibilities

system/network administrators

system developers Organizational processes governing information location

mechanisms enforcing policies and methods for governing information location

automated tools supporting or implementing digitally signatures for software and firmware components

automated tools supporting or implementing verification of digital signatures for software and firmware component installation

**FedRAMP Baseline:** L2 | **Domain:** CM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### CP — Contingency Planning (Manual Controls)

##### Control CP-1: Develop, document, and disseminate to {{ insert: param, cp-1_prm_1 }}: {{ insert: param, cp-01_odp.03 }} contingency planning policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the contingency planning policy and the associated contingency planning controls; Designate an {{ insert: param, cp-01_odp.04 }} to manage the development, documentation, and dissemination of the contingency planning policy and procedures; and Review and update the current contingency planning: Policy {{ insert: param, cp-01_odp.05 }} and following {{ insert: param, cp-01_odp.06 }} ; and Procedures {{ insert: param, cp-01_odp.07 }} and following {{ insert: param, cp-01_odp.08 }}. Contingency planning policy and procedures address the controls in the CP family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of contingency planning policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to contingency planning policy and procedures include assessment or audit findings, security incidents or breaches, or changes in laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. a contingency planning policy is developed and documented; the contingency planning policy is disseminated to {{ insert: param, cp-01_odp.01 }}; contingency planning procedures to facilitate the implementation of the contingency planning policy and associated contingency planning controls are developed and documented; the contingency planning procedures are disseminated to {{ insert: param, cp-01_odp.02 }}; the {{ insert: param, cp-01_odp.03 }} contingency planning policy addresses purpose; the {{ insert: param, cp-01_odp.03 }} contingency planning policy addresses scope; the {{ insert: param, cp-01_odp.03 }} contingency planning policy addresses roles; the {{ insert: param, cp-01_odp.03 }} contingency planning policy addresses responsibilities; the {{ insert: param, cp-01_odp.03 }} contingency planning policy addresses management commitment; the {{ insert: param, cp-01_odp.03 }} contingency planning policy addresses coordination among organizational entities; the {{ insert: param, cp-01_odp.03 }} contingency planning policy addresses compliance; the {{ insert: param, cp-01_odp.03 }} contingency planning policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, cp-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the contingency planning policy and procedures; the current contingency planning policy is reviewed and updated {{ insert: param, cp-01_odp.05 }}; the current contingency planning policy is reviewed and updated following {{ insert: param, cp-01_odp.06 }}; the current contingency planning procedures are reviewed and updated {{ insert: param, cp-01_odp.07 }}; the current contingency planning procedures are reviewed and updated following {{ insert: param, cp-01_odp.08 }}. Contingency planning policy and procedures

system security plan

privacy plan

other relevant documents or records Organizational personnel with contingency planning responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** CP

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CP-3: Provide contingency training to system users consistent with assigned roles and responsibilities: Within {{ insert: param, cp-03_odp.01 }} of assuming a contingency role or responsibility; When required by system changes; and {{ insert: param, cp-03_odp.02 }} thereafter; and Review and update contingency training content {{ insert: param, cp-03_odp.03 }} and following {{ insert: param, cp-03_odp.04 }}. Contingency training provided by organizations is linked to the assigned roles and responsibilities of organizational personnel to ensure that the appropriate content and level of detail is included in such training. For example, some individuals may only need to know when and where to report for duty during contingency operations and if normal duties are affected; system administrators may require additional training on how to establish systems at alternate processing and storage sites; and organizational officials may receive more specific training on how to conduct mission-essential functions in designated off-site locations and how to establish communications with other governmental entities for purposes of coordination on contingency-related activities. Training for contingency roles or responsibilities reflects the specific continuity requirements in the contingency plan. Events that may precipitate an update to contingency training content include, but are not limited to, contingency plan testing or an actual contingency (lessons learned), assessment or audit findings, security incidents or breaches, or changes in laws, executive orders, directives, regulations, policies, standards, and guidelines. At the discretion of the organization, participation in a contingency plan test or exercise, including lessons learned sessions subsequent to the test or exercise, may satisfy contingency plan training requirements. contingency training is provided to system users consistent with assigned roles and responsibilities within {{ insert: param, cp-03_odp.01 }} of assuming a contingency role or responsibility; contingency training is provided to system users consistent with assigned roles and responsibilities when required by system changes; contingency training is provided to system users consistent with assigned roles and responsibilities {{ insert: param, cp-03_odp.02 }} thereafter; the contingency plan training content is reviewed and updated {{ insert: param, cp-03_odp.03 }}; the contingency plan training content is reviewed and updated following {{ insert: param, cp-03_odp.04 }}. Contingency planning policy

procedures addressing contingency training

contingency plan

contingency training curriculum

contingency training material

contingency training records

system security plan

other relevant documents or records Organizational personnel with contingency planning, plan implementation, and training responsibilities

organizational personnel with information security responsibilities Organizational processes for contingency training

**FedRAMP Baseline:** L2 | **Domain:** CP

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CP-5: 

**FedRAMP Baseline:** L2 | **Domain:** CP

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CP-8: Establish alternate telecommunications services, including necessary agreements to permit the resumption of {{ insert: param, cp-08_odp.01 }} for essential mission and business functions within {{ insert: param, cp-08_odp.02 }} when the primary telecommunications capabilities are unavailable at either the primary or alternate processing or storage sites. Telecommunications services (for data and voice) for primary and alternate processing and storage sites are in scope for [CP-8](#cp-8) . Alternate telecommunications services reflect the continuity requirements in contingency plans to maintain essential mission and business functions despite the loss of primary telecommunications services. Organizations may specify different time periods for primary or alternate sites. Alternate telecommunications services include additional organizational or commercial ground-based circuits or lines, network-based approaches to telecommunications, or the use of satellites. Organizations consider factors such as availability, quality of service, and access when entering into alternate telecommunications agreements. alternate telecommunications services, including necessary agreements to permit the resumption of {{ insert: param, cp-08_odp.01 }} , are established for essential mission and business functions within {{ insert: param, cp-08_odp.02 }} when the primary telecommunications capabilities are unavailable at either the primary or alternate processing or storage sites. Contingency planning policy

procedures addressing alternate telecommunications services

contingency plan

primary and alternate telecommunications service agreements

system security plan

other relevant documents or records Organizational personnel with contingency plan telecommunications responsibilities

organizational personnel with system recovery responsibilities

organizational personnel with knowledge of requirements for mission and business functions

organizational personnel with information security responsibilities

organizational personnel with responsibility for acquisitions/contractual agreements Mechanisms supporting telecommunications

**FedRAMP Baseline:** L2 | **Domain:** CP

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CP-11: Provide the capability to employ {{ insert: param, cp-11_odp }} in support of maintaining continuity of operations. Contingency plans and the contingency training or testing associated with those plans incorporate an alternate communications protocol capability as part of establishing resilience in organizational systems. Switching communications protocols may affect software applications and operational aspects of systems. Organizations assess the potential side effects of introducing alternate communications protocols prior to implementation. the capability to employ {{ insert: param, cp-11_odp }} are provided in support of maintaining continuity of operations. Contingency planning policy

procedures addressing alternative communications protocols

contingency plan

continuity of operations plan

system design documentation

system configuration settings and associated documentation

list of alternative communications protocols supporting continuity of operations

system security plan

other relevant documents or records Organizational personnel with contingency planning and plan implementation responsibilities

organizational personnel with continuity of operations planning and plan implementation responsibilities

organizational personnel with information security responsibilities

system/network administrators

system developers Mechanisms employing alternative communications protocols

**FedRAMP Baseline:** L2 | **Domain:** CP

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CP-12: When {{ insert: param, cp-12_odp.02 }} are detected, enter a safe mode of operation with {{ insert: param, cp-12_odp.01 }}. For systems that support critical mission and business functions—including military operations, civilian space operations, nuclear power plant operations, and air traffic control operations (especially real-time operational environments)—organizations can identify certain conditions under which those systems revert to a predefined safe mode of operation. The safe mode of operation, which can be activated either automatically or manually, restricts the operations that systems can execute when those conditions are encountered. Restriction includes allowing only selected functions to execute that can be carried out under limited power or with reduced communications bandwidth. a safe mode of operation is entered with {{ insert: param, cp-12_odp.01 }} when {{ insert: param, cp-12_odp.02 }} are detected. Contingency planning policy

procedures addressing safe mode of operation for the system

contingency plan

system design documentation

system configuration settings and associated documentation

system administration manuals

system operation manuals

system installation manuals

contingency plan test records

incident handling records

system audit records

system security plan

other relevant documents or records Organizational personnel with system operation responsibilities

organizational personnel with information security responsibilities

system/network administrators

system developers Mechanisms implementing safe mode of operation

**FedRAMP Baseline:** L2 | **Domain:** CP

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control CP-13: Employ {{ insert: param, cp-13_odp.01 }} for satisfying {{ insert: param, cp-13_odp.02 }} when the primary means of implementing the security function is unavailable or compromised. Use of alternative security mechanisms supports system resiliency, contingency planning, and continuity of operations. To ensure mission and business continuity, organizations can implement alternative or supplemental security mechanisms. The mechanisms may be less effective than the primary mechanisms. However, having the capability to readily employ alternative or supplemental mechanisms enhances mission and business continuity that might otherwise be adversely impacted if operations had to be curtailed until the primary means of implementing the functions was restored. Given the cost and level of effort required to provide such alternative capabilities, the alternative or supplemental mechanisms are only applied to critical security capabilities provided by systems, system components, or system services. For example, an organization may issue one-time pads to senior executives, officials, and system administrators if multi-factor tokens—the standard means for achieving secure authentication— are compromised. {{ insert: param, cp-13_odp.01 }} are employed for satisfying {{ insert: param, cp-13_odp.02 }} when the primary means of implementing the security function is unavailable or compromised. Contingency planning policy

procedures addressing alternate security mechanisms

contingency plan

continuity of operations plan

system design documentation

system configuration settings and associated documentation

contingency plan test records

contingency plan test results

system security plan

other relevant documents or records Organizational personnel with system operation responsibilities

organizational personnel with information security responsibilities system capability implementing alternative security mechanisms

**FedRAMP Baseline:** L2 | **Domain:** CP

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### IA — Identification and Authentication (Manual Controls)

##### Control IA-1: Develop, document, and disseminate to {{ insert: param, ia-1_prm_1 }}: {{ insert: param, ia-01_odp.03 }} identification and authentication policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the identification and authentication policy and the associated identification and authentication controls; Designate an {{ insert: param, ia-01_odp.04 }} to manage the development, documentation, and dissemination of the identification and authentication policy and procedures; and Review and update the current identification and authentication: Policy {{ insert: param, ia-01_odp.05 }} and following {{ insert: param, ia-01_odp.06 }} ; and Procedures {{ insert: param, ia-01_odp.07 }} and following {{ insert: param, ia-01_odp.08 }}. Identification and authentication policy and procedures address the controls in the IA family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of identification and authentication policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to identification and authentication policy and procedures include assessment or audit findings, security incidents or breaches, or changes in applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. an identification and authentication policy is developed and documented; the identification and authentication policy is disseminated to {{ insert: param, ia-01_odp.01 }}; identification and authentication procedures to facilitate the implementation of the identification and authentication policy and associated identification and authentication controls are developed and documented; the identification and authentication procedures are disseminated to {{ insert: param, ia-01_odp.02 }}; the {{ insert: param, ia-01_odp.03 }} identification and authentication policy addresses purpose; the {{ insert: param, ia-01_odp.03 }} identification and authentication policy addresses scope; the {{ insert: param, ia-01_odp.03 }} identification and authentication policy addresses roles; the {{ insert: param, ia-01_odp.03 }} identification and authentication policy addresses responsibilities; the {{ insert: param, ia-01_odp.03 }} identification and authentication policy addresses management commitment; the {{ insert: param, ia-01_odp.03 }} identification and authentication policy addresses coordination among organizational entities; the {{ insert: param, ia-01_odp.03 }} identification and authentication policy addresses compliance; the {{ insert: param, ia-01_odp.03 }} identification and authentication policy is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, ia-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the identification and authentication policy and procedures; the current identification and authentication policy is reviewed and updated {{ insert: param, ia-01_odp.05 }}; the current identification and authentication policy is reviewed and updated following {{ insert: param, ia-01_odp.06 }}; the current identification and authentication procedures are reviewed and updated {{ insert: param, ia-01_odp.07 }}; the current identification and authentication procedures are reviewed and updated following {{ insert: param, ia-01_odp.08 }}. Identification and authentication policy and procedures

system security plan

privacy plan

risk management strategy documentation

list of events requiring identification and authentication procedures to be reviewed and updated (e.g., audit findings)

other relevant documents or records Organizational personnel with identification and authentication responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** IA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control IA-6: Obscure feedback of authentication information during the authentication process to protect the information from possible exploitation and use by unauthorized individuals. Authentication feedback from systems does not provide information that would allow unauthorized individuals to compromise authentication mechanisms. For some types of systems, such as desktops or notebooks with relatively large monitors, the threat (referred to as shoulder surfing) may be significant. For other types of systems, such as mobile devices with small displays, the threat may be less significant and is balanced against the increased likelihood of typographic input errors due to small keyboards. Thus, the means for obscuring authentication feedback is selected accordingly. Obscuring authentication feedback includes displaying asterisks when users type passwords into input devices or displaying feedback for a very limited time before obscuring it. the feedback of authentication information is obscured during the authentication process to protect the information from possible exploitation and use by unauthorized individuals. Identification and authentication policy

system security plan

procedures addressing authenticator feedback

system design documentation

system configuration settings and associated documentation

system audit records

other relevant documents or records Organizational personnel with information security responsibilities

system/network administrators

system developers Mechanisms supporting and/or implementing the obscuring of feedback of authentication information during authentication

**FedRAMP Baseline:** L2 | **Domain:** IA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control IA-7: Implement mechanisms for authentication to a cryptographic module that meet the requirements of applicable laws, executive orders, directives, policies, regulations, standards, and guidelines for such authentication. Authentication mechanisms may be required within a cryptographic module to authenticate an operator accessing the module and to verify that the operator is authorized to assume the requested role and perform services within that role. mechanisms for authentication to a cryptographic module are implemented that meet the requirements of applicable laws, executive orders, directives, policies, regulations, standards, and guidelines for such authentication. Identification and authentication policy

system security plan

procedures addressing cryptographic module authentication

system design documentation

system configuration settings and associated documentation

system audit records

other relevant documents or records Organizational personnel with responsibility for cryptographic module authentication

organizational personnel with information security responsibilities

system/network administrators

system developers Mechanisms supporting and/or implementing cryptographic module authentication

**FedRAMP Baseline:** L2 | **Domain:** IA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control IA-9: Uniquely identify and authenticate {{ insert: param, ia-09_odp }} before establishing communications with devices, users, or other services or applications. Services that may require identification and authentication include web applications using digital certificates or services or applications that query a database. Identification and authentication methods for system services and applications include information or code signing, provenance graphs, and electronic signatures that indicate the sources of services. Decisions regarding the validity of identification and authentication claims can be made by services separate from the services acting on those decisions. This can occur in distributed system architectures. In such situations, the identification and authentication decisions (instead of actual identifiers and authentication data) are provided to the services that need to act on those decisions. {{ insert: param, ia-09_odp }} are uniquely identified and authenticated before establishing communications with devices, users, or other services or applications. Identification and authentication policy

procedures addressing service identification and authentication

system security plan

system design documentation

security safeguards used to identify and authenticate system services

system configuration settings and associated documentation

system audit records

other relevant documents or records Organizational personnel with system operations responsibilities

organizational personnel with information security responsibilities

system/network administrators

system developers

organizational personnel with identification and authentication responsibilities Security safeguards implementing service identification and authentication capabilities

**FedRAMP Baseline:** L2 | **Domain:** IA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control IA-10: Require individuals accessing the system to employ {{ insert: param, ia-10_odp.01 }} under specific {{ insert: param, ia-10_odp.02 }}. Adversaries may compromise individual authentication mechanisms employed by organizations and subsequently attempt to impersonate legitimate users. To address this threat, organizations may employ specific techniques or mechanisms and establish protocols to assess suspicious behavior. Suspicious behavior may include accessing information that individuals do not typically access as part of their duties, roles, or responsibilities; accessing greater quantities of information than individuals would routinely access; or attempting to access information from suspicious network addresses. When pre-established conditions or triggers occur, organizations can require individuals to provide additional authentication information. Another potential use for adaptive authentication is to increase the strength of mechanism based on the number or types of records being accessed. Adaptive authentication does not replace and is not used to avoid the use of multi-factor authentication mechanisms but can augment implementations of multi-factor authentication. individuals accessing the system are required to employ {{ insert: param, ia-10_odp.01 }} under specific {{ insert: param, ia-10_odp.02 }}. Identification and authentication policy

procedures addressing adaptive/supplemental identification and authentication techniques or mechanisms

system security plan

system design documentation

system configuration settings and associated documentation

supplemental identification and authentication techniques or mechanisms

system audit records

other relevant documents or records Organizational personnel with system operations responsibilities

organizational personnel with information security responsibilities

system/network administrators

system developers

organizational personnel with identification and authentication responsibilities Mechanisms supporting and/or implementing identification and authentication capabilities

**FedRAMP Baseline:** L2 | **Domain:** IA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control IA-12: Identity proof users that require accounts for logical access to systems based on appropriate identity assurance level requirements as specified in applicable standards and guidelines; Resolve user identities to a unique individual; and Collect, validate, and verify identity evidence. Identity proofing is the process of collecting, validating, and verifying a user’s identity information for the purposes of establishing credentials for accessing a system. Identity proofing is intended to mitigate threats to the registration of users and the establishment of their accounts. Standards and guidelines specifying identity assurance levels for identity proofing include [SP 800-63-3](#737513fa-6758-403f-831d-5ddab5e23cb3) and [SP 800-63A](#9099ed2c-922a-493d-bcb4-d896192243ff) . Organizations may be subject to laws, executive orders, directives, regulations, or policies that address the collection of identity evidence. Organizational personnel consult with the senior agency official for privacy and legal counsel regarding such requirements. users who require accounts for logical access to systems based on appropriate identity assurance level requirements as specified in applicable standards and guidelines are identity proofed; user identities are resolved to a unique individual; identity evidence is collected; identity evidence is validated; identity evidence is verified. Identification and authentication policy

procedures addressing identity proofing

system security plan

privacy plan

other relevant documents or records Organizational personnel with system operations responsibilities

organizational personnel with information security and privacy responsibilities

legal counsel

system/network administrators

system developers

organizational personnel with identification and authentication responsibilities Mechanisms supporting and/or implementing identification and authentication capabilities

**FedRAMP Baseline:** L2 | **Domain:** IA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control IA-13: Employ identity providers and authorization servers to manage user, device, and non-person entity (NPE) identities, attributes, and access rights supporting authentication and authorization decisions in accordance with {{ insert: param, ia-13_odp.01 }} using {{ insert: param, ia-13_odp.02 }}. Identity providers, both internal and external to the organization, manage the user, device, and NPE authenticators and issue statements, often called identity assertions, attesting to identities of other systems or systems components. Authorization servers create and issue access tokens to identified and authenticated users and devices that can be used to gain access to system or information resources. For example, single sign-on (SSO) provides identity provider and authorization server functions. Authenticator management (to include credential management) is covered by IA-05. identity providers are employed to manage user, device, and non-person entity (NPE) identities, attributes and access rights supporting authentication decisions in accordance with {{ insert: param, ia-13_odp.02 }} using {{ insert: param, ia-13_odp.02 }}; identity providers are employed to manage user, device, and non-person entity (NPE) identities, attributes and access rights supporting authorization decisions in accordance with {{ insert: param, ia-13_odp.02 }} using {{ insert: param, ia-13_odp.02 }}; authorization servers are employed to manage user, device, and non-person entity (NPE) identities, attributes and access rights supporting authentication decisions in accordance with {{ insert: param, ia-13_odp.02 }} using {{ insert: param, ia-13_odp.02 }}; authorization servers are employed to manage user, device, and non-person entity (NPE) identities, attributes and access rights supporting authorization decisions in accordance with {{ insert: param, ia-13_odp.02 }} using {{ insert: param, ia-13_odp.02 }};  Identification and authentication policy;

procedures addressing user and device identification and authentication;

system security plan;

system design documentation;

system configuration settings and associated documentation;

other relevant documents or records Organizational personnel with system operations responsibilities;

organizational personnel with information security responsibilities;

system/network administrators;

organizational personnel with account management responsibilities;

system developers Mechanisms supporting and/or implementing identification and authentication capabilities and access rights

**FedRAMP Baseline:** L2 | **Domain:** IA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### IR — Incident Response (Manual Controls)

##### Control IR-1: Develop, document, and disseminate to {{ insert: param, ir-1_prm_1 }}: {{ insert: param, ir-01_odp.03 }} incident response policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the incident response policy and the associated incident response controls; Designate an {{ insert: param, ir-01_odp.04 }} to manage the development, documentation, and dissemination of the incident response policy and procedures; and Review and update the current incident response: Policy {{ insert: param, ir-01_odp.05 }} and following {{ insert: param, ir-01_odp.06 }} ; and Procedures {{ insert: param, ir-01_odp.07 }} and following {{ insert: param, ir-01_odp.08 }}. Incident response policy and procedures address the controls in the IR family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of incident response policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to incident response policy and procedures include assessment or audit findings, security incidents or breaches, or changes in laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. an incident response policy is developed and documented; the incident response policy is disseminated to {{ insert: param, ir-01_odp.01 }}; incident response procedures to facilitate the implementation of the incident response policy and associated incident response controls are developed and documented; the incident response procedures are disseminated to {{ insert: param, ir-01_odp.02 }}; the {{ insert: param, ir-01_odp.03 }} incident response policy addresses purpose; the {{ insert: param, ir-01_odp.03 }} incident response policy addresses scope; the {{ insert: param, ir-01_odp.03 }} incident response policy addresses roles; the {{ insert: param, ir-01_odp.03 }} incident response policy addresses responsibilities; the {{ insert: param, ir-01_odp.03 }} incident response policy addresses management commitment; the {{ insert: param, ir-01_odp.03 }} incident response policy addresses coordination among organizational entities; the {{ insert: param, ir-01_odp.03 }} incident response policy addresses compliance; the {{ insert: param, ir-01_odp.03 }} incident response policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, ir-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the incident response policy and procedures; the current incident response policy is reviewed and updated {{ insert: param, ir-01_odp.05 }}; the current incident response policy is reviewed and updated following {{ insert: param, ir-01_odp.06 }}; the current incident response procedures are reviewed and updated {{ insert: param, ir-01_odp.07 }}; the current incident response procedures are reviewed and updated following {{ insert: param, ir-01_odp.08 }}. Incident response policy and procedures

system security plan

privacy plan

other relevant documents or records Organizational personnel with incident response responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** IR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control IR-3: Test the effectiveness of the incident response capability for the system {{ insert: param, ir-03_odp.01 }} using the following tests: {{ insert: param, ir-03_odp.02 }}. Organizations test incident response capabilities to determine their effectiveness and identify potential weaknesses or deficiencies. Incident response testing includes the use of checklists, walk-through or tabletop exercises, and simulations (parallel or full interrupt). Incident response testing can include a determination of the effects on organizational operations and assets and individuals due to incident response. The use of qualitative and quantitative data aids in determining the effectiveness of incident response processes. the effectiveness of the incident response capability for the system is tested {{ insert: param, ir-03_odp.01 }} using {{ insert: param, ir-03_odp.02 }}. Incident response policy

contingency planning policy

procedures addressing incident response testing

procedures addressing contingency plan testing

incident response testing material

incident response test results

incident response test plan

incident response plan

contingency plan

system security plan

privacy plan

other relevant documents or records Organizational personnel with incident response testing responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** IR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control IR-6: Require personnel to report suspected incidents to the organizational incident response capability within {{ insert: param, ir-06_odp.01 }} ; and Report incident information to {{ insert: param, ir-06_odp.02 }}. The types of incidents reported, the content and timeliness of the reports, and the designated reporting authorities reflect applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Incident information can inform risk assessments, control effectiveness assessments, security requirements for acquisitions, and selection criteria for technology products. personnel is/are required to report suspected incidents to the organizational incident response capability within {{ insert: param, ir-06_odp.01 }}; incident information is reported to {{ insert: param, ir-06_odp.02 }}. Incident response policy

procedures addressing incident reporting

incident reporting records and documentation

incident response plan

system security plan

privacy plan

other relevant documents or records Organizational personnel with incident reporting responsibilities

organizational personnel with information security and privacy responsibilities

personnel who have/should have reported incidents

personnel (authorities) to whom incident information is to be reported

system users Organizational processes for incident reporting

mechanisms supporting and/or implementing incident reporting

**FedRAMP Baseline:** L2 | **Domain:** IR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control IR-7: Provide an incident response support resource, integral to the organizational incident response capability, that offers advice and assistance to users of the system for the handling and reporting of incidents. Incident response support resources provided by organizations include help desks, assistance groups, automated ticketing systems to open and track incident response tickets, and access to forensics services or consumer redress services, when required. an incident response support resource, integral to the organizational incident response capability, is provided; the incident response support resource offers advice and assistance to users of the system for the response and reporting of incidents. Incident response policy

procedures addressing incident response assistance

incident response plan

system security plan

privacy plan

other relevant documents or records Organizational personnel with incident response assistance and support responsibilities

organizational personnel with access to incident response support and assistance capability

organizational personnel with information security and privacy responsibilities Organizational processes for incident response assistance

mechanisms supporting and/or implementing incident response assistance

**FedRAMP Baseline:** L2 | **Domain:** IR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control IR-8: Develop an incident response plan that: Provides the organization with a roadmap for implementing its incident response capability; Describes the structure and organization of the incident response capability; Provides a high-level approach for how the incident response capability fits into the overall organization; Meets the unique requirements of the organization, which relate to mission, size, structure, and functions; Defines reportable incidents; Provides metrics for measuring the incident response capability within the organization; Defines the resources and management support needed to effectively maintain and mature an incident response capability; Addresses the sharing of incident information; Is reviewed and approved by {{ insert: param, ir-08_odp.01 }} {{ insert: param, ir-08_odp.02 }} ; and Explicitly designates responsibility for incident response to {{ insert: param, ir-08_odp.03 }}. Distribute copies of the incident response plan to {{ insert: param, ir-08_odp.04 }}; Update the incident response plan to address system and organizational changes or problems encountered during plan implementation, execution, or testing; Communicate incident response plan changes to {{ insert: param, ir-8_prm_5 }} ; and Protect the incident response plan from unauthorized disclosure and modification. It is important that organizations develop and implement a coordinated approach to incident response. Organizational mission and business functions determine the structure of incident response capabilities. As part of the incident response capabilities, organizations consider the coordination and sharing of information with external organizations, including external service providers and other organizations involved in the supply chain. For incidents involving personally identifiable information (i.e., breaches), include a process to determine whether notice to oversight organizations or affected individuals is appropriate and provide that notice accordingly. an incident response plan is developed that provides the organization with a roadmap for implementing its incident response capability; an incident response plan is developed that describes the structure and organization of the incident response capability; an incident response plan is developed that provides a high-level approach for how the incident response capability fits into the overall organization; an incident response plan is developed that meets the unique requirements of the organization with regard to mission, size, structure, and functions; an incident response plan is developed that defines reportable incidents; an incident response plan is developed that provides metrics for measuring the incident response capability within the organization; an incident response plan is developed that defines the resources and management support needed to effectively maintain and mature an incident response capability; an incident response plan is developed that addresses the sharing of incident information; an incident response plan is developed that is reviewed and approved by {{ insert: param, ir-08_odp.01 }} {{ insert: param, ir-08_odp.02 }}; an incident response plan is developed that explicitly designates responsibility for incident response to {{ insert: param, ir-08_odp.03 }}. copies of the incident response plan are distributed to {{ insert: param, ir-08_odp.04 }}; copies of the incident response plan are distributed to {{ insert: param, ir-08_odp.05 }}; the incident response plan is updated to address system and organizational changes or problems encountered during plan implementation, execution, or testing; incident response plan changes are communicated to {{ insert: param, ir-08_odp.06 }}; incident response plan changes are communicated to {{ insert: param, ir-08_odp.07 }}; the incident response plan is protected from unauthorized disclosure; the incident response plan is protected from unauthorized modification. Incident response policy

procedures addressing incident response planning

incident response plan

system security plan

privacy plan

records of incident response plan reviews and approvals

other relevant documents or records Organizational personnel with incident response planning responsibilities

organizational personnel with information security and privacy responsibilities Organizational incident response plan and related organizational processes

**FedRAMP Baseline:** L2 | **Domain:** IR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control IR-9: Respond to information spills by: Assigning {{ insert: param, ir-09_odp.01 }} with responsibility for responding to information spills; Identifying the specific information involved in the system contamination; Alerting {{ insert: param, ir-09_odp.02 }} of the information spill using a method of communication not associated with the spill; Isolating the contaminated system or system component; Eradicating the information from the contaminated system or component; Identifying other systems or system components that may have been subsequently contaminated; and Performing the following additional actions: {{ insert: param, ir-09_odp.03 }}. Information spillage refers to instances where information is placed on systems that are not authorized to process such information. Information spills occur when information that is thought to be a certain classification or impact level is transmitted to a system and subsequently is determined to be of a higher classification or impact level. At that point, corrective action is required. The nature of the response is based on the classification or impact level of the spilled information, the security capabilities of the system, the specific nature of the contaminated storage media, and the access authorizations of individuals with authorized access to the contaminated system. The methods used to communicate information about the spill after the fact do not involve methods directly associated with the actual spill to minimize the risk of further spreading the contamination before such contamination is isolated and eradicated. {{ insert: param, ir-09_odp.01 }} is/are assigned the responsibility to respond to information spills; the specific information involved in the system contamination is identified in response to information spills; {{ insert: param, ir-09_odp.02 }} is/are alerted of the information spill using a method of communication not associated with the spill; the contaminated system or system component is isolated in response to information spills; the information is eradicated from the contaminated system or component in response to information spills; other systems or system components that may have been subsequently contaminated are identified in response to information spills; {{ insert: param, ir-09_odp.03 }} are performed in response to information spills. Incident response policy

procedures addressing information spillage

incident response plan

system security plan

records of information spillage alerts/notifications

list of personnel who should receive alerts of information spillage

list of actions to be performed regarding information spillage

other relevant documents or records Organizational personnel with incident response responsibilities

organizational personnel with information security responsibilities Organizational processes for information spillage response

mechanisms supporting and/or implementing information spillage response actions and related communications

**FedRAMP Baseline:** L2 | **Domain:** IR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control IR-10: 

**FedRAMP Baseline:** L2 | **Domain:** IR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### MA — Maintenance (Manual Controls)

##### Control MA-1: Develop, document, and disseminate to {{ insert: param, ma-1_prm_1 }}: {{ insert: param, ma-01_odp.03 }} maintenance policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the maintenance policy and the associated maintenance controls; Designate an {{ insert: param, ma-01_odp.04 }} to manage the development, documentation, and dissemination of the maintenance policy and procedures; and Review and update the current maintenance: Policy {{ insert: param, ma-01_odp.05 }} and following {{ insert: param, ma-01_odp.06 }} ; and Procedures {{ insert: param, ma-01_odp.07 }} and following {{ insert: param, ma-01_odp.08 }}. Maintenance policy and procedures address the controls in the MA family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of maintenance policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to maintenance policy and procedures assessment or audit findings, security incidents or breaches, or changes in applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. a maintenance policy is developed and documented; the maintenance policy is disseminated to {{ insert: param, ma-01_odp.01 }}; maintenance procedures to facilitate the implementation of the maintenance policy and associated maintenance controls are developed and documented; the maintenance procedures are disseminated to {{ insert: param, ma-01_odp.02 }}; the {{ insert: param, ma-01_odp.03 }} maintenance policy addresses purpose; the {{ insert: param, ma-01_odp.03 }} maintenance policy addresses scope; the {{ insert: param, ma-01_odp.03 }} maintenance policy addresses roles; the {{ insert: param, ma-01_odp.03 }} maintenance policy addresses responsibilities; the {{ insert: param, ma-01_odp.03 }} maintenance policy addresses management commitment; the {{ insert: param, ma-01_odp.03 }} maintenance policy addresses coordination among organizational entities; the {{ insert: param, ma-01_odp.03 }} maintenance policy addresses compliance; the {{ insert: param, ma-01_odp.03 }} maintenance policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, ma-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the maintenance policy and procedures; the current maintenance policy is reviewed and updated {{ insert: param, ma-01_odp.05 }}; the current maintenance policy is reviewed and updated following {{ insert: param, ma-01_odp.06 }}; the current maintenance procedures are reviewed and updated {{ insert: param, ma-01_odp.07 }}; the current maintenance procedures are reviewed and updated following {{ insert: param, ma-01_odp.08 }}. Maintenance policy and procedures

system security plan

privacy plan

organizational risk management strategy

other relevant documents or records Organizational personnel with maintenance responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** MA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control MA-6: Obtain maintenance support and/or spare parts for {{ insert: param, ma-06_odp.01 }} within {{ insert: param, ma-06_odp.02 }} of failure. Organizations specify the system components that result in increased risk to organizational operations and assets, individuals, other organizations, or the Nation when the functionality provided by those components is not operational. Organizational actions to obtain maintenance support include having appropriate contracts in place. maintenance support and/or spare parts are obtained for {{ insert: param, ma-06_odp.01 }} within {{ insert: param, ma-06_odp.02 }} of failure. Maintenance policy

procedures addressing system maintenance

service provider contracts

service-level agreements

inventory and availability of spare parts

system security plan

other relevant documents or records Organizational personnel with system maintenance responsibilities

organizational personnel with acquisition responsibilities

organizational personnel with information security responsibilities

system/network administrators Organizational processes for ensuring timely maintenance

**FedRAMP Baseline:** L2 | **Domain:** MA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control MA-7: Restrict or prohibit field maintenance on {{ insert: param, ma-07_odp.01 }} to {{ insert: param, ma-07_odp.02 }}. Field maintenance is the type of maintenance conducted on a system or system component after the system or component has been deployed to a specific site (i.e., operational environment). In certain instances, field maintenance (i.e., local maintenance at the site) may not be executed with the same degree of rigor or with the same quality control checks as depot maintenance. For critical systems designated as such by the organization, it may be necessary to restrict or prohibit field maintenance at the local site and require that such maintenance be conducted in trusted facilities with additional controls. field maintenance on {{ insert: param, ma-07_odp.01 }} are restricted or prohibited to {{ insert: param, ma-07_odp.02 }}. Maintenance policy

procedures addressing field maintenance

system design documentation

system configuration settings and associated documentation

maintenance records

diagnostic records

system security plan

other relevant documents or records. Organizational personnel with system maintenance responsibilities

organizational personnel with information security responsibilities

system/network administrators Organizational processes for managing field maintenance

mechanisms implementing, supporting, and/or managing field maintenance

mechanisms for strong authentication of field maintenance diagnostic sessions

mechanisms for terminating field maintenance sessions and network connections

**FedRAMP Baseline:** L2 | **Domain:** MA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### MP — Media Protection (Manual Controls)

##### Control MP-1: Develop, document, and disseminate to {{ insert: param, mp-1_prm_1 }}: {{ insert: param, mp-01_odp.03 }} media protection policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the media protection policy and the associated media protection controls; Designate an {{ insert: param, mp-01_odp.04 }} to manage the development, documentation, and dissemination of the media protection policy and procedures; and Review and update the current media protection: Policy {{ insert: param, mp-01_odp.05 }} and following {{ insert: param, mp-01_odp.06 }} ; and Procedures {{ insert: param, mp-01_odp.07 }} and following {{ insert: param, mp-01_odp.08 }}. Media protection policy and procedures address the controls in the MP family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of media protection policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to media protection policy and procedures include assessment or audit findings, security incidents or breaches, or changes in applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. a media protection policy is developed and documented; the media protection policy is disseminated to {{ insert: param, mp-01_odp.01 }}; media protection procedures to facilitate the implementation of the media protection policy and associated media protection controls are developed and documented; the media protection procedures are disseminated to {{ insert: param, mp-01_odp.02 }}; the {{ insert: param, mp-01_odp.03 }} media protection policy addresses purpose; the {{ insert: param, mp-01_odp.03 }} media protection policy addresses scope; the {{ insert: param, mp-01_odp.03 }} media protection policy addresses roles; the {{ insert: param, mp-01_odp.03 }} media protection policy addresses responsibilities; the {{ insert: param, mp-01_odp.03 }} media protection policy addresses management commitment; the {{ insert: param, mp-01_odp.03 }} media protection policy addresses coordination among organizational entities; the {{ insert: param, mp-01_odp.03 }} media protection policy compliance; the media protection policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, mp-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the media protection policy and procedures. the current media protection policy is reviewed and updated {{ insert: param, mp-01_odp.05 }};  the current media protection policy is reviewed and updated following {{ insert: param, mp-01_odp.06 }}; the current media protection procedures are reviewed and updated {{ insert: param, mp-01_odp.07 }};  the current media protection procedures are reviewed and updated following {{ insert: param, mp-01_odp.08 }}. Media protection policy and procedures

organizational risk management strategy

system security plan

privacy plan

other relevant documents or records Organizational personnel with media protection responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** MP

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control MP-8: Establish {{ insert: param, mp-08_odp.01 }} that includes employing downgrading mechanisms with strength and integrity commensurate with the security category or classification of the information; Verify that the system media downgrading process is commensurate with the security category and/or classification level of the information to be removed and the access authorizations of the potential recipients of the downgraded information; Identify {{ insert: param, mp-08_odp.02 }} ; and Downgrade the identified system media using the established process. Media downgrading applies to digital and non-digital media subject to release outside of the organization, whether the media is considered removable or not. When applied to system media, the downgrading process removes information from the media, typically by security category or classification level, such that the information cannot be retrieved or reconstructed. Downgrading of media includes redacting information to enable wider release and distribution. Downgrading ensures that empty space on the media is devoid of information. a {{ insert: param, mp-08_odp.01 }} is established; the {{ insert: param, mp-08_odp.01 }} includes employing downgrading mechanisms with strength and integrity commensurate with the security category or classification of the information; there is verification that the system media downgrading process is commensurate with the security category and/or classification level of the information to be removed; there is verification that the system media downgrading process is commensurate with the access authorizations of the potential recipients of the downgraded information; {{ insert: param, mp-08_odp.02 }} is identified; the identified system media is downgraded using the {{ insert: param, mp-08_odp.01 }}. System media protection policy

procedures addressing media downgrading

system categorization documentation

list of media requiring downgrading

records of media downgrading

audit records

system security plan

other relevant documents or records Organizational personnel with system media downgrading responsibilities

organizational personnel with information security responsibilities

system/network administrators Organizational processes for media downgrading

mechanisms supporting and/or implementing media downgrading

**FedRAMP Baseline:** L2 | **Domain:** MP

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### PE — Physical and Environmental Protection (Manual Controls)

##### Control PE-1: Develop, document, and disseminate to {{ insert: param, pe-1_prm_1 }}: {{ insert: param, pe-01_odp.03 }} physical and environmental protection policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the physical and environmental protection policy and the associated physical and environmental protection controls; Designate an {{ insert: param, pe-01_odp.04 }} to manage the development, documentation, and dissemination of the physical and environmental protection policy and procedures; and Review and update the current physical and environmental protection: Policy {{ insert: param, pe-01_odp.05 }} and following {{ insert: param, pe-01_odp.06 }} ; and Procedures {{ insert: param, pe-01_odp.07 }} and following {{ insert: param, pe-01_odp.08 }}. Physical and environmental protection policy and procedures address the controls in the PE family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of physical and environmental protection policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to physical and environmental protection policy and procedures include assessment or audit findings, security incidents or breaches, or changes in applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. a physical and environmental protection policy is developed and documented; the physical and environmental protection policy is disseminated to {{ insert: param, pe-01_odp.01 }}; physical and environmental protection procedures to facilitate the implementation of the physical and environmental protection policy and associated physical and environmental protection controls are developed and documented; the physical and environmental protection procedures are disseminated to {{ insert: param, pe-01_odp.02 }}; the {{ insert: param, pe-01_odp.03 }} physical and environmental protection policy addresses purpose; the {{ insert: param, pe-01_odp.03 }} physical and environmental protection policy addresses scope; the {{ insert: param, pe-01_odp.03 }} physical and environmental protection policy addresses roles; the {{ insert: param, pe-01_odp.03 }} physical and environmental protection policy addresses responsibilities; the {{ insert: param, pe-01_odp.03 }} physical and environmental protection policy addresses management commitment; the {{ insert: param, pe-01_odp.03 }} physical and environmental protection policy addresses coordination among organizational entities; the {{ insert: param, pe-01_odp.03 }} physical and environmental protection policy addresses compliance; the {{ insert: param, pe-01_odp.03 }} physical and environmental protection policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, pe-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the physical and environmental protection policy and procedures; the current physical and environmental protection policy is reviewed and updated {{ insert: param, pe-01_odp.05 }}; the current physical and environmental protection policy is reviewed and updated following {{ insert: param, pe-01_odp.06 }}; the current physical and environmental protection procedures are reviewed and updated {{ insert: param, pe-01_odp.07 }}; the current physical and environmental protection procedures are reviewed and updated following {{ insert: param, pe-01_odp.08 }}. Physical and environmental protection policy and procedures

system security plan

privacy plan

organizational risk management strategy

other relevant documents or records Organizational personnel with physical and environmental protection responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-4: Control physical access to {{ insert: param, pe-04_odp.01 }} within organizational facilities using {{ insert: param, pe-04_odp.02 }}. Security controls applied to system distribution and transmission lines prevent accidental damage, disruption, and physical tampering. Such controls may also be necessary to prevent eavesdropping or modification of unencrypted transmissions. Security controls used to control physical access to system distribution and transmission lines include disconnected or locked spare jacks, locked wiring closets, protection of cabling by conduit or cable trays, and wiretapping sensors. physical access to {{ insert: param, pe-04_odp.01 }} within organizational facilities is controlled using {{ insert: param, pe-04_odp.02 }}. Physical and environmental protection policy

procedures addressing access control for transmission mediums

system design documentation

facility communications and wiring diagrams

list of physical security safeguards applied to system distribution and transmission lines

system security plan

other relevant documents or records Organizational personnel with physical access control responsibilities

organizational personnel with information security responsibilities Organizational processes for access control to distribution and transmission lines

mechanisms/security safeguards supporting and/or implementing access control to distribution and transmission lines

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-7: 

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-8: Maintain visitor access records to the facility where the system resides for {{ insert: param, pe-08_odp.01 }}; Review visitor access records {{ insert: param, pe-08_odp.02 }} ; and Report anomalies in visitor access records to {{ insert: param, pe-08_odp.03 }}. Visitor access records include the names and organizations of individuals visiting, visitor signatures, forms of identification, dates of access, entry and departure times, purpose of visits, and the names and organizations of individuals visited. Access record reviews determine if access authorizations are current and are still required to support organizational mission and business functions. Access records are not required for publicly accessible areas. visitor access records for the facility where the system resides are maintained for {{ insert: param, pe-08_odp.01 }}; visitor access records are reviewed {{ insert: param, pe-08_odp.02 }}; visitor access records anomalies are reported to {{ insert: param, pe-08_odp.03 }}. Physical and environmental protection policy

procedures addressing visitor access records

visitor access control logs or records

visitor access record or log reviews

system security plan

privacy plan

privacy impact assessment

privacy risk assessment documentation

other relevant documents or records Organizational personnel with visitor access record responsibilities

organizational personnel with information security and privacy responsibilities Organizational processes for maintaining and reviewing visitor access records

mechanisms supporting and/or implementing the maintenance and review of visitor access records

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-9: Protect power equipment and power cabling for the system from damage and destruction. Organizations determine the types of protection necessary for the power equipment and cabling employed at different locations that are both internal and external to organizational facilities and environments of operation. Types of power equipment and cabling include internal cabling and uninterruptable power sources in offices or data centers, generators and power cabling outside of buildings, and power sources for self-contained components such as satellites, vehicles, and other deployable systems. power equipment for the system is protected from damage and destruction; power cabling for the system is protected from damage and destruction. Physical and environmental protection policy

procedures addressing power equipment/cabling protection

facilities housing power equipment/cabling

system security plan

other relevant documents or records Organizational personnel with the responsibility to protect power equipment/cabling

organizational personnel with information security responsibilities Mechanisms supporting and/or implementing the protection of power equipment/cabling

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-10: Provide the capability of shutting off power to {{ insert: param, pe-10_odp.01 }} in emergency situations; Place emergency shutoff switches or devices in {{ insert: param, pe-10_odp.02 }} to facilitate access for authorized personnel; and Protect emergency power shutoff capability from unauthorized activation. Emergency power shutoff primarily applies to organizational facilities that contain concentrations of system resources, including data centers, mainframe computer rooms, server rooms, and areas with computer-controlled machinery. the capability to shut off power to {{ insert: param, pe-10_odp.01 }} in emergency situations is provided; emergency shutoff switches or devices are placed in {{ insert: param, pe-10_odp.02 }} to facilitate access for authorized personnel; the emergency power shutoff capability is protected from unauthorized activation. Physical and environmental protection policy

procedures addressing power source emergency shutoff

emergency shutoff controls or switches

locations housing emergency shutoff switches and devices

security safeguards protecting the emergency power shutoff capability from unauthorized activation

system security plan

other relevant documents or records Organizational personnel with the responsibility for the emergency power shutoff capability (both implementing and using the capability)

organizational personnel with information security responsibilities Mechanisms supporting and/or implementing emergency power shutoff

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-11: Provide an uninterruptible power supply to facilitate {{ insert: param, pe-11_odp }} in the event of a primary power source loss. An uninterruptible power supply (UPS) is an electrical system or mechanism that provides emergency power when there is a failure of the main power source. A UPS is typically used to protect computers, data centers, telecommunication equipment, or other electrical equipment where an unexpected power disruption could cause injuries, fatalities, serious mission or business disruption, or loss of data or information. A UPS differs from an emergency power system or backup generator in that the UPS provides near-instantaneous protection from unanticipated power interruptions from the main power source by providing energy stored in batteries, supercapacitors, or flywheels. The battery duration of a UPS is relatively short but provides sufficient time to start a standby power source, such as a backup generator, or properly shut down the system. an uninterruptible power supply is provided to facilitate {{ insert: param, pe-11_odp }} in the event of a primary power source loss. Physical and environmental protection policy

procedures addressing emergency power

uninterruptible power supply

uninterruptible power supply documentation

uninterruptible power supply test records

system security plan

other relevant documents or records Organizational personnel with the responsibility for emergency power and/or planning

organizational personnel with information security responsibilities Mechanisms supporting and/or implementing an uninterruptible power supply

the uninterruptable power supply

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-12: Employ and maintain automatic emergency lighting for the system that activates in the event of a power outage or disruption and that covers emergency exits and evacuation routes within the facility. The provision of emergency lighting applies primarily to organizational facilities that contain concentrations of system resources, including data centers, server rooms, and mainframe computer rooms. Emergency lighting provisions for the system are described in the contingency plan for the organization. If emergency lighting for the system fails or cannot be provided, organizations consider alternate processing sites for power-related contingencies. automatic emergency lighting that activates in the event of a power outage or disruption is employed for the system; automatic emergency lighting that activates in the event of a power outage or disruption is maintained for the system; automatic emergency lighting for the system covers emergency exits within the facility; automatic emergency lighting for the system covers evacuation routes within the facility. Physical and environmental protection policy

procedures addressing emergency lighting

emergency lighting documentation

emergency lighting test records

emergency exits and evacuation routes

system security plan

other relevant documents or records Organizational personnel with the responsibility for emergency lighting and/or planning

organizational personnel with information security responsibilities Mechanisms supporting and/or implementing an emergency lighting capability

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-13: Employ and maintain fire detection and suppression systems that are supported by an independent energy source. The provision of fire detection and suppression systems applies primarily to organizational facilities that contain concentrations of system resources, including data centers, server rooms, and mainframe computer rooms. Fire detection and suppression systems that may require an independent energy source include sprinkler systems and smoke detectors. An independent energy source is an energy source, such as a microgrid, that is separate, or can be separated, from the energy sources providing power for the other parts of the facility. fire detection systems are employed; employed fire detection systems are supported by an independent energy source; employed fire detection systems are maintained; fire suppression systems are employed; employed fire suppression systems are supported by an independent energy source; employed fire suppression systems are maintained. Physical and environmental protection policy

procedures addressing fire protection

fire suppression and detection devices/systems

fire suppression and detection devices/systems documentation

test records of fire suppression and detection devices/systems

system security plan

other relevant documents or records Organizational personnel with responsibilities for fire detection and suppression devices/systems

organizational personnel with information security responsibilities Mechanisms supporting and/or implementing fire suppression/detection devices/systems

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-14: Maintain {{ insert: param, pe-14_odp.01 }} levels within the facility where the system resides at {{ insert: param, pe-14_odp.03 }} ; and Monitor environmental control levels {{ insert: param, pe-14_odp.04 }}. The provision of environmental controls applies primarily to organizational facilities that contain concentrations of system resources (e.g., data centers, mainframe computer rooms, and server rooms). Insufficient environmental controls, especially in very harsh environments, can have a significant adverse impact on the availability of systems and system components that are needed to support organizational mission and business functions. {{ insert: param, pe-14_odp.01 }} levels are maintained at {{ insert: param, pe-14_odp.03 }} within the facility where the system resides; environmental control levels are monitored {{ insert: param, pe-14_odp.04 }}. Physical and environmental protection policy

procedures addressing temperature and humidity control

temperature and humidity controls

facility housing the system

temperature and humidity controls documentation

temperature and humidity records

system security plan

other relevant documents or records Organizational personnel with responsibilities for system environmental controls

organizational personnel with information security responsibilities Mechanisms supporting and/or implementing the maintenance and monitoring of temperature and humidity levels

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-15: Protect the system from damage resulting from water leakage by providing master shutoff or isolation valves that are accessible, working properly, and known to key personnel. The provision of water damage protection primarily applies to organizational facilities that contain concentrations of system resources, including data centers, server rooms, and mainframe computer rooms. Isolation valves can be employed in addition to or in lieu of master shutoff valves to shut off water supplies in specific areas of concern without affecting entire organizations. the system is protected from damage resulting from water leakage by providing master shutoff or isolation valves; the master shutoff or isolation valves are accessible; the master shutoff or isolation valves are working properly; the master shutoff or isolation valves are known to key personnel. Physical and environmental protection policy

procedures addressing water damage protection

facility housing the system

master shutoff valves

list of key personnel with knowledge of location and activation procedures for master shutoff valves for the plumbing system

master shutoff valve documentation

system security plan

other relevant documents or records Organizational personnel with responsibilities for system environmental controls

organizational personnel with information security responsibilities Master water-shutoff valves

organizational process for activating master water shutoff

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-16: Authorize and control {{ insert: param, pe-16_prm_1 }} entering and exiting the facility; and Maintain records of the system components. Enforcing authorizations for entry and exit of system components may require restricting access to delivery areas and isolating the areas from the system and media libraries. {{ insert: param, pe-16_odp.01 }} are authorized when entering the facility; {{ insert: param, pe-16_odp.01 }} are controlled when entering the facility; {{ insert: param, pe-16_odp.02 }} are authorized when exiting the facility; {{ insert: param, pe-16_odp.02 }} are controlled when exiting the facility; records of the system components are maintained. Physical and environmental protection policy

procedures addressing the delivery and removal of system components from the facility

facility housing the system

records of items entering and exiting the facility

system security plan

other relevant documents or records Organizational personnel with responsibilities for controlling system components entering and exiting the facility

organizational personnel with information security responsibilities Organizational process for authorizing, monitoring, and controlling system-related items entering and exiting the facility

mechanisms supporting and/or implementing, authorizing, monitoring, and controlling system-related items entering and exiting the facility

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-18: Position system components within the facility to minimize potential damage from {{ insert: param, pe-18_odp }} and to minimize the opportunity for unauthorized access. Physical and environmental hazards include floods, fires, tornadoes, earthquakes, hurricanes, terrorism, vandalism, an electromagnetic pulse, electrical interference, and other forms of incoming electromagnetic radiation. Organizations consider the location of entry points where unauthorized individuals, while not being granted access, might nonetheless be near systems. Such proximity can increase the risk of unauthorized access to organizational communications using wireless packet sniffers or microphones, or unauthorized disclosure of information. system components are positioned within the facility to minimize potential damage from {{ insert: param, pe-18_odp }} and to minimize the opportunity for unauthorized access. Physical and environmental protection policy

procedures addressing the positioning of system components

documentation providing the location and position of system components within the facility

locations housing system components within the facility

list of physical and environmental hazards with the potential to damage system components within the facility

system security plan

other relevant documents or records Organizational personnel with responsibilities for positioning system components

organizational personnel with information security responsibilities Organizational processes for positioning system components

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-19: Protect the system from information leakage due to electromagnetic signals emanations. Information leakage is the intentional or unintentional release of data or information to an untrusted environment from electromagnetic signals emanations. The security categories or classifications of systems (with respect to confidentiality), organizational security policies, and risk tolerance guide the selection of controls employed to protect systems against information leakage due to electromagnetic signals emanations. the system is protected from information leakage due to electromagnetic signal emanations. Physical and environmental protection policy

procedures addressing information leakage due to electromagnetic signal emanations

mechanisms protecting the system against electronic signal emanations

facility housing the system

records from electromagnetic signal emanation tests

system security plan

other relevant documents or records Organizational personnel with responsibilities for system environmental controls

organizational personnel with information security responsibilities Mechanisms supporting and/or implementing protection from information leakage due to electromagnetic signal emanations

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-20: Employ {{ insert: param, pe-20_odp.01 }} to track and monitor the location and movement of {{ insert: param, pe-20_odp.02 }} within {{ insert: param, pe-20_odp.03 }}. Asset location technologies can help ensure that critical assets—including vehicles, equipment, and system components—remain in authorized locations. Organizations consult with the Office of the General Counsel and senior agency official for privacy regarding the deployment and use of asset location technologies to address potential privacy concerns. {{ insert: param, pe-20_odp.01 }} are employed to track and monitor the location and movement of {{ insert: param, pe-20_odp.02 }} within {{ insert: param, pe-20_odp.03 }}. Physical and environmental protection policy

procedures addressing asset monitoring and tracking

documentation showing the use of asset location technologies

system configuration documentation

list of organizational assets requiring tracking and monitoring

asset monitoring and tracking records

system security plan

privacy plan

other relevant documents or records Organizational personnel with asset monitoring and tracking responsibilities

legal counsel

organizational personnel with information security and privacy responsibilities Organizational processes for tracking and monitoring assets

mechanisms supporting and/or implementing the tracking and monitoring of assets

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-21: Employ {{ insert: param, pe-21_odp.01 }} against electromagnetic pulse damage for {{ insert: param, pe-21_odp.02 }}. An electromagnetic pulse (EMP) is a short burst of electromagnetic energy that is spread over a range of frequencies. Such energy bursts may be natural or man-made. EMP interference may be disruptive or damaging to electronic equipment. Protective measures used to mitigate EMP risk include shielding, surge suppressors, ferro-resonant transformers, and earth grounding. EMP protection may be especially significant for systems and applications that are part of the U.S. critical infrastructure. {{ insert: param, pe-21_odp.01 }} are employed against electromagnetic pulse damage for {{ insert: param, pe-21_odp.02 }}. Physical and environmental protection policy

procedures addressing protective measures to mitigate EMP risk to systems and components

documentation detailing protective measures to mitigate EMP risk

list of locations where protective measures to mitigate EMP risk are implemented

system security plan

other relevant documents or records Organizational personnel with responsibilities for physical and environmental protection

system developers/integrators

organizational personnel with information security responsibilities Mechanisms for mitigating EMP risk

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-22: Mark {{ insert: param, pe-22_odp }} indicating the impact level or classification level of the information permitted to be processed, stored, or transmitted by the hardware component. Hardware components that may require marking include input and output devices. Input devices include desktop and notebook computers, keyboards, tablets, and smart phones. Output devices include printers, monitors/video displays, facsimile machines, scanners, copiers, and audio devices. Permissions controlling output to the output devices are addressed in [AC-3](#ac-3) or [AC-4](#ac-4) . Components are marked to indicate the impact level or classification level of the system to which the devices are connected, or the impact level or classification level of the information permitted to be output. Security marking refers to the use of human-readable security attributes. Security labeling refers to the use of security attributes for internal system data structures. Security marking is generally not required for hardware components that process, store, or transmit information determined by organizations to be in the public domain or to be publicly releasable. However, organizations may require markings for hardware components that process, store, or transmit public information in order to indicate that such information is publicly releasable. Marking of system hardware components reflects applicable laws, executive orders, directives, policies, regulations, and standards. {{ insert: param, pe-22_odp }} are marked indicating the impact level or classification level of the information permitted to be processed, stored, or transmitted by the hardware component. Physical and environmental protection policy

procedures addressing component marking

list of component marking security attributes

component inventory

information types and their impact/classification level

system security plan

other relevant documents or records Organizational personnel with component marking responsibilities

organizational personnel with component inventory responsibilities

organizational personnel with information categorization/classification responsibilities

organizational personnel with information security responsibilities Organizational processes for component marking

automated mechanisms supporting and/or implementing component marking

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PE-23: Plan the location or site of the facility where the system resides considering physical and environmental hazards; and For existing facilities, consider the physical and environmental hazards in the organizational risk management strategy. Physical and environmental hazards include floods, fires, tornadoes, earthquakes, hurricanes, terrorism, vandalism, an electromagnetic pulse, electrical interference, and other forms of incoming electromagnetic radiation. The location of system components within the facility is addressed in [PE-18](#pe-18). the location or site of the facility where the system resides is planned considering physical and environmental hazards; for existing facilities, physical and environmental hazards are considered in the organizational risk management strategy. Physical and environmental protection policy

physical site planning documents

organizational assessment of risk

contingency plan

risk mitigation strategy documentation

system security plan

other relevant documents or records Organizational personnel with site selection responsibilities for the facility housing the system

organizational personnel with risk mitigation responsibilities

organizational personnel with information security responsibilities Organizational processes for site planning

**FedRAMP Baseline:** L2 | **Domain:** PE

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### PL — Planning (Manual Controls)

##### Control PL-1: Develop, document, and disseminate to {{ insert: param, pl-1_prm_1 }}: {{ insert: param, pl-01_odp.03 }} planning policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the planning policy and the associated planning controls; Designate an {{ insert: param, pl-01_odp.04 }} to manage the development, documentation, and dissemination of the planning policy and procedures; and Review and update the current planning: Policy {{ insert: param, pl-01_odp.05 }} and following {{ insert: param, pl-01_odp.06 }} ; and Procedures {{ insert: param, pl-01_odp.07 }} and following {{ insert: param, pl-01_odp.08 }}. Planning policy and procedures for the controls in the PL family implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on their development. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission level or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission/business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to planning policy and procedures include, but are not limited to, assessment or audit findings, security incidents or breaches, or changes in laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. a planning policy is developed and documented. the planning policy is disseminated to {{ insert: param, pl-01_odp.01 }}; planning procedures to facilitate the implementation of the planning policy and associated planning controls are developed and documented; the planning procedures are disseminated to {{ insert: param, pl-01_odp.02 }}; the {{ insert: param, pl-01_odp.03 }} planning policy addresses purpose; the {{ insert: param, pl-01_odp.03 }} planning policy addresses scope; the {{ insert: param, pl-01_odp.03 }} planning policy addresses roles; the {{ insert: param, pl-01_odp.03 }} planning policy addresses responsibilities; the {{ insert: param, pl-01_odp.03 }} planning policy addresses management commitment; the {{ insert: param, pl-01_odp.03 }} planning policy addresses coordination among organizational entities; the {{ insert: param, pl-01_odp.03 }} planning policy addresses compliance; the {{ insert: param, pl-01_odp.03 }} planning policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, pl-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the planning policy and procedures; the current planning policy is reviewed and updated {{ insert: param, pl-01_odp.05 }}; the current planning policy is reviewed and updated following {{ insert: param, pl-01_odp.06 }}; the current planning procedures are reviewed and updated {{ insert: param, pl-01_odp.07 }}; the current planning procedures are reviewed and updated following {{ insert: param, pl-01_odp.08 }}. Planning policy and procedures

system security plan

privacy plan

other relevant documents or records Organizational personnel with planning responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** PL

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PL-3: 

**FedRAMP Baseline:** L2 | **Domain:** PL

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PL-4: Establish and provide to individuals requiring access to the system, the rules that describe their responsibilities and expected behavior for information and system usage, security, and privacy; Receive a documented acknowledgment from such individuals, indicating that they have read, understand, and agree to abide by the rules of behavior, before authorizing access to information and the system; Review and update the rules of behavior {{ insert: param, pl-04_odp.01 }} ; and Require individuals who have acknowledged a previous version of the rules of behavior to read and re-acknowledge {{ insert: param, pl-04_odp.02 }}. Rules of behavior represent a type of access agreement for organizational users. Other types of access agreements include nondisclosure agreements, conflict-of-interest agreements, and acceptable use agreements (see [PS-6](#ps-6) ). Organizations consider rules of behavior based on individual user roles and responsibilities and differentiate between rules that apply to privileged users and rules that apply to general users. Establishing rules of behavior for some types of non-organizational users, including individuals who receive information from federal systems, is often not feasible given the large number of such users and the limited nature of their interactions with the systems. Rules of behavior for organizational and non-organizational users can also be established in [AC-8](#ac-8) . The related controls section provides a list of controls that are relevant to organizational rules of behavior. [PL-4b](#pl-4_smt.b) , the documented acknowledgment portion of the control, may be satisfied by the literacy training and awareness and role-based training programs conducted by organizations if such training includes rules of behavior. Documented acknowledgements for rules of behavior include electronic or physical signatures and electronic agreement check boxes or radio buttons. rules that describe responsibilities and expected behavior for information and system usage, security, and privacy are established for individuals requiring access to the system; rules that describe responsibilities and expected behavior for information and system usage, security, and privacy are provided to individuals requiring access to the system; before authorizing access to information and the system, a documented acknowledgement from such individuals indicating that they have read, understand, and agree to abide by the rules of behavior is received; rules of behavior are reviewed and updated {{ insert: param, pl-04_odp.01 }}; individuals who have acknowledged a previous version of the rules of behavior are required to read and reacknowledge {{ insert: param, pl-04_odp.02 }}. Security and privacy planning policy

procedures addressing rules of behavior for system users

rules of behavior

signed acknowledgements

records for rules of behavior reviews and updates

other relevant documents or records Organizational personnel with responsibility for establishing, reviewing, and updating rules of behavior

organizational personnel with responsibility for literacy training and awareness and role-based training

organizational personnel who are authorized users of the system and have signed and resigned rules of behavior

organizational personnel with information security and privacy responsibilities Organizational processes for establishing, reviewing, disseminating, and updating rules of behavior

mechanisms supporting and/or implementing the establishment, review, dissemination, and update of rules of behavior

**FedRAMP Baseline:** L2 | **Domain:** PL

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PL-5: 

**FedRAMP Baseline:** L2 | **Domain:** PL

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PL-6: 

**FedRAMP Baseline:** L2 | **Domain:** PL

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PL-7: Develop a Concept of Operations (CONOPS) for the system describing how the organization intends to operate the system from the perspective of information security and privacy; and Review and update the CONOPS {{ insert: param, pl-07_odp }}. The CONOPS may be included in the security or privacy plans for the system or in other system development life cycle documents. The CONOPS is a living document that requires updating throughout the system development life cycle. For example, during system design reviews, the concept of operations is checked to ensure that it remains consistent with the design for controls, the system architecture, and the operational procedures. Changes to the CONOPS are reflected in ongoing updates to the security and privacy plans, security and privacy architectures, and other organizational documents, such as procurement specifications, system development life cycle documents, and systems engineering documents. a CONOPS for the system describing how the organization intends to operate the system from the perspective of information security and privacy is developed; the CONOPS is reviewed and updated {{ insert: param, pl-07_odp }}. Security and privacy planning policy

procedures addressing security and privacy CONOPS development

procedures addressing security and privacy CONOPS reviews and updates

security and privacy CONOPS for the system

system security plan

privacy plan

records of security and privacy CONOPS reviews and updates

other relevant documents or records Organizational personnel with security and privacy planning and plan implementation responsibilities

organizational personnel with information security and privacy responsibilities Organizational processes for developing, reviewing, and updating the security CONOPS

mechanisms supporting and/or implementing the development, review, and update of the security CONOPS

**FedRAMP Baseline:** L2 | **Domain:** PL

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PL-9: Centrally manage {{ insert: param, pl-09_odp }}. Central management refers to organization-wide management and implementation of selected controls and processes. This includes planning, implementing, assessing, authorizing, and monitoring the organization-defined, centrally managed controls and processes. As the central management of controls is generally associated with the concept of common (inherited) controls, such management promotes and facilitates standardization of control implementations and management and the judicious use of organizational resources. Centrally managed controls and processes may also meet independence requirements for assessments in support of initial and ongoing authorizations to operate and as part of organizational continuous monitoring.

Automated tools (e.g., security information and event management tools or enterprise security monitoring and management tools) can improve the accuracy, consistency, and availability of information associated with centrally managed controls and processes. Automation can also provide data aggregation and data correlation capabilities; alerting mechanisms; and dashboards to support risk-based decision-making within the organization.

As part of the control selection processes, organizations determine the controls that may be suitable for central management based on resources and capabilities. It is not always possible to centrally manage every aspect of a control. In such cases, the control can be treated as a hybrid control with the control managed and implemented centrally or at the system level. The controls and control enhancements that are candidates for full or partial central management include but are not limited to: [AC-2(1)](#ac-2.1), [AC-2(2)](#ac-2.2), [AC-2(3)](#ac-2.3), [AC-2(4)](#ac-2.4), [AC-4(all)](#ac-4), [AC-17(1)](#ac-17.1), [AC-17(2)](#ac-17.2), [AC-17(3)](#ac-17.3), [AC-17(9)](#ac-17.9), [AC-18(1)](#ac-18.1), [AC-18(3)](#ac-18.3), [AC-18(4)](#ac-18.4), [AC-18(5)](#ac-18.5), [AC-19(4)](#ac-19.4), [AC-22](#ac-22), [AC-23](#ac-23), [AT-2(1)](#at-2.1), [AT-2(2)](#at-2.2), [AT-3(1)](#at-3.1), [AT-3(2)](#at-3.2), [AT-3(3)](#at-3.3), [AT-4](#at-4), [AU-3](#au-3), [AU-6(1)](#au-6.1), [AU-6(3)](#au-6.3), [AU-6(5)](#au-6.5), [AU-6(6)](#au-6.6), [AU-6(9)](#au-6.9), [AU-7(1)](#au-7.1), [AU-7(2)](#au-7.2), [AU-11](#au-11), [AU-13](#au-13), [AU-16](#au-16), [CA-2(1)](#ca-2.1), [CA-2(2)](#ca-2.2), [CA-2(3)](#ca-2.3), [CA-3(1)](#ca-3.1), [CA-3(2)](#ca-3.2), [CA-3(3)](#ca-3.3), [CA-7(1)](#ca-7.1), [CA-9](#ca-9), [CM-2(2)](#cm-2.2), [CM-3(1)](#cm-3.1), [CM-3(4)](#cm-3.4), [CM-4](#cm-4), [CM-6](#cm-6), [CM-6(1)](#cm-6.1), [CM-7(2)](#cm-7.2), [CM-7(4)](#cm-7.4), [CM-7(5)](#cm-7.5), [CM-8(all)](#cm-8), [CM-9(1)](#cm-9.1), [CM-10](#cm-10), [CM-11](#cm-11), [CP-7(all)](#cp-7), [CP-8(all)](#cp-8), [SC-43](#sc-43), [SI-2](#si-2), [SI-3](#si-3), [SI-4(all)](#si-4), [SI-7](#si-7), [SI-8](#si-8). {{ insert: param, pl-09_odp }} are centrally managed. Security and privacy planning policy

procedures addressing security and privacy plan development and implementation

system security plan

privacy plan

other relevant documents or records Organizational personnel with security and privacy planning and plan implementation responsibilities

organizational personnel with responsibilities for planning/implementing central management of controls and related processes

organizational personnel with information security and privacy responsibilities Organizational processes for the central management of controls and related processes

mechanisms supporting and/or implementing central management of controls and related processes

**FedRAMP Baseline:** L2 | **Domain:** PL

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PL-10: Select a control baseline for the system. Control baselines are predefined sets of controls specifically assembled to address the protection needs of a group, organization, or community of interest. Controls are chosen for baselines to either satisfy mandates imposed by laws, executive orders, directives, regulations, policies, standards, and guidelines or address threats common to all users of the baseline under the assumptions specific to the baseline. Baselines represent a starting point for the protection of individuals’ privacy, information, and information systems with subsequent tailoring actions to manage risk in accordance with mission, business, or other constraints (see [PL-11](#pl-11) ). Federal control baselines are provided in [SP 800-53B](#46d9e201-840e-440e-987c-2c773333c752) . The selection of a control baseline is determined by the needs of stakeholders. Stakeholder needs consider mission and business requirements as well as mandates imposed by applicable laws, executive orders, directives, policies, regulations, standards, and guidelines. For example, the control baselines in [SP 800-53B](#46d9e201-840e-440e-987c-2c773333c752) are based on the requirements from [FISMA](#0c67b2a9-bede-43d2-b86d-5f35b8be36e9) and [PRIVACT](#18e71fec-c6fd-475a-925a-5d8495cf8455) . The requirements, along with the NIST standards and guidelines implementing the legislation, direct organizations to select one of the control baselines after the reviewing the information types and the information that is processed, stored, and transmitted on the system; analyzing the potential adverse impact of the loss or compromise of the information or system on the organization’s operations and assets, individuals, other organizations, or the Nation; and considering the results from system and organizational risk assessments. [CNSSI 1253](#4e4fbc93-333d-45e6-a875-de36b878b6b9) provides guidance on control baselines for national security systems. a control baseline for the system is selected. Security and privacy planning policy

procedures addressing system security and privacy plan development and implementation

procedures addressing system security and privacy plan reviews and updates

system design documentation

system architecture and configuration documentation

system categorization decision

information types stored, transmitted, and processed by the system

system element/component information

stakeholder needs analysis

list of security and privacy requirements allocated to the system, system elements, and environment of operation

list of contractual requirements allocated to external providers of the system or system element

business impact analysis or criticality analysis

risk assessments

risk management strategy

organizational security and privacy policy

federal or organization-approved or mandated baselines or overlays

system security plan

privacy plan

other relevant documents or records Organizational personnel with security and privacy planning and plan implementation responsibilities

organizational personnel with information security and privacy responsibilities

organizational personnel with responsibility for organizational risk management activities

**FedRAMP Baseline:** L2 | **Domain:** PL

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PL-11: Tailor the selected control baseline by applying specified tailoring actions. The concept of tailoring allows organizations to specialize or customize a set of baseline controls by applying a defined set of tailoring actions. Tailoring actions facilitate such specialization and customization by allowing organizations to develop security and privacy plans that reflect their specific mission and business functions, the environments where their systems operate, the threats and vulnerabilities that can affect their systems, and any other conditions or situations that can impact their mission or business success. Tailoring guidance is provided in [SP 800-53B](#46d9e201-840e-440e-987c-2c773333c752) . Tailoring a control baseline is accomplished by identifying and designating common controls, applying scoping considerations, selecting compensating controls, assigning values to control parameters, supplementing the control baseline with additional controls as needed, and providing information for control implementation. The general tailoring actions in [SP 800-53B](#46d9e201-840e-440e-987c-2c773333c752) can be supplemented with additional actions based on the needs of organizations. Tailoring actions can be applied to the baselines in [SP 800-53B](#46d9e201-840e-440e-987c-2c773333c752) in accordance with the security and privacy requirements from [FISMA](#0c67b2a9-bede-43d2-b86d-5f35b8be36e9), [PRIVACT](#18e71fec-c6fd-475a-925a-5d8495cf8455) , and [OMB A-130](#27847491-5ce1-4f6a-a1e4-9e483782f0ef) . Alternatively, other communities of interest adopting different control baselines can apply the tailoring actions in [SP 800-53B](#46d9e201-840e-440e-987c-2c773333c752) to specialize or customize the controls that represent the specific needs and concerns of those entities. the selected control baseline is tailored by applying specified tailoring actions. Security and privacy planning policy

procedures addressing system security and privacy plan development and implementation

system design documentation

system categorization decision

information types stored, transmitted, and processed by the system

system element/component information

stakeholder needs analysis

list of security and privacy requirements allocated to the system, system elements, and environment of operation

list of contractual requirements allocated to external providers of the system or system element

business impact analysis or criticality analysis

risk assessments

risk management strategy

organizational security and privacy policy

federal or organization-approved or mandated baselines or overlays

baseline tailoring rationale

system security plan

privacy plan

records of system security and privacy plan reviews and updates

other relevant documents or records Organizational personnel with security and privacy planning and plan implementation responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** PL

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### PM — Program Management (Manual Controls)

##### Control PM-1: Develop and disseminate an organization-wide information security program plan that: Provides an overview of the requirements for the security program and a description of the security program management controls and common controls in place or planned for meeting those requirements; Includes the identification and assignment of roles, responsibilities, management commitment, coordination among organizational entities, and compliance; Reflects the coordination among organizational entities responsible for information security; and Is approved by a senior official with responsibility and accountability for the risk being incurred to organizational operations (including mission, functions, image, and reputation), organizational assets, individuals, other organizations, and the Nation; Review and update the organization-wide information security program plan {{ insert: param, pm-01_odp.01 }} and following {{ insert: param, pm-01_odp.02 }} ; and Protect the information security program plan from unauthorized disclosure and modification. An information security program plan is a formal document that provides an overview of the security requirements for an organization-wide information security program and describes the program management controls and common controls in place or planned for meeting those requirements. An information security program plan can be represented in a single document or compilations of documents. Privacy program plans and supply chain risk management plans are addressed separately in [PM-18](#pm-18) and [SR-2](#sr-2) , respectively.

An information security program plan documents implementation details about program management and common controls. The plan provides sufficient information about the controls (including specification of parameters for assignment and selection operations, explicitly or by reference) to enable implementations that are unambiguously compliant with the intent of the plan and a determination of the risk to be incurred if the plan is implemented as intended. Updates to information security program plans include organizational changes and problems identified during plan implementation or control assessments.

Program management controls may be implemented at the organization level or the mission or business process level, and are essential for managing the organization’s information security program. Program management controls are distinct from common, system-specific, and hybrid controls because program management controls are independent of any particular system. Together, the individual system security plans and the organization-wide information security program plan provide complete coverage for the security controls employed within the organization.

Common controls available for inheritance by organizational systems are documented in an appendix to the organization’s information security program plan unless the controls are included in a separate security plan for a system. The organization-wide information security program plan indicates which separate security plans contain descriptions of common controls.

Events that may precipitate an update to the information security program plan include, but are not limited to, organization-wide assessment or audit findings, security incidents or breaches, or changes in laws, executive orders, directives, regulations, policies, standards, and guidelines. an organization-wide information security program plan is developed; the information security program plan is disseminated; the information security program plan provides an overview of the requirements for the security program; the information security program plan provides a description of the security program management controls in place or planned for meeting those requirements; the information security program plan provides a description of the common controls in place or planned for meeting those requirements; the information security program plan includes the identification and assignment of roles; the information security program plan includes the identification and assignment of responsibilities; the information security program plan addresses management commitment; the information security program plan addresses coordination among organizational entities; the information security program plan addresses compliance; the information security program plan reflects the coordination among the organizational entities responsible for information security; the information security program plan is approved by a senior official with responsibility and accountability for the risk being incurred to organizational operations (including mission, functions, image, and reputation), organizational assets, individuals, other organizations, and the Nation; the information security program plan is reviewed and updated {{ insert: param, pm-01_odp.01 }}; the information security program plan is reviewed and updated following {{ insert: param, pm-01_odp.02 }}; the information security program plan is protected from unauthorized disclosure; the information security program plan is protected from unauthorized modification. Information security program plan

procedures addressing program plan development and implementation

procedures addressing program plan reviews and updates

procedures addressing coordination of the program plan with relevant entities

procedures for program plan approvals

records of program plan reviews and updates

other relevant documents or records Organizational personnel with information security program planning and plan implementation responsibilities

organizational personnel with information security responsibilities Organizational processes for information security program plan development, review, update, and approval

mechanisms supporting and/or implementing the information security program plan

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-2: Appoint a senior agency information security officer with the mission and resources to coordinate, develop, implement, and maintain an organization-wide information security program. The senior agency information security officer is an organizational official. For federal agencies (as defined by applicable laws, executive orders, regulations, directives, policies, and standards), this official is the senior agency information security officer. Organizations may also refer to this official as the senior information security officer or chief information security officer. a senior agency information security officer is appointed; the senior agency information security officer is provided with the mission and resources to coordinate an organization-wide information security program; the senior agency information security officer is provided with the mission and resources to develop an organization-wide information security program; the senior agency information security officer is provided with the mission and resources to implement an organization-wide information security program; the senior agency information security officer is provided with the mission and resources to maintain an organization-wide information security program. Information security program plan

procedures addressing program plan development and implementation

procedures addressing program plan reviews and updates

procedures addressing coordination of the program plan with relevant entities

other relevant documents or records Organizational personnel with information security program planning and plan implementation responsibilities

senior information security officer

organizational personnel with information security responsibilities

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-3: Include the resources needed to implement the information security and privacy programs in capital planning and investment requests and document all exceptions to this requirement; Prepare documentation required for addressing information security and privacy programs in capital planning and investment requests in accordance with applicable laws, executive orders, directives, policies, regulations, standards; and Make available for expenditure, the planned information security and privacy resources. Organizations consider establishing champions for information security and privacy and, as part of including the necessary resources, assign specialized expertise and resources as needed. Organizations may designate and empower an Investment Review Board or similar group to manage and provide oversight for the information security and privacy aspects of the capital planning and investment control process. the resources needed to implement the information security program are included in capital planning and investment requests, and all exceptions are documented; the resources needed to implement the privacy program are included in capital planning and investment requests, and all exceptions are documented; the documentation required for addressing the information security program in capital planning and investment requests is prepared in accordance with applicable laws, executive orders, directives, policies, regulations, standards; the documentation required for addressing the privacy program in capital planning and investment requests is prepared in accordance with applicable laws, executive orders, directives, policies, regulations, standards; information security resources are made available for expenditure as planned; privacy resources are made available for expenditure as planned. Information security program plan

Exhibit 300

Exhibit 53

business cases for capital planning and investment

procedures for capital planning and investment

documentation of exceptions to capital planning requirements

other relevant documents or records Organizational personnel with information security program planning responsibilities

organizational personnel with privacy program planning responsibilities

organizational personnel responsible for capital planning and investment

organizational personnel with information security responsibilities

organizational personnel with privacy responsibilities Organizational processes for capital planning and investment

organizational processes for business case, Exhibit 300, and Exhibit 53 development

mechanisms supporting the capital planning and investment process

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-4: Implement a process to ensure that plans of action and milestones for the information security, privacy, and supply chain risk management programs and associated organizational systems: Are developed and maintained; Document the remedial information security, privacy, and supply chain risk management actions to adequately respond to risk to organizational operations and assets, individuals, other organizations, and the Nation; and Are reported in accordance with established reporting requirements. Review plans of action and milestones for consistency with the organizational risk management strategy and organization-wide priorities for risk response actions. The plan of action and milestones is a key organizational document and is subject to reporting requirements established by the Office of Management and Budget. Organizations develop plans of action and milestones with an organization-wide perspective, prioritizing risk response actions and ensuring consistency with the goals and objectives of the organization. Plan of action and milestones updates are based on findings from control assessments and continuous monitoring activities. There can be multiple plans of action and milestones corresponding to the information system level, mission/business process level, and organizational/governance level. While plans of action and milestones are required for federal organizations, other types of organizations can help reduce risk by documenting and tracking planned remediations. Specific guidance on plans of action and milestones at the system level is provided in [CA-5](#ca-5). a process to ensure that plans of action and milestones for the information security program and associated organizational systems are developed; a process to ensure that plans of action and milestones for the information security program and associated organizational systems are maintained; a process to ensure that plans of action and milestones for the privacy program and associated organizational systems are developed; a process to ensure that plans of action and milestones for the privacy program and associated organizational systems are maintained; a process to ensure that plans of action and milestones for the supply chain risk management program and associated organizational systems are developed; a process to ensure that plans of action and milestones for the supply chain risk management program and associated organizational systems are maintained; a process to ensure that plans of action and milestones for the information security program and associated organizational systems document remedial information security risk management actions to adequately respond to risks to organizational operations and assets, individuals, other organizations, and the Nation; a process to ensure that plans of action and milestones for the privacy program and associated organizational systems document remedial privacy risk management actions to adequately respond to risks to organizational operations and assets, individuals, other organizations, and the Nation; a process to ensure that plans of action and milestones for the supply chain risk management program and associated organizational systems document remedial supply chain risk management actions to adequately respond to risks to organizational operations and assets, individuals, other organizations, and the Nation; a process to ensure that plans of action and milestones for the information security risk management programs and associated organizational systems are reported in accordance with established reporting requirements; a process to ensure that plans of action and milestones for the privacy risk management programs and associated organizational systems are reported in accordance with established reporting requirements; a process to ensure that plans of action and milestones for the supply chain risk management programs and associated organizational systems are reported in accordance with established reporting requirements; plans of action and milestones are reviewed for consistency with the organizational risk management strategy; plans of action and milestones are reviewed for consistency with organization-wide priorities for risk response actions. Information security program plan

plans of action and milestones

procedures addressing plans of action and milestones development and maintenance

procedures addressing plans of action and milestones reporting

procedures for reviewing plans of action and milestones for consistency with risk management strategy and risk response priorities

results of risk assessments associated with plans of action and milestones

OMB FISMA reporting requirements

other relevant documents or records Organizational personnel with responsibilities for developing, maintaining, reviewing, and reporting plans of action and milestones

organizational personnel with information security responsibilities Organizational processes for plan of action and milestones development, review, maintenance, and reporting

mechanisms supporting plans of action and milestones

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-5: Develop and update {{ insert: param, pm-05_odp }} an inventory of organizational systems. [OMB A-130](#27847491-5ce1-4f6a-a1e4-9e483782f0ef) provides guidance on developing systems inventories and associated reporting requirements. System inventory refers to an organization-wide inventory of systems, not system components as described in [CM-8](#cm-8). an inventory of organizational systems is developed; the inventory of organizational systems is updated {{ insert: param, pm-05_odp }}. Information security program plan

system inventory

procedures addressing system inventory development and maintenance

OMB FISMA reporting guidance

other relevant documents or records Organizational personnel with information security program planning and plan implementation responsibilities

organizational personnel responsible for developing and maintaining the system inventory

organizational personnel with information security responsibilities Organizational processes for system inventory development and maintenance

mechanisms supporting the system inventory

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-6: Develop, monitor, and report on the results of information security and privacy measures of performance. Measures of performance are outcome-based metrics used by an organization to measure the effectiveness or efficiency of the information security and privacy programs and the controls employed in support of the program. To facilitate security and privacy risk management, organizations consider aligning measures of performance with the organizational risk tolerance as defined in the risk management strategy. information security measures of performance are developed; information security measures of performance are monitored; the results of information security measures of performance are reported; privacy measures of performance are developed; privacy measures of performance are monitored; the results of privacy measures of performance are reported. Information security program plan

privacy program plan

information security measures of performance

privacy measures of performance

procedures addressing the development, monitoring, and reporting of information security and privacy measures of performance

risk management strategy

other relevant documents or records Organizational personnel with information security and privacy program planning and plan implementation responsibilities

organizational personnel responsible for developing, monitoring, and reporting information security and privacy measures of performance

organizational personnel with information security and privacy responsibilities Organizational processes for developing, monitoring, and reporting information security and privacy measures of performance

mechanisms supporting the development, monitoring, and reporting of information security and privacy measures of performance

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-7: Develop and maintain an enterprise architecture with consideration for information security, privacy, and the resulting risk to organizational operations and assets, individuals, other organizations, and the Nation. The integration of security and privacy requirements and controls into the enterprise architecture helps to ensure that security and privacy considerations are addressed throughout the system development life cycle and are explicitly related to the organization’s mission and business processes. The process of security and privacy requirements integration also embeds into the enterprise architecture and the organization’s security and privacy architectures consistent with the organizational risk management strategy. For PM-7, security and privacy architectures are developed at a system-of-systems level, representing all organizational systems. For [PL-8](#pl-8) , the security and privacy architectures are developed at a level that represents an individual system. The system-level architectures are consistent with the security and privacy architectures defined for the organization. Security and privacy requirements and control integration are most effectively accomplished through the rigorous application of the Risk Management Framework [SP 800-37](#482e4c99-9dc4-41ad-bba8-0f3f0032c1f8) and supporting security standards and guidelines. an enterprise architecture is developed with consideration for information security; an enterprise architecture is maintained with consideration for information security; an enterprise architecture is developed with consideration for privacy; an enterprise architecture is maintained with consideration for privacy; an enterprise architecture is developed with consideration for the resulting risk to organizational operations and assets, individuals, other organizations, and the Nation; an enterprise architecture is maintained with consideration for the resulting risk to organizational operations and assets, individuals, other organizations, and the Nation. Information security program plan

privacy program plan

enterprise architecture documentation

procedures addressing enterprise architecture development

results of risk assessments of enterprise architecture

other relevant documents or records Organizational personnel with information security and privacy program planning and plan implementation responsibilities

organizational personnel responsible for developing enterprise architecture

organizational personnel responsible for risk assessments of enterprise architecture

organizational personnel with information security and privacy responsibilities Organizational processes for enterprise architecture development

mechanisms supporting the enterprise architecture and its development

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-8: Address information security and privacy issues in the development, documentation, and updating of a critical infrastructure and key resources protection plan. Protection strategies are based on the prioritization of critical assets and resources. The requirement and guidance for defining critical infrastructure and key resources and for preparing an associated critical infrastructure protection plan are found in applicable laws, executive orders, directives, policies, regulations, standards, and guidelines. information security issues are addressed in the development of a critical infrastructure and key resources protection plan; information security issues are addressed in the documentation of a critical infrastructure and key resources protection plan; information security issues are addressed in the update of a critical infrastructure and key resources protection plan; privacy issues are addressed in the development of a critical infrastructure and key resources protection plan; privacy issues are addressed in the documentation of a critical infrastructure and key resources protection plan; privacy issues are addressed in the update of a critical infrastructure and key resources protection plan. Information security program plan

privacy program plan

critical infrastructure and key resources protection plan

procedures addressing the development, documentation, and updating of the critical infrastructure and key resources protection plan

HSPD 7

National Infrastructure Protection Plan

other relevant documents or records Organizational personnel with information security and privacy program planning and plan implementation responsibilities

organizational personnel responsible for developing, documenting, and updating the critical infrastructure and key resources protection plan

organizational personnel with information security and privacy responsibilities Organizational processes for developing, documenting, and updating the critical infrastructure and key resources protection plan

mechanisms supporting the development, documentation, and updating of the critical infrastructure and key resources protection plan

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-9: Develops a comprehensive strategy to manage: Security risk to organizational operations and assets, individuals, other organizations, and the Nation associated with the operation and use of organizational systems; and Privacy risk to individuals resulting from the authorized processing of personally identifiable information; Implement the risk management strategy consistently across the organization; and Review and update the risk management strategy {{ insert: param, pm-09_odp }} or as required, to address organizational changes. An organization-wide risk management strategy includes an expression of the security and privacy risk tolerance for the organization, security and privacy risk mitigation strategies, acceptable risk assessment methodologies, a process for evaluating security and privacy risk across the organization with respect to the organization’s risk tolerance, and approaches for monitoring risk over time. The senior accountable official for risk management (agency head or designated official) aligns information security management processes with strategic, operational, and budgetary planning processes. The risk executive function, led by the senior accountable official for risk management, can facilitate consistent application of the risk management strategy organization-wide. The risk management strategy can be informed by security and privacy risk-related inputs from other sources, both internal and external to the organization, to ensure that the strategy is broad-based and comprehensive. The supply chain risk management strategy described in [PM-30](#pm-30) can also provide useful inputs to the organization-wide risk management strategy. a comprehensive strategy is developed to manage security risk to organizational operations and assets, individuals, other organizations, and the Nation associated with the operation and use of organizational systems; a comprehensive strategy is developed to manage privacy risk to individuals resulting from the authorized processing of personally identifiable information; the risk management strategy is implemented consistently across the organization; the risk management strategy is reviewed and updated {{ insert: param, pm-09_odp }} or as required to address organizational changes. Information security program plan

privacy program plan

risk management strategy

supply chain risk management strategy

procedures addressing the development, implementation, review, and update of the risk management strategy

risk assessment results relevant to the risk management strategy

other relevant documents or records Organizational personnel with information security and privacy program planning and plan implementation responsibilities

organizational personnel responsible for the development, implementation, review, and update of the risk management strategy

organizational personnel with information security and privacy responsibilities Organizational processes for the development, implementation, review, and update of the risk management strategy

mechanisms supporting the development, implementation, review, and update of the risk management strategy

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-10: Manage the security and privacy state of organizational systems and the environments in which those systems operate through authorization processes; Designate individuals to fulfill specific roles and responsibilities within the organizational risk management process; and Integrate the authorization processes into an organization-wide risk management program. Authorization processes for organizational systems and environments of operation require the implementation of an organization-wide risk management process and associated security and privacy standards and guidelines. Specific roles for risk management processes include a risk executive (function) and designated authorizing officials for each organizational system and common control provider. The authorization processes for the organization are integrated with continuous monitoring processes to facilitate ongoing understanding and acceptance of security and privacy risks to organizational operations, organizational assets, individuals, other organizations, and the Nation. the security state of organizational systems and the environments in which those systems operate are managed through authorization processes; the privacy state of organizational systems and the environments in which those systems operate are managed through authorization processes; individuals are designated to fulfill specific roles and responsibilities within the organizational risk management process; the authorization processes are integrated into an organization-wide risk management program. Information security program plan

privacy program plan

procedures addressing management (i.e., documentation, tracking, and reporting) of the authorization process

assessment, authorization, and monitoring policy

assessment, authorization, and monitoring procedures

system authorization documentation

lists or other documentation about authorization process roles and responsibilities

risk assessment results relevant to the authorization process and the organization-wide risk management program

organizational risk management strategy

other relevant documents or records Organizational personnel with information security and privacy program planning and plan implementation responsibilities

organizational personnel responsible for management of the authorization process

organizational personnel with information security and privacy responsibilities Organizational processes for authorization

mechanisms supporting the authorization process

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-11: Define organizational mission and business processes with consideration for information security and privacy and the resulting risk to organizational operations, organizational assets, individuals, other organizations, and the Nation; and Determine information protection and personally identifiable information processing needs arising from the defined mission and business processes; and Review and revise the mission and business processes {{ insert: param, pm-11_odp }}. Protection needs are technology-independent capabilities that are required to counter threats to organizations, individuals, systems, and the Nation through the compromise of information (i.e., loss of confidentiality, integrity, availability, or privacy). Information protection and personally identifiable information processing needs are derived from the mission and business needs defined by organizational stakeholders, the mission and business processes designed to meet those needs, and the organizational risk management strategy. Information protection and personally identifiable information processing needs determine the required controls for the organization and the systems. Inherent to defining protection and personally identifiable information processing needs is an understanding of the adverse impact that could result if a compromise or breach of information occurs. The categorization process is used to make such potential impact determinations. Privacy risks to individuals can arise from the compromise of personally identifiable information, but they can also arise as unintended consequences or a byproduct of the processing of personally identifiable information at any stage of the information life cycle. Privacy risk assessments are used to prioritize the risks that are created for individuals from system processing of personally identifiable information. These risk assessments enable the selection of the required privacy controls for the organization and systems. Mission and business process definitions and the associated protection requirements are documented in accordance with organizational policies and procedures. organizational mission and business processes are defined with consideration for information security; organizational mission and business processes are defined with consideration for privacy; organizational mission and business processes are defined with consideration for the resulting risk to organizational operations, organizational assets, individuals, other organizations, and the Nation; information protection needs arising from the defined mission and business processes are determined; personally identifiable information processing needs arising from the defined mission and business processes are determined; the mission and business processes are reviewed and revised {{ insert: param, pm-11_odp }}. Information security program plan

privacy program plan

risk management strategy

procedures for determining mission and business protection needs

information security and privacy risk assessment results relevant to the determination of mission and business protection needs

personally identifiable information processing policy

personally identifiable information inventory

other relevant documents or records Organizational personnel with information security and privacy program planning and plan implementation responsibilities

organizational personnel responsible for enterprise risk management

organizational personnel responsible for determining information protection needs for mission and business processes

organizational personnel with information security and privacy responsibilities Organizational processes for defining mission and business processes and their information protection needs

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-12: Implement an insider threat program that includes a cross-discipline insider threat incident handling team. Organizations that handle classified information are required, under Executive Order 13587 [EO 13587](#0af071a6-cf8e-48ee-8c82-fe91efa20f94) and the National Insider Threat Policy [ODNI NITP](#06d74ea9-2178-449c-a9c5-b2980f804ac8) , to establish insider threat programs. The same standards and guidelines that apply to insider threat programs in classified environments can also be employed effectively to improve the security of controlled unclassified and other information in non-national security systems. Insider threat programs include controls to detect and prevent malicious insider activity through the centralized integration and analysis of both technical and nontechnical information to identify potential insider threat concerns. A senior official is designated by the department or agency head as the responsible individual to implement and provide oversight for the program. In addition to the centralized integration and analysis capability, insider threat programs require organizations to prepare department or agency insider threat policies and implementation plans, conduct host-based user monitoring of individual employee activities on government-owned classified computers, provide insider threat awareness training to employees, receive access to information from offices in the department or agency for insider threat analysis, and conduct self-assessments of department or agency insider threat posture.

Insider threat programs can leverage the existence of incident handling teams that organizations may already have in place, such as computer security incident response teams. Human resources records are especially important in this effort, as there is compelling evidence to show that some types of insider crimes are often preceded by nontechnical behaviors in the workplace, including ongoing patterns of disgruntled behavior and conflicts with coworkers and other colleagues. These precursors can guide organizational officials in more focused, targeted monitoring efforts. However, the use of human resource records could raise significant concerns for privacy. The participation of a legal team, including consultation with the senior agency official for privacy, ensures that monitoring activities are performed in accordance with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. an insider threat program that includes a cross-discipline insider threat incident handling team is implemented. Organizational personnel with information security and privacy program planning and plan implementation responsibilities

organizational personnel responsible for the insider threat program

members of the cross-discipline insider threat incident handling team

legal counsel

organizational personnel with information security and privacy responsibilities Organizational processes for implementing the insider threat program and the cross-discipline insider threat incident handling team

mechanisms supporting and/or implementing the insider threat program and the cross-discipline insider threat incident handling team

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-13: Establish a security and privacy workforce development and improvement program. Security and privacy workforce development and improvement programs include defining the knowledge, skills, and abilities needed to perform security and privacy duties and tasks; developing role-based training programs for individuals assigned security and privacy roles and responsibilities; and providing standards and guidelines for measuring and building individual qualifications for incumbents and applicants for security- and privacy-related positions. Such workforce development and improvement programs can also include security and privacy career paths to encourage security and privacy professionals to advance in the field and fill positions with greater responsibility. The programs encourage organizations to fill security- and privacy-related positions with qualified personnel. Security and privacy workforce development and improvement programs are complementary to organizational security awareness and training programs and focus on developing and institutionalizing the core security and privacy capabilities of personnel needed to protect organizational operations, assets, and individuals. a security workforce development and improvement program is established; a privacy workforce development and improvement program is established. Information security program plan

privacy program plan

information security and privacy workforce development and improvement program documentation

procedures for the information security and privacy workforce development and improvement program

information security and privacy role-based training program documentation

other relevant documents or records Organizational personnel with information security and privacy program planning and plan implementation responsibilities

organizational personnel responsible for the information security and privacy workforce development and improvement program

organizational personnel with information security and privacy responsibilities Organizational processes for implementing the information security and privacy workforce development and improvement program

mechanisms supporting and/or implementing the information security and privacy workforce development and improvement program

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-14: Implement a process for ensuring that organizational plans for conducting security and privacy testing, training, and monitoring activities associated with organizational systems: Are developed and maintained; and Continue to be executed; and Review testing, training, and monitoring plans for consistency with the organizational risk management strategy and organization-wide priorities for risk response actions. A process for organization-wide security and privacy testing, training, and monitoring helps ensure that organizations provide oversight for testing, training, and monitoring activities and that those activities are coordinated. With the growing importance of continuous monitoring programs, the implementation of information security and privacy across the three levels of the risk management hierarchy and the widespread use of common controls, organizations coordinate and consolidate the testing and monitoring activities that are routinely conducted as part of ongoing assessments supporting a variety of controls. Security and privacy training activities, while focused on individual systems and specific roles, require coordination across all organizational elements. Testing, training, and monitoring plans and activities are informed by current threat and vulnerability assessments. a process is implemented for ensuring that organizational plans for conducting security testing, training, and monitoring activities associated with organizational systems are developed; a process is implemented for ensuring that organizational plans for conducting security testing, training, and monitoring activities associated with organizational systems are maintained; a process is implemented for ensuring that organizational plans for conducting privacy testing, training, and monitoring activities associated with organizational systems are developed; a process is implemented for ensuring that organizational plans for conducting privacy testing, training, and monitoring activities associated with organizational systems are maintained; a process is implemented for ensuring that organizational plans for conducting security testing, training, and monitoring activities associated with organizational systems continue to be executed; a process is implemented for ensuring that organizational plans for conducting privacy testing, training, and monitoring activities associated with organizational systems continue to be executed; testing plans are reviewed for consistency with the organizational risk management strategy; training plans are reviewed for consistency with the organizational risk management strategy; monitoring plans are reviewed for consistency with the organizational risk management strategy; testing plans are reviewed for consistency with organization-wide priorities for risk response actions; training plans are reviewed for consistency with organization-wide priorities for risk response actions; monitoring plans are reviewed for consistency with organization-wide priorities for risk response actions. Information security program plan

privacy program plan

plans for conducting security and privacy testing, training, and monitoring activities

organizational procedures addressing the development and maintenance of plans for conducting security and privacy testing, training, and monitoring activities

risk management strategy

procedures for the review of plans for conducting security and privacy testing, training, and monitoring activities for consistency with risk management strategy and risk response priorities

results of risk assessments associated with conducting security and privacy testing, training, and monitoring activities

documentation of the timely execution of plans for conducting security and privacy testing, training, and monitoring activities

other relevant documents or records Organizational personnel with responsibilities for developing and maintaining plans for conducting security and privacy testing, training, and monitoring activities

organizational personnel with information security and privacy responsibilities Organizational processes for the development and maintenance of plans for conducting security and privacy testing, training, and monitoring activities

mechanisms supporting the development and maintenance of plans for conducting security and privacy testing, training, and monitoring activities

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-15: Establish and institutionalize contact with selected groups and associations within the security and privacy communities: To facilitate ongoing security and privacy education and training for organizational personnel; To maintain currency with recommended security and privacy practices, techniques, and technologies; and To share current security and privacy information, including threats, vulnerabilities, and incidents. Ongoing contact with security and privacy groups and associations is important in an environment of rapidly changing technologies and threats. Groups and associations include special interest groups, professional associations, forums, news groups, users’ groups, and peer groups of security and privacy professionals in similar organizations. Organizations select security and privacy groups and associations based on mission and business functions. Organizations share threat, vulnerability, and incident information as well as contextual insights, compliance techniques, and privacy problems consistent with applicable laws, executive orders, directives, policies, regulations, standards, and guidelines. contact is established and institutionalized with selected groups and associations within the security community to facilitate ongoing security education and training for organizational personnel; contact is established and institutionalized with selected groups and associations within the privacy community to facilitate ongoing privacy education and training for organizational personnel; contact is established and institutionalized with selected groups and associations within the security community to maintain currency with recommended security practices, techniques, and technologies; contact is established and institutionalized with selected groups and associations within the privacy community to maintain currency with recommended privacy practices, techniques, and technologies; contact is established and institutionalized with selected groups and associations within the security community to share current security information, including threats, vulnerabilities, and incidents; contact is established and institutionalized with selected groups and associations within the privacy community to share current privacy information, including threats, vulnerabilities, and incidents. Information security program plan

privacy program plan

risk management strategy

procedures for establishing and institutionalizing contacts with security and privacy groups and associations

lists or other records of contacts with and/or membership in security and privacy groups and associations

other relevant documents or records Organizational personnel with information security and privacy program planning and plan implementation responsibilities

organizational personnel responsible for establishing and institutionalizing contact with security and privacy groups and associations

organizational personnel with information security and privacy responsibilities

personnel from selected groups and associations with which the organization has established and institutionalized contact Organizational processes for establishing and institutionalizing contact with security and privacy groups and associations

mechanisms supporting contact with security and privacy groups and associations

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-16: Implement a threat awareness program that includes a cross-organization information-sharing capability for threat intelligence. Because of the constantly changing and increasing sophistication of adversaries, especially the advanced persistent threat (APT), it may be more likely that adversaries can successfully breach or compromise organizational systems. One of the best techniques to address this concern is for organizations to share threat information, including threat events (i.e., tactics, techniques, and procedures) that organizations have experienced, mitigations that organizations have found are effective against certain types of threats, and threat intelligence (i.e., indications and warnings about threats). Threat information sharing may be bilateral or multilateral. Bilateral threat sharing includes government-to-commercial and government-to-government cooperatives. Multilateral threat sharing includes organizations taking part in threat-sharing consortia. Threat information may require special agreements and protection, or it may be freely shared. a threat awareness program that includes a cross-organization information-sharing capability for threat intelligence is implemented. Information security program plan

privacy program plan

threat awareness program policy

threat awareness program procedures

risk assessment results relevant to threat awareness

documentation about the cross-organization information-sharing capability

other relevant documents or records Organizational personnel with information security and privacy program planning and plan implementation responsibilities

organizational personnel responsible for the threat awareness program

organizational personnel responsible for the cross-organization information-sharing capability

organizational personnel with information security and privacy responsibilities

external personnel with whom threat awareness information is shared by the organization Organizational processes for implementing the threat awareness program

organizational processes for implementing the cross-organization information-sharing capability

mechanisms supporting and/or implementing the threat awareness program

mechanisms supporting and/or implementing the cross-organization information-sharing capability

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-17: Establish policy and procedures to ensure that requirements for the protection of controlled unclassified information that is processed, stored or transmitted on external systems, are implemented in accordance with applicable laws, executive orders, directives, policies, regulations, and standards; and Review and update the policy and procedures {{ insert: param, pm-17_prm_1 }}. Controlled unclassified information is defined by the National Archives and Records Administration along with the safeguarding and dissemination requirements for such information and is codified in [32 CFR 2002](#91f992fb-f668-4c91-a50f-0f05b95ccee3) and, specifically for systems external to the federal organization, [32 CFR 2002.14h](https://www.govinfo.gov/content/pkg/CFR-2017-title32-vol6/xml/CFR-2017-title32-vol6-part2002.xml) . The policy prescribes the specific use and conditions to be implemented in accordance with organizational procedures, including via its contracting processes. policy is established to ensure that requirements for the protection of controlled unclassified information that is processed, stored, or transmitted on external systems are implemented in accordance with applicable laws, executive orders, directives, policies, regulations, and standards; procedures are established to ensure that requirements for the protection of controlled unclassified information that is processed, stored, or transmitted on external systems are implemented in accordance with applicable laws, executive orders, directives, policies, regulations, and standards; policy is reviewed and updated {{ insert: param, pm-17_odp.01 }}; procedures are reviewed and updated {{ insert: param, pm-17_odp.02 }}  Controlled unclassified information policy

controlled unclassified information procedures

other relevant documents or records. Organizational personnel with controlled unclassified information responsibilities

organizational personnel with information security responsibilities.

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-18: Develop and disseminate an organization-wide privacy program plan that provides an overview of the agency’s privacy program, and: Includes a description of the structure of the privacy program and the resources dedicated to the privacy program; Provides an overview of the requirements for the privacy program and a description of the privacy program management controls and common controls in place or planned for meeting those requirements; Includes the role of the senior agency official for privacy and the identification and assignment of roles of other privacy officials and staff and their responsibilities; Describes management commitment, compliance, and the strategic goals and objectives of the privacy program; Reflects coordination among organizational entities responsible for the different aspects of privacy; and Is approved by a senior official with responsibility and accountability for the privacy risk being incurred to organizational operations (including mission, functions, image, and reputation), organizational assets, individuals, other organizations, and the Nation; and Update the plan {{ insert: param, pm-18_odp }} and to address changes in federal privacy laws and policy and organizational changes and problems identified during plan implementation or privacy control assessments. A privacy program plan is a formal document that provides an overview of an organization’s privacy program, including a description of the structure of the privacy program, the resources dedicated to the privacy program, the role of the senior agency official for privacy and other privacy officials and staff, the strategic goals and objectives of the privacy program, and the program management controls and common controls in place or planned for meeting applicable privacy requirements and managing privacy risks. Privacy program plans can be represented in single documents or compilations of documents.

The senior agency official for privacy is responsible for designating which privacy controls the organization will treat as program management, common, system-specific, and hybrid controls. Privacy program plans provide sufficient information about the privacy program management and common controls (including the specification of parameters and assignment and selection operations explicitly or by reference) to enable control implementations that are unambiguously compliant with the intent of the plans and a determination of the risk incurred if the plans are implemented as intended.

Program management controls are generally implemented at the organization level and are essential for managing the organization’s privacy program. Program management controls are distinct from common, system-specific, and hybrid controls because program management controls are independent of any particular information system. Together, the privacy plans for individual systems and the organization-wide privacy program plan provide complete coverage for the privacy controls employed within the organization.

Common controls are documented in an appendix to the organization’s privacy program plan unless the controls are included in a separate privacy plan for a system. The organization-wide privacy program plan indicates which separate privacy plans contain descriptions of privacy controls. an organization-wide privacy program plan that provides an overview of the agency’s privacy program is developed; the privacy program plan includes a description of the structure of the privacy program; the privacy program plan includes a description of the resources dedicated to the privacy program; the privacy program plan provides an overview of the requirements for the privacy program; the privacy program plan provides a description of the privacy program management controls in place or planned for meeting the requirements of the privacy program; the privacy program plan provides a description of common controls in place or planned for meeting the requirements of the privacy program; the privacy program plan includes the role of the senior agency official for privacy; the privacy program plan includes the identification and assignment of the roles of other privacy officials and staff and their responsibilities; the privacy program plan describes management commitment; the privacy program plan describes compliance; the privacy program plan describes the strategic goals and objectives of the privacy program; the privacy program plan reflects coordination among organizational entities responsible for the different aspects of privacy; the privacy program plan is approved by a senior official with responsibility and accountability for the privacy risk being incurred by organizational operations (including, mission, functions, image, and reputation), organizational assets, individuals, other organizations, and the Nation; the privacy program plan is disseminated; the privacy program plan is updated {{ insert: param, pm-18_odp }}; the privacy program plan is updated to address changes in federal privacy laws and policies; the privacy program plan is updated to address organizational changes; the privacy program plan is updated to address problems identified during plan implementation or privacy control assessments. Privacy program plan

procedures addressing program plan development and implementation

procedures addressing program plan reviews, updates, and approvals

procedures addressing coordination of the program plan with relevant entities

records of program plan reviews, updates, and approvals

other relevant documents or records Organizational personnel with privacy program planning and plan implementation responsibilities

organizational personnel with privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-19: Appoint a senior agency official for privacy with the authority, mission, accountability, and resources to coordinate, develop, and implement, applicable privacy requirements and manage privacy risks through the organization-wide privacy program. The privacy officer is an organizational official. For federal agencies—as defined by applicable laws, executive orders, directives, regulations, policies, standards, and guidelines—this official is designated as the senior agency official for privacy. Organizations may also refer to this official as the chief privacy officer. The senior agency official for privacy also has roles on the data management board (see [PM-23](#pm-23) ) and the data integrity board (see [PM-24](#pm-24)). a senior agency official for privacy with authority, mission, accountability, and resources is appointed; the senior agency official for privacy coordinates applicable privacy requirements; the senior agency official for privacy develops applicable privacy requirements; the senior agency official for privacy implements applicable privacy requirements; the senior agency official for privacy manages privacy risks through the organization-wide privacy program. Privacy program documents, including policies, procedures, plans, and reports

public privacy notices, including Federal Register notices

privacy impact assessments

privacy risk assessments

Privacy Act statements

system of records notices

computer matching agreements and notices

contracts, information sharing agreements, and memoranda of understanding

governing requirements, including laws, executive orders, regulations, standards, and guidance

other relevant documents or records Organizational personnel with privacy program planning and plan implementation responsibilities

organizational personnel with privacy responsibilities

senior agency official for privacy

privacy officials

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-20: Maintain a central resource webpage on the organization’s principal public website that serves as a central source of information about the organization’s privacy program and that: Ensures that the public has access to information about organizational privacy activities and can communicate with its senior agency official for privacy; Ensures that organizational privacy practices and reports are publicly available; and Employs publicly facing email addresses and/or phone lines to enable the public to provide feedback and/or direct questions to privacy offices regarding privacy practices. For federal agencies, the webpage is located at www.[agency].gov/privacy. Federal agencies include public privacy impact assessments, system of records notices, computer matching notices and agreements, [PRIVACT](#18e71fec-c6fd-475a-925a-5d8495cf8455) exemption and implementation rules, privacy reports, privacy policies, instructions for individuals making an access or amendment request, email addresses for questions/complaints, blogs, and periodic publications. a central resource webpage is maintained on the organization’s principal public website; the webpage serves as a central source of information about the organization’s privacy program; the webpage ensures that the public has access to information about organizational privacy activities; the webpage ensures that the public can communicate with its senior agency official for privacy; the webpage ensures that organizational privacy practices are publicly available; the webpage ensures that organizational privacy reports are publicly available; the webpage employs publicly facing email addresses and/or phone numbers to enable the public to provide feedback and/or direct questions to privacy offices regarding privacy practices. Public website

publicly posted privacy program documents, including policies, procedures, plans, and reports

position description of the senior agency official for privacy

public privacy notices, including Federal Register notices

privacy impact assessments

privacy risk assessments

Privacy Act statements and system of records notices

computer matching agreements and notices

other relevant documents or records Organizational personnel with privacy program information dissemination responsibilities

organizational personnel with privacy responsibilities Location, access, availability, and functionality of privacy resource webpage

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-21: Develop and maintain an accurate accounting of disclosures of personally identifiable information, including: Date, nature, and purpose of each disclosure; and Name and address, or other contact information of the individual or organization to which the disclosure was made; Retain the accounting of disclosures for the length of the time the personally identifiable information is maintained or five years after the disclosure is made, whichever is longer; and Make the accounting of disclosures available to the individual to whom the personally identifiable information relates upon request. The purpose of accounting of disclosures is to allow individuals to learn to whom their personally identifiable information has been disclosed, to provide a basis for subsequently advising recipients of any corrected or disputed personally identifiable information, and to provide an audit trail for subsequent reviews of organizational compliance with conditions for disclosures. For federal agencies, keeping an accounting of disclosures is required by the [PRIVACT](#18e71fec-c6fd-475a-925a-5d8495cf8455) ; agencies should consult with their senior agency official for privacy and legal counsel on this requirement and be aware of the statutory exceptions and OMB guidance relating to the provision.

Organizations can use any system for keeping notations of disclosures, if it can construct from such a system, a document listing of all disclosures along with the required information. Automated mechanisms can be used by organizations to determine when personally identifiable information is disclosed, including commercial services that provide notifications and alerts. Accounting of disclosures may also be used to help organizations verify compliance with applicable privacy statutes and policies governing the disclosure or dissemination of information and dissemination restrictions. an accurate accounting of disclosures of personally identifiable information is developed and maintained; the accounting includes the date of each disclosure; the accounting includes the nature of each disclosure; the accounting includes the purpose of each disclosure; the accounting includes the name of the individual or organization to whom the disclosure was made; the accounting includes the address or other contact information of the individual or organization to whom the disclosure was made; the accounting of disclosures is retained for the length of time that the personally identifiable information is maintained or five years after the disclosure is made, whichever is longer; the accounting of disclosures is made available to the individual to whom the personally identifiable information relates upon request. Privacy program plan

disclosure policies and procedures

records of disclosures

audit logs

Privacy Act policies and procedures

system of records notice

Privacy Act exemption rules. Organizational personnel with privacy program responsibilities

organizational personnel with privacy responsibilities. Organizational processes for disclosures

mechanisms supporting the accounting of disclosures, including commercial services that provide notifications and alerts.

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-22: Develop and document organization-wide policies and procedures for: Reviewing for the accuracy, relevance, timeliness, and completeness of personally identifiable information across the information life cycle; Correcting or deleting inaccurate or outdated personally identifiable information; Disseminating notice of corrected or deleted personally identifiable information to individuals or other appropriate entities; and Appeals of adverse decisions on correction or deletion requests. Personally identifiable information quality management includes steps that organizations take to confirm the accuracy and relevance of personally identifiable information throughout the information life cycle. The information life cycle includes the creation, collection, use, processing, storage, maintenance, dissemination, disclosure, and disposition of personally identifiable information. Organizational policies and procedures for personally identifiable information quality management are important because inaccurate or outdated personally identifiable information maintained by organizations may cause problems for individuals. Organizations consider the quality of personally identifiable information involved in business functions where inaccurate information may result in adverse decisions or the denial of benefits and services, or the disclosure of the information may cause stigmatization. Correct information, in certain circumstances, can cause problems for individuals that outweigh the benefits of organizations maintaining the information. Organizations consider creating policies and procedures for the removal of such information.

The senior agency official for privacy ensures that practical means and mechanisms exist and are accessible for individuals or their authorized representatives to seek the correction or deletion of personally identifiable information. Processes for correcting or deleting data are clearly defined and publicly available. Organizations use discretion in determining whether data is to be deleted or corrected based on the scope of requests, the changes sought, and the impact of the changes. Additionally, processes include the provision of responses to individuals of decisions to deny requests for correction or deletion. The responses include the reasons for the decisions, a means to record individual objections to the decisions, and a means of requesting reviews of the initial determinations.

Organizations notify individuals or their designated representatives when their personally identifiable information is corrected or deleted to provide transparency and confirm the completed action. Due to the complexity of data flows and storage, other entities may need to be informed of the correction or deletion. Notice supports the consistent correction and deletion of personally identifiable information across the data ecosystem. organization-wide policies for personally identifiable information quality management are developed and documented; organization-wide procedures for personally identifiable information quality management are developed and documented; the policies address reviewing the accuracy of personally identifiable information across the information life cycle; the policies address reviewing the relevance of personally identifiable information across the information life cycle; the policies address reviewing the timeliness of personally identifiable information across the information life cycle; the policies address reviewing the completeness of personally identifiable information across the information life cycle; the procedures address reviewing the accuracy of personally identifiable information across the information life cycle; the procedures address reviewing the relevance of personally identifiable information across the information life cycle; the procedures address reviewing the timeliness of personally identifiable information across the information life cycle; the procedures address reviewing the completeness of personally identifiable information across the information life cycle; the policies address correcting or deleting inaccurate or outdated personally identifiable information; the procedures address correcting or deleting inaccurate or outdated personally identifiable information; the policies address disseminating notice of corrected or deleted personally identifiable information to individuals or other appropriate entities; the procedures address disseminating notice of corrected or deleted personally identifiable information to individuals or other appropriate entities; the policies address appeals of adverse decisions on correction or deletion requests; the procedures address appeals of adverse decisions on correction or deletion requests. Privacy program plan

policies and procedures addressing personally identifiable information quality management, information life cycle documentation, and sample notices of correction or deletion

records of monitoring PII quality management practices

documentation of reviews and updates of policies and procedures Organizational personnel with privacy program information dissemination responsibilities

organizational personnel with privacy responsibilities [Organizational processes for data quality and personally identifiable information quality management procedures

mechanisms supporting and/or implementing quality management requirements

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-23: Establish a Data Governance Body consisting of {{ insert: param, pm-23_odp.01 }} with {{ insert: param, pm-23_odp.02 }}. A Data Governance Body can help ensure that the organization has coherent policies and the ability to balance the utility of data with security and privacy requirements. The Data Governance Body establishes policies, procedures, and standards that facilitate data governance so that data, including personally identifiable information, is effectively managed and maintained in accordance with applicable laws, executive orders, directives, regulations, policies, standards, and guidance. Responsibilities can include developing and implementing guidelines that support data modeling, quality, integrity, and the de-identification needs of personally identifiable information across the information life cycle as well as reviewing and approving applications to release data outside of the organization, archiving the applications and the released data, and performing post-release monitoring to ensure that the assumptions made as part of the data release continue to be valid. Members include the chief information officer, senior agency information security officer, and senior agency official for privacy. Federal agencies are required to establish a Data Governance Body with specific roles and responsibilities in accordance with the [EVIDACT](#511da9ca-604d-43f7-be41-b862085420a9) and policies set forth under [OMB M-19-23](#d886c141-c832-4ad7-ac6d-4b94f4b550d3). a Data Governance Body consisting of {{ insert: param, pm-23_odp.01 }} with {{ insert: param, pm-23_odp.02 }} is established. Privacy program plan

documentation relating to the Data Governance Body, including documents establishing such a body, its charter of operations, and any plans and reports

records of board meetings and decisions

records of requests to review data

policies, procedures, and standards that facilitate data governance Officials serving on the Data Governance Body (e.g., chief information officer, senior agency information security officer, and senior agency official for privacy)

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-24: Establish a Data Integrity Board to: Review proposals to conduct or participate in a matching program; and Conduct an annual review of all matching programs in which the agency has participated. A Data Integrity Board is the board of senior officials designated by the head of a federal agency and is responsible for, among other things, reviewing the agency’s proposals to conduct or participate in a matching program and conducting an annual review of all matching programs in which the agency has participated. As a general matter, a matching program is a computerized comparison of records from two or more automated [PRIVACT](#18e71fec-c6fd-475a-925a-5d8495cf8455) systems of records or an automated system of records and automated records maintained by a non-federal agency (or agent thereof). A matching program either pertains to Federal benefit programs or Federal personnel or payroll records. At a minimum, the Data Integrity Board includes the Inspector General of the agency, if any, and the senior agency official for privacy. a Data Integrity Board is established; the Data Integrity Board reviews proposals to conduct or participate in a matching program; the Data Integrity Board conducts an annual review of all matching programs in which the agency has participated. Privacy program plan

privacy program documents relating to the Data Integrity Board, including documents establishing the board, its charter of operations, and any plans and reports

computer matching agreements and notices

information sharing agreements

memoranda of understanding

records documenting annual reviews

governing requirements, including laws, executive orders, regulations, standards, and guidance members of the Data Integrity Board (e.g., the chief information officer, senior information security officer, senior agency official for privacy, and agency Inspector General)

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-25: Develop, document, and implement policies and procedures that address the use of personally identifiable information for internal testing, training, and research; Limit or minimize the amount of personally identifiable information used for internal testing, training, and research purposes; Authorize the use of personally identifiable information when such information is required for internal testing, training, and research; and Review and update policies and procedures {{ insert: param, pm-25_prm_1 }}. The use of personally identifiable information in testing, research, and training increases the risk of unauthorized disclosure or misuse of such information. Organizations consult with the senior agency official for privacy and/or legal counsel to ensure that the use of personally identifiable information in testing, training, and research is compatible with the original purpose for which it was collected. When possible, organizations use placeholder data to avoid exposure of personally identifiable information when conducting testing, training, and research. policies that address the use of personally identifiable information for internal testing are developed and documented; policies that address the use of personally identifiable information for internal training are developed and documented; policies that address the use of personally identifiable information for internal research are developed and documented; procedures that address the use of personally identifiable information for internal testing are developed and documented; procedures that address the use of personally identifiable information for internal training are developed and documented; procedures that address the use of personally identifiable information for internal research are developed and documented; policies that address the use of personally identifiable information for internal testing, are implemented; policies that address the use of personally identifiable information for training are implemented; policies that address the use of personally identifiable information for research are implemented; procedures that address the use of personally identifiable information for internal testing are implemented; procedures that address the use of personally identifiable information for training are implemented; procedures that address the use of personally identifiable information for research are implemented; the amount of personally identifiable information used for internal testing purposes is limited or minimized; the amount of personally identifiable information used for internal training purposes is limited or minimized; the amount of personally identifiable information used for internal research purposes is limited or minimized; the required use of personally identifiable information for internal testing is authorized; the required use of personally identifiable information for internal training is authorized; the required use of personally identifiable information for internal research is authorized; policies are reviewed {{ insert: param, pm-25_odp.01 }}; policies are updated {{ insert: param, pm-25_odp.02 }}; procedures are reviewed {{ insert: param, pm-25_odp.03 }}; procedures are updated {{ insert: param, pm-25_odp.04 }}. Privacy program plan

policies and procedures for the minimization of personally identifiable information used in testing, training, and research

documentation supporting policy implementation (e.g., templates for testing, training, and research

privacy threshold analysis

privacy risk assessment)

data sets used for testing, training, and research Organizational personnel with privacy program responsibilities

organizational personnel with privacy responsibilities

system developers

personnel with IRB responsibilities Organizational processes for data quality and personally identifiable information management

mechanisms supporting data quality management and personally identifiable information management to minimize the use of personally identifiable information

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-26: Implement a process for receiving and responding to complaints, concerns, or questions from individuals about the organizational security and privacy practices that includes: Mechanisms that are easy to use and readily accessible by the public; All information necessary for successfully filing complaints; Tracking mechanisms to ensure all complaints received are reviewed and addressed within {{ insert: param, pm-26_prm_1 }}; Acknowledgement of receipt of complaints, concerns, or questions from individuals within {{ insert: param, pm-26_odp.03 }} ; and Response to complaints, concerns, or questions from individuals within {{ insert: param, pm-26_odp.04 }}. Complaints, concerns, and questions from individuals can serve as valuable sources of input to organizations and ultimately improve operational models, uses of technology, data collection practices, and controls. Mechanisms that can be used by the public include telephone hotline, email, or web-based forms. The information necessary for successfully filing complaints includes contact information for the senior agency official for privacy or other official designated to receive complaints. Privacy complaints may also include personally identifiable information which is handled in accordance with relevant policies and processes. a process for receiving complaints, concerns, or questions from individuals about organizational security and privacy practices is implemented; a process for responding to complaints, concerns, or questions from individuals about organizational security and privacy practices is implemented; the complaint management process includes mechanisms that are easy to use by the public; the complaint management process includes mechanisms that are readily accessible by the public; the complaint management process includes all information necessary for successfully filing complaints; the complaint management process includes tracking mechanisms to ensure that all complaints are reviewed within {{ insert: param, pm-26_odp.01 }}; the complaint management process includes tracking mechanisms to ensure that all complaints are addressed within {{ insert: param, pm-26_odp.02 }}; the complaint management process includes acknowledging the receipt of complaints, concerns, or questions from individuals within {{ insert: param, pm-26_odp.03 }}; the complaint management process includes responding to complaints, concerns, or questions from individuals within {{ insert: param, pm-26_odp.04 }}. Privacy program plan

procedures addressing complaint management

complaint documentation

procedures addressing the reviews of complaints

other relevant documents or records Organizational personnel with privacy program responsibilities

organizational personnel with privacy responsibilities Organizational processes for complaint management

mechanisms supporting complaint management

tools used by the public to submit complaints, concerns, and questions (e.g., telephone, hotline, email, or web-based forms

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-27: Develop {{ insert: param, pm-27_odp.01 }} and disseminate to: {{ insert: param, pm-27_odp.02 }} to demonstrate accountability with statutory, regulatory, and policy privacy mandates; and {{ insert: param, pm-27_odp.03 }} and other personnel with responsibility for monitoring privacy program compliance; and Review and update privacy reports {{ insert: param, pm-27_odp.04 }}. Through internal and external reporting, organizations promote accountability and transparency in organizational privacy operations. Reporting can also help organizations to determine progress in meeting privacy compliance requirements and privacy controls, compare performance across the federal government, discover vulnerabilities, identify gaps in policy and implementation, and identify models for success. For federal agencies, privacy reports include annual senior agency official for privacy reports to OMB, reports to Congress required by Implementing Regulations of the 9/11 Commission Act, and other public reports required by law, regulation, or policy, including internal policies of organizations. The senior agency official for privacy consults with legal counsel, where appropriate, to ensure that organizations meet all applicable privacy reporting requirements. {{ insert: param, pm-27_odp.01 }} are developed; the privacy reports are disseminated to {{ insert: param, pm-27_odp.02 }} to demonstrate accountability with statutory, regulatory, and policy privacy mandates; the privacy reports are disseminated to {{ insert: param, pm-27_odp.03 }}; the privacy reports are disseminated to other personnel responsible for monitoring privacy program compliance; the privacy reports are reviewed and updated {{ insert: param, pm-27_odp.04 }}. Privacy program plan

internal and external privacy reports

privacy program plan

annual senior agency official for privacy reports to OMB

reports to Congress required by law, regulation, or policy, including internal policies

records documenting the dissemination of reports to oversight bodies and officials responsible for monitoring privacy program compliance

records of review and updates of privacy reports. Organizational personnel with privacy program responsibilities

organizational personnel with privacy responsibilities

legal counsel.

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-28: Identify and document: Assumptions affecting risk assessments, risk responses, and risk monitoring; Constraints affecting risk assessments, risk responses, and risk monitoring; Priorities and trade-offs considered by the organization for managing risk; and Organizational risk tolerance; Distribute the results of risk framing activities to {{ insert: param, pm-28_odp.01 }} ; and Review and update risk framing considerations {{ insert: param, pm-28_odp.02 }}. Risk framing is most effective when conducted at the organization level and in consultation with stakeholders throughout the organization including mission, business, and system owners. The assumptions, constraints, risk tolerance, priorities, and trade-offs identified as part of the risk framing process inform the risk management strategy, which in turn informs the conduct of risk assessment, risk response, and risk monitoring activities. Risk framing results are shared with organizational personnel, including mission and business owners, information owners or stewards, system owners, authorizing officials, senior agency information security officer, senior agency official for privacy, and senior accountable official for risk management. assumptions affecting risk assessments are identified and documented; assumptions affecting risk responses are identified and documented; assumptions affecting risk monitoring are identified and documented; constraints affecting risk assessments are identified and documented; constraints affecting risk responses are identified and documented; constraints affecting risk monitoring are identified and documented; priorities considered by the organization for managing risk are identified and documented; trade-offs considered by the organization for managing risk are identified and documented; organizational risk tolerance is identified and documented; the results of risk framing activities are distributed to {{ insert: param, pm-28_odp.01 }}; risk framing considerations are reviewed and updated {{ insert: param, pm-28_odp.02 }}. Information security program plan

privacy program plan

supply chain risk management strategy

documentation of risk framing activities

policies and procedures for risk framing activities

risk management strategy Organizational personnel (including mission, business, and system owners or stewards

authorizing officials

senior agency information security officer

senior agency official for privacy

and senior accountable official for risk management) Organizational procedures and practices for authorizing, conducting, managing, and reviewing personally identifiable information processing

organizational processes for risk framing

mechanisms supporting the development, review, update, and approval of risk framing

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-29: Appoint a Senior Accountable Official for Risk Management to align organizational information security and privacy management processes with strategic, operational, and budgetary planning processes; and Establish a Risk Executive (function) to view and analyze risk from an organization-wide perspective and ensure management of risk is consistent across the organization. The senior accountable official for risk management leads the risk executive (function) in organization-wide risk management activities. a Senior Accountable Official for Risk Management is appointed; a Senior Accountable Official for Risk Management aligns information security and privacy management processes with strategic, operational, and budgetary planning processes; a Risk Executive (function) is established; a Risk Executive (function) views and analyzes risk from an organization-wide perspective; a Risk Executive (function) ensures that the management of risk is consistent across the organization. Information security program plan

privacy program plan

risk management strategy

supply chain risk management strategy

documentation of appointment, roles, and responsibilities of a Senior Accountable Official for Risk Management

documentation of actions taken by the Official

documentation of the establishment, policies, and procedures of a Risk Executive (function) Senior Accountable Official for Risk Management

chief information officer

senior agency information security officer

senior agency official for privacy

organizational personnel with information security and privacy program responsibilities

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-30: Develop an organization-wide strategy for managing supply chain risks associated with the development, acquisition, maintenance, and disposal of systems, system components, and system services; Implement the supply chain risk management strategy consistently across the organization; and Review and update the supply chain risk management strategy on {{ insert: param, pm-30_odp }} or as required, to address organizational changes. An organization-wide supply chain risk management strategy includes an unambiguous expression of the supply chain risk appetite and tolerance for the organization, acceptable supply chain risk mitigation strategies or controls, a process for consistently evaluating and monitoring supply chain risk, approaches for implementing and communicating the supply chain risk management strategy, and the associated roles and responsibilities. Supply chain risk management includes considerations of the security and privacy risks associated with the development, acquisition, maintenance, and disposal of systems, system components, and system services. The supply chain risk management strategy can be incorporated into the organization’s overarching risk management strategy and can guide and inform supply chain policies and system-level supply chain risk management plans. In addition, the use of a risk executive function can facilitate a consistent, organization-wide application of the supply chain risk management strategy. The supply chain risk management strategy is implemented at the organization and mission/business levels, whereas the supply chain risk management plan (see [SR-2](#sr-2) ) is implemented at the system level. an organization-wide strategy for managing supply chain risks is developed; the supply chain risk management strategy addresses risks associated with the development of systems; the supply chain risk management strategy addresses risks associated with the development of system components; the supply chain risk management strategy addresses risks associated with the development of system services; the supply chain risk management strategy addresses risks associated with the acquisition of systems; the supply chain risk management strategy addresses risks associated with the acquisition of system components; the supply chain risk management strategy addresses risks associated with the acquisition of system services; the supply chain risk management strategy addresses risks associated with the maintenance of systems; the supply chain risk management strategy addresses risks associated with the maintenance of system components; the supply chain risk management strategy addresses risks associated with the maintenance of system services; the supply chain risk management strategy addresses risks associated with the disposal of systems; the supply chain risk management strategy addresses risks associated with the disposal of system components; the supply chain risk management strategy addresses risks associated with the disposal of system services; the supply chain risk management strategy is implemented consistently across the organization; the supply chain risk management strategy is reviewed and updated {{ insert: param, pm-30_odp }} or as required to address organizational changes. Supply chain risk management strategy

organizational risk management strategy

enterprise risk management documents

other relevant documents or records Organizational personnel with supply chain risk management responsibilities

organizational personnel with information security responsibilities

organizational personnel with acquisition responsibilities

organizational personnel with enterprise risk management responsibilities

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-31: Develop an organization-wide continuous monitoring strategy and implement continuous monitoring programs that include: Establishing the following organization-wide metrics to be monitored: {{ insert: param, pm-31_odp.01 }}; Establishing {{ insert: param, pm-31_odp.02 }} and {{ insert: param, pm-31_odp.03 }} for control effectiveness; Ongoing monitoring of organizationally-defined metrics in accordance with the continuous monitoring strategy; Correlation and analysis of information generated by control assessments and monitoring; Response actions to address results of the analysis of control assessment and monitoring information; and Reporting the security and privacy status of organizational systems to {{ insert: param, pm-31_prm_4 }} {{ insert: param, pm-31_prm_5 }}. Continuous monitoring at the organization level facilitates ongoing awareness of the security and privacy posture across the organization to support organizational risk management decisions. The terms "continuous" and "ongoing" imply that organizations assess and monitor their controls and risks at a frequency sufficient to support risk-based decisions. Different types of controls may require different monitoring frequencies. The results of continuous monitoring guide and inform risk response actions by organizations. Continuous monitoring programs allow organizations to maintain the authorizations of systems and common controls in highly dynamic environments of operation with changing mission and business needs, threats, vulnerabilities, and technologies. Having access to security- and privacy-related information on a continuing basis through reports and dashboards gives organizational officials the capability to make effective, timely, and informed risk management decisions, including ongoing authorization decisions. To further facilitate security and privacy risk management, organizations consider aligning organization-defined monitoring metrics with organizational risk tolerance as defined in the risk management strategy. Monitoring requirements, including the need for monitoring, may be referenced in other controls and control enhancements such as, [AC-2g](#ac-2_smt.g), [AC-2(7)](#ac-2.7), [AC-2(12)(a)](#ac-2.12_smt.a), [AC-2(7)(b)](#ac-2.7_smt.b), [AC-2(7)(c)](#ac-2.7_smt.c), [AC-17(1)](#ac-17.1), [AT-4a](#at-4_smt.a), [AU-13](#au-13), [AU-13(1)](#au-13.1), [AU-13(2)](#au-13.2), [CA-7](#ca-7), [CM-3f](#cm-3_smt.f), [CM-6d](#cm-6_smt.d), [CM-11c](#cm-11_smt.c), [IR-5](#ir-5), [MA-2b](#ma-2_smt.b), [MA-3a](#ma-3_smt.a), [MA-4a](#ma-4_smt.a), [PE-3d](#pe-3_smt.d), [PE-6](#pe-6), [PE-14b](#pe-14_smt.b), [PE-16](#pe-16), [PE-20](#pe-20), [PM-6](#pm-6), [PM-23](#pm-23), [PS-7e](#ps-7_smt.e), [SA-9c](#sa-9_smt.c), [SC-5(3)(b)](#sc-5.3_smt.b), [SC-7a](#sc-7_smt.a), [SC-7(24)(b)](#sc-7.24_smt.b), [SC-18b](#sc-18_smt.b), [SC-43b](#sc-43_smt.b), [SI-4](#si-4). an organization-wide continuous monitoring strategy is developed; continuous monitoring programs are implemented that include establishing {{ insert: param, pm-31_odp.01 }} to be monitored; continuous monitoring programs are implemented that establish {{ insert: param, pm-31_odp.02 }} for monitoring; continuous monitoring programs are implemented that establish {{ insert: param, pm-31_odp.03 }} for assessment of control effectiveness; continuous monitoring programs are implemented that include monitoring {{ insert: param, pm-31_odp.01 }} on an ongoing basis in accordance with the continuous monitoring strategy; continuous monitoring programs are implemented that include correlating information generated by control assessments and monitoring; continuous monitoring programs are implemented that include analyzing information generated by control assessments and monitoring; continuous monitoring programs are implemented that include response actions to address the analysis of control assessment information; continuous monitoring programs are implemented that include response actions to address the analysis of monitoring information; continuous monitoring programs are implemented that include reporting the security status of organizational systems to {{ insert: param, pm-31_odp.04 }} {{ insert: param, pm-31_odp.06 }}; continuous monitoring programs are implemented that include reporting the privacy status of organizational systems to {{ insert: param, pm-31_odp.05 }} {{ insert: param, pm-31_odp.07 }}. Information security program plan

privacy program plan

supply chain risk management plan

continuous monitoring strategy

risk management strategy

information security continuous monitoring program documentation, reporting, metrics, and artifacts

information security continuous monitoring program assessment documentation, reporting, metrics, and artifacts

assessment and authorization policy

procedures addressing the continuous monitoring of controls

privacy program continuous monitoring documentation, reporting, metrics, and artifacts

continuous monitoring program records, security, and privacy impact analyses

status reports

risk response documentation

other relevant documents or records. Senior Accountable Official for Risk Management

chief information officer

senior agency information security officer

senior agency official for privacy

organizational personnel with information security, privacy, and supply chain risk management program responsibilities Organizational procedures and mechanisms used for information security, privacy, and supply chain continuous monitoring

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PM-32: Analyze {{ insert: param, pm-32_odp }} supporting mission essential services or functions to ensure that the information resources are being used consistent with their intended purpose. Systems are designed to support a specific mission or business function. However, over time, systems and system components may be used to support services and functions that are outside of the scope of the intended mission or business functions. This can result in exposing information resources to unintended environments and uses that can significantly increase threat exposure. In doing so, the systems are more vulnerable to compromise, which can ultimately impact the services and functions for which they were intended. This is especially impactful for mission-essential services and functions. By analyzing resource use, organizations can identify such potential exposures. {{ insert: param, pm-32_odp }} supporting mission-essential services or functions are analyzed to ensure that the information resources are being used in a manner that is consistent with their intended purpose. Information security program plan

privacy program plan

list of essential services and functions

organizational analysis of information resources

risk management strategy

other relevant documents or records. Organizational personnel with information security, privacy, and supply chain risk management program responsibilities

**FedRAMP Baseline:** L2 | **Domain:** PM

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### PS — Personnel Security (Manual Controls)

##### Control PS-1: Develop, document, and disseminate to {{ insert: param, ps-1_prm_1 }}: {{ insert: param, ps-01_odp.03 }} personnel security policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the personnel security policy and the associated personnel security controls; Designate an {{ insert: param, ps-01_odp.04 }} to manage the development, documentation, and dissemination of the personnel security policy and procedures; and Review and update the current personnel security: Policy {{ insert: param, ps-01_odp.05 }} and following {{ insert: param, ps-01_odp.06 }} ; and Procedures {{ insert: param, ps-01_odp.07 }} and following {{ insert: param, ps-01_odp.08 }}. Personnel security policy and procedures for the controls in the PS family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on their development. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission level or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies reflecting the complex nature of organizations. Procedures can be established for security and privacy programs, for mission/business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to personnel security policy and procedures include, but are not limited to, assessment or audit findings, security incidents or breaches, or changes in applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. a personnel security policy is developed and documented; the personnel security policy is disseminated to {{ insert: param, ps-01_odp.01 }}; personnel security procedures to facilitate the implementation of the personnel security policy and associated personnel security controls are developed and documented; the personnel security procedures are disseminated to {{ insert: param, ps-01_odp.02 }}; the {{ insert: param, ps-01_odp.03 }} personnel security policy addresses purpose; the {{ insert: param, ps-01_odp.03 }} personnel security policy addresses scope; the {{ insert: param, ps-01_odp.03 }} personnel security policy addresses roles; the {{ insert: param, ps-01_odp.03 }} personnel security policy addresses responsibilities; the {{ insert: param, ps-01_odp.03 }} personnel security policy addresses management commitment; the {{ insert: param, ps-01_odp.03 }} personnel security policy addresses coordination among organizational entities; the {{ insert: param, ps-01_odp.03 }} personnel security policy addresses compliance; the {{ insert: param, ps-01_odp.03 }} personnel security policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, ps-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the personnel security policy and procedures; the current personnel security policy is reviewed and updated {{ insert: param, ps-01_odp.05 }}; the current personnel security policy is reviewed and updated following {{ insert: param, ps-01_odp.06 }}; the current personnel security procedures are reviewed and updated {{ insert: param, ps-01_odp.07 }}; the current personnel security procedures are reviewed and updated following {{ insert: param, ps-01_odp.08 }}. Personnel security policy

personnel security procedures

system security plan

privacy plan

risk management strategy documentation

audit findings

other relevant documents or records Organizational personnel with personnel security responsibilities

organizational personnel with information security responsibilities

**FedRAMP Baseline:** L2 | **Domain:** PS

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PS-2: Assign a risk designation to all organizational positions; Establish screening criteria for individuals filling those positions; and Review and update position risk designations {{ insert: param, ps-02_odp }}. Position risk designations reflect Office of Personnel Management (OPM) policy and guidance. Proper position designation is the foundation of an effective and consistent suitability and personnel security program. The Position Designation System (PDS) assesses the duties and responsibilities of a position to determine the degree of potential damage to the efficiency or integrity of the service due to misconduct of an incumbent of a position and establishes the risk level of that position. The PDS assessment also determines if the duties and responsibilities of the position present the potential for position incumbents to bring about a material adverse effect on national security and the degree of that potential effect, which establishes the sensitivity level of a position. The results of the assessment determine what level of investigation is conducted for a position. Risk designations can guide and inform the types of authorizations that individuals receive when accessing organizational information and information systems. Position screening criteria include explicit information security role appointment requirements. Parts 1400 and 731 of Title 5, Code of Federal Regulations, establish the requirements for organizations to evaluate relevant covered positions for a position sensitivity and position risk designation commensurate with the duties and responsibilities of those positions. a risk designation is assigned to all organizational positions; screening criteria are established for individuals filling organizational positions; position risk designations are reviewed and updated {{ insert: param, ps-02_odp }}. Personnel security policy

procedures addressing position categorization

appropriate codes of federal regulations

list of risk designations for organizational positions

records of position risk designation reviews and updates

system security plan

other relevant documents or records Organizational personnel with personnel security responsibilities

organizational personnel with information security responsibilities Organizational processes for assigning, reviewing, and updating position risk designations

organizational processes for establishing screening criteria

**FedRAMP Baseline:** L2 | **Domain:** PS

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PS-5: Review and confirm ongoing operational need for current logical and physical access authorizations to systems and facilities when individuals are reassigned or transferred to other positions within the organization; Initiate {{ insert: param, ps-05_odp.01 }} within {{ insert: param, ps-05_odp.02 }}; Modify access authorization as needed to correspond with any changes in operational need due to reassignment or transfer; and Notify {{ insert: param, ps-05_odp.03 }} within {{ insert: param, ps-05_odp.04 }}. Personnel transfer applies when reassignments or transfers of individuals are permanent or of such extended duration as to make the actions warranted. Organizations define actions appropriate for the types of reassignments or transfers, whether permanent or extended. Actions that may be required for personnel transfers or reassignments to other positions within organizations include returning old and issuing new keys, identification cards, and building passes; closing system accounts and establishing new accounts; changing system access authorizations (i.e., privileges); and providing for access to official records to which individuals had access at previous work locations and in previous system accounts. the ongoing operational need for current logical and physical access authorizations to systems and facilities are reviewed and confirmed when individuals are reassigned or transferred to other positions within the organization; {{ insert: param, ps-05_odp.01 }} are initiated within {{ insert: param, ps-05_odp.02 }}; access authorization is modified as needed to correspond with any changes in operational need due to reassignment or transfer; {{ insert: param, ps-05_odp.03 }} are notified within {{ insert: param, ps-05_odp.04 }}. Personnel security policy

procedures addressing personnel transfer

records of personnel transfer actions

list of system and facility access authorizations

system security plan

other relevant documents or records Organizational personnel with personnel security responsibilities

organizational personnel with account management responsibilities

system/network administrators

organizational personnel with information security responsibilities Organizational processes for personnel transfer

mechanisms supporting and/or implementing personnel transfer notifications

mechanisms for disabling system access/revoking authenticators

**FedRAMP Baseline:** L2 | **Domain:** PS

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PS-6: Develop and document access agreements for organizational systems; Review and update the access agreements {{ insert: param, ps-06_odp.01 }} ; and Verify that individuals requiring access to organizational information and systems: Sign appropriate access agreements prior to being granted access; and Re-sign access agreements to maintain access to organizational systems when access agreements have been updated or {{ insert: param, ps-06_odp.02 }}. Access agreements include nondisclosure agreements, acceptable use agreements, rules of behavior, and conflict-of-interest agreements. Signed access agreements include an acknowledgement that individuals have read, understand, and agree to abide by the constraints associated with organizational systems to which access is authorized. Organizations can use electronic signatures to acknowledge access agreements unless specifically prohibited by organizational policy. access agreements are developed and documented for organizational systems; the access agreements are reviewed and updated {{ insert: param, ps-06_odp.01 }}; individuals requiring access to organizational information and systems sign appropriate access agreements prior to being granted access; individuals requiring access to organizational information and systems re-sign access agreements to maintain access to organizational systems when access agreements have been updated or {{ insert: param, ps-06_odp.02 }}. Personnel security policy

personnel security procedures

procedures addressing access agreements for organizational information and systems

access control policy

access control procedures

access agreements (including non-disclosure agreements, acceptable use agreements, rules of behavior, and conflict-of-interest agreements)

documentation of access agreement reviews, updates, and re-signing

system security plan

privacy plan

other relevant documents or records Organizational personnel with personnel security responsibilities

organizational personnel who have signed/resigned access agreements

organizational personnel with information security and privacy responsibilities Organizational processes for reviewing, updating, and re-signing access agreements

mechanisms supporting the reviewing, updating, and re-signing of access agreements

**FedRAMP Baseline:** L2 | **Domain:** PS

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PS-7: Establish personnel security requirements, including security roles and responsibilities for external providers; Require external providers to comply with personnel security policies and procedures established by the organization; Document personnel security requirements; Require external providers to notify {{ insert: param, ps-07_odp.01 }} of any personnel transfers or terminations of external personnel who possess organizational credentials and/or badges, or who have system privileges within {{ insert: param, ps-07_odp.02 }} ; and Monitor provider compliance with personnel security requirements. External provider refers to organizations other than the organization operating or acquiring the system. External providers include service bureaus, contractors, and other organizations that provide system development, information technology services, testing or assessment services, outsourced applications, and network/security management. Organizations explicitly include personnel security requirements in acquisition-related documents. External providers may have personnel working at organizational facilities with credentials, badges, or system privileges issued by organizations. Notifications of external personnel changes ensure the appropriate termination of privileges and credentials. Organizations define the transfers and terminations deemed reportable by security-related characteristics that include functions, roles, and the nature of credentials or privileges associated with transferred or terminated individuals. personnel security requirements are established, including security roles and responsibilities for external providers; external providers are required to comply with personnel security policies and procedures established by the organization; personnel security requirements are documented; external providers are required to notify {{ insert: param, ps-07_odp.01 }} of any personnel transfers or terminations of external personnel who possess organizational credentials and/or badges or who have system privileges within {{ insert: param, ps-07_odp.02 }}; provider compliance with personnel security requirements is monitored. Personnel security policy

procedures addressing external personnel security

list of personnel security requirements

acquisition documents

service-level agreements

compliance monitoring process

system security plan

other relevant documents or records Organizational personnel with personnel security responsibilities

external providers

system/network administrators

organizational personnel with account management responsibilities

organizational personnel with information security responsibilities Organizational processes for managing and monitoring external personnel security

mechanisms supporting and/or implementing the monitoring of provider compliance

**FedRAMP Baseline:** L2 | **Domain:** PS

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PS-8: Employ a formal sanctions process for individuals failing to comply with established information security and privacy policies and procedures; and Notify {{ insert: param, ps-08_odp.01 }} within {{ insert: param, ps-08_odp.02 }} when a formal employee sanctions process is initiated, identifying the individual sanctioned and the reason for the sanction. Organizational sanctions reflect applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Sanctions processes are described in access agreements and can be included as part of general personnel policies for organizations and/or specified in security and privacy policies. Organizations consult with the Office of the General Counsel regarding matters of employee sanctions. a formal sanctions process is employed for individuals failing to comply with established information security and privacy policies and procedures; {{ insert: param, ps-08_odp.01 }} is/are notified within {{ insert: param, ps-08_odp.02 }} when a formal employee sanctions process is initiated, identifying the individual sanctioned and the reason for the sanction. Personnel security policy

personnel security procedures

procedures addressing personnel sanctions

access agreements (including non-disclosure agreements, acceptable use agreements, rules of behavior, and conflict-of-interest agreements)

list of personnel or roles to be notified of formal employee sanctions

records or notifications of formal employee sanctions

system security plan

privacy plan

personally identifiable information processing policy

other relevant documents or records Organizational personnel with personnel security responsibilities

legal counsel

organizational personnel with information security and privacy responsibilities Organizational processes for managing formal employee sanctions

mechanisms supporting and/or implementing formal employee sanctions notifications

**FedRAMP Baseline:** L2 | **Domain:** PS

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PS-9: Incorporate security and privacy roles and responsibilities into organizational position descriptions. Specification of security and privacy roles in individual organizational position descriptions facilitates clarity in understanding the security or privacy responsibilities associated with the roles and the role-based security and privacy training requirements for the roles. security roles and responsibilities are incorporated into organizational position descriptions; privacy roles and responsibilities are incorporated into organizational position descriptions. Personnel security policy

personnel security procedures

procedures addressing position descriptions

security and privacy position descriptions

system security plan

privacy plan

privacy program plan

other relevant documents or records Organizational personnel with personnel security responsibilities

organizational personnel with information security and privacy responsibilities

organizational personnel with human capital management responsibilities Organizational processes for managing position descriptions

**FedRAMP Baseline:** L2 | **Domain:** PS

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### PT — Personally Identifiable Information Processing and Transparency (Manual Controls)

##### Control PT-1: Develop, document, and disseminate to {{ insert: param, pt-1_prm_1 }}: {{ insert: param, pt-01_odp.03 }} personally identifiable information processing and transparency policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the personally identifiable information processing and transparency policy and the associated personally identifiable information processing and transparency controls; Designate an {{ insert: param, pt-01_odp.04 }} to manage the development, documentation, and dissemination of the personally identifiable information processing and transparency policy and procedures; and Review and update the current personally identifiable information processing and transparency: Policy {{ insert: param, pt-01_odp.05 }} and following {{ insert: param, pt-01_odp.06 }} ; and Procedures {{ insert: param, pt-01_odp.07 }} and following {{ insert: param, pt-01_odp.08 }}. Personally identifiable information processing and transparency policy and procedures address the controls in the PT family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of personally identifiable information processing and transparency policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to personally identifiable information processing and transparency policy and procedures include assessment or audit findings, breaches, or changes in applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. a personally identifiable information processing and transparency policy is developed and documented; the personally identifiable information processing and transparency policy is disseminated to {{ insert: param, pt-01_odp.01 }}; personally identifiable information processing and transparency procedures to facilitate the implementation of the personally identifiable information processing and transparency policy and associated personally identifiable information processing and transparency controls are developed and documented; the personally identifiable information processing and transparency procedures are disseminated to {{ insert: param, pt-01_odp.02 }}; the {{ insert: param, pt-01_odp.03 }} personally identifiable information processing and transparency policy addresses purpose; the {{ insert: param, pt-01_odp.03 }} personally identifiable information processing and transparency policy addresses scope; the {{ insert: param, pt-01_odp.03 }} personally identifiable information processing and transparency policy addresses roles; the {{ insert: param, pt-01_odp.03 }} personally identifiable information processing and transparency policy addresses responsibilities; the {{ insert: param, pt-01_odp.03 }} personally identifiable information processing and transparency policy addresses management commitment; the {{ insert: param, pt-01_odp.03 }} personally identifiable information processing and transparency policy addresses coordination among organizational entities; the {{ insert: param, pt-01_odp.03 }} personally identifiable information processing and transparency policy addresses compliance; the {{ insert: param, pt-01_odp.03 }} personally identifiable information processing and transparency policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, pt-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the personally identifiable information processing and transparency policy and procedures; the current personally identifiable information processing and transparency policy is reviewed and updated {{ insert: param, pt-01_odp.05 }}; the current personally identifiable information processing and transparency policy is reviewed and updated following {{ insert: param, pt-01_odp.06 }}; the current personally identifiable information processing and transparency procedures are reviewed and updated {{ insert: param, pt-01_odp.07 }}; the current personally identifiable information processing and transparency procedures are reviewed and updated following {{ insert: param, pt-01_odp.08 }}. Personally identifiable information processing and transparency policy and procedures

privacy plan

privacy program plan

other relevant documents or records Organizational personnel with personally identifiable information processing and transparency responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** PT

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PT-5: Provide notice to individuals about the processing of personally identifiable information that: Is available to individuals upon first interacting with an organization, and subsequently at {{ insert: param, pt-05_odp.01 }}; Is clear and easy-to-understand, expressing information about personally identifiable information processing in plain language; Identifies the authority that authorizes the processing of personally identifiable information; Identifies the purposes for which personally identifiable information is to be processed; and Includes {{ insert: param, pt-05_odp.02 }}. Privacy notices help inform individuals about how their personally identifiable information is being processed by the system or organization. Organizations use privacy notices to inform individuals about how, under what authority, and for what purpose their personally identifiable information is processed, as well as other information such as choices individuals might have with respect to that processing and other parties with whom information is shared. Laws, executive orders, directives, regulations, or policies may require that privacy notices include specific elements or be provided in specific formats. Federal agency personnel consult with the senior agency official for privacy and legal counsel regarding when and where to provide privacy notices, as well as elements to include in privacy notices and required formats. In circumstances where laws or government-wide policies do not require privacy notices, organizational policies and determinations may require privacy notices and may serve as a source of the elements to include in privacy notices.

Privacy risk assessments identify the privacy risks associated with the processing of personally identifiable information and may help organizations determine appropriate elements to include in a privacy notice to manage such risks. To help individuals understand how their information is being processed, organizations write materials in plain language and avoid technical jargon. a notice to individuals about the processing of personally identifiable information is provided such that the notice is available to individuals upon first interacting with an organization; a notice to individuals about the processing of personally identifiable information is provided such that the notice is subsequently available to individuals {{ insert: param, pt-05_odp.01 }}; a notice to individuals about the processing of personally identifiable information is provided that is clear, easy-to-understand, and expresses information about personally identifiable information processing in plain language; a notice to individuals about the processing of personally identifiable information that identifies the authority that authorizes the processing of personally identifiable information is provided; a notice to individuals about the processing of personally identifiable information that identifies the purpose for which personally identifiable information is to be processed is provided; a notice to individuals about the processing of personally identifiable information which includes {{ insert: param, pt-05_odp.02 }} is provided. Personally identifiable information processing and transparency policy and procedures

privacy notice

Privacy Act statements

privacy plan

other relevant documents or records Organizational personnel with personally identifiable information processing and transparency responsibilities

organizational personnel with user interface or user experience responsibilities

organizational personnel with information security and privacy responsibilities Organizational processes and implementation support or mechanisms for providing notice to individuals regarding the processing of their personally identifiable information

**FedRAMP Baseline:** L2 | **Domain:** PT

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PT-6: For systems that process information that will be maintained in a Privacy Act system of records: Draft system of records notices in accordance with OMB guidance and submit new and significantly modified system of records notices to the OMB and appropriate congressional committees for advance review; Publish system of records notices in the Federal Register; and Keep system of records notices accurate, up-to-date, and scoped in accordance with policy. The [PRIVACT](#18e71fec-c6fd-475a-925a-5d8495cf8455) requires that federal agencies publish a system of records notice in the Federal Register upon the establishment and/or modification of a [PRIVACT](#18e71fec-c6fd-475a-925a-5d8495cf8455) system of records. As a general matter, a system of records notice is required when an agency maintains a group of any records under the control of the agency from which information is retrieved by the name of an individual or by some identifying number, symbol, or other identifier. The notice describes the existence and character of the system and identifies the system of records, the purpose(s) of the system, the authority for maintenance of the records, the categories of records maintained in the system, the categories of individuals about whom records are maintained, the routine uses to which the records are subject, and additional details about the system as described in [OMB A-108](#3671ff20-c17c-44d6-8a88-7de203fa74aa). system of records notices are drafted in accordance with OMB guidance for systems that process information that will be maintained in a Privacy Act system of records; new and significantly modified system of records notices are submitted to the OMB and appropriate congressional committees for advance review for systems that process information that will be maintained in a Privacy Act system of records; system of records notices are published in the Federal Register for systems that process information that will be maintained in a Privacy Act system of records; system of records notices are kept accurate, up-to-date, and scoped in accordance with policy for systems that process information that will be maintained in a Privacy Act system of records. Personally identifiable information processing and transparency policy and procedures

privacy notice

Privacy Act system of records

Federal Register notices

privacy plan

other relevant documents or records Organizational personnel with personally identifiable information processing and transparency responsibilities

organizational personnel with information security and privacy responsibilities Organizational processes for Privacy Act system of records maintenance

**FedRAMP Baseline:** L2 | **Domain:** PT

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PT-7: Apply {{ insert: param, pt-07_odp }} for specific categories of personally identifiable information. Organizations apply any conditions or protections that may be necessary for specific categories of personally identifiable information. These conditions may be required by laws, executive orders, directives, regulations, policies, standards, or guidelines. The requirements may also come from the results of privacy risk assessments that factor in contextual changes that may result in an organizational determination that a particular category of personally identifiable information is particularly sensitive or raises particular privacy risks. Organizations consult with the senior agency official for privacy and legal counsel regarding any protections that may be necessary. {{ insert: param, pt-07_odp }} are applied for specific categories of personally identifiable information. Personally identifiable information processing and transparency policy and procedures

privacy notice

Privacy Act system of records

computer matching agreements and notices

contracts

privacy information sharing agreements

memoranda of understanding

governing requirements

privacy plan

other relevant documents or records Organizational personnel with personally identifiable information processing and transparency responsibilities

organizational personnel with information security and privacy responsibilities Organizational processes for supporting and/or implementing personally identifiable information processing

**FedRAMP Baseline:** L2 | **Domain:** PT

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control PT-8: When a system or organization processes information for the purpose of conducting a matching program: Obtain approval from the Data Integrity Board to conduct the matching program; Develop and enter into a computer matching agreement; Publish a matching notice in the Federal Register; Independently verify the information produced by the matching program before taking adverse action against an individual, if required; and Provide individuals with notice and an opportunity to contest the findings before taking adverse action against an individual. The [PRIVACT](#18e71fec-c6fd-475a-925a-5d8495cf8455) establishes requirements for federal and non-federal agencies if they engage in a matching program. In general, a matching program is a computerized comparison of records from two or more automated [PRIVACT](#18e71fec-c6fd-475a-925a-5d8495cf8455) systems of records or an automated system of records and automated records maintained by a non-federal agency (or agent thereof). A matching program either pertains to federal benefit programs or federal personnel or payroll records. A federal benefit match is performed to determine or verify eligibility for payments under federal benefit programs or to recoup payments or delinquent debts under federal benefit programs. A matching program involves not just the matching activity itself but also the investigative follow-up and ultimate action, if any. approval to conduct the matching program is obtained from the Data Integrity Board when a system or organization processes information for the purpose of conducting a matching program; a computer matching agreement is developed when a system or organization processes information for the purpose of conducting a matching program; a computer matching agreement is entered into when a system or organization processes information for the purpose of conducting a matching program; a matching notice is published in the Federal Register when a system or organization processes information for the purpose of conducting a matching program; the information produced by the matching program is independently verified before taking adverse action against an individual, if required, when a system or organization processes information for the purpose of conducting a matching program; individuals are provided with notice when a system or organization processes information for the purpose of conducting a matching program; individuals are provided with an opportunity to contest the findings before adverse action is taken against them when a system or organization processes information for the purpose of conducting a matching program. Personally identifiable information processing and transparency policy and procedures

privacy notice

Privacy Act system of records

Federal Register notices

Data Integrity Board determinations

contracts

information sharing agreements

memoranda of understanding

governing requirements

privacy plan

other relevant documents or records Organizational personnel with personally identifiable information processing and transparency responsibilities

organizational personnel with information security and privacy responsibilities Organizational processes for supporting and/or implementing personally identifiable information processing

matching program

**FedRAMP Baseline:** L2 | **Domain:** PT

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### RA — Risk Assessment (Manual Controls)

##### Control RA-1: Develop, document, and disseminate to {{ insert: param, ra-1_prm_1 }}: {{ insert: param, ra-01_odp.03 }} risk assessment policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the risk assessment policy and the associated risk assessment controls; Designate an {{ insert: param, ra-01_odp.04 }} to manage the development, documentation, and dissemination of the risk assessment policy and procedures; and Review and update the current risk assessment: Policy {{ insert: param, ra-01_odp.05 }} and following {{ insert: param, ra-01_odp.06 }} ; and Procedures {{ insert: param, ra-01_odp.07 }} and following {{ insert: param, ra-01_odp.08 }}. Risk assessment policy and procedures address the controls in the RA family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of risk assessment policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies reflecting the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to risk assessment policy and procedures include assessment or audit findings, security incidents or breaches, or changes in laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. a risk assessment policy is developed and documented; the risk assessment policy is disseminated to {{ insert: param, ra-01_odp.01 }}; risk assessment procedures to facilitate the implementation of the risk assessment policy and associated risk assessment controls are developed and documented; the risk assessment procedures are disseminated to {{ insert: param, ra-01_odp.02 }}; the {{ insert: param, ra-01_odp.03 }} risk assessment policy addresses purpose; the {{ insert: param, ra-01_odp.03 }} risk assessment policy addresses scope; the {{ insert: param, ra-01_odp.03 }} risk assessment policy addresses roles; the {{ insert: param, ra-01_odp.03 }} risk assessment policy addresses responsibilities; the {{ insert: param, ra-01_odp.03 }} risk assessment policy addresses management commitment; the {{ insert: param, ra-01_odp.03 }} risk assessment policy addresses coordination among organizational entities; the {{ insert: param, ra-01_odp.03 }} risk assessment policy addresses compliance; the {{ insert: param, ra-01_odp.03 }} risk assessment policy is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, ra-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the risk assessment policy and procedures; the current risk assessment policy is reviewed and updated {{ insert: param, ra-01_odp.05 }}; the current risk assessment policy is reviewed and updated following {{ insert: param, ra-01_odp.06 }}; the current risk assessment procedures are reviewed and updated {{ insert: param, ra-01_odp.07 }}; the current risk assessment procedures are reviewed and updated following {{ insert: param, ra-01_odp.08 }}. Risk assessment policy and procedures

system security plan

privacy plan

other relevant documents or records Organizational personnel with risk assessment responsibilities

organizational personnel with security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** RA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control RA-2: Categorize the system and information it processes, stores, and transmits; Document the security categorization results, including supporting rationale, in the security plan for the system; and Verify that the authorizing official or authorizing official designated representative reviews and approves the security categorization decision. Security categories describe the potential adverse impacts or negative consequences to organizational operations, organizational assets, and individuals if organizational information and systems are compromised through a loss of confidentiality, integrity, or availability. Security categorization is also a type of asset loss characterization in systems security engineering processes that is carried out throughout the system development life cycle. Organizations can use privacy risk assessments or privacy impact assessments to better understand the potential adverse effects on individuals. [CNSSI 1253](#4e4fbc93-333d-45e6-a875-de36b878b6b9) provides additional guidance on categorization for national security systems.

Organizations conduct the security categorization process as an organization-wide activity with the direct involvement of chief information officers, senior agency information security officers, senior agency officials for privacy, system owners, mission and business owners, and information owners or stewards. Organizations consider the potential adverse impacts to other organizations and, in accordance with [USA PATRIOT](#13f0c39d-eaf7-417a-baef-69a041878bb5) and Homeland Security Presidential Directives, potential national-level adverse impacts.

Security categorization processes facilitate the development of inventories of information assets and, along with [CM-8](#cm-8) , mappings to specific system components where information is processed, stored, or transmitted. The security categorization process is revisited throughout the system development life cycle to ensure that the security categories remain accurate and relevant. the system and the information it processes, stores, and transmits are categorized; the security categorization results, including supporting rationale, are documented in the security plan for the system; the authorizing official or authorizing official designated representative reviews and approves the security categorization decision. Risk assessment policy

security planning policy and procedures

procedures addressing security categorization of organizational information and systems

security categorization documentation

system security plan

privacy plan

other relevant documents or records Organizational personnel with security categorization and risk assessment responsibilities

organizational personnel with security and privacy responsibilities Organizational processes for security categorization

**FedRAMP Baseline:** L2 | **Domain:** RA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control RA-4: 

**FedRAMP Baseline:** L2 | **Domain:** RA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control RA-6: Employ a technical surveillance countermeasures survey at {{ insert: param, ra-06_odp.01 }} {{ insert: param, ra-06_odp.02 }}. A technical surveillance countermeasures survey is a service provided by qualified personnel to detect the presence of technical surveillance devices and hazards and to identify technical security weaknesses that could be used in the conduct of a technical penetration of the surveyed facility. Technical surveillance countermeasures surveys also provide evaluations of the technical security posture of organizations and facilities and include visual, electronic, and physical examinations of surveyed facilities, internally and externally. The surveys also provide useful input for risk assessments and information regarding organizational exposure to potential adversaries. a technical surveillance countermeasures survey is employed at {{ insert: param, ra-06_odp.01 }} {{ insert: param, ra-06_odp.02 }}. Risk assessment policy

procedures addressing technical surveillance countermeasures surveys

audit records/event logs

system security plan

other relevant documents or records Organizational personnel with technical surveillance countermeasures surveys responsibilities

system/network administrators

organizational personnel with security responsibilities Organizational processes for technical surveillance countermeasures surveys

mechanisms/tools supporting and/or implementing technical surveillance countermeasure surveys

**FedRAMP Baseline:** L2 | **Domain:** RA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control RA-7: Respond to findings from security and privacy assessments, monitoring, and audits in accordance with organizational risk tolerance. Organizations have many options for responding to risk including mitigating risk by implementing new controls or strengthening existing controls, accepting risk with appropriate justification or rationale, sharing or transferring risk, or avoiding risk. The risk tolerance of the organization influences risk response decisions and actions. Risk response addresses the need to determine an appropriate response to risk before generating a plan of action and milestones entry. For example, the response may be to accept risk or reject risk, or it may be possible to mitigate the risk immediately so that a plan of action and milestones entry is not needed. However, if the risk response is to mitigate the risk, and the mitigation cannot be completed immediately, a plan of action and milestones entry is generated. findings from security assessments are responded to in accordance with organizational risk tolerance; findings from privacy assessments are responded to in accordance with organizational risk tolerance; findings from monitoring are responded to in accordance with organizational risk tolerance; findings from audits are responded to in accordance with organizational risk tolerance. Risk assessment policy

assessment reports

audit records/event logs

system security plan

privacy plan

other relevant documents or records Organizational personnel with assessment and auditing responsibilities

system/network administrators

organizational personnel with security and privacy responsibilities Organizational processes for assessments and audits

mechanisms/tools supporting and/or implementing assessments and auditing

**FedRAMP Baseline:** L2 | **Domain:** RA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control RA-8: Conduct privacy impact assessments for systems, programs, or other activities before: Developing or procuring information technology that processes personally identifiable information; and Initiating a new collection of personally identifiable information that: Will be processed using information technology; and Includes personally identifiable information permitting the physical or virtual (online) contacting of a specific individual, if identical questions have been posed to, or identical reporting requirements imposed on, ten or more individuals, other than agencies, instrumentalities, or employees of the federal government. A privacy impact assessment is an analysis of how personally identifiable information is handled to ensure that handling conforms to applicable privacy requirements, determine the privacy risks associated with an information system or activity, and evaluate ways to mitigate privacy risks. A privacy impact assessment is both an analysis and a formal document that details the process and the outcome of the analysis.

Organizations conduct and develop a privacy impact assessment with sufficient clarity and specificity to demonstrate that the organization fully considered privacy and incorporated appropriate privacy protections from the earliest stages of the organization’s activity and throughout the information life cycle. In order to conduct a meaningful privacy impact assessment, the organization’s senior agency official for privacy works closely with program managers, system owners, information technology experts, security officials, counsel, and other relevant organization personnel. Moreover, a privacy impact assessment is not a time-restricted activity that is limited to a particular milestone or stage of the information system or personally identifiable information life cycles. Rather, the privacy analysis continues throughout the system and personally identifiable information life cycles. Accordingly, a privacy impact assessment is a living document that organizations update whenever changes to the information technology, changes to the organization’s practices, or other factors alter the privacy risks associated with the use of such information technology.

To conduct the privacy impact assessment, organizations can use security and privacy risk assessments. Organizations may also use other related processes that may have different names, including privacy threshold analyses. A privacy impact assessment can also serve as notice to the public regarding the organization’s practices with respect to privacy. Although conducting and publishing privacy impact assessments may be required by law, organizations may develop such policies in the absence of applicable laws. For federal agencies, privacy impact assessments may be required by [EGOV](#7b0b9634-741a-4335-b6fa-161228c3a76e) ; agencies should consult with their senior agency official for privacy and legal counsel on this requirement and be aware of the statutory exceptions and OMB guidance relating to the provision. privacy impact assessments are conducted for systems, programs, or other activities before developing or procuring information technology that processes personally identifiable information; privacy impact assessments are conducted for systems, programs, or other activities before initiating a collection of personally identifiable information that will be processed using information technology; privacy impact assessments are conducted for systems, programs, or other activities before initiating a collection of personally identifiable information that includes personally identifiable information permitting the physical or virtual (online) contacting of a specific individual, if identical questions have been posed to, or identical reporting requirements imposed on, ten or more individuals, other than agencies, instrumentalities, or employees of the federal government. Risk assessment policy

security and privacy risk assessment reports

acquisitions documents

system security plan

privacy plan

other relevant documents or records Organizational personnel with assessment and auditing responsibilities

system/network administrators

system developers

program managers

legal counsel

organizational personnel with security and privacy responsibilities Organizational processes for assessments and audits

mechanisms/tools supporting and/or implementing assessments and auditing

**FedRAMP Baseline:** L2 | **Domain:** RA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control RA-9: Identify critical system components and functions by performing a criticality analysis for {{ insert: param, ra-09_odp.01 }} at {{ insert: param, ra-09_odp.02 }}. Not all system components, functions, or services necessarily require significant protections. For example, criticality analysis is a key tenet of supply chain risk management and informs the prioritization of protection activities. The identification of critical system components and functions considers applicable laws, executive orders, regulations, directives, policies, standards, system functionality requirements, system and component interfaces, and system and component dependencies. Systems engineers conduct a functional decomposition of a system to identify mission-critical functions and components. The functional decomposition includes the identification of organizational missions supported by the system, decomposition into the specific functions to perform those missions, and traceability to the hardware, software, and firmware components that implement those functions, including when the functions are shared by many components within and external to the system.

The operational environment of a system or a system component may impact the criticality, including the connections to and dependencies on cyber-physical systems, devices, system-of-systems, and outsourced IT services. System components that allow unmediated access to critical system components or functions are considered critical due to the inherent vulnerabilities that such components create. Component and function criticality are assessed in terms of the impact of a component or function failure on the organizational missions that are supported by the system that contains the components and functions.

Criticality analysis is performed when an architecture or design is being developed, modified, or upgraded. If such analysis is performed early in the system development life cycle, organizations may be able to modify the system design to reduce the critical nature of these components and functions, such as by adding redundancy or alternate paths into the system design. Criticality analysis can also influence the protection measures required by development contractors. In addition to criticality analysis for systems, system components, and system services, criticality analysis of information is an important consideration. Such analysis is conducted as part of security categorization in [RA-2](#ra-2). critical system components and functions are identified by performing a criticality analysis for {{ insert: param, ra-09_odp.01 }} at {{ insert: param, ra-09_odp.02 }}. Risk assessment policy

assessment reports

criticality analysis/finalized criticality for each component/subcomponent

audit records/event logs

analysis reports

system security plan

other relevant documents or records Organizational personnel with assessment and auditing responsibilities

organizational personnel with criticality analysis responsibilities

system/network administrators

organizational personnel with security responsibilities Organizational processes for assessments and audits

mechanisms/tools supporting and/or implementing assessments and auditing

**FedRAMP Baseline:** L2 | **Domain:** RA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control RA-10: Establish and maintain a cyber threat hunting capability to: Search for indicators of compromise in organizational systems; and Detect, track, and disrupt threats that evade existing controls; and Employ the threat hunting capability {{ insert: param, ra-10_odp }}. Threat hunting is an active means of cyber defense in contrast to traditional protection measures, such as firewalls, intrusion detection and prevention systems, quarantining malicious code in sandboxes, and Security Information and Event Management technologies and systems. Cyber threat hunting involves proactively searching organizational systems, networks, and infrastructure for advanced threats. The objective is to track and disrupt cyber adversaries as early as possible in the attack sequence and to measurably improve the speed and accuracy of organizational responses. Indications of compromise include unusual network traffic, unusual file changes, and the presence of malicious code. Threat hunting teams leverage existing threat intelligence and may create new threat intelligence, which is shared with peer organizations, Information Sharing and Analysis Organizations (ISAO), Information Sharing and Analysis Centers (ISAC), and relevant government departments and agencies. a cyber threat capability is established and maintained to search for indicators of compromise in organizational systems; a cyber threat capability is established and maintained to detect, track, and disrupt threats that evade existing controls; the threat hunting capability is employed {{ insert: param, ra-10_odp }}. Risk assessment policy

assessment reports

audit records/event logs

threat hunting capability

system security plan

other relevant documents or records Organizational personnel with threat hunting responsibilities

system/network administrators

organizational personnel with security responsibilities Organizational processes for assessments and audits

mechanisms/tools supporting and/or implementing threat hunting capabilities

**FedRAMP Baseline:** L2 | **Domain:** RA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### SA — System and Services Acquisition (Manual Controls)

##### Control SA-1: Develop, document, and disseminate to {{ insert: param, sa-1_prm_1 }}: {{ insert: param, sa-01_odp.03 }} system and services acquisition policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the system and services acquisition policy and the associated system and services acquisition controls; Designate an {{ insert: param, sa-01_odp.04 }} to manage the development, documentation, and dissemination of the system and services acquisition policy and procedures; and Review and update the current system and services acquisition: Policy {{ insert: param, sa-01_odp.05 }} and following {{ insert: param, sa-01_odp.06 }} ; and Procedures {{ insert: param, sa-01_odp.07 }} and following {{ insert: param, sa-01_odp.08 }}. System and services acquisition policy and procedures address the controls in the SA family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of system and services acquisition policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to system and services acquisition policy and procedures include assessment or audit findings, security incidents or breaches, or changes in laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. a system and services acquisition policy is developed and documented; the system and services acquisition policy is disseminated to {{ insert: param, sa-01_odp.01 }}; system and services acquisition procedures to facilitate the implementation of the system and services acquisition policy and associated system and services acquisition controls are developed and documented; the system and services acquisition procedures are disseminated to {{ insert: param, sa-01_odp.02 }}; the {{ insert: param, sa-01_odp.03 }} system and services acquisition policy addresses purpose; the {{ insert: param, sa-01_odp.03 }} system and services acquisition policy addresses scope; the {{ insert: param, sa-01_odp.03 }} system and services acquisition policy addresses roles; the {{ insert: param, sa-01_odp.03 }} system and services acquisition policy addresses responsibilities; the {{ insert: param, sa-01_odp.03 }} system and services acquisition policy addresses management commitment; the {{ insert: param, sa-01_odp.03 }} system and services acquisition policy addresses coordination among organizational entities; the {{ insert: param, sa-01_odp.03 }} system and services acquisition policy addresses compliance; the {{ insert: param, sa-01_odp.03 }} system and services acquisition policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, sa-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the system and services acquisition policy and procedures; the system and services acquisition policy is reviewed and updated {{ insert: param, sa-01_odp.05 }}; the current system and services acquisition policy is reviewed and updated following {{ insert: param, sa-01_odp.06 }}; the current system and services acquisition procedures are reviewed and updated {{ insert: param, sa-01_odp.07 }}; the current system and services acquisition procedures are reviewed and updated following {{ insert: param, sa-01_odp.08 }}. System and services acquisition policy

system and services acquisition procedures

supply chain risk management policy

supply chain risk management procedures

supply chain risk management plan

system security plan

privacy plan

other relevant documents or records Organizational personnel with system and services acquisition responsibilities

organizational personnel with information security and privacy responsibilities

organizational personnel with supply chain risk management responsibilities

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-2: Determine the high-level information security and privacy requirements for the system or system service in mission and business process planning; Determine, document, and allocate the resources required to protect the system or system service as part of the organizational capital planning and investment control process; and Establish a discrete line item for information security and privacy in organizational programming and budgeting documentation. Resource allocation for information security and privacy includes funding for system and services acquisition, sustainment, and supply chain-related risks throughout the system development life cycle. the high-level information security requirements for the system or system service are determined in mission and business process planning; the high-level privacy requirements for the system or system service are determined in mission and business process planning; the resources required to protect the system or system service are determined and documented as part of the organizational capital planning and investment control process; the resources required to protect the system or system service are allocated as part of the organizational capital planning and investment control process; a discrete line item for information security is established in organizational programming and budgeting documentation; a discrete line item for privacy is established in organizational programming and budgeting documentation. System and services acquisition policy

system and services acquisition procedures

system and services acquisition strategy and plans

procedures addressing the allocation of resources to information security and privacy requirements

procedures addressing capital planning and investment control

organizational programming and budgeting documentation

system security plan

privacy plan

supply chain risk management policy

other relevant documents or records Organizational personnel with capital planning, investment control, organizational programming, and budgeting responsibilities

organizational personnel with information security and privacy responsibilities

organizational personnel with supply chain risk management responsibilities Organizational processes for determining information security and privacy requirements

organizational processes for capital planning, programming, and budgeting

mechanisms supporting and/or implementing organizational capital planning, programming, and budgeting

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-4: Include the following requirements, descriptions, and criteria, explicitly or by reference, using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service: Security and privacy functional requirements; Strength of mechanism requirements; Security and privacy assurance requirements; Controls needed to satisfy the security and privacy requirements. Security and privacy documentation requirements; Requirements for protecting security and privacy documentation; Description of the system development environment and environment in which the system is intended to operate; Allocation of responsibility or identification of parties responsible for information security, privacy, and supply chain risk management; and Acceptance criteria. Security and privacy functional requirements are typically derived from the high-level security and privacy requirements described in [SA-2](#sa-2) . The derived requirements include security and privacy capabilities, functions, and mechanisms. Strength requirements associated with such capabilities, functions, and mechanisms include degree of correctness, completeness, resistance to tampering or bypass, and resistance to direct attack. Assurance requirements include development processes, procedures, and methodologies as well as the evidence from development and assessment activities that provide grounds for confidence that the required functionality is implemented and possesses the required strength of mechanism. [SP 800-160-1](#e3cc0520-a366-4fc9-abc2-5272db7e3564) describes the process of requirements engineering as part of the system development life cycle.

Controls can be viewed as descriptions of the safeguards and protection capabilities appropriate for achieving the particular security and privacy objectives of the organization and for reflecting the security and privacy requirements of stakeholders. Controls are selected and implemented in order to satisfy system requirements and include developer and organizational responsibilities. Controls can include technical, administrative, and physical aspects. In some cases, the selection and implementation of a control may necessitate additional specification by the organization in the form of derived requirements or instantiated control parameter values. The derived requirements and control parameter values may be necessary to provide the appropriate level of implementation detail for controls within the system development life cycle.

Security and privacy documentation requirements address all stages of the system development life cycle. Documentation provides user and administrator guidance for the implementation and operation of controls. The level of detail required in such documentation is based on the security categorization or classification level of the system and the degree to which organizations depend on the capabilities, functions, or mechanisms to meet risk response expectations. Requirements can include mandated configuration settings that specify allowed functions, ports, protocols, and services. Acceptance criteria for systems, system components, and system services are defined in the same manner as the criteria for any organizational acquisition or procurement.

Organizations can determine other requirements that support security and operations, to include responsibilities for the organization and developer, and notification and timing requirements for support, maintenance and updates. security functional requirements, descriptions, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service; privacy functional requirements, descriptions, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service; strength of mechanism requirements, descriptions, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service; security assurance requirements, descriptions, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service; privacy assurance requirements, descriptions, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service; controls needed to satisfy the security requirements, descriptions, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service; controls needed to satisfy the privacy requirements, descriptions, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service; security documentation requirements, descriptions, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service; privacy documentation requirements, descriptions, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service; requirements for protecting security documentation, descriptions, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service; requirements for protecting privacy documentation, descriptions, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service; the description of the system development environment and environment in which the system is intended to operate, requirements, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service; the allocation of responsibility or identification of parties responsible for information security requirements, descriptions, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service; the allocation of responsibility or identification of parties responsible for privacy requirements, descriptions, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }}; the allocation of responsibility or identification of parties responsible for supply chain risk management requirements, descriptions, and criteria are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }}; acceptance criteria requirements and descriptions are included explicitly or by reference using {{ insert: param, sa-04_odp.01 }} in the acquisition contract for the system, system component, or system service. System and services acquisition policy

system and services acquisition procedures

procedures addressing the integration of information security and privacy and supply chain risk management into the acquisition process

configuration management plan

acquisition contracts for the system, system component, or system service

system design documentation

system security plan

supply chain risk management plan

privacy plan

other relevant documents or records Organizational personnel with acquisition/contracting responsibilities

organizational personnel with information security and privacy responsibilities

system/network administrators

organizational personnel with supply chain risk management responsibilities Organizational processes for determining system security and privacy functional, strength, and assurance requirements

organizational processes for developing acquisition contracts

mechanisms supporting and/or implementing acquisitions and the inclusion of security and privacy requirements in contracts

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-5: Obtain or develop administrator documentation for the system, system component, or system service that describes: Secure configuration, installation, and operation of the system, component, or service; Effective use and maintenance of security and privacy functions and mechanisms; and Known vulnerabilities regarding configuration and use of administrative or privileged functions; Obtain or develop user documentation for the system, system component, or system service that describes: User-accessible security and privacy functions and mechanisms and how to effectively use those functions and mechanisms; Methods for user interaction, which enables individuals to use the system, component, or service in a more secure manner and protect individual privacy; and User responsibilities in maintaining the security of the system, component, or service and privacy of individuals; Document attempts to obtain system, system component, or system service documentation when such documentation is either unavailable or nonexistent and take {{ insert: param, sa-05_odp.01 }} in response; and Distribute documentation to {{ insert: param, sa-05_odp.02 }}. System artifacts and documentation created by the developer helps organizational personnel understand the implementation and operation of controls. Organizations consider establishing specific measures to determine the quality and completeness of the content provided. System documentation may be used to delineate roles, responsibilities and expectations of the developer and organization, support the management of supply chain risk, incident response, flaw remediation, and other functions. Personnel or roles that require documentation include system owners, system security officers, and system administrators. Attempts to obtain documentation include contacting manufacturers or suppliers and conducting web-based searches. The inability to obtain documentation may occur due to the age of the system or component or the lack of support from developers and contractors. When documentation cannot be obtained, organizations may need to recreate the documentation if it is essential to the implementation or operation of the controls. The protection provided for the documentation is commensurate with the security category or classification of the system. Documentation that addresses system vulnerabilities may require an increased level of protection. Secure operation of the system includes initially starting the system and resuming secure system operation after a lapse in system operation. An example of least privilege in software development is minimizing the functions that operate with elevated privileges (e.g., limiting the tools and functionality that operate in kernel mode) administrator documentation for the system, system component, or system service that describes the secure configuration of the system, component, or service is obtained or developed; administrator documentation for the system, system component, or system service that describes the secure installation of the system, component, or service is obtained or developed; administrator documentation for the system, system component, or system service that describes the secure operation of the system, component, or service is obtained or developed; administrator documentation for the system, system component, or system service that describes the effective use of security functions and mechanisms is obtained or developed; administrator documentation for the system, system component, or system service that describes the effective maintenance of security functions and mechanisms is obtained or developed; administrator documentation for the system, system component, or system service that describes the effective use of privacy functions and mechanisms is obtained or developed; administrator documentation for the system, system component, or system service that describes the effective maintenance of privacy functions and mechanisms is obtained or developed; administrator documentation for the system, system component, or system service that describes known vulnerabilities regarding the configuration of administrative or privileged functions is obtained or developed; administrator documentation for the system, system component, or system service that describes known vulnerabilities regarding the use of administrative or privileged functions is obtained or developed; user documentation for the system, system component, or system service that describes user-accessible security functions and mechanisms is obtained or developed; user documentation for the system, system component, or system service that describes how to effectively use those (user-accessible security) functions and mechanisms is obtained or developed; user documentation for the system, system component, or system service that describes user-accessible privacy functions and mechanisms is obtained or developed; user documentation for the system, system component, or system service that describes how to effectively use those (user-accessible privacy) functions and mechanisms is obtained or developed; user documentation for the system, system component, or system service that describes methods for user interaction, which enable individuals to use the system, component, or service in a more secure manner is obtained or developed; user documentation for the system, system component, or system service that describes methods for user interaction, which enable individuals to use the system, component, or service to protect individual privacy is obtained or developed; user documentation for the system, system component, or system service that describes user responsibilities for maintaining the security of the system, component, or service is obtained or developed; user documentation for the system, system component, or system service that describes user responsibilities for maintaining the privacy of individuals is obtained or developed; attempts to obtain system, system component, or system service documentation when such documentation is either unavailable or nonexistent is documented; after attempts to obtain system, system component, or system service documentation when such documentation is either unavailable or nonexistent, {{ insert: param, sa-05_odp.01 }} are taken in response; documentation is distributed to {{ insert: param, sa-05_odp.02 }}. System and services acquisition policy

system and services acquisition procedures

procedures addressing system documentation

system documentation, including administrator and user guides

system design documentation

records documenting attempts to obtain unavailable or nonexistent system documentation

list of actions to be taken in response to documented attempts to obtain system, system component, or system service documentation

risk management strategy documentation

system security plan

privacy plan

privacy impact assessment

privacy risk assessment documentation

other relevant documents or records Organizational personnel with acquisition/contracting responsibilities

organizational personnel with information security and privacy responsibilities

system administrators

organizational personnel responsible for operating, using, and/or maintaining the system

system developers Organizational processes for obtaining, protecting, and distributing system administrator and user documentation

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-6: 

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-7: 

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-8: Apply the following systems security and privacy engineering principles in the specification, design, development, implementation, and modification of the system and system components: {{ insert: param, sa-8_prm_1 }}. Systems security and privacy engineering principles are closely related to and implemented throughout the system development life cycle (see [SA-3](#sa-3) ). Organizations can apply systems security and privacy engineering principles to new systems under development or to systems undergoing upgrades. For existing systems, organizations apply systems security and privacy engineering principles to system upgrades and modifications to the extent feasible, given the current state of hardware, software, and firmware components within those systems.

The application of systems security and privacy engineering principles helps organizations develop trustworthy, secure, and resilient systems and reduces the susceptibility to disruptions, hazards, threats, and the creation of privacy problems for individuals. Examples of system security engineering principles include: developing layered protections; establishing security and privacy policies, architecture, and controls as the foundation for design and development; incorporating security and privacy requirements into the system development life cycle; delineating physical and logical security boundaries; ensuring that developers are trained on how to build secure software; tailoring controls to meet organizational needs; and performing threat modeling to identify use cases, threat agents, attack vectors and patterns, design patterns, and compensating controls needed to mitigate risk.

Organizations that apply systems security and privacy engineering concepts and principles can facilitate the development of trustworthy, secure systems, system components, and system services; reduce risk to acceptable levels; and make informed risk management decisions. System security engineering principles can also be used to protect against certain supply chain risks, including incorporating tamper-resistant hardware into a design. {{ insert: param, sa-08_odp.01 }} are applied in the specification of the system and system components; {{ insert: param, sa-08_odp.01 }} are applied in the design of the system and system components; {{ insert: param, sa-08_odp.01 }} are applied in the development of the system and system components; {{ insert: param, sa-08_odp.01 }} are applied in the implementation of the system and system components; {{ insert: param, sa-08_odp.01 }} are applied in the modification of the system and system components; {{ insert: param, sa-08_odp.02 }} are applied in the specification of the system and system components; {{ insert: param, sa-08_odp.02 }} are applied in the design of the system and system components; {{ insert: param, sa-08_odp.02 }} are applied in the development of the system and system components; {{ insert: param, sa-08_odp.02 }} are applied in the implementation of the system and system components; {{ insert: param, sa-08_odp.02 }} are applied in the modification of the system and system components. System and services acquisition policy

system and services acquisition procedures

assessment and authorization procedures

procedures addressing security and privacy engineering principles used in the specification, design, development, implementation, and modification of the system

system design documentation

security and privacy requirements and specifications for the system

system security plan

privacy plan

privacy impact assessment

privacy risk assessment documentation

other relevant documents or records Organizational personnel with acquisition/contracting responsibilities

organizational personnel with information security and privacy responsibilities

organizational personnel with system specification, design, development, implementation, and modification responsibilities

system developers Organizational processes for applying security and privacy engineering principles in system specification, design, development, implementation, and modification

mechanisms supporting the application of security and privacy engineering principles in system specification, design, development, implementation, and modification

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-9: Require that providers of external system services comply with organizational security and privacy requirements and employ the following controls: {{ insert: param, sa-09_odp.01 }}; Define and document organizational oversight and user roles and responsibilities with regard to external system services; and Employ the following processes, methods, and techniques to monitor control compliance by external service providers on an ongoing basis: {{ insert: param, sa-09_odp.02 }}. External system services are provided by an external provider, and the organization has no direct control over the implementation of the required controls or the assessment of control effectiveness. Organizations establish relationships with external service providers in a variety of ways, including through business partnerships, contracts, interagency agreements, lines of business arrangements, licensing agreements, joint ventures, and supply chain exchanges. The responsibility for managing risks from the use of external system services remains with authorizing officials. For services external to organizations, a chain of trust requires that organizations establish and retain a certain level of confidence that each provider in the consumer-provider relationship provides adequate protection for the services rendered. The extent and nature of this chain of trust vary based on relationships between organizations and the external providers. Organizations document the basis for the trust relationships so that the relationships can be monitored. External system services documentation includes government, service providers, end user security roles and responsibilities, and service-level agreements. Service-level agreements define the expectations of performance for implemented controls, describe measurable outcomes, and identify remedies and response requirements for identified instances of noncompliance. providers of external system services comply with organizational security requirements; providers of external system services comply with organizational privacy requirements; providers of external system services employ {{ insert: param, sa-09_odp.01 }}; organizational oversight with regard to external system services are defined and documented; user roles and responsibilities with regard to external system services are defined and documented; {{ insert: param, sa-09_odp.02 }} are employed to monitor control compliance by external service providers on an ongoing basis. System and services acquisition policy

system and services acquisition procedures

procedures addressing methods and techniques for monitoring control compliance by external service providers of system services

acquisition documentation

contracts

service level agreements

interagency agreements

licensing agreements

list of organizational security and privacy requirements for external provider services

control assessment results or reports from external providers of system services

system security plan

privacy plan

supply chain risk management plan

other relevant documents or records Organizational personnel with acquisition responsibilities

external providers of system services

organizational personnel with information security and privacy responsibilities

organizational personnel with supply chain risk management responsibilities Organizational processes for monitoring security and privacy control compliance by external service providers on an ongoing basis

mechanisms for monitoring security and privacy control compliance by external service providers on an ongoing basis

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-12: 

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-13: 

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-14: 

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-15: Require the developer of the system, system component, or system service to follow a documented development process that: Explicitly addresses security and privacy requirements; Identifies the standards and tools used in the development process; Documents the specific tool options and tool configurations used in the development process; and Documents, manages, and ensures the integrity of changes to the process and/or tools used in development; and Review the development process, standards, tools, tool options, and tool configurations {{ insert: param, sa-15_odp.01 }} to determine if the process, standards, tools, tool options and tool configurations selected and employed can satisfy the following security and privacy requirements: {{ insert: param, sa-15_prm_2 }}. Development tools include programming languages and computer-aided design systems. Reviews of development processes include the use of maturity models to determine the potential effectiveness of such processes. Maintaining the integrity of changes to tools and processes facilitates effective supply chain risk assessment and mitigation. Such integrity requires configuration control throughout the system development life cycle to track authorized changes and prevent unauthorized changes. the developer of the system, system component, or system service is required to follow a documented development process that explicitly addresses security requirements; the developer of the system, system component, or system service is required to follow a documented development process that explicitly addresses privacy requirements; the developer of the system, system component, or system service is required to follow a documented development process that identifies the standards used in the development process; the developer of the system, system component, or system service is required to follow a documented development process that identifies the tools used in the development process; the developer of the system, system component, or system service is required to follow a documented development process that documents the specific tool used in the development process; the developer of the system, system component, or system service is required to follow a documented development process that documents the specific tool configurations used in the development process; the developer of the system, system component, or system service is required to follow a documented development process that documents, manages, and ensures the integrity of changes to the process and/or tools used in development; the developer of the system, system component, or system service is required to follow a documented development process in which the development process, standards, tools, tool options, and tool configurations are reviewed {{ insert: param, sa-15_odp.01 }} to determine that the process, standards, tools, tool options, and tool configurations selected and employed satisfy {{ insert: param, sa-15_odp.02 }}; the developer of the system, system component, or system service is required to follow a documented development process in which the development process, standards, tools, tool options, and tool configurations are reviewed {{ insert: param, sa-15_odp.01 }} to determine that the process, standards, tools, tool options, and tool configurations selected and employed satisfy {{ insert: param, sa-15_odp.03 }}. System and services acquisition policy

system and services acquisition procedures

procedures addressing development process, standards, and tools

procedures addressing the integration of security and privacy requirements during the development process

solicitation documentation

acquisition documentation

critical component inventory documentation

service level agreements

acquisition contracts for the system, system component, or system service

system developer documentation listing tool options/configuration guides

configuration management policy

configuration management records

documentation of development process reviews using maturity models

change control records

configuration control records

documented reviews of the development process, standards, tools, and tool options/configurations

system security plan

privacy plan

privacy impact assessment

privacy risk assessment documentation

other relevant documents or records Organizational personnel with system and service acquisition responsibilities

organizational personnel with information security and privacy responsibilities

system developer

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-16: Require the developer of the system, system component, or system service to provide the following training on the correct use and operation of the implemented security and privacy functions, controls, and/or mechanisms: {{ insert: param, sa-16_odp }}. Developer-provided training applies to external and internal (in-house) developers. Training personnel is essential to ensuring the effectiveness of the controls implemented within organizational systems. Types of training include web-based and computer-based training, classroom-style training, and hands-on training (including micro-training). Organizations can also request training materials from developers to conduct in-house training or offer self-training to organizational personnel. Organizations determine the type of training necessary and may require different types of training for different security and privacy functions, controls, and mechanisms. the developer of the system, system component, or system service is required to provide {{ insert: param, sa-16_odp }} on the correct use and operation of the implemented security and privacy functions, controls, and/or mechanisms. System and services acquisition policy

system and services acquisition procedures

procedures addressing developer-provided training

solicitation documentation

acquisition documentation

service level agreements

acquisition contracts for the system, system component, or system service

organizational security and privacy training policy

developer-provided training materials

training records

system security plan

privacy plan

privacy impact assessment

privacy risk assessment documentation

other relevant documents or records Organizational personnel with system and service acquisition responsibilities

organizational personnel with information security and privacy responsibilities

system developer

external or internal (in-house) developers with training responsibilities for the system, system component, or information system service

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-17: Require the developer of the system, system component, or system service to produce a design specification and security and privacy architecture that: Is consistent with the organization’s security and privacy architecture that is an integral part the organization’s enterprise architecture; Accurately and completely describes the required security and privacy functionality, and the allocation of controls among physical and logical components; and Expresses how individual security and privacy functions, mechanisms, and services work together to provide required security and privacy capabilities and a unified approach to protection. Developer security and privacy architecture and design are directed at external developers, although they could also be applied to internal (in-house) development. In contrast, [PL-8](#pl-8) is directed at internal developers to ensure that organizations develop a security and privacy architecture that is integrated with the enterprise architecture. The distinction between SA-17 and [PL-8](#pl-8) is especially important when organizations outsource the development of systems, system components, or system services and when there is a requirement to demonstrate consistency with the enterprise architecture and security and privacy architecture of the organization. [ISO 15408-2](#87087451-2af5-43d4-88c1-d66ad850f614), [ISO 15408-3](#4452efc0-e79e-47b8-aa30-b54f3ef61c2f) , and [SP 800-160-1](#e3cc0520-a366-4fc9-abc2-5272db7e3564) provide information on security architecture and design, including formal policy models, security-relevant components, formal and informal correspondence, conceptually simple design, and structuring for least privilege and testing. the developer of the system, system component, or system service is required to produce a design specification and security architecture that are consistent with the organization’s security architecture, which is an integral part the organization’s enterprise architecture; the developer of the system, system component, or system service is required to produce a design specification and privacy architecture that are consistent with the organization’s privacy architecture, which is an integral part the organization’s enterprise architecture; the developer of the system, system component, or system service is required to produce a design specification and security architecture that accurately and completely describe the required security functionality and the allocation of controls among physical and logical components; the developer of the system, system component, or system service is required to produce a design specification and privacy architecture that accurately and completely describe the required privacy functionality and the allocation of controls among physical and logical components; the developer of the system, system component, or system service is required to produce a design specification and security architecture that express how individual security functions, mechanisms, and services work together to provide required security capabilities and a unified approach to protection; the developer of the system, system component, or system service is required to produce a design specification and privacy architecture that express how individual privacy functions, mechanisms, and services work together to provide required privacy capabilities and a unified approach to protection. System and services acquisition policy

system and services acquisition procedures

enterprise architecture policy

enterprise architecture documentation

procedures addressing developer security and privacy architecture and design specifications for the system

solicitation documentation

acquisition documentation

service level agreements

acquisition contracts for the system, system component, or system service

system design documentation

information system configuration settings and associated documentation

system security plan

privacy plan

other relevant documents or records Organizational personnel with acquisition responsibilities

organizational personnel with information security and privacy responsibilities

system developer

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-18: 

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-19: 

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-20: Reimplement or custom develop the following critical system components: {{ insert: param, sa-20_odp }}. Organizations determine that certain system components likely cannot be trusted due to specific threats to and vulnerabilities in those components for which there are no viable security controls to adequately mitigate risk. Reimplementation or custom development of such components may satisfy requirements for higher assurance and is carried out by initiating changes to system components (including hardware, software, and firmware) such that the standard attacks by adversaries are less likely to succeed. In situations where no alternative sourcing is available and organizations choose not to reimplement or custom develop critical system components, additional controls can be employed. Controls include enhanced auditing, restrictions on source code and system utility access, and protection from deletion of system and application files. {{ insert: param, sa-20_odp }} are reimplemented or custom-developed. Supply chain risk management plan

system and services acquisition policy

procedures addressing the customized development of critical system components

system design documentation

system configuration settings and associated documentation

system development life cycle documentation addressing the custom development of critical system components

configuration management records

system audit records

system security plan

other relevant documents or records Organizational personnel with system and service acquisition responsibilities

organizational personnel with information security responsibilities

organizational personnel with responsibility for the reimplementation or customized development of critical system components Organizational processes for the reimplementation or customized development of critical system components

mechanisms supporting and/or implementing the reimplementation or customized development of critical system components

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-21: Require that the developer of {{ insert: param, sa-21_odp.01 }}: Has appropriate access authorizations as determined by assigned {{ insert: param, sa-21_odp.02 }} ; and Satisfies the following additional personnel screening criteria: {{ insert: param, sa-21_odp.03 }}. Developer screening is directed at external developers. Internal developer screening is addressed by [PS-3](#ps-3) . Because the system, system component, or system service may be used in critical activities essential to the national or economic security interests of the United States, organizations have a strong interest in ensuring that developers are trustworthy. The degree of trust required of developers may need to be consistent with that of the individuals who access the systems, system components, or system services once deployed. Authorization and personnel screening criteria include clearances, background checks, citizenship, and nationality. Developer trustworthiness may also include a review and analysis of company ownership and relationships that the company has with entities that may potentially affect the quality and reliability of the systems, components, or services being developed. Satisfying the required access authorizations and personnel screening criteria includes providing a list of all individuals who are authorized to perform development activities on the selected system, system component, or system service so that organizations can validate that the developer has satisfied the authorization and screening requirements. the developer of {{ insert: param, sa-21_odp.01 }} is required to have appropriate access authorizations as determined by assigned {{ insert: param, sa-21_odp.02 }}; the developer of {{ insert: param, sa-21_odp.01 }} is required to satisfy {{ insert: param, sa-21_odp.03 }}. System and services acquisition policy

personnel security policy and procedures

procedures addressing personnel screening

system design documentation

acquisition documentation

service level agreements

acquisition contracts for developer services

system configuration settings and associated documentation

list of appropriate access authorizations required by the developers of the system

personnel screening criteria and associated documentation

system security plan

supply chain risk management plan

other relevant documents or records Organizational personnel with system and service acquisition responsibilities

organizational personnel with information security responsibilities

organizational personnel responsible for developer screening Organizational processes for developer screening

mechanisms supporting developer screening

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-23: Employ {{ insert: param, sa-23_odp.01 }} on {{ insert: param, sa-23_odp.02 }} supporting mission essential services or functions to increase the trustworthiness in those systems or components. It is often necessary for a system or system component that supports mission-essential services or functions to be enhanced to maximize the trustworthiness of the resource. Sometimes this enhancement is done at the design level. In other instances, it is done post-design, either through modifications of the system in question or by augmenting the system with additional components. For example, supplemental authentication or non-repudiation functions may be added to the system to enhance the identity of critical resources to other resources that depend on the organization-defined resources. {{ insert: param, sa-23_odp.01 }} is employed on {{ insert: param, sa-23_odp.02 }} supporting essential services or functions to increase the trustworthiness in those systems or components. System and services acquisition policy

procedures addressing design modification, augmentation, or reconfiguration of systems or system components

documented evidence of design modification, augmentation, or reconfiguration

system security plan

supply chain risk management plan

other relevant documents or records Organizational personnel with system and service acquisition responsibilities

organizational personnel with information security responsibilities

organizational personnel with the responsibility for security architecture

organizational personnel responsible for configuration management Organizational processes for the modification of design, augmentation, or reconfiguration of systems or system components

mechanisms supporting and/or implementing design modification, augmentation, or reconfiguration of systems or system components

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SA-24: Design organizational systems, system components, or system services to achieve cyber resiliency by: Defining the following cyber resiliency goals: {{ insert: param, sa-24_odp.01 }}. Defining the following cyber resiliency objectives: {{ insert: param, sa-24_odp.02 }}. Defining the following cyber resiliency techniques: {{ insert: param, sa-24_odp.03 }}. Defining the following cyber resiliency implementation approaches: {{ insert: param, sa-24_odp.04 }}. Defining the following cyber resiliency design principles: {{ insert: param, sa-24_odp.05 }}. Implement the selected cyber resiliency goals, objectives, techniques, implementation approaches, and design principles as part of an organizational risk management process or systems security engineering process. Cyber resiliency is critical to ensuring the survivability of mission critical systems and high value assets. Cyber resiliency focuses on limiting the damage from adversity or the conditions that can cause a loss of assets. Damage can affect: (1) organizations (e.g., loss of reputation, increased existential risk); (2) missions or business functions (e.g., decreased capability to complete current missions and to accomplish future missions); (3) security (e.g., decreased capability to achieve security objectives or to prevent, detect, and respond to cyber incidents); (4) systems (e.g., unauthorized use of system resources or decreased capability to meet system requirements); or (5) specific system elements (e.g., physical destruction; corruption, modification, or fabrication of information).

Cyber resiliency goals are intended to help organizations maintain a state of informed preparedness for adversity, continue essential mission or business functions despite adversity, restore mission or business functions during and after adversity, and modify mission or business functions and their supporting capabilities in response to predicted changes in technical, operational, or threat environments.

NIST SP 800-160, Volume 2 provides additional information on the Cyber Resiliency Engineering Framework to include detailed descriptions of cyber resiliency goals, objectives, techniques, implementation approaches, and design principles. NIST SP 800-160, Vol 1 provides additional information on achieving cyber resiliency as an emergent property of an engineered system. Determine if: organizational systems, system components, or system services achieve cyber resiliency through {{ insert: param, sa-24_odp.01 }}; organizational systems, system components, or system services achieve cyber resiliency through {{ insert: param, sa-24_odp.02 }}; organizational systems, system components, or system services achieve cyber resiliency through {{ insert: param, sa-24_odp.03 }}; organizational systems, system components, or system services achieve cyber resiliency through {{ insert: param, sa-24_odp.04 }}; organizational systems, system components, or system services achieve cyber resiliency through {{ insert: param, sa-24_odp.05 }}; selected cyber resiliency goals are implemented as part of an organizational risk management process of systems security engineering process; selected cyber resiliency objectives are implemented as part of an organizational risk management process of systems security engineering process; selected cyber resiliency techniques are implemented as part of an organizational risk management process of systems security engineering process; selected cyber resiliency implementation approaches are implemented as part of an organizational risk management process of systems security engineering process; selected cyber resiliency design principles are implemented as part of an organizational risk management process of systems security engineering process. System and services acquisition policy;

system and services acquisition procedures;

assessment and authorization procedures; 

procedures addressing cyber resiliency goals, objectives, techniques, implementation approaches, and design principles used in the specification, design, development, implementation, and modification of the system; 

system design documentation; 

security and privacy requirements and specifications for the system; 

system security plan;

privacy plan; 

privacy impact assessment; 

privacy risk assessment documentation. Organizational personnel with acquisition/contracting responsibilities; 

organizational personnel with information security and privacy responsibilities; 

organizational personnel with system specification, design, development, implementation, and modification responsibilities; 

system developers. Organizational processes for applying cyber resiliency principles in system specification, design, development, implementation, and modification;

mechanisms supporting the application of cyber resiliency principles in system specification, design, development, implementation, and modification.

**FedRAMP Baseline:** L2 | **Domain:** SA

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### SC — System and Communications Protection (Manual Controls)

##### Control SC-1: Develop, document, and disseminate to {{ insert: param, sc-1_prm_1 }}: {{ insert: param, sc-01_odp.03 }} system and communications protection policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the system and communications protection policy and the associated system and communications protection controls; Designate an {{ insert: param, sc-01_odp.04 }} to manage the development, documentation, and dissemination of the system and communications protection policy and procedures; and Review and update the current system and communications protection: Policy {{ insert: param, sc-01_odp.05 }} and following {{ insert: param, sc-01_odp.06 }} ; and Procedures {{ insert: param, sc-01_odp.07 }} and following {{ insert: param, sc-01_odp.08 }}. System and communications protection policy and procedures address the controls in the SC family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of system and communications protection policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to system and communications protection policy and procedures include assessment or audit findings, security incidents or breaches, or changes in applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. a system and communications protection policy is developed and documented; the system and communications protection policy is disseminated to {{ insert: param, sc-01_odp.01 }}; system and communications protection procedures to facilitate the implementation of the system and communications protection policy and associated system and communications protection controls are developed and documented; the system and communications protection procedures are disseminated to {{ insert: param, sc-01_odp.02 }}; the {{ insert: param, sc-01_odp.03 }} system and communications protection policy addresses purpose; the {{ insert: param, sc-01_odp.03 }} system and communications protection policy addresses scope; the {{ insert: param, sc-01_odp.03 }} system and communications protection policy addresses roles; the {{ insert: param, sc-01_odp.03 }} system and communications protection policy addresses responsibilities; the {{ insert: param, sc-01_odp.03 }} system and communications protection policy addresses management commitment; the {{ insert: param, sc-01_odp.03 }} system and communications protection policy addresses coordination among organizational entities; the {{ insert: param, sc-01_odp.03 }} system and communications protection policy addresses compliance; the {{ insert: param, sc-01_odp.03 }} system and communications protection policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, sc-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the system and communications protection policy and procedures; the current system and communications protection policy is reviewed and updated {{ insert: param, sc-01_odp.05 }}; the current system and communications protection policy is reviewed and updated following {{ insert: param, sc-01_odp.06 }}; the current system and communications protection procedures are reviewed and updated {{ insert: param, sc-01_odp.07 }}; the current system and communications protection procedures are reviewed and updated following {{ insert: param, sc-01_odp.08 }}. System and communications protection policy

system and communications protection procedures

system security plan

privacy plan

risk management strategy documentation

audit findings

other relevant documents or records Organizational personnel with system and communications protection responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-2: Separate user functionality, including user interface services, from system management functionality. System management functionality includes functions that are necessary to administer databases, network components, workstations, or servers. These functions typically require privileged user access. The separation of user functions from system management functions is physical or logical. Organizations may separate system management functions from user functions by using different computers, instances of operating systems, central processing units, or network addresses; by employing virtualization techniques; or some combination of these or other methods. Separation of system management functions from user functions includes web administrative interfaces that employ separate authentication methods for users of any other system resources. Separation of system and user functions may include isolating administrative interfaces on different domains and with additional access controls. The separation of system and user functionality can be achieved by applying the systems security engineering design principles in [SA-8](#sa-8) , including [SA-8(1)](#sa-8.1), [SA-8(3)](#sa-8.3), [SA-8(4)](#sa-8.4), [SA-8(10)](#sa-8.10), [SA-8(12)](#sa-8.12), [SA-8(13)](#sa-8.13), [SA-8(14)](#sa-8.14) , and [SA-8(18)](#sa-8.18). user functionality, including user interface services, is separated from system management functionality. System and communications protection policy

procedures addressing application partitioning

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

system developer Separation of user functionality from system management functionality

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-3: Isolate security functions from nonsecurity functions. Security functions are isolated from nonsecurity functions by means of an isolation boundary implemented within a system via partitions and domains. The isolation boundary controls access to and protects the integrity of the hardware, software, and firmware that perform system security functions. Systems implement code separation in many ways, such as through the provision of security kernels via processor rings or processor modes. For non-kernel code, security function isolation is often achieved through file system protections that protect the code on disk and address space protections that protect executing code. Systems can restrict access to security functions using access control mechanisms and by implementing least privilege capabilities. While the ideal is for all code within the defined security function isolation boundary to only contain security-relevant code, it is sometimes necessary to include nonsecurity functions as an exception. The isolation of security functions from nonsecurity functions can be achieved by applying the systems security engineering design principles in [SA-8](#sa-8) , including [SA-8(1)](#sa-8.1), [SA-8(3)](#sa-8.3), [SA-8(4)](#sa-8.4), [SA-8(10)](#sa-8.10), [SA-8(12)](#sa-8.12), [SA-8(13)](#sa-8.13), [SA-8(14)](#sa-8.14) , and [SA-8(18)](#sa-8.18). security functions are isolated from non-security functions. System and communications protection policy

procedures addressing security function isolation

list of security functions to be isolated from non-security functions

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

system developer Separation of security functions from non-security functions within the system

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-4: Prevent unauthorized and unintended information transfer via shared system resources. Preventing unauthorized and unintended information transfer via shared system resources stops information produced by the actions of prior users or roles (or the actions of processes acting on behalf of prior users or roles) from being available to current users or roles (or current processes acting on behalf of current users or roles) that obtain access to shared system resources after those resources have been released back to the system. Information in shared system resources also applies to encrypted representations of information. In other contexts, control of information in shared system resources is referred to as object reuse and residual information protection. Information in shared system resources does not address information remanence, which refers to the residual representation of data that has been nominally deleted; covert channels (including storage and timing channels), where shared system resources are manipulated to violate information flow restrictions; or components within systems for which there are only single users or roles. unauthorized information transfer via shared system resources is prevented; unintended information transfer via shared system resources is prevented. System and communications protection policy

procedures addressing information protection in shared system resources

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

system developer Mechanisms preventing the unauthorized and unintended transfer of information via shared system resources

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-5: {{ insert: param, sc-05_odp.02 }} the effects of the following types of denial-of-service events: {{ insert: param, sc-05_odp.01 }} ; and Employ the following controls to achieve the denial-of-service objective: {{ insert: param, sc-05_odp.03 }}. Denial-of-service events may occur due to a variety of internal and external causes, such as an attack by an adversary or a lack of planning to support organizational needs with respect to capacity and bandwidth. Such attacks can occur across a wide range of network protocols (e.g., IPv4, IPv6). A variety of technologies are available to limit or eliminate the origination and effects of denial-of-service events. For example, boundary protection devices can filter certain types of packets to protect system components on internal networks from being directly affected by or the source of denial-of-service attacks. Employing increased network capacity and bandwidth combined with service redundancy also reduces the susceptibility to denial-of-service events. the effects of {{ insert: param, sc-05_odp.01 }} are {{ insert: param, sc-05_odp.02 }}; {{ insert: param, sc-05_odp.03 }} are employed to achieve the denial-of-service protection objective. System and communications protection policy

procedures addressing denial-of-service protection

system design documentation

list of denial-of-service attacks requiring employment of security safeguards to protect against or limit effects of such attacks

list of security safeguards protecting against or limiting the effects of denial-of-service attacks

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel with incident response responsibilities

system developer Mechanisms protecting against or limiting the effects of denial-of-service attacks

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-6: Protect the availability of resources by allocating {{ insert: param, sc-06_odp.01 }} by {{ insert: param, sc-06_odp.02 }}. Priority protection prevents lower-priority processes from delaying or interfering with the system that services higher-priority processes. Quotas prevent users or processes from obtaining more than predetermined amounts of resources. the availability of resources is protected by allocating {{ insert: param, sc-06_odp.01 }} by {{ insert: param, sc-06_odp.02 }}. System and communications protection policy

procedures addressing prioritization of system resources

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

system developer Mechanisms supporting and/or implementing a resource allocation capability

safeguards employed to protect availability of resources

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-9: 

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-11: Provide a {{ insert: param, sc-11_odp.01 }} isolated trusted communications path for communications between the user and the trusted components of the system; and Permit users to invoke the trusted communications path for communications between the user and the following security functions of the system, including at a minimum, authentication and re-authentication: {{ insert: param, sc-11_odp.02 }}. Trusted paths are mechanisms by which users can communicate (using input devices such as keyboards) directly with the security functions of systems with the requisite assurance to support security policies. Trusted path mechanisms can only be activated by users or the security functions of organizational systems. User responses that occur via trusted paths are protected from modification by and disclosure to untrusted applications. Organizations employ trusted paths for trustworthy, high-assurance connections between security functions of systems and users, including during system logons. The original implementations of trusted paths employed an out-of-band signal to initiate the path, such as using the <BREAK> key, which does not transmit characters that can be spoofed. In later implementations, a key combination that could not be hijacked was used (e.g., the <CTRL> + <ALT> + <DEL> keys). Such key combinations, however, are platform-specific and may not provide a trusted path implementation in every case. The enforcement of trusted communications paths is provided by a specific implementation that meets the reference monitor concept. a {{ insert: param, sc-11_odp.01 }} isolated trusted communication path is provided for communications between the user and the trusted components of the system; users are permitted to invoke the trusted communication path for communications between the user and the {{ insert: param, sc-11_odp.02 }} of the system, including authentication and re-authentication, at a minimum. System and communications protection policy

procedures addressing trusted communication paths

security plan

system design documentation

system configuration settings and associated documentation

assessment results from independent, testing organizations

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

system developer Mechanisms supporting and/or implementing trusted communication paths

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-14: 

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-16: Associate {{ insert: param, sc-16_prm_1 }} with information exchanged between systems and between system components. Security and privacy attributes can be explicitly or implicitly associated with the information contained in organizational systems or system components. Attributes are abstractions that represent the basic properties or characteristics of an entity with respect to protecting information or the management of personally identifiable information. Attributes are typically associated with internal data structures, including records, buffers, and files within the system. Security and privacy attributes are used to implement access control and information flow control policies; reflect special dissemination, management, or distribution instructions, including permitted uses of personally identifiable information; or support other aspects of the information security and privacy policies. Privacy attributes may be used independently or in conjunction with security attributes. {{ insert: param, sc-16_odp.01 }} are associated with information exchanged between systems; {{ insert: param, sc-16_odp.01 }} are associated with information exchanged between system components; {{ insert: param, sc-16_odp.02 }} are associated with information exchanged between systems; {{ insert: param, sc-16_odp.02 }} are associated with information exchanged between system components. System and communications protection policy

procedures addressing the transmission of security and privacy attributes

access control policy and procedures

information flow control policy

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

privacy plan

other relevant documents or records System/network administrators

organizational personnel with information security and privacy responsibilities Mechanisms supporting and/or implementing the transmission of security and privacy attributes between systems

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-17: Issue public key certificates under an {{ insert: param, sc-17_odp }} or obtain public key certificates from an approved service provider; and Include only approved trust anchors in trust stores or certificate stores managed by the organization. Public key infrastructure (PKI) certificates are certificates with visibility external to organizational systems and certificates related to the internal operations of systems, such as application-specific time services. In cryptographic systems with a hierarchical structure, a trust anchor is an authoritative source (i.e., a certificate authority) for which trust is assumed and not derived. A root certificate for a PKI system is an example of a trust anchor. A trust store or certificate store maintains a list of trusted root certificates. public key certificates are issued under {{ insert: param, sc-17_odp }} , or public key certificates are obtained from an approved service provider; only approved trust anchors are included in trust stores or certificate stores managed by the organization. System and communications protection policy

procedures addressing public key infrastructure certificates

public key certificate policy or policies

public key issuing process

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel with responsibilities for issuing public key certificates

service providers Mechanisms supporting and/or implementing the management of public key infrastructure certificates

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-19: Technology-specific; addressed as any other technology or protocol.

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-20: Provide additional data origin authentication and integrity verification artifacts along with the authoritative name resolution data the system returns in response to external name/address resolution queries; and Provide the means to indicate the security status of child zones and (if the child supports secure resolution services) to enable verification of a chain of trust among parent and child domains, when operating as part of a distributed, hierarchical namespace. Providing authoritative source information enables external clients, including remote Internet clients, to obtain origin authentication and integrity verification assurances for the host/service name to network address resolution information obtained through the service. Systems that provide name and address resolution services include domain name system (DNS) servers. Additional artifacts include DNS Security Extensions (DNSSEC) digital signatures and cryptographic keys. Authoritative data includes DNS resource records. The means for indicating the security status of child zones include the use of delegation signer resource records in the DNS. Systems that use technologies other than the DNS to map between host and service names and network addresses provide other means to assure the authenticity and integrity of response data. additional data origin authentication is provided along with the authoritative name resolution data that the system returns in response to external name/address resolution queries; integrity verification artifacts are provided along with the authoritative name resolution data that the system returns in response to external name/address resolution queries; the means to indicate the security status of child zones (and if the child supports secure resolution services) is provided when operating as part of a distributed, hierarchical namespace; the means to enable verification of a chain of trust among parent and child domains when operating as part of a distributed, hierarchical namespace is provided. System and communications protection policy

procedures addressing secure name/address resolution services (authoritative source)

system design documentation

system configuration settings and associated documentation

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel with responsibilities for managing DNS Mechanisms supporting and/or implementing secure name/address resolution services

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-21: Request and perform data origin authentication and data integrity verification on the name/address resolution responses the system receives from authoritative sources. Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Systems that provide name and address resolution services for local clients include recursive resolving or caching domain name system (DNS) servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations. Systems that use technologies other than the DNS to map between host and service names and network addresses provide some other means to enable clients to verify the authenticity and integrity of response data. data origin authentication is requested for the name/address resolution responses that the system receives from authoritative sources; data origin authentication is performed on the name/address resolution responses that the system receives from authoritative sources; data integrity verification is requested for the name/address resolution responses that the system receives from authoritative sources; data integrity verification is performed on the name/address resolution responses that the system receives from authoritative sources. System and communications protection policy

procedures addressing secure name/address resolution services (recursive or caching resolver)

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel with responsibilities for managing DNS Mechanisms supporting and/or implementing data origin authentication and data integrity verification for name/address resolution services

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-22: Ensure the systems that collectively provide name/address resolution service for an organization are fault-tolerant and implement internal and external role separation. Systems that provide name and address resolution services include domain name system (DNS) servers. To eliminate single points of failure in systems and enhance redundancy, organizations employ at least two authoritative domain name system servers—one configured as the primary server and the other configured as the secondary server. Additionally, organizations typically deploy the servers in two geographically separated network subnetworks (i.e., not located in the same physical facility). For role separation, DNS servers with internal roles only process name and address resolution requests from within organizations (i.e., from internal clients). DNS servers with external roles only process name and address resolution information requests from clients external to organizations (i.e., on external networks, including the Internet). Organizations specify clients that can access authoritative DNS servers in certain roles (e.g., by address ranges and explicit lists). the systems that collectively provide name/address resolution services for an organization are fault-tolerant; the systems that collectively provide name/address resolution services for an organization implement internal role separation; the systems that collectively provide name/address resolution services for an organization implement external role separation. System and communications protection policy

procedures addressing architecture and provisioning for name/address resolution services

access control policy and procedures

system design documentation

assessment results from independent testing organizations

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel with responsibilities for managing DNS Mechanisms supporting and/or implementing name/address resolution services for fault tolerance and role separation

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-24: Fail to a {{ insert: param, sc-24_odp.02 }} for the following failures on the indicated components while preserving {{ insert: param, sc-24_odp.03 }} in failure: {{ insert: param, sc-24_odp.01 }}. Failure in a known state addresses security concerns in accordance with the mission and business needs of organizations. Failure in a known state prevents the loss of confidentiality, integrity, or availability of information in the event of failures of organizational systems or system components. Failure in a known safe state helps to prevent systems from failing to a state that may cause injury to individuals or destruction to property. Preserving system state information facilitates system restart and return to the operational mode with less disruption of mission and business processes. {{ insert: param, sc-24_odp.01 }} fail to a {{ insert: param, sc-24_odp.02 }} while preserving {{ insert: param, sc-24_odp.03 }} in failure. System and communications protection policy

procedures addressing system failure to known state

system design documentation

system configuration settings and associated documentation

list of failures requiring system to fail in a known state

state information to be preserved in system failure

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

system developer Mechanisms supporting and/or implementing the fail in known state capability

mechanisms preserving system state information in the event of a system failure

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-25: Employ minimal functionality and information storage on the following system components: {{ insert: param, sc-25_odp }}. The deployment of system components with minimal functionality reduces the need to secure every endpoint and may reduce the exposure of information, systems, and services to attacks. Reduced or minimal functionality includes diskless nodes and thin client technologies. minimal functionality for {{ insert: param, sc-25_odp }} is employed; minimal information storage on {{ insert: param, sc-25_odp }} is allocated. System and communications protection policy

procedures addressing use of thin nodes

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities Mechanisms supporting and/or implementing thin nodes

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-26: Include components within organizational systems specifically designed to be the target of malicious attacks for detecting, deflecting, and analyzing such attacks. Decoys (i.e., honeypots, honeynets, or deception nets) are established to attract adversaries and deflect attacks away from the operational systems that support organizational mission and business functions. Use of decoys requires some supporting isolation measures to ensure that any deflected malicious code does not infect organizational systems. Depending on the specific usage of the decoy, consultation with the Office of the General Counsel before deployment may be needed. components within organizational systems specifically designed to be the target of malicious attacks are included to detect such attacks; components within organizational systems specifically designed to be the target of malicious attacks are included to deflect such attacks; components within organizational systems specifically designed to be the target of malicious attacks are included to analyze such attacks. System and communications protection policy

procedures addressing the use of decoys

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

system developer Mechanisms supporting and/or implementing decoys

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-27: Include within organizational systems the following platform independent applications: {{ insert: param, sc-27_odp }}. Platforms are combinations of hardware, firmware, and software components used to execute software applications. Platforms include operating systems, the underlying computer architectures, or both. Platform-independent applications are applications with the capability to execute on multiple platforms. Such applications promote portability and reconstitution on different platforms. Application portability and the ability to reconstitute on different platforms increase the availability of mission-essential functions within organizations in situations where systems with specific operating systems are under attack. {{ insert: param, sc-27_odp }} are included within organizational systems. System and communications protection policy

procedures addressing platform-independent applications

system design documentation

system configuration settings and associated documentation

list of platform-independent applications

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

system developer Mechanisms supporting and/or implementing platform-independent applications

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-29: Employ a diverse set of information technologies for the following system components in the implementation of the system: {{ insert: param, sc-29_odp }}. Increasing the diversity of information technologies within organizational systems reduces the impact of potential exploitations or compromises of specific technologies. Such diversity protects against common mode failures, including those failures induced by supply chain attacks. Diversity in information technologies also reduces the likelihood that the means adversaries use to compromise one system component will be effective against other system components, thus further increasing the adversary work factor to successfully complete planned attacks. An increase in diversity may add complexity and management overhead that could ultimately lead to mistakes and unauthorized configurations. a diverse set of information technologies is employed for {{ insert: param, sc-29_odp }} in the implementation of the system. System and communications protection policy

system design documentation

system configuration settings and associated documentation

list of technologies deployed in the system

acquisition documentation

acquisition contracts for system components or services

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel with system acquisition, development, and implementation responsibilities Mechanisms supporting and/or implementing the employment of a diverse set of information technologies

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-30: Employ the following concealment and misdirection techniques for {{ insert: param, sc-30_odp.02 }} at {{ insert: param, sc-30_odp.03 }} to confuse and mislead adversaries: {{ insert: param, sc-30_odp.01 }}. Concealment and misdirection techniques can significantly reduce the targeting capabilities of adversaries (i.e., window of opportunity and available attack surface) to initiate and complete attacks. For example, virtualization techniques provide organizations with the ability to disguise systems, potentially reducing the likelihood of successful attacks without the cost of having multiple platforms. The increased use of concealment and misdirection techniques and methods—including randomness, uncertainty, and virtualization—may sufficiently confuse and mislead adversaries and subsequently increase the risk of discovery and/or exposing tradecraft. Concealment and misdirection techniques may provide additional time to perform core mission and business functions. The implementation of concealment and misdirection techniques may add to the complexity and management overhead required for the system. {{ insert: param, sc-30_odp.01 }} are employed for {{ insert: param, sc-30_odp.02 }} for {{ insert: param, sc-30_odp.03 }} to confuse and mislead adversaries. System and communications protection policy

procedures addressing concealment and misdirection techniques for the system

system design documentation

system configuration settings and associated documentation

system architecture

list of concealment and misdirection techniques to be employed for organizational systems

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel with the responsibility to implement concealment and misdirection techniques for systems Mechanisms supporting and/or implementing concealment and misdirection techniques

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-31: Perform a covert channel analysis to identify those aspects of communications within the system that are potential avenues for covert {{ insert: param, sc-31_odp }} channels; and Estimate the maximum bandwidth of those channels. Developers are in the best position to identify potential areas within systems that might lead to covert channels. Covert channel analysis is a meaningful activity when there is the potential for unauthorized information flows across security domains, such as in the case of systems that contain export-controlled information and have connections to external networks (i.e., networks that are not controlled by organizations). Covert channel analysis is also useful for multilevel secure systems, multiple security level systems, and cross-domain systems. a covert channel analysis is performed to identify those aspects of communications within the system that are potential avenues for covert {{ insert: param, sc-31_odp }} channels; the maximum bandwidth of those channels is estimated. System and communications protection policy

procedures addressing covert channel analysis

system design documentation

system configuration settings and associated documentation

covert channel analysis documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel with covert channel analysis responsibilities

system developers/integrators Organizational process for conducting covert channel analysis

mechanisms supporting and/or implementing covert channel analysis

mechanisms supporting and/or implementing the capability to estimate the bandwidth of covert channels

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-32: Partition the system into {{ insert: param, sc-32_odp.01 }} residing in separate {{ insert: param, sc-32_odp.02 }} domains or environments based on {{ insert: param, sc-32_odp.03 }}. System partitioning is part of a defense-in-depth protection strategy. Organizations determine the degree of physical separation of system components. Physical separation options include physically distinct components in separate racks in the same room, critical components in separate rooms, and geographical separation of critical components. Security categorization can guide the selection of candidates for domain partitioning. Managed interfaces restrict or prohibit network access and information flow among partitioned system components. the system is partitioned into {{ insert: param, sc-32_odp.01 }} residing in separate {{ insert: param, sc-32_odp.02 }} domains or environments based on {{ insert: param, sc-32_odp.03 }}. System and communications protection policy

procedures addressing system partitioning

system design documentation

system configuration settings and associated documentation

system architecture

list of system physical domains (or environments)

system facility diagrams

system network diagrams

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel installing, configuring, and/or maintaining the system

system developers/integrators Mechanisms supporting and/or implementing the physical separation of system components

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-33: 

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-34: For {{ insert: param, sc-34_odp.01 }} , load and execute: The operating environment from hardware-enforced, read-only media; and The following applications from hardware-enforced, read-only media: {{ insert: param, sc-34_odp.02 }}. The operating environment for a system contains the code that hosts applications, including operating systems, executives, or virtual machine monitors (i.e., hypervisors). It can also include certain applications that run directly on hardware platforms. Hardware-enforced, read-only media include Compact Disc-Recordable (CD-R) and Digital Versatile Disc-Recordable (DVD-R) disk drives as well as one-time, programmable, read-only memory. The use of non-modifiable storage ensures the integrity of software from the point of creation of the read-only image. The use of reprogrammable, read-only memory can be accepted as read-only media provided that integrity can be adequately protected from the point of initial writing to the insertion of the memory into the system, and there are reliable hardware protections against reprogramming the memory while installed in organizational systems. the operating environment for {{ insert: param, sc-34_odp.01 }} is loaded and executed from hardware-enforced, read-only media; {{ insert: param, sc-34_odp.02 }} for {{ insert: param, sc-34_odp.01 }} are loaded and executed from hardware-enforced, read-only media. System and communications protection policy

procedures addressing non-modifiable executable programs

system design documentation

system configuration settings and associated documentation

system architecture

list of operating system components to be loaded from hardware-enforced, read-only media

list of applications to be loaded from hardware-enforced, read-only media

media used to load and execute the system operating environment

media used to load and execute system applications

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

system developer

organizational personnel installing, configuring, and/or maintaining the system

system developers/integrators Mechanisms supporting and/or implementing, loading, and executing the operating environment from hardware-enforced, read-only media

mechanisms supporting and/or implementing, loading, and executing applications from hardware-enforced, read-only media

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-35: Include system components that proactively seek to identify network-based malicious code or malicious websites. External malicious code identification differs from decoys in [SC-26](#sc-26) in that the components actively probe networks, including the Internet, in search of malicious code contained on external websites. Like decoys, the use of external malicious code identification techniques requires some supporting isolation measures to ensure that any malicious code discovered during the search and subsequently executed does not infect organizational systems. Virtualization is a common technique for achieving such isolation. system components that proactively seek to identify network-based malicious code or malicious websites are included. System and communications protection policy

procedures addressing external malicious code identification

system design documentation

system configuration settings and associated documentation

system components deployed to identify malicious websites and/or web-based malicious code

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel installing, configuring, and/or maintaining the system

system developers/integrators Automated mechanisms supporting and/or implementing external malicious code identification

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-36: Distribute the following processing and storage components across multiple {{ insert: param, sc-36_prm_1 }}: {{ insert: param, sc-36_prm_2 }}. Distributing processing and storage across multiple physical locations or logical domains provides a degree of redundancy or overlap for organizations. The redundancy and overlap increase the work factor of adversaries to adversely impact organizational operations, assets, and individuals. The use of distributed processing and storage does not assume a single primary processing or storage location. Therefore, it allows for parallel processing and storage. {{ insert: param, sc-36_odp.01 }} are distributed across {{ insert: param, sc-36_odp.02 }}; {{ insert: param, sc-36_odp.03 }} are distributed across {{ insert: param, sc-36_odp.04 }}. System and communications protection policy

contingency planning policy and procedures

contingency plan

system design documentation

system configuration settings and associated documentation

system architecture

list of system physical locations (or environments) with distributed processing and storage

system facility diagrams

processing site agreements

storage site agreements

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel installing, configuring, and/or maintaining the system

organizational personnel with contingency planning and plan implementation responsibilities

system developers/integrators Organizational processes for distributed processing and storage across multiple physical locations

mechanisms supporting and/or implementing the capability to distribute processing and storage across multiple physical locations

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-37: Employ the following out-of-band channels for the physical delivery or electronic transmission of {{ insert: param, sc-37_odp.02 }} to {{ insert: param, sc-37_odp.03 }}: {{ insert: param, sc-37_odp.01 }}. Out-of-band channels include local, non-network accesses to systems; network paths physically separate from network paths used for operational traffic; or non-electronic paths, such as the U.S. Postal Service. The use of out-of-band channels is contrasted with the use of in-band channels (i.e., the same channels) that carry routine operational traffic. Out-of-band channels do not have the same vulnerability or exposure as in-band channels. Therefore, the confidentiality, integrity, or availability compromises of in-band channels will not compromise or adversely affect the out-of-band channels. Organizations may employ out-of-band channels in the delivery or transmission of organizational items, including authenticators and credentials; cryptographic key management information; system and data backups; configuration management changes for hardware, firmware, or software; security updates; maintenance information; and malicious code protection updates. For example, cryptographic keys for encrypted files are delivered using a different channel than the file. {{ insert: param, sc-37_odp.01 }} are employed for the physical delivery or electronic transmission of {{ insert: param, sc-37_odp.02 }} to {{ insert: param, sc-37_odp.03 }}. System and communications protection policy

procedures addressing the use of out-of-band channels

access control policy and procedures

identification and authentication policy and procedures

system design documentation

system architecture

system configuration settings and associated documentation

list of out-of-band channels

types of information, system components, or devices requiring the use of out-of-band channels for physical delivery or electronic transmission to authorized individuals or systems

physical delivery records

electronic transmission records

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel installing, configuring, and/or maintaining the system

organizational personnel authorizing, installing, configuring, operating, and/or using out-of-band channels

system developers/integrators Organizational processes for the use of out-of-band channels

mechanisms supporting and/or implementing the use of out-of-band channels

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-38: Employ the following operations security controls to protect key organizational information throughout the system development life cycle: {{ insert: param, sc-38_odp }}. Operations security (OPSEC) is a systematic process by which potential adversaries can be denied information about the capabilities and intentions of organizations by identifying, controlling, and protecting generally unclassified information that specifically relates to the planning and execution of sensitive organizational activities. The OPSEC process involves five steps: identification of critical information, analysis of threats, analysis of vulnerabilities, assessment of risks, and the application of appropriate countermeasures. OPSEC controls are applied to organizational systems and the environments in which those systems operate. OPSEC controls protect the confidentiality of information, including limiting the sharing of information with suppliers, potential suppliers, and other non-organizational elements and individuals. Information critical to organizational mission and business functions includes user identities, element uses, suppliers, supply chain processes, functional requirements, security requirements, system design specifications, testing and evaluation protocols, and security control implementation details. {{ insert: param, sc-38_odp }} are employed to protect key organizational information throughout the system development life cycle. System and communications protection policy

procedures addressing operations security

security plan

list of operations security safeguards

security control assessments

risk assessments

threat and vulnerability assessments

plans of action and milestones

system development life cycle documentation

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel installing, configuring, and/or maintaining the system

system developers/integrators Organizational processes for protecting organizational information throughout the system development life cycle

mechanisms supporting and/or implementing safeguards to protect organizational information throughout the system development life cycle

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-39: Maintain a separate execution domain for each executing system process. Systems can maintain separate execution domains for each executing process by assigning each process a separate address space. Each system process has a distinct address space so that communication between processes is performed in a manner controlled through the security functions, and one process cannot modify the executing code of another process. Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces. Process isolation technologies, including sandboxing or virtualization, logically separate software and firmware from other software, firmware, and data. Process isolation helps limit the access of potentially untrusted software to other system resources. The capability to maintain separate execution domains is available in commercial operating systems that employ multi-state processor technologies. a separate execution domain is maintained for each executing system process. System design documentation

system architecture

independent verification and validation documentation

testing and evaluation documentation

other relevant documents or records System developers/integrators

system security architect Mechanisms supporting and/or implementing separate execution domains for each executing process

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-40: Protect external and internal {{ insert: param, sc-40_prm_1 }} from the following signal parameter attacks: {{ insert: param, sc-40_prm_2 }}. Wireless link protection applies to internal and external wireless communication links that may be visible to individuals who are not authorized system users. Adversaries can exploit the signal parameters of wireless links if such links are not adequately protected. There are many ways to exploit the signal parameters of wireless links to gain intelligence, deny service, or spoof system users. Protection of wireless links reduces the impact of attacks that are unique to wireless systems. If organizations rely on commercial service providers for transmission services as commodity items rather than as fully dedicated services, it may not be possible to implement wireless link protections to the extent necessary to meet organizational security requirements. external {{ insert: param, sc-40_odp.01 }} are protected from {{ insert: param, sc-40_odp.02 }}. internal {{ insert: param, sc-40_odp.03 }} are protected from {{ insert: param, sc-40_odp.04 }}. System and communications protection policy

access control policy and procedures

procedures addressing wireless link protection

system design documentation

wireless network diagrams

system configuration settings and associated documentation

system architecture

list of internal and external wireless links

list of signal parameter attacks or references to sources for attacks

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

system developer

organizational personnel installing, configuring, and/or maintaining the system

organizational personnel authorizing, installing, configuring, and/or maintaining internal and external wireless links Mechanisms supporting and/or implementing the protection of wireless links

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-41: {{ insert: param, sc-41_odp.02 }} disable or remove {{ insert: param, sc-41_odp.01 }} on the following systems or system components: {{ insert: param, sc-41_odp.03 }}. Connection ports include Universal Serial Bus (USB), Thunderbolt, and Firewire (IEEE 1394). Input/output (I/O) devices include compact disc and digital versatile disc drives. Disabling or removing such connection ports and I/O devices helps prevent the exfiltration of information from systems and the introduction of malicious code from those ports or devices. Physically disabling or removing ports and/or devices is the stronger action. {{ insert: param, sc-41_odp.01 }} are {{ insert: param, sc-41_odp.02 }} disabled or removed on {{ insert: param, sc-41_odp.03 }}. System and communications protection policy

access control policy and procedures

procedures addressing port and input/output device access

system design documentation

system configuration settings and associated documentation

system architecture

systems or system components

list of connection ports or input/output devices to be physically disabled or removed on systems or system components

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel installing, configuring, and/or maintaining the system Mechanisms supporting and/or implementing the disabling of connection ports or input/output devices

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-42: Prohibit {{ insert: param, sc-42_odp.01 }} ; and Provide an explicit indication of sensor use to {{ insert: param, sc-42_odp.05 }}. Sensor capability and data applies to types of systems or system components characterized as mobile devices, such as cellular telephones, smart phones, and tablets. Mobile devices often include sensors that can collect and record data regarding the environment where the system is in use. Sensors that are embedded within mobile devices include microphones, cameras, Global Positioning System (GPS) mechanisms, and accelerometers. While the sensors on mobiles devices provide an important function, if activated covertly, such devices can potentially provide a means for adversaries to learn valuable information about individuals and organizations. For example, remotely activating the GPS function on a mobile device could provide an adversary with the ability to track the movements of an individual. Organizations may prohibit individuals from bringing cellular telephones or digital cameras into certain designated facilities or controlled areas within facilities where classified information is stored or sensitive conversations are taking place. {{ insert: param, sc-42_odp.01 }} is/are prohibited; an explicit indication of sensor use is provided to {{ insert: param, sc-42_odp.05 }}. System and communications protection policy

procedures addressing sensor capabilities and data collection

access control policy and procedures

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

privacy plan

other relevant documents or records System/network administrators

organizational personnel with information security and privacy responsibilities

system developer

organizational personnel installing, configuring, and/or maintaining the system

organizational personnel responsible for sensor capabilities Mechanisms implementing access controls for the remote activation of system sensor capabilities

mechanisms implementing the capability to indicate sensor use

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-43: Establish usage restrictions and implementation guidelines for the following system components: {{ insert: param, sc-43_odp }} ; and Authorize, monitor, and control the use of such components within the system. Usage restrictions apply to all system components including but not limited to mobile code, mobile devices, wireless access, and wired and wireless peripheral components (e.g., copiers, printers, scanners, optical devices, and other similar technologies). The usage restrictions and implementation guidelines are based on the potential for system components to cause damage to the system and help to ensure that only authorized system use occurs. usage restrictions and implementation guidelines are established for {{ insert: param, sc-43_odp }}; the use of {{ insert: param, sc-43_odp }} is authorized within the system; the use of {{ insert: param, sc-43_odp }} is monitored within the system; the use of {{ insert: param, sc-43_odp }} is controlled within the system. System and communications protection policy

usage restrictions

procedures addressing usage restrictions

implementation policy and procedures

authorization records

system monitoring records

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel installing, configuring, and/or maintaining the system Organizational processes for authorizing, monitoring, and controlling the use of components with usage restrictions

mechanisms supporting and/or implementing, authorizing, monitoring, and controlling the use of components with usage restrictions

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-44: Employ a detonation chamber capability within {{ insert: param, sc-44_odp }}. Detonation chambers, also known as dynamic execution environments, allow organizations to open email attachments, execute untrusted or suspicious applications, and execute Universal Resource Locator requests in the safety of an isolated environment or a virtualized sandbox. Protected and isolated execution environments provide a means of determining whether the associated attachments or applications contain malicious code. While related to the concept of deception nets, the employment of detonation chambers is not intended to maintain a long-term environment in which adversaries can operate and their actions can be observed. Rather, detonation chambers are intended to quickly identify malicious code and either reduce the likelihood that the code is propagated to user environments of operation or prevent such propagation completely. a detonation chamber capability is employed within the {{ insert: param, sc-44_odp }}. System and communications protection policy

procedures addressing detonation chambers

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel installing, configuring, and/or maintaining the system Mechanisms supporting and/or implementing the detonation chamber capability

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-45: Synchronize system clocks within and between systems and system components. Time synchronization of system clocks is essential for the correct execution of many system services, including identification and authentication processes that involve certificates and time-of-day restrictions as part of access control. Denial of service or failure to deny expired credentials may result without properly synchronized clocks within and between systems and system components. Time is commonly expressed in Coordinated Universal Time (UTC), a modern continuation of Greenwich Mean Time (GMT), or local time with an offset from UTC. The granularity of time measurements refers to the degree of synchronization between system clocks and reference clocks, such as clocks synchronizing within hundreds of milliseconds or tens of milliseconds. Organizations may define different time granularities for system components. Time service can be critical to other security capabilities—such as access control and identification and authentication—depending on the nature of the mechanisms used to support the capabilities. system clocks are synchronized within and between systems and system components. System and communications protection policy

procedures addressing time synchronization

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel installing, configuring, and/or maintaining the system Mechanisms supporting and/or implementing system time synchronization

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-46: Implement a policy enforcement mechanism {{ insert: param, sc-46_odp }} between the physical and/or network interfaces for the connecting security domains. For logical policy enforcement mechanisms, organizations avoid creating a logical path between interfaces to prevent the ability to bypass the policy enforcement mechanism. For physical policy enforcement mechanisms, the robustness of physical isolation afforded by the physical implementation of policy enforcement to preclude the presence of logical covert channels penetrating the security domain may be needed. Contact [ncdsmo@nsa.gov](mailto:ncdsmo@nsa.gov) for more information. a policy enforcement mechanism is {{ insert: param, sc-46_odp }} implemented between the physical and/or network interfaces for the connecting security domains. System and communications protection policy

procedures addressing cross-domain policy enforcement

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel installing, configuring, and/or maintaining the system Mechanisms supporting and/or implementing cross-domain policy enforcement

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-47: Establish {{ insert: param, sc-47_odp }} for system operations organizational command and control. An incident, whether adversarial- or nonadversarial-based, can disrupt established communications paths used for system operations and organizational command and control. Alternate communications paths reduce the risk of all communications paths being affected by the same incident. To compound the problem, the inability of organizational officials to obtain timely information about disruptions or to provide timely direction to operational elements after a communications path incident, can impact the ability of the organization to respond to such incidents in a timely manner. Establishing alternate communications paths for command and control purposes, including designating alternative decision makers if primary decision makers are unavailable and establishing the extent and limitations of their actions, can greatly facilitate the organization’s ability to continue to operate and take appropriate actions during an incident. {{ insert: param, sc-47_odp }} are established for system operations and operational command and control. System and communications protection policy

procedures addressing communication paths

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

system developers Mechanisms supporting and/or implementing alternate communication paths for system operations

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-48: Relocate {{ insert: param, sc-48_odp.01 }} to {{ insert: param, sc-48_odp.02 }} under the following conditions or circumstances: {{ insert: param, sc-48_odp.03 }}. Adversaries may take various paths and use different approaches as they move laterally through an organization (including its systems) to reach their target or as they attempt to exfiltrate information from the organization. The organization often only has a limited set of monitoring and detection capabilities, and they may be focused on the critical or likely infiltration or exfiltration paths. By using communications paths that the organization typically does not monitor, the adversary can increase its chances of achieving its desired goals. By relocating its sensors or monitoring capabilities to new locations, the organization can impede the adversary’s ability to achieve its goals. The relocation of the sensors or monitoring capabilities might be done based on threat information that the organization has acquired or randomly to confuse the adversary and make its lateral transition through the system or organization more challenging. {{ insert: param, sc-48_odp.01 }} are relocated to {{ insert: param, sc-48_odp.02 }} under {{ insert: param, sc-48_odp.03 }}. System and communications protection policy

procedures addressing sensor and monitoring capability relocation

list of sensors/monitoring capabilities to be relocated

change control records

configuration management records

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel installing, configuring, and/or maintaining the system Mechanisms supporting and/or implementing sensor relocation

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-49: Implement hardware-enforced separation and policy enforcement mechanisms between {{ insert: param, sc-49_odp }}. System owners may require additional strength of mechanism and robustness to ensure domain separation and policy enforcement for specific types of threats and environments of operation. Hardware-enforced separation and policy enforcement provide greater strength of mechanism than software-enforced separation and policy enforcement. hardware-enforced separation and policy enforcement mechanisms are implemented between {{ insert: param, sc-49_odp }}. System and communications protection policy

procedures addressing cross-domain policy enforcement

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel installing, configuring, and/or maintaining the system Mechanisms supporting and/or implementing hardware-enforced security domain separation and policy enforcement

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-50: Implement software-enforced separation and policy enforcement mechanisms between {{ insert: param, sc-50_odp }}. System owners may require additional strength of mechanism to ensure domain separation and policy enforcement for specific types of threats and environments of operation. software-enforced separation and policy enforcement mechanisms are implemented between {{ insert: param, sc-50_odp }}. System and communications protection policy

procedures addressing cross-domain policy enforcement

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel installing, configuring, and/or maintaining the system Mechanisms supporting and/or implementing software-enforced separation and policy enforcement

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SC-51: Employ hardware-based, write-protect for {{ insert: param, sc-51_odp.01 }} ; and Implement specific procedures for {{ insert: param, sc-51_odp.02 }} to manually disable hardware write-protect for firmware modifications and re-enable the write-protect prior to returning to operational mode. None. hardware-based write-protect for {{ insert: param, sc-51_odp.01 }} is employed; specific procedures are implemented for {{ insert: param, sc-51_odp.02 }} to manually disable hardware write-protect for firmware modifications; specific procedures are implemented for {{ insert: param, sc-51_odp.02 }} to re-enable the write-protect prior to returning to operational mode. System and communications protection policy

procedures addressing firmware modifications

system design documentation

system configuration settings and associated documentation

system architecture

system audit records

system security plan

other relevant documents or records System/network administrators

organizational personnel with information security responsibilities

organizational personnel installing, configuring, and/or maintaining the system

system developers/integrators Organizational processes for modifying system firmware

mechanisms supporting and/or implementing hardware-based write-protection for system firmware

**FedRAMP Baseline:** L2 | **Domain:** SC

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### SI — System and Information Integrity (Manual Controls)

##### Control SI-1: Develop, document, and disseminate to {{ insert: param, si-1_prm_1 }}: {{ insert: param, si-01_odp.03 }} system and information integrity policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the system and information integrity policy and the associated system and information integrity controls; Designate an {{ insert: param, si-01_odp.04 }} to manage the development, documentation, and dissemination of the system and information integrity policy and procedures; and Review and update the current system and information integrity: Policy {{ insert: param, si-01_odp.05 }} and following {{ insert: param, si-01_odp.06 }} ; and Procedures {{ insert: param, si-01_odp.07 }} and following {{ insert: param, si-01_odp.08 }}. System and information integrity policy and procedures address the controls in the SI family that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of system and information integrity policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to system and information integrity policy and procedures include assessment or audit findings, security incidents or breaches, or changes in applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. a system and information integrity policy is developed and documented; the system and information integrity policy is disseminated to {{ insert: param, si-01_odp.01 }}; system and information integrity procedures to facilitate the implementation of the system and information integrity policy and associated system and information integrity controls are developed and documented; the system and information integrity procedures are disseminated to {{ insert: param, si-01_odp.02 }}; the {{ insert: param, si-01_odp.03 }} system and information integrity policy addresses purpose; the {{ insert: param, si-01_odp.03 }} system and information integrity policy addresses scope; the {{ insert: param, si-01_odp.03 }} system and information integrity policy addresses roles; the {{ insert: param, si-01_odp.03 }} system and information integrity policy addresses responsibilities; the {{ insert: param, si-01_odp.03 }} system and information integrity policy addresses management commitment; the {{ insert: param, si-01_odp.03 }} system and information integrity policy addresses coordination among organizational entities; the {{ insert: param, si-01_odp.03 }} system and information integrity policy addresses compliance; the {{ insert: param, si-01_odp.03 }} system and information integrity policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, si-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the system and information integrity policy and procedures; the current system and information integrity policy is reviewed and updated {{ insert: param, si-01_odp.05 }}; the current system and information integrity policy is reviewed and updated following {{ insert: param, si-01_odp.06 }}; the current system and information integrity procedures are reviewed and updated {{ insert: param, si-01_odp.07 }}; the current system and information integrity procedures are reviewed and updated following {{ insert: param, si-01_odp.08 }}. System and information integrity policy

system and information integrity procedures

system security plan

privacy plan

other relevant documents or records Organizational personnel with system and information integrity responsibilities

organizational personnel with information security and privacy responsibilities

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-6: Verify the correct operation of {{ insert: param, si-6_prm_1 }}; Perform the verification of the functions specified in SI-6a {{ insert: param, si-06_odp.03 }}; Alert {{ insert: param, si-06_odp.06 }} to failed security and privacy verification tests; and {{ insert: param, si-06_odp.07 }} when anomalies are discovered. Transitional states for systems include system startup, restart, shutdown, and abort. System notifications include hardware indicator lights, electronic alerts to system administrators, and messages to local computer consoles. In contrast to security function verification, privacy function verification ensures that privacy functions operate as expected and are approved by the senior agency official for privacy or that privacy attributes are applied or used as expected. {{ insert: param, si-06_odp.01 }} are verified to be operating correctly; {{ insert: param, si-06_odp.02 }} are verified to be operating correctly; {{ insert: param, si-06_odp.01 }} are verified {{ insert: param, si-06_odp.03 }}; {{ insert: param, si-06_odp.02 }} are verified {{ insert: param, si-06_odp.03 }}; {{ insert: param, si-06_odp.06 }} is/are alerted to failed security verification tests; {{ insert: param, si-06_odp.06 }} is/are alerted to failed privacy verification tests; {{ insert: param, si-06_odp.07 }} is/are initiated when anomalies are discovered. System and information integrity policy

system and information integrity procedures

procedures addressing security and privacy function verification

system design documentation

system configuration settings and associated documentation

alerts/notifications of failed security verification tests

list of system transition states requiring security functionality verification

system audit records

system security plan

privacy plan

other relevant documents or records Organizational personnel with security and privacy function verification responsibilities

organizational personnel implementing, operating, and maintaining the system

system/network administrators

organizational personnel with information security and privacy responsibilities

system developer Organizational processes for security and privacy function verification

mechanisms supporting and/or implementing the security and privacy function verification capability

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-7: Employ integrity verification tools to detect unauthorized changes to the following software, firmware, and information: {{ insert: param, si-7_prm_1 }} ; and Take the following actions when unauthorized changes to the software, firmware, and information are detected: {{ insert: param, si-7_prm_2 }}. Unauthorized changes to software, firmware, and information can occur due to errors or malicious activity. Software includes operating systems (with key internal components, such as kernels or drivers), middleware, and applications. Firmware interfaces include Unified Extensible Firmware Interface (UEFI) and Basic Input/Output System (BIOS). Information includes personally identifiable information and metadata that contains security and privacy attributes associated with information. Integrity-checking mechanisms—including parity checks, cyclical redundancy checks, cryptographic hashes, and associated tools—can automatically monitor the integrity of systems and hosted applications. integrity verification tools are employed to detect unauthorized changes to {{ insert: param, si-07_odp.01 }}; integrity verification tools are employed to detect unauthorized changes to {{ insert: param, si-07_odp.02 }}; integrity verification tools are employed to detect unauthorized changes to {{ insert: param, si-07_odp.03 }}; {{ insert: param, si-07_odp.04 }} are taken when unauthorized changes to the software, are detected; {{ insert: param, si-07_odp.05 }} are taken when unauthorized changes to the firmware are detected; {{ insert: param, si-07_odp.06 }} are taken when unauthorized changes to the information are detected. System and information integrity policy

system and information integrity procedures

procedures addressing software, firmware, and information integrity

personally identifiable information processing policy

system design documentation

system configuration settings and associated documentation

integrity verification tools and associated documentation

records generated or triggered by integrity verification tools regarding unauthorized software, firmware, and information changes

system audit records

system security plan

privacy plan

other relevant documents or records Organizational personnel responsible for software, firmware, and/or information integrity

organizational personnel with information security and privacy responsibilities

system/network administrators Software, firmware, and information integrity verification tools

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-8: Employ spam protection mechanisms at system entry and exit points to detect and act on unsolicited messages; and Update spam protection mechanisms when new releases are available in accordance with organizational configuration management policy and procedures. System entry and exit points include firewalls, remote-access servers, electronic mail servers, web servers, proxy servers, workstations, notebook computers, and mobile devices. Spam can be transported by different means, including email, email attachments, and web accesses. Spam protection mechanisms include signature definitions. spam protection mechanisms are employed at system entry points to detect unsolicited messages; spam protection mechanisms are employed at system exit points to detect unsolicited messages; spam protection mechanisms are employed at system entry points to act on unsolicited messages; spam protection mechanisms are employed at system exit points to act on unsolicited messages; spam protection mechanisms are updated when new releases are available in accordance with organizational configuration management policies and procedures. System and information integrity policy

system and information integrity procedures

configuration management policies and procedures (CM-01)

procedures addressing spam protection

spam protection mechanisms

records of spam protection updates

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records Organizational personnel responsible for spam protection

organizational personnel with information security responsibilities

system/network administrators

system developer Organizational processes for implementing spam protection

mechanisms supporting and/or implementing spam protection

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-9: 

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-10: Check the validity of the following information inputs: {{ insert: param, si-10_odp }}. Checking the valid syntax and semantics of system inputs—including character set, length, numerical range, and acceptable values—verifies that inputs match specified definitions for format and content. For example, if the organization specifies that numerical values between 1-100 are the only acceptable inputs for a field in a given application, inputs of "387," "abc," or "%K%" are invalid inputs and are not accepted as input to the system. Valid inputs are likely to vary from field to field within a software application. Applications typically follow well-defined protocols that use structured messages (i.e., commands or queries) to communicate between software modules or system components. Structured messages can contain raw or unstructured data interspersed with metadata or control information. If software applications use attacker-supplied inputs to construct structured messages without properly encoding such messages, then the attacker could insert malicious commands or special characters that can cause the data to be interpreted as control information or metadata. Consequently, the module or component that receives the corrupted output will perform the wrong operations or otherwise interpret the data incorrectly. Prescreening inputs prior to passing them to interpreters prevents the content from being unintentionally interpreted as commands. Input validation ensures accurate and correct inputs and prevents attacks such as cross-site scripting and a variety of injection attacks. the validity of the {{ insert: param, si-10_odp }} is checked. System and information integrity policy

system and information integrity procedures

access control policy and procedures

separation of duties policy and procedures

procedures addressing information input validation

documentation for automated tools and applications to verify the validity of information

list of information inputs requiring validity checks

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records Organizational personnel responsible for information input validation

organizational personnel with information security responsibilities

system/network administrators

system developer Mechanisms supporting and/or implementing validity checks on information inputs

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-11: Generate error messages that provide information necessary for corrective actions without revealing information that could be exploited; and Reveal error messages only to {{ insert: param, si-11_odp }}. Organizations consider the structure and content of error messages. The extent to which systems can handle error conditions is guided and informed by organizational policy and operational requirements. Exploitable information includes stack traces and implementation details; erroneous logon attempts with passwords mistakenly entered as the username; mission or business information that can be derived from, if not stated explicitly by, the information recorded; and personally identifiable information, such as account numbers, social security numbers, and credit card numbers. Error messages may also provide a covert channel for transmitting information. error messages that provide the information necessary for corrective actions are generated without revealing information that could be exploited; error messages are revealed only to {{ insert: param, si-11_odp }}. System and information integrity policy

system and information integrity procedures

procedures addressing system error handling

system design documentation

system configuration settings and associated documentation

documentation providing the structure and content of error messages

system audit records

system security plan

other relevant documents or records Organizational personnel responsible for information input validation

organizational personnel with information security responsibilities

system/network administrators

system developer Organizational processes for error handling

automated mechanisms supporting and/or implementing error handling

automated mechanisms supporting and/or implementing the management of error messages

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-12: Manage and retain information within the system and information output from the system in accordance with applicable laws, executive orders, directives, regulations, policies, standards, guidelines and operational requirements. Information management and retention requirements cover the full life cycle of information, in some cases extending beyond system disposal. Information to be retained may also include policies, procedures, plans, reports, data output from control implementation, and other types of administrative information. The National Archives and Records Administration (NARA) provides federal policy and guidance on records retention and schedules. If organizations have a records management office, consider coordinating with records management personnel. Records produced from the output of implemented controls that may require management and retention include, but are not limited to: All XX-1, [AC-6(9)](#ac-6.9), [AT-4](#at-4), [AU-12](#au-12), [CA-2](#ca-2), [CA-3](#ca-3), [CA-5](#ca-5), [CA-6](#ca-6), [CA-7](#ca-7), [CA-8](#ca-8), [CA-9](#ca-9), [CM-2](#cm-2), [CM-3](#cm-3), [CM-4](#cm-4), [CM-6](#cm-6), [CM-8](#cm-8), [CM-9](#cm-9), [CM-12](#cm-12), [CM-13](#cm-13), [CP-2](#cp-2), [IR-6](#ir-6), [IR-8](#ir-8), [MA-2](#ma-2), [MA-4](#ma-4), [PE-2](#pe-2), [PE-8](#pe-8), [PE-16](#pe-16), [PE-17](#pe-17), [PL-2](#pl-2), [PL-4](#pl-4), [PL-7](#pl-7), [PL-8](#pl-8), [PM-5](#pm-5), [PM-8](#pm-8), [PM-9](#pm-9), [PM-18](#pm-18), [PM-21](#pm-21), [PM-27](#pm-27), [PM-28](#pm-28), [PM-30](#pm-30), [PM-31](#pm-31), [PS-2](#ps-2), [PS-6](#ps-6), [PS-7](#ps-7), [PT-2](#pt-2), [PT-3](#pt-3), [PT-7](#pt-7), [RA-2](#ra-2), [RA-3](#ra-3), [RA-5](#ra-5), [RA-8](#ra-8), [SA-4](#sa-4), [SA-5](#sa-5), [SA-8](#sa-8), [SA-10](#sa-10), [SI-4](#si-4), [SR-2](#sr-2), [SR-4](#sr-4), [SR-8](#sr-8). information within the system is managed in accordance with applicable laws, Executive Orders, directives, regulations, policies, standards, guidelines, and operational requirements; information within the system is retained in accordance with applicable laws, Executive Orders, directives, regulations, policies, standards, guidelines, and operational requirements; information output from the system is managed in accordance with applicable laws, Executive Orders, directives, regulations, policies, standards, guidelines, and operational requirements; information output from the system is retained in accordance with applicable laws, Executive Orders, directives, regulations, policies, standards, guidelines, and operational requirements. System and information integrity policy

system and information integrity procedures

personally identifiable information processing policy

records retention and disposition policy

records retention and disposition procedures

federal laws, Executive Orders, directives, policies, regulations, standards, and operational requirements applicable to information management and retention

media protection policy

media protection procedures

audit findings

system security plan

privacy plan

privacy program plan

personally identifiable information inventory

privacy impact assessment

privacy risk assessment documentation

other relevant documents or records Organizational personnel with information and records management, retention, and disposition responsibilities

organizational personnel with information security and privacy responsibilities

network administrators Organizational processes for information management, retention, and disposition

automated mechanisms supporting and/or implementing information management, retention, and disposition

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-13: Determine mean time to failure (MTTF) for the following system components in specific environments of operation: {{ insert: param, si-13_odp.01 }} ; and Provide substitute system components and a means to exchange active and standby components in accordance with the following criteria: {{ insert: param, si-13_odp.02 }}. While MTTF is primarily a reliability issue, predictable failure prevention is intended to address potential failures of system components that provide security capabilities. Failure rates reflect installation-specific consideration rather than the industry-average. Organizations define the criteria for the substitution of system components based on the MTTF value with consideration for the potential harm from component failures. The transfer of responsibilities between active and standby components does not compromise safety, operational readiness, or security capabilities. The preservation of system state variables is also critical to help ensure a successful transfer process. Standby components remain available at all times except for maintenance issues or recovery failures in progress. mean time to failure (MTTF) is determined for {{ insert: param, si-13_odp.01 }} in specific environments of operation; substitute system components and a means to exchange active and standby components are provided in accordance with {{ insert: param, si-13_odp.02 }}. System and information integrity policy

system and information integrity procedures

procedures addressing predictable failure prevention

system design documentation

system configuration settings and associated documentation

list of MTTF substitution criteria

system audit records

system security plan

other relevant documents or records Organizational personnel responsible for MTTF determinations and activities

organizational personnel with information security responsibilities

system/network administrators

organizational personnel with contingency planning responsibilities Organizational processes for managing MTTF

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-14: Implement non-persistent {{ insert: param, si-14_odp.01 }} that are initiated in a known state and terminated {{ insert: param, si-14_odp.02 }}. Implementation of non-persistent components and services mitigates risk from advanced persistent threats (APTs) by reducing the targeting capability of adversaries (i.e., window of opportunity and available attack surface) to initiate and complete attacks. By implementing the concept of non-persistence for selected system components, organizations can provide a trusted, known state computing resource for a specific time period that does not give adversaries sufficient time to exploit vulnerabilities in organizational systems or operating environments. Since the APT is a high-end, sophisticated threat with regard to capability, intent, and targeting, organizations assume that over an extended period, a percentage of attacks will be successful. Non-persistent system components and services are activated as required using protected information and terminated periodically or at the end of sessions. Non-persistence increases the work factor of adversaries attempting to compromise or breach organizational systems.

Non-persistence can be achieved by refreshing system components, periodically reimaging components, or using a variety of common virtualization techniques. Non-persistent services can be implemented by using virtualization techniques as part of virtual machines or as new instances of processes on physical machines (either persistent or non-persistent). The benefit of periodic refreshes of system components and services is that it does not require organizations to first determine whether compromises of components or services have occurred (something that may often be difficult to determine). The refresh of selected system components and services occurs with sufficient frequency to prevent the spread or intended impact of attacks, but not with such frequency that it makes the system unstable. Refreshes of critical components and services may be done periodically to hinder the ability of adversaries to exploit optimum windows of vulnerabilities. non-persistent {{ insert: param, si-14_odp.01 }} that are initiated in a known state are implemented; non-persistent {{ insert: param, si-14_odp.01 }} are terminated {{ insert: param, si-14_odp.02 }}. System and information integrity policy

system and information integrity procedures

procedures addressing non-persistence for system components

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records Organizational personnel responsible for non-persistence

organizational personnel with information security responsibilities

system/network administrators

system developer Automated mechanisms supporting and/or implementing the initiation and termination of non-persistent components

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-15: Validate information output from the following software programs and/or applications to ensure that the information is consistent with the expected content: {{ insert: param, si-15_odp }}. Certain types of attacks, including SQL injections, produce output results that are unexpected or inconsistent with the output results that would be expected from software programs or applications. Information output filtering focuses on detecting extraneous content, preventing such extraneous content from being displayed, and then alerting monitoring tools that anomalous behavior has been discovered. information output from {{ insert: param, si-15_odp }} is validated to ensure that the information is consistent with the expected content. System and information integrity policy

system and information integrity procedures

procedures addressing information output filtering

system design documentation

system configuration settings and associated documentation

system audit records

system security plan

other relevant documents or records Organizational personnel responsible for validating information output

organizational personnel with information security responsibilities

system/network administrators

system developer Organizational processes for validating information output

automated mechanisms supporting and/or implementing information output validation

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-16: Implement the following controls to protect the system memory from unauthorized code execution: {{ insert: param, si-16_odp }}. Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Controls employed to protect memory include data execution prevention and address space layout randomization. Data execution prevention controls can either be hardware-enforced or software-enforced with hardware enforcement providing the greater strength of mechanism. {{ insert: param, si-16_odp }} are implemented to protect the system memory from unauthorized code execution. System and information integrity policy

system and information integrity procedures

procedures addressing memory protection for the system

system design documentation

system configuration settings and associated documentation

list of security safeguards protecting system memory from unauthorized code execution

system audit records

system security plan

other relevant documents or records Organizational personnel responsible for memory protection

organizational personnel with information security responsibilities

system/network administrators

system developer Automated mechanisms supporting and/or implementing safeguards to protect the system memory from unauthorized code execution

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-17: Implement the indicated fail-safe procedures when the indicated failures occur: {{ insert: param, si-17_prm_1 }}. Failure conditions include the loss of communications among critical system components or between system components and operational facilities. Fail-safe procedures include alerting operator personnel and providing specific instructions on subsequent steps to take. Subsequent steps may include doing nothing, reestablishing system settings, shutting down processes, restarting the system, or contacting designated organizational personnel. {{ insert: param, si-17_odp.01 }} are implemented when {{ insert: param, si-17_odp.02 }} occur. System and information integrity policy

system and information integrity procedures

documentation addressing fail-safe procedures for the system

system design documentation

system configuration settings and associated documentation

list of security safeguards protecting the system memory from unauthorized code execution

system audit records

system security plan

other relevant documents or records Organizational personnel responsible for fail-safe procedures

organizational personnel with information security responsibilities

system/network administrators

system developer Organizational fail-safe procedures

automated mechanisms supporting and/or implementing fail-safe procedures

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-18: Check the accuracy, relevance, timeliness, and completeness of personally identifiable information across the information life cycle {{ insert: param, si-18_prm_1 }} ; and Correct or delete inaccurate or outdated personally identifiable information. Personally identifiable information quality operations include the steps that organizations take to confirm the accuracy and relevance of personally identifiable information throughout the information life cycle. The information life cycle includes the creation, collection, use, processing, storage, maintenance, dissemination, disclosure, and disposal of personally identifiable information. Personally identifiable information quality operations include editing and validating addresses as they are collected or entered into systems using automated address verification look-up application programming interfaces. Checking personally identifiable information quality includes the tracking of updates or changes to data over time, which enables organizations to know how and what personally identifiable information was changed should erroneous information be identified. The measures taken to protect personally identifiable information quality are based on the nature and context of the personally identifiable information, how it is to be used, how it was obtained, and the potential de-identification methods employed. The measures taken to validate the accuracy of personally identifiable information used to make determinations about the rights, benefits, or privileges of individuals covered under federal programs may be more comprehensive than the measures used to validate personally identifiable information used for less sensitive purposes. the accuracy of personally identifiable information across the information life cycle is checked {{ insert: param, si-18_odp.01 }}; the relevance of personally identifiable information across the information life cycle is checked {{ insert: param, si-18_odp.02 }}; the timeliness of personally identifiable information across the information life cycle is checked {{ insert: param, si-18_odp.03 }}; the completeness of personally identifiable information across the information life cycle is checked {{ insert: param, si-18_odp.04 }}; inaccurate or outdated personally identifiable information is corrected or deleted. System and information integrity policy

system and information integrity procedures

personally identifiable information processing policy

documentation addressing personally identifiable information quality operations

quality reports

maintenance logs

system audit records

audit findings

system security plan

privacy plan

privacy impact assessment

privacy risk assessment documentation

other relevant documents or records Organizational personnel responsible for performing personally identifiable information quality inspections

organizational personnel with information security responsibilities

organizational personnel with privacy responsibilities Organizational processes for personally identifiable information quality inspection

automated mechanisms supporting and/or implementing personally identifiable information quality operations

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-19: Remove the following elements of personally identifiable information from datasets: {{ insert: param, si-19_odp.01 }} ; and Evaluate {{ insert: param, si-19_odp.02 }} for effectiveness of de-identification. De-identification is the general term for the process of removing the association between a set of identifying data and the data subject. Many datasets contain information about individuals that can be used to distinguish or trace an individual’s identity, such as name, social security number, date and place of birth, mother’s maiden name, or biometric records. Datasets may also contain other information that is linked or linkable to an individual, such as medical, educational, financial, and employment information. Personally identifiable information is removed from datasets by trained individuals when such information is not (or no longer) necessary to satisfy the requirements envisioned for the data. For example, if the dataset is only used to produce aggregate statistics, the identifiers that are not needed for producing those statistics are removed. Removing identifiers improves privacy protection since information that is removed cannot be inadvertently disclosed or improperly used. Organizations may be subject to specific de-identification definitions or methods under applicable laws, regulations, or policies. Re-identification is a residual risk with de-identified data. Re-identification attacks can vary, including combining new datasets or other improvements in data analytics. Maintaining awareness of potential attacks and evaluating for the effectiveness of the de-identification over time support the management of this residual risk. {{ insert: param, si-19_odp.01 }} are removed from datasets; the effectiveness of de-identification is evaluated {{ insert: param, si-19_odp.02 }}. System and information integrity policy

system and information integrity procedures

personally identifiable information processing policy

de-identification procedures

system configuration

datasets with personally identifiable information removed

system security plan

privacy plan

privacy impact assessment

privacy risk assessment documentation

other relevant documents or records Organizational personnel responsible for identifying unnecessary identifiers

organizational personnel responsible for removing personally identifiable information from datasets

organizational personnel with information security and privacy responsibilities Automated mechanisms supporting and/or implementing the removal of personally identifiable information elements

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-20: Embed data or capabilities in the following systems or system components to determine if organizational data has been exfiltrated or improperly removed from the organization: {{ insert: param, si-20_odp }}. Many cyber-attacks target organizational information, or information that the organization holds on behalf of other entities (e.g., personally identifiable information), and exfiltrate that data. In addition, insider attacks and erroneous user procedures can remove information from the system that is in violation of the organizational policies. Tainting approaches can range from passive to active. A passive tainting approach can be as simple as adding false email names and addresses to an internal database. If the organization receives email at one of the false email addresses, it knows that the database has been compromised. Moreover, the organization knows that the email was sent by an unauthorized entity, so any packets it includes potentially contain malicious code, and that the unauthorized entity may have potentially obtained a copy of the database. Another tainting approach can include embedding false data or steganographic data in files to enable the data to be found via open-source analysis. Finally, an active tainting approach can include embedding software in the data that is able to "call home," thereby alerting the organization to its "capture," and possibly its location, and the path by which it was exfiltrated or removed. data or capabilities are embedded in {{ insert: param, si-20_odp }} to determine if organizational data has been exfiltrated or improperly removed from the organization. System and information integrity policy

system and information integrity procedures

personally identifiable information processing policy

procedures addressing software and information integrity

system design documentation

system configuration settings and associated documentation

policy and procedures addressing the systems security engineering technique of deception

system security plan

privacy plan

other relevant documents or records Organizational personnel responsible for detecting tainted data

organizational personnel with systems security engineering responsibilities

organizational personnel with information security and privacy responsibilities Automated mechanisms for post-breach detection

decoys, traps, lures, and methods for deceiving adversaries

detection and notification mechanisms

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-21: Refresh {{ insert: param, si-21_odp.01 }} at {{ insert: param, si-21_odp.02 }} or generate the information on demand and delete the information when no longer needed. Retaining information for longer than it is needed makes it an increasingly valuable and enticing target for adversaries. Keeping information available for the minimum period of time needed to support organizational missions or business functions reduces the opportunity for adversaries to compromise, capture, and exfiltrate that information. the {{ insert: param, si-21_odp.01 }} is refreshed {{ insert: param, si-21_odp.02 }} or is generated on demand and deleted when no longer needed. System and information integrity policy

system and information integrity procedures

personally identifiable information processing policy

procedures addressing software and information integrity

system design documentation

system configuration settings and associated documentation

information refresh procedures

list of information to be refreshed

system security plan

privacy plan

other relevant documents or records Organizational personnel responsible for refreshing information

organizational personnel with information security and privacy responsibilities

organizational personnel with systems security engineering responsibilities

system developers Mechanisms for information refresh

organizational processes for information refresh

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-22: Identify the following alternative sources of information for {{ insert: param, si-22_odp.02 }}: {{ insert: param, si-22_odp.01 }} ; and Use an alternative information source for the execution of essential functions or services on {{ insert: param, si-22_odp.03 }} when the primary source of information is corrupted or unavailable. Actions taken by a system service or a function are often driven by the information it receives. Corruption, fabrication, modification, or deletion of that information could impact the ability of the service function to properly carry out its intended actions. By having multiple sources of input, the service or function can continue operation if one source is corrupted or no longer available. It is possible that the alternative sources of information may be less precise or less accurate than the primary source of information. But having such sub-optimal information sources may still provide a sufficient level of quality that the essential service or function can be carried out, even in a degraded or debilitated manner. {{ insert: param, si-22_odp.01 }} for {{ insert: param, si-22_odp.02 }} are identified; an alternative information source is used for the execution of essential functions or services on {{ insert: param, si-22_odp.03 }} when the primary source of information is corrupted or unavailable. System and information integrity policy

system and information integrity procedures

personally identifiable information processing policy

system design documentation

system configuration settings and associated documentation

list of information sources

system security plan

privacy plan

other relevant documents or records Organizational personnel with information security and privacy responsibilities

organizational personnel with systems security engineering responsibilities

system developers Automated methods and mechanisms to convert information from an analog to digital medium

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SI-23: Based on {{ insert: param, si-23_odp.01 }}: Fragment the following information: {{ insert: param, si-23_odp.02 }} ; and Distribute the fragmented information across the following systems or system components: {{ insert: param, si-23_odp.03 }}. One objective of the advanced persistent threat is to exfiltrate valuable information. Once exfiltrated, there is generally no way for the organization to recover the lost information. Therefore, organizations may consider dividing the information into disparate elements and distributing those elements across multiple systems or system components and locations. Such actions will increase the adversary’s work factor to capture and exfiltrate the desired information and, in so doing, increase the probability of detection. The fragmentation of information impacts the organization’s ability to access the information in a timely manner. The extent of the fragmentation is dictated by the impact or classification level (and value) of the information, threat intelligence information received, and whether data tainting is used (i.e., data tainting-derived information about the exfiltration of some information could result in the fragmentation of the remaining information). under {{ insert: param, si-23_odp.01 }}, {{ insert: param, si-23_odp.02 }} is fragmented; under {{ insert: param, si-23_odp.01 }} , the fragmented information is distributed across {{ insert: param, si-23_odp.03 }}. System and information integrity policy

system and information integrity procedures

personally identifiable information processing policy

procedures addressing software and information integrity

system design documentation

system configuration settings and associated documentation

procedures to identify information for fragmentation and distribution across systems/system components

list of distributed and fragmented information

list of circumstances requiring information fragmentation

enterprise architecture

system security architecture

system security plan

privacy plan

other relevant documents or records Organizational personnel with information security and privacy responsibilities

organizational personnel with systems security engineering responsibilities

system developers

security architects Organizational processes to identify information for fragmentation and distribution across systems/system components

automated mechanisms supporting and/or implementing information fragmentation and distribution across systems/system components

**FedRAMP Baseline:** L2 | **Domain:** SI

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### SR — Supply Chain Risk Management (Manual Controls)

##### Control SR-1: Develop, document, and disseminate to {{ insert: param, sr-1_prm_1 }}: {{ insert: param, sr-01_odp.03 }} supply chain risk management policy that: Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and Procedures to facilitate the implementation of the supply chain risk management policy and the associated supply chain risk management controls; Designate an {{ insert: param, sr-01_odp.04 }} to manage the development, documentation, and dissemination of the supply chain risk management policy and procedures; and Review and update the current supply chain risk management: Policy {{ insert: param, sr-01_odp.05 }} and following {{ insert: param, sr-01_odp.06 }} ; and Procedures {{ insert: param, sr-01_odp.07 }} and following {{ insert: param, sr-01_odp.08 }}. Supply chain risk management policy and procedures address the controls in the SR family as well as supply chain-related controls in other families that are implemented within systems and organizations. The risk management strategy is an important factor in establishing such policies and procedures. Policies and procedures contribute to security and privacy assurance. Therefore, it is important that security and privacy programs collaborate on the development of supply chain risk management policy and procedures. Security and privacy program policies and procedures at the organization level are preferable, in general, and may obviate the need for mission- or system-specific policies and procedures. The policy can be included as part of the general security and privacy policy or be represented by multiple policies that reflect the complex nature of organizations. Procedures can be established for security and privacy programs, for mission or business processes, and for systems, if needed. Procedures describe how the policies or controls are implemented and can be directed at the individual or role that is the object of the procedure. Procedures can be documented in system security and privacy plans or in one or more separate documents. Events that may precipitate an update to supply chain risk management policy and procedures include assessment or audit findings, security incidents or breaches, or changes in applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Simply restating controls does not constitute an organizational policy or procedure. a supply chain risk management policy is developed and documented; the supply chain risk management policy is disseminated to {{ insert: param, sr-01_odp.01 }}; supply chain risk management procedures to facilitate the implementation of the supply chain risk management policy and the associated supply chain risk management controls are developed and documented; the supply chain risk management procedures are disseminated to {{ insert: param, sr-01_odp.02 }}. the {{ insert: param, sr-01_odp.03 }} supply chain risk management policy addresses purpose; the {{ insert: param, sr-01_odp.03 }} supply chain risk management policy addresses scope;  {{ insert: param, sr-01_odp.03 }} supply chain risk management policy addresses roles; the {{ insert: param, sr-01_odp.03 }} supply chain risk management policy addresses responsibilities; the {{ insert: param, sr-01_odp.03 }} supply chain risk management policy addresses management commitment; the {{ insert: param, sr-01_odp.03 }} supply chain risk management policy addresses coordination among organizational entities; the {{ insert: param, sr-01_odp.03 }} supply chain risk management policy addresses compliance. the {{ insert: param, sr-01_odp.03 }} supply chain risk management policy is consistent with applicable laws, Executive Orders, directives, regulations, policies, standards, and guidelines; the {{ insert: param, sr-01_odp.04 }} is designated to manage the development, documentation, and dissemination of the supply chain risk management policy and procedures; the current supply chain risk management policy is reviewed and updated {{ insert: param, sr-01_odp.05 }}; the current supply chain risk management policy is reviewed and updated following {{ insert: param, sr-01_odp.06 }}; the current supply chain risk management procedures are reviewed and updated {{ insert: param, sr-01_odp.07 }}; the current supply chain risk management procedures are reviewed and updated following {{ insert: param, sr-01_odp.08 }}. Supply chain risk management policy

supply chain risk management procedures

system security plan

privacy plan

other relevant documents or records Organizational personnel with supply chain risk management responsibilities

organizational personnel with information security and privacy responsibilities

organizational personnel with acquisition responsibilities

organizational personnel with enterprise risk management responsibilities

**FedRAMP Baseline:** L2 | **Domain:** SR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SR-4: Document, monitor, and maintain valid provenance of the following systems, system components, and associated data: {{ insert: param, sr-04_odp }}. Every system and system component has a point of origin and may be changed throughout its existence. Provenance is the chronology of the origin, development, ownership, location, and changes to a system or system component and associated data. It may also include personnel and processes used to interact with or make modifications to the system, component, or associated data. Organizations consider developing procedures (see [SR-1](#sr-1) ) for allocating responsibilities for the creation, maintenance, and monitoring of provenance for systems and system components; transferring provenance documentation and responsibility between organizations; and preventing and monitoring for unauthorized changes to the provenance records. Organizations have methods to document, monitor, and maintain valid provenance baselines for systems, system components, and related data. These actions help track, assess, and document any changes to the provenance, including changes in supply chain elements or configuration, and help ensure non-repudiation of provenance information and the provenance change records. Provenance considerations are addressed throughout the system development life cycle and incorporated into contracts and other arrangements, as appropriate. valid provenance is documented for {{ insert: param, sr-04_odp }}; valid provenance is monitored for {{ insert: param, sr-04_odp }}; valid provenance is maintained for {{ insert: param, sr-04_odp }}. Supply chain risk management policy

supply chain risk management procedures

supply chain risk management plan

documentation of critical systems, critical system components, and associated data

documentation showing the history of ownership, custody, and location of and changes to critical systems or critical system components

system architecture

inter-organizational agreements and procedures

contracts

system security plan

privacy plan

personally identifiable information processing policy

other relevant documents or records Organizational personnel with acquisition responsibilities

organizational personnel with information security and privacy responsibilities

organizational personnel with supply chain risk management responsibilities Organizational processes for identifying the provenance of critical systems and critical system components

mechanisms used to document, monitor, or maintain provenance

**FedRAMP Baseline:** L2 | **Domain:** SR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SR-5: Employ the following acquisition strategies, contract tools, and procurement methods to protect against, identify, and mitigate supply chain risks: {{ insert: param, sr-05_odp }}. The use of the acquisition process provides an important vehicle to protect the supply chain. There are many useful tools and techniques available, including obscuring the end use of a system or system component, using blind or filtered buys, requiring tamper-evident packaging, or using trusted or controlled distribution. The results from a supply chain risk assessment can guide and inform the strategies, tools, and methods that are most applicable to the situation. Tools and techniques may provide protections against unauthorized production, theft, tampering, insertion of counterfeits, insertion of malicious software or backdoors, and poor development practices throughout the system development life cycle. Organizations also consider providing incentives for suppliers who implement controls, promote transparency into their processes and security and privacy practices, provide contract language that addresses the prohibition of tainted or counterfeit components, and restrict purchases from untrustworthy suppliers. Organizations consider providing training, education, and awareness programs for personnel regarding supply chain risk, available mitigation strategies, and when the programs should be employed. Methods for reviewing and protecting development plans, documentation, and evidence are commensurate with the security and privacy requirements of the organization. Contracts may specify documentation protection requirements. {{ insert: param, sr-05_odp }} are employed to protect against supply chain risks; {{ insert: param, sr-05_odp }} are employed to identify supply chain risks; {{ insert: param, sr-05_odp }} are employed to mitigate supply chain risks. Supply chain risk management policy

supply chain risk management procedures

supply chain risk management plan

system and services acquisition policy

system and services acquisition procedures

procedures addressing supply chain protection

procedures addressing the integration of information security and privacy requirements into the acquisition process

solicitation documentation

acquisition documentation (including purchase orders)

service level agreements

acquisition contracts for systems, system components, or services

documentation of training, education, and awareness programs for personnel regarding supply chain risk

system security plan

privacy plan

other relevant documents or records Organizational personnel with acquisition responsibilities

organizational personnel with information security and privacy responsibilities

organizational personnel with supply chain risk management responsibilities Organizational processes for defining and employing tailored acquisition strategies, contract tools, and procurement methods

mechanisms supporting and/or implementing the definition and employment of tailored acquisition strategies, contract tools, and procurement methods

**FedRAMP Baseline:** L2 | **Domain:** SR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SR-6: Assess and review the supply chain-related risks associated with suppliers or contractors and the system, system component, or system service they provide {{ insert: param, sr-06_odp }}. An assessment and review of supplier risk includes security and supply chain risk management processes, foreign ownership, control or influence (FOCI), and the ability of the supplier to effectively assess subordinate second-tier and third-tier suppliers and contractors. The reviews may be conducted by the organization or by an independent third party. The reviews consider documented processes, documented controls, all-source intelligence, and publicly available information related to the supplier or contractor. Organizations can use open-source information to monitor for indications of stolen information, poor development and quality control practices, information spillage, or counterfeits. In some cases, it may be appropriate or required to share assessment and review results with other organizations in accordance with any applicable rules, policies, or inter-organizational agreements or contracts. the supply chain-related risks associated with suppliers or contractors and the systems, system components, or system services they provide are assessed and reviewed {{ insert: param, sr-06_odp }}. Supply chain risk management policy and procedures

supply chain risk management strategy

supply chain risk management plan

system and services acquisition policy

procedures addressing supply chain protection

procedures addressing the integration of information security requirements into the acquisition process

records of supplier due diligence reviews

system security plan

other relevant documents or records Organizational personnel with system and services acquisition responsibilities

organizational personnel with information security responsibilities

organizational personnel with supply chain protection responsibilities Organizational processes for conducting supplier reviews

mechanisms supporting and/or implementing supplier reviews

**FedRAMP Baseline:** L2 | **Domain:** SR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SR-7: Employ the following Operations Security (OPSEC) controls to protect supply chain-related information for the system, system component, or system service: {{ insert: param, sr-07_odp }}. Supply chain OPSEC expands the scope of OPSEC to include suppliers and potential suppliers. OPSEC is a process that includes identifying critical information, analyzing friendly actions related to operations and other activities to identify actions that can be observed by potential adversaries, determining indicators that potential adversaries might obtain that could be interpreted or pieced together to derive information in sufficient time to cause harm to organizations, implementing safeguards or countermeasures to eliminate or reduce exploitable vulnerabilities and risk to an acceptable level, and considering how aggregated information may expose users or specific uses of the supply chain. Supply chain information includes user identities; uses for systems, system components, and system services; supplier identities; security and privacy requirements; system and component configurations; supplier processes; design specifications; and testing and evaluation results. Supply chain OPSEC may require organizations to withhold mission or business information from suppliers and may include the use of intermediaries to hide the end use or users of systems, system components, or system services. {{ insert: param, sr-07_odp }} are employed to protect supply chain-related information for the system, system component, or system service. Supply chain risk management plan

supply chain risk management procedures

system and services acquisition policy

system and services acquisition procedures

procedures addressing supply chain protection

list of OPSEC controls to be employed

solicitation documentation

acquisition documentation

acquisition contracts for the system, system component, or system service

records of all-source intelligence analyses

system security plan

privacy plan

other relevant documents or records Organizational personnel with acquisition responsibilities

organizational personnel with information security and privacy responsibilities

organizational personnel with OPSEC responsibilities

organizational personnel with supply chain risk management responsibilities Organizational processes for defining and employing OPSEC safeguards

mechanisms supporting and/or implementing the definition and employment of OPSEC safeguards

**FedRAMP Baseline:** L2 | **Domain:** SR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SR-8: Establish agreements and procedures with entities involved in the supply chain for the system, system component, or system service for the {{ insert: param, sr-08_odp.01 }}. The establishment of agreements and procedures facilitates communications among supply chain entities. Early notification of compromises and potential compromises in the supply chain that can potentially adversely affect or have adversely affected organizational systems or system components is essential for organizations to effectively respond to such incidents. The results of assessments or audits may include open-source information that contributed to a decision or result and could be used to help the supply chain entity resolve a concern or improve its processes. agreements and procedures are established with entities involved in the supply chain for the system, system components, or system service for {{ insert: param, sr-08_odp.01 }}. Supply chain risk management policy and procedures

supply chain risk management plan

system and services acquisition policy

procedures addressing supply chain protection

acquisition documentation

service level agreements

acquisition contracts for the system, system component, or system service

inter-organizational agreements and procedures

system security plan

other relevant documents or records Organizational personnel with system and service acquisition responsibilities

organizational personnel with information security responsibilities

organizational personnel with supply chain risk management responsibilities Organizational processes for establishing inter-organizational agreements and procedures with supply chain entities

**FedRAMP Baseline:** L2 | **Domain:** SR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SR-9: Implement a tamper protection program for the system, system component, or system service. Anti-tamper technologies, tools, and techniques provide a level of protection for systems, system components, and services against many threats, including reverse engineering, modification, and substitution. Strong identification combined with tamper resistance and/or tamper detection is essential to protecting systems and components during distribution and when in use. a tamper protection program is implemented for the system, system component, or system service. Supply chain risk management policy and procedures

supply chain risk management plan

system and services acquisition policy

procedures addressing supply chain protection

procedures addressing tamper resistance and detection

tamper protection program documentation

tamper protection tools and techniques documentation

tamper resistance and detection tools and techniques documentation

acquisition documentation

service level agreements

acquisition contracts for the system, system component, or system service

system security plan

other relevant documents or records Organizational personnel with tamper protection program responsibilities

organizational personnel with information security responsibilities

organizational personnel with supply chain risk management responsibilities Organizational processes for the implementation of the tamper protection program

mechanisms supporting and/or implementing the tamper protection program

**FedRAMP Baseline:** L2 | **Domain:** SR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SR-10: Inspect the following systems or system components {{ insert: param, sr-10_odp.02 }} to detect tampering: {{ insert: param, sr-10_odp.01 }}. The inspection of systems or systems components for tamper resistance and detection addresses physical and logical tampering and is applied to systems and system components removed from organization-controlled areas. Indications of a need for inspection include changes in packaging, specifications, factory location, or entity in which the part is purchased, and when individuals return from travel to high-risk locations. {{ insert: param, sr-10_odp.01 }} are inspected {{ insert: param, sr-10_odp.02 }} to detect tampering. Supply chain risk management policy and procedures

supply chain risk management plan

system and services acquisition policy

records of random inspections

inspection reports/results

assessment reports/results

acquisition documentation

service level agreements

acquisition contracts for the system, system component, or system service

inter-organizational agreements and procedures

system security plan

other relevant documents or records Organizational personnel with system and services acquisition responsibilities

organizational personnel with information security responsibilities

organizational personnel with supply chain risk management responsibilities Organizational processes for establishing inter-organizational agreements and procedures with supply chain entities

organizational processes to inspect for tampering

**FedRAMP Baseline:** L2 | **Domain:** SR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Control SR-12: Dispose of {{ insert: param, sr-12_odp.01 }} using the following techniques and methods: {{ insert: param, sr-12_odp.02 }}. Data, documentation, tools, or system components can be disposed of at any time during the system development life cycle (not only in the disposal or retirement phase of the life cycle). For example, disposal can occur during research and development, design, prototyping, or operations/maintenance and include methods such as disk cleaning, removal of cryptographic keys, partial reuse of components. Opportunities for compromise during disposal affect physical and logical data, including system documentation in paper-based or digital files; shipping and delivery documentation; memory sticks with software code; or complete routers or servers that include permanent media, which contain sensitive or proprietary information. Additionally, proper disposal of system components helps to prevent such components from entering the gray market. {{ insert: param, sr-12_odp.01 }} are disposed of using {{ insert: param, sr-12_odp.02 }}. Supply chain risk management policy and procedures

supply chain risk management plan

disposal procedures addressing supply chain protection

media disposal policy

media protection policy

disposal records for system components

documentation of the system components identified for disposal

documentation of the disposal techniques and methods employed for system components

system security plan

other relevant documents or records Organizational personnel with system component disposal responsibilities

organizational personnel with information security responsibilities

organizational personnel with supply chain protection responsibilities Organizational techniques and methods for system component disposal

mechanisms supporting and/or implementing system component disposal

**FedRAMP Baseline:** L2 | **Domain:** SR

**Determination Criteria:**

- **Met:** All 0 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---


---

## 8. Appendix A — API Call Reference

Complete list of unique cloud API calls made by the scanner, organized by provider.

### AWS (117 unique API calls across 43 services)

| Service | API Call | Used By (Controls) |
|---------|---------|---------------------|
| ACM | `acm.list_certificates` | SC-12, SC-23 |
| API Gateway | `apigateway.get_rest_apis` | PT-4, SA-9.2, SC-10 |
| Athena | `athena.list_named_queries` | AU-7 |
| Backup | `backup.describe_backup_vault` | CP-9.8 |
| Backup | `backup.get_backup_vault_access_policy` | MP-4(2) |
| Backup | `backup.list_backup_vaults` | CP-9, CP-9.3, MP-4(2) |
| Backup | `backup.list_restore_jobs` | CP-9.1 |
| CloudFormation | `cloudformation.list_stacks` | SA-10 |
| CloudFront | `cloudfront.list_distributions` | SC-8 |
| CloudTrail | `cloudtrail.describe_trails` | AC-2(9), AU-2, AU-3, AU-6, CM-3 |
| CloudTrail | `cloudtrail.get_event_selectors` | AU-2 |
| CloudTrail | `cloudtrail.get_insight_selectors` | SI-4(4) |
| CloudWatch | `cloudwatch.describe_alarms` | AU-5 |
| CloudWatch | `cloudwatch.describe_anomaly_detectors` | SI-4(4) |
| CloudWatch | `logs.describe_log_groups` | AU-7 |
| CodeBuild | `codebuild.batch_get_projects` | SA-11, SR-3 |
| CodeBuild | `codebuild.list_projects` | SA-3 |
| CodeCommit | `codecommit.list_repositories` | SA-10 |
| CodeGuru | `codeguru-reviewer.list_repository_associations` | SA-11.1 |
| CodePipeline | `codepipeline.list_pipelines` | CM-5, SA-3 |
| Config | `config.describe_compliance_by_config_rule` | CA-7 |
| Config | `config.describe_config_rules` | CM-6 |
| Config | `config.describe_configuration_recorders` | CM-2 |
| Config | `config.describe_delivery_channels` | CM-3 |
| DynamoDB | `dynamodb.describe_continuous_backups` | CP-9 |
| DynamoDB | `dynamodb.describe_table` | SC-28(1) |
| EC2 | `ec2.describe_flow_logs` | PL-8 |
| EC2 | `ec2.describe_images` | CM-2 |
| EC2 | `ec2.describe_images()` | SC-7(8) |
| EC2 | `ec2.describe_instances` | AC-4(4), IA-2 |
| EC2 | `ec2.describe_instances()` | AU-8 |
| EC2 | `ec2.describe_regions + ec2.describe_instances` | CP-7 |
| EC2 | `ec2.describe_security_groups` | AC-17(3), CM-7, CM-7(1), SA-4.9, SC-7(21) |
| EC2 | `ec2.describe_snapshot_attribute` | SC-7(8) |
| EC2 | `ec2.describe_snapshots` | CP-9 |
| EC2 | `ec2.describe_volumes` | MP-4 |
| EC2 | `ec2.get_ebs_encryption_by_default` | AC-20(1), MP-4, SC-28(1) |
| EC2 + RDS | `ec2.describe_instances + rds.describe_db_instances` | CP-2, CP-10, PL-8, PT-3 |
| ECR | `ecr.describe_repositories` | RA-5 |
| ECR | `ecr.describe_repositories + ecr.get_registry_scanning_configuration` | SR-2 |
| ECR | `ecr.get_registry_policy + ecr.describe_repositories` | SR-11 |
| EFS | `efs.describe_file_systems` | MP-5 |
| ELB | `elbv2.describe_listeners` | SC-8 |
| ELB | `elbv2.describe_load_balancer_attributes` | SC-10 |
| ELB | `elbv2.describe_load_balancers() + describe_listeners()` | AC-17(2) |
| EventBridge | `events.list_rules` | IR-2 |
| GuardDuty | `events.list_rules()` | SI-5 |
| GuardDuty | `guardduty.get_detector` | CA-7, SC-7, SI-3, SI-3(1), SI-3(2) (+1 more) |
| GuardDuty | `guardduty.get_detector()` | SI-3, SI-3(2) |
| GuardDuty | `guardduty.list_detectors` | AC-7, IR-2 |
| GuardDuty | `guardduty.list_findings` | SI-4(4) |
| Health | `health.describe_events` | SI-5 |
| IAM | `accessanalyzer.list_analyzers` | AC-6 |
| IAM | `iam.generate_credential_report` | AC-2, IA-2(1), IA-3, IA-4(4) |
| IAM | `iam.get_account_password_policy` | AC-2, IA-5, IA-5(1) |
| IAM | `iam.get_account_summary` | AC-2, IA-3 |
| IAM | `iam.get_credential_report()` | IA-8 |
| IAM | `iam.get_policy_version` | AC-5, IA-2(1) |
| IAM | `iam.get_role` | AC-11 |
| IAM | `iam.list_entities_for_policy` | AC-6, AU-9(4) |
| IAM | `iam.list_mfa_devices` | IA-2(2) |
| IAM | `iam.list_policies` | AC-3 |
| IAM | `iam.list_roles` | AC-5, AC-6(3), AC-12, CM-5, CM-7 (+1 more) |
| IAM | `iam.list_saml_providers/list_open_id_connect_providers` | AC-20 |
| IAM | `iam.list_user_policies` | AC-6 |
| IAM | `iam.list_users` | AC-3, IA-2, IA-4 |
| IAM | `iam.list_users()` | AU-3 |
| IAM | `iam.list_virtual_mfa_devices` | IA-2(1) |
| IAM | `sts.get_caller_identity` | SC-13 |
| IAM Identity Center | `sso-admin.describe_instance` | AC-12 |
| IAM Identity Center | `sso-admin.list_instances()` | AC-7, IA-5(2) |
| Inspector | `inspector2.list_account_permissions` | RA-5, SI-3(2) |
| Inspector | `inspector2.list_findings` | RA-5, RA-5(5), SI-2 |
| Inspector2 | `inspector2.list_coverage` | SR-2 |
| Inspector2 | `inspector2.list_findings` | SA-22 |
| KMS | `kms.get_key_policy` | SC-12 |
| KMS | `kms.get_key_rotation_status` | SC-12 |
| Lambda | `lambda.list_functions` | SR-11 |
| Macie2 | `macie2.get_macie_session` | PT-2 |
| Multiple | `ec2/guardduty/cloudtrail/kms` | SC-7(5) |
| Network Firewall | `network-firewall.list_firewall_policies` | SI-4 |
| Network Firewall | `network-firewall.list_firewalls` | SC-7 |
| Organizations | `organizations.list_policies` | AC-2(9), AU-9(4), CM-7(1) |
| RDS | `rds.describe_db_instances` | CP-6, CP-9, CP-10.2, IA-8, MA-2 (+3 more) |
| RDS | `rds.describe_db_snapshots` | CP-9.8 |
| RDS | `rds.list_tags_for_resource` | PT-2 |
| ResilienceHub | `resiliencehub.list_app_assessments` | CP-4 |
| Route 53 | `route53.list_hosted_zones` | SC-23 |
| Route53 | `route53.list_health_checks` | CP-7 |
| S3 | `s3.get_bucket_encryption` | AU-9, MP-5, SC-13, SC-28(1) |
| S3 | `s3.get_bucket_lifecycle_configuration` | AU-2 |
| S3 | `s3.get_bucket_logging` | AU-9 |
| S3 | `s3.get_bucket_policy` | MP-4, SC-8 |
| S3 | `s3.get_bucket_policy_status` | AC-4(4) |
| S3 | `s3.get_bucket_replication` | CP-6, MP-4(2) |
| S3 | `s3.get_bucket_tagging` | PT-2 |
| S3 | `s3.get_bucket_versioning` | AU-9 |
| S3 | `s3control.get_public_access_block` | AC-3(8), AC-4 |
| SNS | `sns.list_topics()` | AU-5 |
| SSM | `iam.get_policy_version` | MA-4 |
| SSM | `ssm.describe_document` | AC-17(1) |
| SSM | `ssm.describe_instance_information` | AC-18, CM-2, SC-7(7) |
| SSM | `ssm.describe_instance_information()` | CM-8, SI-3(1) |
| SSM | `ssm.describe_instance_patch_states` | MA-2, RA-5(5), SI-2 |
| SSM | `ssm.describe_patch_baselines` | MA-2, SI-2 |
| SSM | `ssm.get_inventory` | SA-22 |
| SSM | `ssm.list_documents` | CM-7(5), IR-2, PL-2 |
| SSM | `ssm.list_inventory_entries` | SI-3 |
| STS | `iam.list_roles` | IA-2(2) |
| Security Hub | `events.list_rules()` | SI-5 |
| Security Hub | `securityhub.describe_hub` | AU-6, CA-7, IR-2 |
| Security Hub | `securityhub.describe_standards_subscriptions` | CM-6 |
| VPC | `ec2.describe_client_vpn_endpoints` | AC-17(3), MA-4, SC-7(7) |
| VPC | `ec2.describe_flow_logs` | AC-4, SC-7, SI-4 |
| VPC | `ec2.describe_nat_gateways` | SC-7(4) |
| VPC | `ec2.describe_network_acls` | SC-7(21) |
| VPC | `ec2.describe_subnets` | SC-7(4), SC-7(7) |
| VPC | `ec2.describe_transit_gateway_attachments` | AC-21 |
| VPC | `ec2.describe_vpc_peering_connections` | AC-21 |
| VPC | `ec2.describe_vpn_connections` | AC-17(1), AC-17(2) |
| VPC | `ec2.describe_vpn_connections/describe_client_vpn_endpoints` | AC-19 |
| WAFv2 | `wafv2.list_web_acls` | SC-7, SC-18 |

### Azure (88 unique API calls across 19 services)

| Service | API Call | Used By (Controls) |
|---------|---------|---------------------|
| Advisor | `advisor.recommendations.list` | CM-7 |
| App Service | `web.certificates.list` | SC-23 |
| App Service | `web.web_apps.list` | IA-8, SC-8, SI-2 |
| Authorization | `AuthorizationManagementClient.role_assignments.list_for_scope` | AC-2 |
| Authorization | `authorization.role_assignments.list` | AC-5, AU-9(4) |
| Authorization | `authorization.role_definitions.list` | AC-3 |
| Automation | `automation.automation_account.list + automation.runbook.list_by_automation_account` | SA-11 |
| Automation | `automation.automation_accounts.list` | CM-8 |
| Automation | `automation_account.list` | MA-2, RA-5(5) |
| Azure AD | `NetworkManagementClient.network_watchers.list_all + resources.list` | AU-2 |
| Azure AD | `graph.authentication_method_configurations.get` | IA-2(2) |
| Azure AD | `graph.authorization_policy.get` | AC-2 |
| Azure AD | `graph.conditional_access_policies.list` | AC-11, AC-18, IA-2(1), IA-3, MA-4 |
| Azure AD | `graph.deleted_users.list` | IA-4 |
| Azure AD | `graph.directory_roles.members.list` | AC-6 |
| Azure AD | `graph.identity_protection.risk_detections.list` | SI-4(4) |
| Azure AD | `graph.identity_protection.risky_users.list` | SI-4(4) |
| Azure AD | `graph.identity_security_defaults_enforcement_policy.get` | AC-2 |
| Azure AD | `graph.reports.credential_user_registration_details.list` | IA-3 |
| Azure AD | `graph.settings.list` | AC-7, IA-5, IA-5(1) |
| Azure AD | `graph.sign_in_logs.list` | AU-3 |
| Azure AD | `graph.token_lifetime_policies.list` | AC-12 |
| Azure AD | `graph.users.list` | IA-2, IA-4(4), IA-5(2) |
| Azure AD | `graph/directoryRoles/*/members` | AC-6(3) |
| Azure AD | `graph/roleManagement/directory/roleAssignmentScheduleInstances` | AC-3 |
| Compute | `StorageManagementClient.storage_accounts.list` | SC-13 |
| Compute | `compute.disks.list` | AC-20(1), MP-4, SC-7(8), SC-28(1) |
| Compute | `compute.virtual_machine_extensions.list` | SI-3, SI-3(2) |
| Compute | `compute.virtual_machines.list` | AU-8, IA-2, MA-2, SI-2 |
| Compute | `compute.virtual_machines.list_all` | CP-7 |
| Key Vault | `KeyVaultManagementClient.vaults.list + get` | SC-12 |
| Key Vault | `keyvault.vaults.list` | SC-12 |
| Monitor | `MonitorManagementClient.activity_log_alerts.list_by_subscription_id` | AU-2 |
| Monitor | `diagnostic_settings.list` | CM-3 |
| Monitor | `monitor.activity_log_alerts.list` | AC-2(9), AU-5, SI-5 |
| Monitor | `monitor.diagnostic_settings.list` | AU-2 |
| Monitor | `operationalinsights.workspaces.list` | AU-7, AU-9 |
| Multiple | `network/keyvault/monitor/security` | SC-7(5) |
| Network | `NetworkManagementClient.flow_logs.list` | PL-8 |
| Network | `NetworkManagementClient.network_security_groups.list_all` | SA-4.9 |
| Network | `network.application_gateways.list` | SC-10 |
| Network | `network.azure_firewalls.list` | AC-4, SC-7, SC-7(21), SI-4 |
| Network | `network.bastion_hosts.list` | AC-17(1) |
| Network | `network.network_security_groups.list` | AC-17(3), CM-7(1), SC-7(21) |
| Network | `network.virtual_network_gateway_connections.list` | AC-17(2) |
| Network | `network.virtual_network_gateways.list` | AC-19, SC-7(7) |
| Network | `network.virtual_network_peerings.list` | AC-21 |
| Network | `network.virtual_networks.list` | SC-7(4), SC-7(7) |
| Network | `network.web_application_firewall_policies.list` | SC-7, SC-18 |
| Network | `network_watchers.list_all + nsgs.list_all` | AC-4, SC-7, SI-4 |
| Policy | `policy.policy_assignments.list` | CM-6, PL-2, SA-10 |
| Policy | `policy.policy_states.list` | CA-7 |
| Policy | `policy_assignments.list` | CM-2 |
| Recovery Services | `RecoveryServicesBackupClient.backup_protected_items.list` | CP-9 |
| Recovery Services | `RecoveryServicesBackupClient.restore_jobs.list` | CP-9.1 |
| Recovery Services | `RecoveryServicesClient.replication_protected_items.list` | CP-10 |
| Recovery Services | `RecoveryServicesClient.vaults.list_by_subscription_id` | CP-9.3 |
| Recovery Services | `backup.backup_jobs.list` | CP-4 |
| Recovery Services | `recoveryservices.vaults.list` | CP-9.8, MP-4(2) |
| Resource Graph | `resourcegraph.resources` | CM-2 |
| Resources | `ResourceManagementClient.resources.list` | CP-2, PL-8, PT-3 |
| Resources | `resource.resources.list` | CP-7, PT-2, PT-4, SA-3, SA-9.2 (+2 more) |
| Resources | `resources.management_locks.list` | CM-5 |
| SQL | `SqlManagementClient.restorable_dropped_databases.list` | CP-10.2 |
| SQL | `sql.encryption_protectors.get` | SC-28(1) |
| SQL | `sql.server_vulnerability_assessments.get` | RA-5 |
| SQL | `sql.servers.list` | PT-2 |
| SQL | `sql.servers.list + sql.backup_short_term_retention_policies.get` | CP-9 |
| SQL | `sql.servers.list + sql.replication_links.list_by_database` | CP-6 |
| SQL | `sql.transparent_data_encryptions.get` | MP-5 |
| Security Center | `ResourceManagementClient.providers.get('Microsoft.Security')` | SI-4 |
| Security Center | `SecurityCenter.assessments.list` | SA-22 |
| Security Center | `assessments.list` | SI-3(2) |
| Security Center | `security.assessments.list` | CA-7, CM-7(5), RA-5(5), SR-3 |
| Security Center | `security.dev_ops_configurations.list` | SA-11.1 |
| Security Center | `security.jit_network_access_policies.list` | AC-6 |
| Security Center | `security.pricings.get` | RA-5, SI-3, SI-3(1) |
| Security Center | `security.pricings.list` | IR-2 |
| Security Center | `security.secure_scores.list` | CM-6 |
| Security Center | `security.security_contacts.list` | SI-5 |
| Security Center | `security.sub_assessments.list` | RA-5, SI-2 |
| Security/Authorization | `resource_client.providers.get/auth_client.role_assignments.list` | AC-20 |
| Sentinel | `securityinsight.automation_rules.list` | IR-2 |
| Sentinel | `securityinsight.sentinel_onboarding_states.list` | AU-6, IR-2 |
| Sentinel | `sentinel_onboarding_states.list` | SI-4(4) |
| Storage | `StorageManagementClient.blob_services.get_service_properties` | CP-9 |
| Storage | `StorageManagementClient.storage_accounts.list` | CP-6, PT-2 |
| Storage | `storage.storage_accounts.list` | AC-3(8), AC-4(4), MP-4, MP-5, SC-8 (+1 more) |
| Storage | `storage_accounts.list` | AU-9 |

### GCP (66 unique API calls across 33 services)

| Service | API Call | Used By (Controls) |
|---------|---------|---------------------|
| API Gateway | `apigateway.projects.locations.apis.list` | SA-9.2 |
| Artifact Registry | `artifactregistry.projects.locations.repositories.list` | SR-2 |
| Artifact Registry | `containeranalysis.projects.occurrences.list` | MA-2 |
| Asset Inventory | `cloudasset.assets.list` | CM-2 |
| Backup and DR | `backupdr.projects.locations.backupVaults.list` | MP-4(2) |
| BigQuery | `bigquery.datasets.list` | PT-2, SC-28(1) |
| Binary Authorization | `binaryauthorization.projects.getPolicy` | CM-7(5) |
| Binary Authorization | `binaryauthorization.projects.policy.get` | SR-11 |
| Cloud Armor | `compute.securityPolicies.list` | SC-7, SC-18 |
| Cloud Build | `cloudbuild.projects.builds.list` | SA-11, SA-11.1, SR-3 |
| Cloud Build | `cloudbuild.projects.triggers.list` | SA-3 |
| Cloud IDS | `ids.projects.locations.endpoints.list` | SI-4 |
| Cloud SQL | `sqladmin.instances.list` | CP-6, CP-9, CP-10.2, IA-8, MP-5 (+2 more) |
| Cloud Source Repositories | `sourcerepo.projects.repos.list` | SA-10 |
| Compute | `compute.backendServices.list` | SC-10 |
| Compute | `compute.disks.list` | MP-4 |
| Compute | `compute.firewalls.list` | AC-17(1) |
| Compute | `compute.images.getIamPolicy` | SC-7(8) |
| Compute | `compute.instances.list` | AU-8, SI-3, SI-3(1) |
| Compute | `compute.projects.get` | AC-18 |
| Compute | `compute.sslCertificates.list` | SC-23 |
| Compute | `compute.sslPolicies.list` | SC-8 |
| Compute Engine | `compute.backendServices.list` | CP-7 |
| Compute Engine | `compute.firewalls.list` | SA-4.9 |
| Compute Engine | `compute.instanceGroupManagers.aggregatedList` | CP-7 |
| Compute Engine | `compute.instances.aggregatedList` | CP-2, CP-10, PL-8 |
| Compute Engine | `compute.instances.aggregatedList + storage.buckets.list` | PT-3 |
| Compute Engine | `compute.resourcePolicies.list` | CP-9 |
| Compute Engine | `compute.snapshots.list` | CP-9.1, CP-9.3, CP-9.8 |
| Compute Engine | `compute.subnetworks.list` | PL-8 |
| Container Analysis | `containeranalysis.projects.occurrences.list` | RA-5, SI-2, SI-3(2) |
| DLP | `dlp.projects.dlpJobs.list` | PT-2 |
| GKE | `container.projects.locations.clusters.list` | SI-2 |
| IAM | `cloudresourcemanager.projects.getIamPolicy` | AC-2, AC-3, AC-5, AC-6, AC-6(3) (+2 more) |
| IAM | `compute.instances.list` | AC-2 |
| IAM | `iam.projects.roles.list` | AC-3 |
| IAM | `iam.projects.serviceAccounts.keys.list` | AC-2, IA-4(4) |
| IAM | `iam.projects.serviceAccounts.list` | AC-12, IA-2 |
| IAM | `recommender.projects.locations.recommenders.recommendations.list` | AC-6 |
| KMS | `cloudkms.projects.locations.keyRings.cryptoKeys.list` | SC-13 |
| KMS | `cloudkms.projects.locations.keyRings.getIamPolicy` | SC-12 |
| KMS | `kms_v1.KeyManagementServiceClient.list_key_rings` | SC-12 |
| Logging | `cloudresourcemanager.projects.getIamPolicy` | AU-2 |
| Logging | `logging.entries.list` | AU-3, CM-3, CP-4, SI-4(4) |
| Logging | `logging.projects.locations.buckets.list` | AU-7 |
| Logging | `logging.projects.logs.list` | AC-2(9), AU-2 |
| Logging | `logging.projects.sinks.list` | AU-2 |
| Monitoring | `monitoring.projects.alertPolicies.list` | AC-2(9), AU-5, SI-4(4), SI-5 |
| Multiple | `compute/kms/logging/orgpolicy` | SC-7(5) |
| OS Config | `compute.instances.aggregatedList` | CM-2 |
| OS Config | `osconfig.patchDeployments.list` | CM-8, RA-5(5) |
| OS Config | `osconfig.projects.patchDeployments.list` | MA-2, SI-2 |
| OrgPolicy | `BeyondCorp / session management` | AC-11 |
| OrgPolicy | `orgpolicy.projects.policies.get` | AC-3(8), AC-20 |
| OrgPolicy/Compute | `orgpolicy/compute.disks.list` | AC-20(1) |
| Organization Policy | `cloudresourcemanager.projects.getEffectiveOrgPolicy` | PL-2 |
| Organization Policy | `orgpolicy.projects.policies.list` | CA-7, CM-6 |
| Resource Manager | `cloudresourcemanager.liens.list` | CM-5 |
| SCC | `securitycenter.organizations.getOrganizationSettings` | CA-7, IR-2 |
| SCC | `securitycenter.organizations.notificationConfigs.list` | IR-2, SI-5 |
| SCC | `securitycenter.securityHealthAnalyticsSettings` | AU-6, CM-6, IR-2, RA-5, RA-5(5) (+2 more) |
| SCC | `websecurityscanner.projects.scanConfigs.list` | RA-5, SI-3(2) |
| Security Command Center | `securitycenter.organizations.findings.list` | SA-22 |
| Service Usage | `serviceusage.services.list` | PT-4 |
| Storage | `storage.buckets.get` | AU-9, CP-9, MP-5, PT-2, SC-28(1) |
| Storage | `storage.buckets.getIamPolicy` | AC-4(4), AU-9, MP-4 |
| Storage | `storage.buckets.list` | CP-6, SI-3 |
| VPC | `compute.firewalls.list` | AC-4, AC-17(3), CM-7, CM-7(1), SC-7(21) |
| VPC | `compute.networks.listPeering` | AC-21 |
| VPC | `compute.packetMirrorings.list` | SC-7 |
| VPC | `compute.subnetworks.list` | AC-4, SC-7, SC-7(4), SC-7(7), SI-4 |
| VPN | `compute.vpnGateways.list/vpnTunnels.list` | AC-19 |
| VPN | `compute.vpnTunnels.list` | AC-17(2), SC-7(7) |
| Workspace Admin | `admin.directory.users.list` | AC-7, IA-2(1), IA-2(2), IA-3, IA-4 (+4 more) |

---

## 9. Appendix B — Glossary

| Term | Definition |
|------|-----------|
| **3PAO** | Certified FedRAMP Assessor — individual authorized to conduct FedRAMP assessments |
| **3PAO** | FedRAMP Third-Party Assessment Organization — accredited organization that employs 3PAOs |
| **OSC** | Organization Seeking Certification — the CSP being assessed |
| **CUI** | Controlled Unclassified Information — sensitive government information requiring protection |
| **FCI** | Federal Contract Information — information provided by or generated for the government under contract |
| **DIB** | Defense Industrial Base — companies that supply products/services to the DoD |
| **CSP** | Cloud Service Provider — AWS, Azure, or GCP |
| **Met** | The control/objective is fully implemented based on automated or manual evidence |
| **Not Met** | The control/objective is not implemented or has deficiencies |
| **Manual Review** | The control requires 3PAO manual assessment — cannot be determined by automated checks alone |
| **Assessment Objective** | A specific "determine if" statement from NIST SP 800-53A that must be evaluated |
| **POA&M** | Plan of Action and Milestones — remediation plan for Not Met findings |
| **SSP** | System Security Plan — document describing the system boundary, environment, and security controls |
| **STS** | Security Token Service — AWS service for assuming cross-account roles |
| **IAM** | Identity and Access Management — cloud service for managing users, roles, and permissions |

---

## Document Information

This methodology reference is auto-generated from the scanner's configuration files (`config/nist_800_53_controls.json` and `config/checks/*.json`). All check definitions, objective mappings, and coverage data are derived directly from the scanner's authoritative data sources.

For the interactive version of this document, see the **Assessment Methodology** tab in the scanner's Help blade.
