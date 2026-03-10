# FedRAMP Cloud Compliance Scanner — Assessment Methodology

**Document Classification:** For Official Use — Assessment Staff Only

**Version:** 1.0 | **Date:** March 07, 2026 | **Author:** Securitybricks (3PAO, powered by Aprio)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Purpose and Audience](#2-purpose-and-audience)
3. [Authoritative Sources and Traceability](#3-authoritative-sources-and-traceability)
4. [Assessment Architecture](#4-assessment-architecture)
   - 4.1 [Check-to-Objective Mapping](#41-check-to-objective-mapping)
   - 4.2 [Three-Tier Evaluation Model](#42-three-tier-evaluation-model)
   - 4.3 [Cloud Provider API Baselines](#43-cloud-provider-api-baselines)
5. [Coverage Matrix Summary](#5-coverage-matrix-summary)
   - 5.1 [Overall Statistics](#51-overall-statistics)
   - 5.2 [Domain-Level Coverage](#52-domain-level-coverage)
   - 5.3 [Objective Automatable Classification](#53-objective-automatable-classification)
6. [Complete Practice Reference](#6-complete-practice-reference)
   - 6.1 [AC — Access Control](#ac--access-control)
   - 6.2 [AT — Awareness and Training](#at--awareness-and-training)
   - 6.3 [AU — Audit and Accountability](#au--audit-and-accountability)
   - 6.4 [CM — Configuration Management](#cm--configuration-management)
   - 6.5 [IA — Identification and Authentication](#ia--identification-and-authentication)
   - 6.6 [IR — Incident Response](#ir--incident-response)
   - 6.7 [MA — Maintenance](#ma--maintenance)
   - 6.8 [MP — Media Protection](#mp--media-protection)
   - 6.9 [PS — Personnel Security](#ps--personnel-security)
   - 6.10 [PE — Physical Protection](#pe--physical-protection)
   - 6.11 [RA — Risk Assessment](#ra--risk-assessment)
   - 6.12 [CA — Security Assessment](#ca--security-assessment)
   - 6.13 [SC — System and Communications Protection](#sc--system-and-communications-protection)
   - 6.14 [SI — System and Information Integrity](#si--system-and-information-integrity)
7. [CCA Manual Assessment Guide](#7-cca-manual-assessment-guide)
   - 7.1 [How to Use This Guide](#71-how-to-use-this-guide)
   - 7.2 [Manual Practice Reference](#72-manual-practice-reference)
8. [Appendix A — API Call Reference](#8-appendix-a--api-call-reference)
9. [Appendix B — Glossary](#9-appendix-b--glossary)

---

## 1. Executive Summary

The FedRAMP Cloud Compliance Scanner is an automated assessment tool built by Securitybricks, a FedRAMP Third-Party Assessment Organization (3PAO) powered by Aprio. It evaluates Defense Industrial Base (CSP) contractor cloud environments against FedRAMP requirements by querying cloud service provider (CSP) APIs and comparing configuration states to NIST SP 800-53 Rev 5 security practices.

This document serves as the **authoritative methodology reference** for FedRAMP Assessors (3PAOs) using the scanner. It explains:

- **How** each of the 110 NIST 800-53 Rev 5 controls is evaluated
- **Which** cloud APIs are queried and what constitutes a passing or failing check
- **Why** each check maps to specific NIST SP 800-53A assessment objectives
- **What** CCAs must do for the 39 controls that require manual assessment
- **Where** the authoritative sources and traceability chain originates

The scanner implements **393 cloud-specific technical checks** across AWS (164), Azure (115), and GCP (114), mapped to **319 NIST SP 800-53A assessment objectives** across all 110 controls and 14 FedRAMP control families.

---

## 2. Purpose and Audience

### Who Should Read This Document

| Role | How to Use This Document |
|------|------------------------|
| **Lead CCA** | Validate the scanner's methodology against 800-53A before accepting automated results |
| **CCA (Technical)** | Reference during assessment to understand what each check evaluates and which API responses constitute evidence |
| **CCA (Policy/Process)** | Use Section 7 as a structured guide for manual practice assessments — interview questions, evidence artifacts, and determination criteria |
| **Assessment Team Lead** | Review coverage matrix to understand which objectives are automated vs. manual |
| **Quality Assurance** | Verify traceability from check results back to 800-53A objectives |

### How This Document Builds Trust

For a CCA to rely on automated tool results in a FedRAMP assessment, they need to verify:

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
| **NIST SP 800-53 Rev 5** | Feb 2020 | 110 security practices across 14 families | [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-53 Rev 5/rev-2/final) |
| **NIST SP 800-53A** | Jun 2018 | 319 assessment objectives ("determine if" statements) | [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-53 Rev 5a/final) |
| **NIST SP 800-172** | Feb 2021 | Enhanced security practices for High | [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-172/final) |
| **FAR 52.204-21** | 2016 | 17 basic safeguarding practices for Low | [acquisition.gov](https://www.acquisition.gov/far/52.204-21) |
| **FedRAMP Model** | Dec 2021 | Three-level certification model | [dodcio.defense.gov](https://dodcio.defense.gov/FedRAMP/) |
| **AWS Config Rules** | Current | ~200 rules mapped to NIST 800-53 Rev 5 | [docs.aws.amazon.com](https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist_800-53 Rev 5.html) |
| **Azure Policy** | Current | ~200 policy definitions for NIST 800-53 Rev 5 R2 | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/governance/policy/samples/nist-sp-800-53 Rev 5-r2) |
| **GCP CIS Benchmark** | Current | GCP security controls aligned to NIST controls | [cloud.google.com](https://cloud.google.com/security/compliance/cis-benchmarks) |

### Traceability Chain

Every check in the scanner traces back through the following chain:

| Step | Stage | Description |
|------|-------|-------------|
| 1 | **FedRAMP Baseline** | L1 / L2 / L3 certification tier |
| 2 | **NIST SP 800-53 Rev 5 Practice** | One of 110 security requirements |
| 3 | **800-53A Assessment Objective** | Specific "determine if" statement |
| 4 | **Scanner Check** | Cloud-specific configuration test |
| 5 | **Cloud API Call** | Read-only query to AWS, Azure, or GCP |
| 6 | **Compliance Determination** | Met / Not Met / Manual Review |

Every finding in the scanner report traces back through this chain to the authoritative NIST standard.

---

## 4. Assessment Architecture

### 4.1 Check-to-Objective Mapping

NIST SP 800-53A defines **319 assessment objectives** across the 110 NIST SP 800-53 Rev 5 controls. Each objective is a discrete "determine if" statement that an assessor must evaluate.

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

**Objective [d]** for practice 3.1.1 states: *"system access is limited to authorized users."* Disabling root account access keys directly enforces this by preventing the most privileged account from using long-term credentials.

This mapping enables:
- **Per-objective coverage scoring** — the report shows which objectives are covered by automated checks, which require documentation, and which are not tested
- **Gap identification** — CCAs can immediately see which objectives need manual verification
- **Audit traceability** — every Met/Not Met determination links to specific 800-53A language

### 4.2 Three-Tier Evaluation Model

The scanner classifies every 800-53A assessment objective into one of three tiers:

| Tier | Classification | Count | Description |
|------|---------------|-------|-------------|
| **Tier 1** | Fully Automatable | 77 | Cloud API configuration check provides a definitive Met/Not Met determination |
| **Tier 2** | Partially Automatable | 139 | Cloud API provides supporting evidence, but CCA must verify organizational context |
| **Tier 3** | Not Automatable | 103 | Requires documentation review, interviews, or physical inspection |

**Tier 1 — Fully Automatable:** The API response alone determines compliance. Example: *"MFA is enabled for all console users"* — the credential report provides a binary yes/no.

**Tier 2 — Partially Automatable:** The API response provides evidence that supports a determination, but the CCA must also verify organizational context. Example: *"Authorized users are identified"* — IAM user lists show WHO has access, but the CCA must verify this matches the organization's authorized user roster.

**Tier 3 — Not Automatable:** No cloud API can evaluate this objective. Example: *"Visitors are escorted"* (physical security) or *"Security awareness training is provided"* (organizational process).

### 4.3 Cloud Provider API Baselines

The scanner uses read-only API calls across three cloud service providers. All access is via read-only IAM roles — **no configuration changes are ever made** to the client's environment.

| Provider | Access Method | Permissions Required | Checks |
|----------|--------------|---------------------|--------|
| **AWS** | STS AssumeRole (cross-account) | `SecurityAudit` + `ViewOnlyAccess` managed policies | 164 |
| **Azure** | Service Principal (ClientSecretCredential) | `Reader` + `Security Reader` roles + Microsoft Graph API | 115 |
| **GCP** | Service Account (JSON key) | `Viewer` + `Security Reviewer` + `Security Center Admin` roles | 114 |

**Key AWS Services Queried:** IAM, STS, EC2, VPC, S3, CloudTrail, CloudWatch, Config, GuardDuty, Security Hub, KMS, SSM, Inspector, WAFv2, ELB, CloudFront, RDS, Organizations, ACM, Route 53, Network Firewall, DynamoDB, API Gateway, CodePipeline, Athena, SNS, ECR, Health

**Key Azure Services Queried:** Entra ID (Graph API), Network, Compute, Storage, Key Vault, Security Center, Monitor, Policy, Authorization, SQL, App Service, Sentinel, Advisor, Automation, Resource Graph, Guest Configuration

**Key GCP Services Queried:** IAM, Cloud Resource Manager, Compute, VPC, Storage, Cloud KMS, Cloud Logging, Cloud Monitoring, Security Command Center, OS Config, Binary Authorization, Container Analysis, Web Security Scanner, Cloud SQL, BigQuery, Cloud DNS, Recommender, Cloud IDS, Cloud Armor, BeyondCorp, Organization Policy

---

## 5. Coverage Matrix Summary

### 5.1 Overall Statistics

| Metric | Value |
|--------|-------|
| NIST 800-53 Rev 5 Practices | 110 |
| NIST 800-53A Assessment Objectives | 319 |
| Practices with Automated Checks | 71 (64%) |
| Practices Requiring Manual Assessment | 39 (35%) |
| Total Cloud-Specific Technical Checks | 393 |
| AWS Checks | 164 |
| Azure Checks | 115 |
| GCP Checks | 114 |
| Documentation Evidence Requirements | 104 |

### 5.2 Domain-Level Coverage

The table below shows the scanner's coverage across all 14 FedRAMP control families. Each domain is broken down by the number of NIST 800-53 Rev 5 controls, how many are automated vs. manual, the total 800-53A assessment objectives, and the cloud-specific checks implemented for each provider. The **Automation Rate** shows the percentage of practices in each domain that are fully automated by the scanner.

| Domain | Name | Practices | Automated | Manual | Objectives | AWS | Azure | GCP | Automation Rate |
|--------|------|-----------|-----------|--------|------------|-----|-------|-----|-----------------|
| AC | Access Control | 22 | 16 | 6 | 70 | 35 | 25 | 26 | 73% |
| AT | Awareness and Training | 3 | 0 | 3 | 9 | 0 | 0 | 0 | 0% |
| AU | Audit and Accountability | 9 | 8 | 1 | 29 | 18 | 11 | 11 | 89% |
| CM | Configuration Management | 9 | 8 | 1 | 44 | 15 | 10 | 10 | 89% |
| IA | Identification and Authentication | 11 | 10 | 1 | 25 | 18 | 13 | 12 | 91% |
| IR | Incident Response | 3 | 1 | 2 | 14 | 4 | 3 | 3 | 33% |
| MA | Maintenance | 6 | 2 | 4 | 10 | 5 | 3 | 3 | 33% |
| MP | Media Protection | 9 | 3 | 6 | 15 | 9 | 6 | 5 | 33% |
| PE | Physical Protection | 6 | 0 | 6 | 16 | 0 | 0 | 0 | 0% |
| PS | Personnel Security | 2 | 0 | 2 | 4 | 0 | 0 | 0 | 0% |
| RA | Risk Assessment | 3 | 2 | 1 | 9 | 5 | 5 | 5 | 67% |
| CA | Security Assessment | 4 | 1 | 3 | 13 | 3 | 2 | 2 | 25% |
| SC | System and Communications Protection | 16 | 13 | 3 | 41 | 31 | 21 | 21 | 81% |
| SI | System and Information Integrity | 7 | 7 | 0 | 20 | 21 | 16 | 16 | 100% |
| **Total** | | **110** | **71** | **39** | **319** | **164** | **115** | **114** | **65%** |

### 5.3 Objective Automatable Classification

| Classification | Count | Percentage | Scanner Handling |
|---------------|-------|------------|-----------------|
| Fully Automatable | 77 | 24% | Automated check provides Met/Not Met determination |
| Partially Automatable | 139 | 43% | Automated check provides evidence; CCA verifies context |
| Not Automatable | 103 | 32% | Flagged as Documentation Required; CCA assesses manually |

---

## 6. Complete Practice Reference

This section provides the complete technical reference for every NIST SP 800-53 Rev 5 practice, organized by FedRAMP family. For each practice, it shows:

- The requirement text and FedRAMP baseline
- All NIST SP 800-53A assessment objectives
- Cloud-specific automated checks with API calls, services, and severity
- Objective mapping (which checks support which objectives)
- Documentation requirements for non-automatable objectives

### AC — Access Control

**Practices:** 22 | **Automated:** 16 | **Manual:** 6 | **Objectives:** 70 | **Checks:** AWS 35, Azure 25, GCP 26

#### 3.1.1 — Limit information system access to authorized users, processes acting on behalf of authorized users, or devices (including other information systems).

**Level:** L1 | **Type:** Automated | **Objectives:** 6
 | **FAR 52.204-21:** b.1.i

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.1[a] | authorized users are identified. | Partial |
| 3.1.1[b] | processes acting on behalf of authorized users are identified. | Partial |
| 3.1.1[c] | devices (including other systems) authorized to connect to the system are identified. | Partial |
| 3.1.1[d] | system access is limited to authorized users. | Yes |
| 3.1.1[e] | system access is limited to processes acting on behalf of authorized users. | Yes |
| 3.1.1[f] | system access is limited to authorized devices (including other systems). | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.1-aws-001` | AWS | Root account access keys disabled | IAM | `iam.get_account_summary` | critical | [d] |
| `ac-3.1.1-aws-002` | AWS | IAM users have active credentials reviewed | IAM | `iam.generate_credential_report` | high | [a], [d] |
| `ac-3.1.1-aws-003` | AWS | IAM password policy enforced | IAM | `iam.get_account_password_policy` | high | [a], [d] |
| `ac-3.1.1-azure-001` | AZURE | Conditional Access policies configured | Azure AD | `graph.conditional_access_policies.list` | high | [a], [d], [f] |
| `ac-3.1.1-azure-002` | AZURE | Guest user access restricted | Azure AD | `graph.authorization_policy.get` | medium | [a], [d] |
| `ac-3.1.1-azure-003` | AZURE | Security defaults or Conditional Access enabled | Azure AD | `graph.identity_security_defaults_enforcement_policy.get` | high | [a], [d], [f] |
| `ac-3.1.1-gcp-001` | GCP | Organization-level IAM bindings reviewed | IAM | `cloudresourcemanager.projects.getIamPolicy` | critical | [a], [c] |
| `ac-3.1.1-gcp-002` | GCP | Service account keys rotated | IAM | `iam.projects.serviceAccounts.keys.list` | high | [b], [e] |
| `ac-3.1.1-gcp-003` | GCP | Default service account not used | IAM | `compute.instances.list` | high | [b], [e] |


#### 3.1.2 — Limit information system access to the types of transactions and functions that authorized users are permitted to execute.

**Level:** L1 | **Type:** Automated | **Objectives:** 2
 | **FAR 52.204-21:** b.1.ii

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.2[a] | the types of transactions and functions that authorized users are permitted to execute are defined | Partial |
| 3.1.2[b] | system access is limited to the defined types of transactions and functions for authorized users. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.2-aws-001` | AWS | IAM policies follow least privilege | IAM | `iam.list_policies` | high | [b] |
| `ac-3.1.2-aws-002` | AWS | IAM permission boundaries configured for delegated admin | IAM | `iam.list_users` | medium | [a], [b] |
| `ac-3.1.2-azure-001` | AZURE | Custom RBAC roles use least privilege | Authorization | `authorization.role_definitions.list` | high | [a], [b] |
| `ac-3.1.2-azure-002` | AZURE | PIM enabled for privileged roles | Azure AD | `graph.privileged_access.list` | high | [a], [b] |
| `ac-3.1.2-gcp-001` | GCP | Custom IAM roles scoped appropriately | IAM | `iam.projects.roles.list` | high | [a], [b] |
| `ac-3.1.2-gcp-002` | GCP | Primitive roles not assigned to users | IAM | `cloudresourcemanager.projects.getIamPolicy` | high | [a], [b] |


#### 3.1.3 — Control the flow of CUI in accordance with approved authorizations.

**Level:** L2 | **Type:** Automated | **Objectives:** 5

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.3[a] | information flow control policies are defined. | Partial |
| 3.1.3[b] | methods and enforcement mechanisms for controlling the flow of CUI are defined. | Partial |
| 3.1.3[c] | designated sources and destinations (e.g., networks, individuals, and devices) for CUI within systems and between interc | Partial |
| 3.1.3[d] | authorizations for controlling the flow of CUI are defined. | Partial |
| 3.1.3[e] | approved authorizations for controlling the flow of CUI are enforced. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.3-aws-001` | AWS | VPC Flow Logs enabled | VPC | `ec2.describe_flow_logs` | high | [a], [b], [d], [e] |
| `ac-3.1.3-aws-002` | AWS | S3 Block Public Access enabled at account level | S3 | `s3control.get_public_access_block` | critical | [a], [b], [d], [e] |
| `ac-3.1.3-azure-001` | AZURE | NSG flow logs enabled | Network | `network.flow_logs.list` | high | [a], [b], [d], [e] |
| `ac-3.1.3-azure-002` | AZURE | Azure Firewall or Network Virtual Appliance deployed | Network | `network.azure_firewalls.list` | high | [a], [b], [d], [e] |
| `ac-3.1.3-gcp-001` | GCP | VPC Flow Logs enabled | VPC | `compute.subnetworks.list` | high | [a], [b], [d], [e] |
| `ac-3.1.3-gcp-002` | GCP | Firewall rules reviewed for least privilege | VPC | `compute.firewalls.list` | critical | [a], [b], [d], [e] |

**Documentation Requirements:**

- **3.1.3[c]**: designated sources and destinations (e.g., networks, individuals, and devices) for CUI within systems and between interconnected systems are identified. — *Provide documentation showing that designated sources and destinations (e.g., networks, individuals, and devices) for cui within systems and between interconnected systems are identified and documented.*


#### 3.1.4 — Separate the duties of individuals to reduce the risk of malevolent activity without collusion.

**Level:** L2 | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.4[a] | the duties of individuals requiring separation to reduce the risk of malevolent activity are defined. | Partial |
| 3.1.4[b] | organization-defined duties of individuals requiring separation are separated. | Partial |
| 3.1.4[c] | separate accounts for individuals whose duties and accesses must be separated to reduce the risk of malevolent activity  | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.4-aws-001` | AWS | Separate IAM roles for admin and operational tasks | IAM | `iam.list_roles` | medium | [a], [b], [c] |
| `ac-3.1.4-aws-002` | AWS | No single user has both deploy and approve permissions | IAM | `iam.get_policy_version` | high | [a], [b], [c] |
| `ac-3.1.4-azure-001` | AZURE | Separation of duties for subscription management | Authorization | `authorization.role_assignments.list` | medium | [a], [b], [c] |
| `ac-3.1.4-gcp-001` | GCP | Separation of duties for project management | IAM | `cloudresourcemanager.projects.getIamPolicy` | medium | [a], [b], [c] |


#### 3.1.5 — Employ the principle of least privilege, including for specific security functions and privileged accounts.

**Level:** L2 | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.5[a] | privileged accounts are identified. | Partial |
| 3.1.5[b] | access to privileged accounts is authorized in accordance with the principle of least privilege. | Partial |
| 3.1.5[c] | security functions are identified. | Partial |
| 3.1.5[d] | access to security functions is authorized in accordance with the principle of least privilege. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.5-aws-001` | AWS | No inline IAM policies with wildcard permissions | IAM | `iam.list_user_policies` | high | [b] |
| `ac-3.1.5-aws-002` | AWS | IAM Access Analyzer enabled | IAM | `accessanalyzer.list_analyzers` | medium | [a], [b] |
| `ac-3.1.5-aws-003` | AWS | No IAM users with AdministratorAccess policy | IAM | `iam.list_entities_for_policy` | high | [a], [b], [c], [d] |
| `ac-3.1.5-azure-001` | AZURE | Global Administrator role limited | Azure AD | `graph.directory_roles.members.list` | high | [a], [b], [c], [d] |
| `ac-3.1.5-azure-002` | AZURE | JIT VM access configured | Security Center | `security.jit_network_access_policies.list` | medium | [a], [b], [d] |
| `ac-3.1.5-gcp-001` | GCP | No user has Owner role on multiple projects | IAM | `cloudresourcemanager.projects.getIamPolicy` | high | [a], [d] |
| `ac-3.1.5-gcp-002` | GCP | IAM recommender reviewed | IAM | `recommender.projects.locations.recommenders.recommendations.list` | medium | [b] |


#### 3.1.6 — Use non-privileged accounts or roles when accessing nonsecurity functions.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.6[a] | nonsecurity functions are identified. | Partial |
| 3.1.6[b] | users are required to use non-privileged accounts or roles when accessing nonsecurity functions. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.6-aws-001` | AWS | Separate admin and standard user roles defined | IAM | `iam.list_roles` | medium | [a], [b] |
| `ac-3.1.6-azure-001` | AZURE | Admin accounts separate from daily-use accounts | Azure AD | `graph.users.list` | medium | [a], [b] |
| `ac-3.1.6-gcp-001` | GCP | Admin and user roles separated | IAM | `cloudresourcemanager.projects.getIamPolicy` | medium | [a], [b] |


#### 3.1.7 — Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs.

**Level:** L2 | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.7[a] | privileged functions are defined. | Partial |
| 3.1.7[b] | non-privileged users are defined. | Partial |
| 3.1.7[c] | non-privileged users are prevented from executing privileged functions. | Yes |
| 3.1.7[d] | the execution of privileged functions is captured in audit logs. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.7-aws-001` | AWS | CloudTrail logging enabled for all management events | CloudTrail | `cloudtrail.describe_trails` | critical | [a], [c], [d] |
| `ac-3.1.7-aws-002` | AWS | SCP prevents disabling CloudTrail | Organizations | `organizations.list_policies` | high | [b], [c], [d] |
| `ac-3.1.7-azure-001` | AZURE | Activity Log alerts for privilege escalation | Monitor | `monitor.activity_log_alerts.list` | high | [a], [b], [c], [d] |
| `ac-3.1.7-gcp-001` | GCP | Admin Activity audit logs enabled | Logging | `logging.projects.logs.list` | high | [c], [d] |
| `ac-3.1.7-gcp-002` | GCP | Log-based metrics and alerts for IAM changes | Monitoring | `monitoring.projects.alertPolicies.list` | high | [b], [c], [d] |


#### 3.1.8 — Limit unsuccessful logon attempts.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.8[a] | the means of limiting unsuccessful logon attempts is defined. | Partial |
| 3.1.8[b] | the defined means of limiting unsuccessful logon attempts is implemented. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.8-aws-001` | AWS | Account lockout policy configured in IAM Identity Center | IAM Identity Center | `sso-admin.describe_instance_access_control_attribute_configuration` | high | [a], [b] |
| `ac-3.1.8-aws-002` | AWS | GuardDuty brute force finding type enabled | GuardDuty | `guardduty.list_detectors` | medium | [a], [b] |
| `ac-3.1.8-azure-001` | AZURE | Smart lockout configured in Azure AD | Azure AD | `graph.settings.list` | high | [a], [b] |
| `ac-3.1.8-gcp-001` | GCP | Google Workspace login challenge enabled | Workspace Admin | `admin.directory.users.list` | medium | [a], [b] |


#### 3.1.9 — Provide privacy and security notices consistent with applicable CUI rules.

**Level:** L2 | **Type:** Manual | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.9[a] | privacy and security notices required by CUI-specified rules are identified, consistent, and associated with the specifi | No |
| 3.1.9[b] | privacy and security notices are displayed. | No |

**Documentation Requirements:**

- **3.1.9[a]**: privacy and security notices required by CUI-specified rules are identified, consistent, and associated with the specific CUI category — *Provide documentation showing that privacy and security notices required by cui-specified rules are identified and documented.*
- **3.1.9[b]**: privacy and security notices are displayed. — *Provide documentation or process evidence: privacy and security notices are displayed.*

**CCA Manual Assessment Guidance:** Verify login banners and system use notification messages are configured on all systems processing CUI.


#### 3.1.10 — Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity.

**Level:** L2 | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.10[a] | the period of inactivity after which the system initiates a session lock is defined. | Partial |
| 3.1.10[b] | access to the system and viewing of data is prevented by initiating a session lock after the defined period of inactivit | Yes |
| 3.1.10[c] | previously visible information is concealed via a pattern-hiding display after the defined period of inactivity. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.10-aws-001` | AWS | Console session timeout configured | IAM | `iam.get_role` | medium | [a], [b], [c] |
| `ac-3.1.10-azure-001` | AZURE | Conditional Access session controls configured | Azure AD | `graph.conditional_access_policies.list` | medium | [a], [b], [c] |
| `ac-3.1.10-gcp-001` | GCP | Session control policy configured | BeyondCorp | `beyondcorp.projects.locations.appConnections.list` | medium | [a], [b], [c] |


#### 3.1.11 — Terminate (automatically) a user session after a defined condition.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.11[a] | conditions requiring a user session to terminate are defined. | Partial |
| 3.1.11[b] | a user session is automatically terminated after any of the defined conditions occur. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.11-aws-001` | AWS | IAM role session duration limited | IAM | `iam.list_roles` | medium | [a], [b] |
| `ac-3.1.11-aws-002` | AWS | SSO session timeout configured | IAM Identity Center | `sso-admin.describe_instance` | medium | [a], [b] |
| `ac-3.1.11-azure-001` | AZURE | Token lifetime policy configured | Azure AD | `graph.token_lifetime_policies.list` | medium | [a], [b] |
| `ac-3.1.11-gcp-001` | GCP | OAuth token expiration configured | IAM | `iam.projects.serviceAccounts.list` | medium | [a], [b] |


#### 3.1.12 — Monitor and control remote access sessions.

**Level:** L2 | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.12[a] | remote access sessions are permitted. | Partial |
| 3.1.12[b] | the types of permitted remote access are identified. | Partial |
| 3.1.12[c] | remote access sessions are controlled. | Yes |
| 3.1.12[d] | remote access sessions are monitored. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.12-aws-001` | AWS | VPN connections use CloudWatch monitoring | VPC | `ec2.describe_vpn_connections` | high | [a], [b], [c], [d] |
| `ac-3.1.12-aws-002` | AWS | Systems Manager Session Manager logging enabled | SSM | `ssm.describe_document` | high | [a], [b], [c], [d] |
| `ac-3.1.12-azure-001` | AZURE | Azure Bastion deployed for remote access | Network | `network.bastion_hosts.list` | high | [a], [b], [c], [d] |
| `ac-3.1.12-gcp-001` | GCP | IAP for TCP forwarding enabled | IAP | `iap.projects.iap_tunnel.locations.destGroups.list` | high | [a], [b], [c], [d] |


#### 3.1.13 — Employ cryptographic mechanisms to protect the confidentiality of remote access sessions.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.13[a] | cryptographic mechanisms to protect the confidentiality of remote access sessions are identified. | Partial |
| 3.1.13[b] | cryptographic mechanisms to protect the confidentiality of remote access sessions are implemented. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.13-aws-001` | AWS | VPN uses approved encryption | VPC | `ec2.describe_vpn_connections` | high | [a], [b] |
| `ac-3.1.13-aws-002` | AWS | TLS 1.2+ enforced on all load balancers | ELB | `elbv2.describe_ssl_policies` | high | [a], [b] |
| `ac-3.1.13-azure-001` | AZURE | VPN Gateway uses IKEv2 with strong encryption | Network | `network.virtual_network_gateway_connections.list` | high | [a], [b] |
| `ac-3.1.13-gcp-001` | GCP | Cloud VPN uses IKEv2 with strong ciphers | VPN | `compute.vpnTunnels.list` | high | [a], [b] |


#### 3.1.14 — Route remote access via managed access control points.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.14[a] | managed access control points are identified and implemented. | Partial |
| 3.1.14[b] | remote access is routed through managed network access control points. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.14-aws-001` | AWS | Client VPN endpoint configured | VPC | `ec2.describe_client_vpn_endpoints` | high | [a], [b] |
| `ac-3.1.14-aws-002` | AWS | No direct SSH/RDP access from internet | EC2 | `ec2.describe_security_groups` | critical | [a], [b] |
| `ac-3.1.14-azure-001` | AZURE | No direct RDP/SSH from internet | Network | `network.network_security_groups.list` | critical | [a], [b] |
| `ac-3.1.14-gcp-001` | GCP | No direct SSH from internet via firewall rules | VPC | `compute.firewalls.list` | critical | [a], [b] |


#### 3.1.15 — Authorize remote execution of privileged commands and remote access to security-relevant information.

**Level:** L2 | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.15[a] | privileged commands authorized for remote execution are identified. | Partial |
| 3.1.15[b] | security-relevant information authorized to be accessed remotely is identified. | Partial |
| 3.1.15[c] | the execution of the identified privileged commands via remote access is authorized. | Partial |
| 3.1.15[d] | access to the identified security-relevant information via remote access is authorized. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.15-aws-001` | AWS | Session Manager used for privileged remote access | SSM | `ssm.describe_instance_information` | high | [a], [b], [c], [d] |
| `ac-3.1.15-azure-001` | AZURE | Privileged Access Workstation policy enforced | Azure AD | `graph.conditional_access_policies.list` | high | [a], [b], [c], [d] |
| `ac-3.1.15-gcp-001` | GCP | OS Login enabled for privileged access | Compute | `compute.projects.get` | high | [a], [b], [c], [d] |


#### 3.1.16 — Authorize wireless access prior to allowing such connections.

**Level:** L2 | **Type:** Manual | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.16[a] | wireless access points are identified. | No |
| 3.1.16[b] | wireless access is authorized prior to allowing such connections. | No |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.16-aws-001` | AWS | VPN infrastructure for remote access authorization | VPC | `ec2.describe_vpn_connections/describe_client_vpn_endpoints` | high |  |
| `ac-3.1.16-azure-001` | AZURE | VPN gateway for remote access authorization | Network | `network.virtual_network_gateways.list` | high |  |
| `ac-3.1.16-gcp-001` | GCP | Cloud VPN for remote access authorization | VPN | `compute.vpnGateways.list/vpnTunnels.list` | high |  |

**Documentation Requirements:**

- **3.1.16[a]**: wireless access points are identified. — *Provide documentation showing that wireless access points are identified and documented.*
- **3.1.16[b]**: wireless access is authorized prior to allowing such connections. — *Provide documentation or process evidence: wireless access is authorized prior to allowing such connections.*

**CCA Manual Assessment Guidance:** Review wireless access policies and verify that wireless connections require explicit authorization. Check for rogue access point detection.


#### 3.1.17 — Protect wireless access using authentication and encryption.

**Level:** L2 | **Type:** Manual | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.17[a] | wireless access to the system is protected using encryption. | No |
| 3.1.17[b] | wireless access to the system is protected using authentication. | No |

**Documentation Requirements:**

- **3.1.17[a]**: wireless access to the system is protected using encryption. — *Provide documentation or process evidence: wireless access to the system is protected using encryption.*
- **3.1.17[b]**: wireless access to the system is protected using authentication. — *Provide documentation or process evidence: wireless access to the system is protected using authentication.*

**CCA Manual Assessment Guidance:** Verify wireless networks use WPA2/WPA3-Enterprise with 802.1X authentication. Check encryption standards meet FIPS 140-2 requirements.


#### 3.1.18 — Control connection of mobile devices.

**Level:** L2 | **Type:** Manual | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.18[a] | mobile devices that process, store, or transmit CUI are identified. | No |
| 3.1.18[b] | the connection of mobile devices is authorized. | No |
| 3.1.18[c] | mobile device connections are monitored and logged. | No |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.18-aws-001` | AWS | Centralized identity providers for device control | IAM | `iam.list_saml_providers/list_open_id_connect_providers` | high |  |
| `ac-3.1.18-azure-001` | AZURE | Defender for Cloud and managed identity for device control | Security/Authorization | `resource_client.providers.get/auth_client.role_assignments.list` | high |  |
| `ac-3.1.18-gcp-001` | GCP | OS Login and device security org policies | OrgPolicy | `orgpolicy.projects.policies.get` | high |  |

**Documentation Requirements:**

- **3.1.18[a]**: mobile devices that process, store, or transmit CUI are identified. — *Provide documentation showing that mobile devices that process, store, or transmit cui are identified and documented.*
- **3.1.18[b]**: the connection of mobile devices is authorized. — *Provide documentation or process evidence: the connection of mobile devices is authorized.*
- **3.1.18[c]**: mobile device connections are monitored and logged. — *Provide documentation or process evidence: mobile device connections are monitored and logged.*

**CCA Manual Assessment Guidance:** Review mobile device management (MDM) policies. Verify enrollment requirements, device compliance checks, and connection restrictions for mobile devices accessing CUI.


#### 3.1.19 — Encrypt CUI on mobile devices and mobile computing platforms.

**Level:** L2 | **Type:** Manual | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.19[a] | mobile devices and mobile computing platforms that process, store, or transmit CUI are identified. | No |
| 3.1.19[b] | encryption is employed to protect CUI on identified mobile devices and mobile computing platforms. | No |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.19-aws-001` | AWS | EBS default encryption enabled for compute platforms | EC2 | `ec2.get_ebs_encryption_by_default` | high |  |
| `ac-3.1.19-azure-001` | AZURE | All managed disks encrypted | Compute | `compute.disks.list` | high |  |
| `ac-3.1.19-gcp-001` | GCP | CMEK org policy or disk-level CMEK enforced | OrgPolicy/Compute | `orgpolicy/compute.disks.list` | high |  |

**Documentation Requirements:**

- **3.1.19[a]**: mobile devices and mobile computing platforms that process, store, or transmit CUI are identified. — *Provide documentation showing that mobile devices and mobile computing platforms that process, store, or transmit cui are identified and documented.*
- **3.1.19[b]**: encryption is employed to protect CUI on identified mobile devices and mobile computing platforms. — *Provide documentation or process evidence: encryption is employed to protect CUI on identified mobile devices and mobile computing platforms.*

**CCA Manual Assessment Guidance:** Verify MDM enforces full-device encryption on mobile devices. Check that CUI storage on mobile devices uses FIPS-validated encryption.


#### 3.1.20 — Verify and control/limit connections to and use of external information systems.

**Level:** L1 | **Type:** Automated | **Objectives:** 6
 | **FAR 52.204-21:** b.1.iii

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.20[a] | connections to external systems are identified. | Partial |
| 3.1.20[b] | use of external systems is identified. | Partial |
| 3.1.20[c] | connections to external systems are verified. | Partial |
| 3.1.20[d] | use of external systems is verified. | Partial |
| 3.1.20[e] | connections to external systems are controlled/limited. | Yes |
| 3.1.20[f] | use of external systems is controlled/limited. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.20-aws-001` | AWS | VPC peering connections reviewed | VPC | `ec2.describe_vpc_peering_connections` | medium | [a], [b], [c], [d], [e], [f] |
| `ac-3.1.20-aws-002` | AWS | Transit Gateway attachments reviewed | VPC | `ec2.describe_transit_gateway_attachments` | medium | [a], [b], [c], [d], [e], [f] |
| `ac-3.1.20-azure-001` | AZURE | VNet peering connections reviewed | Network | `network.virtual_network_peerings.list` | medium | [a], [b], [c], [d], [e], [f] |
| `ac-3.1.20-gcp-001` | GCP | VPC peering connections reviewed | VPC | `compute.networks.listPeering` | medium | [a], [b], [c], [d], [e], [f] |


#### 3.1.21 — Limit use of organizational portable storage devices on external information systems.

**Level:** L2 | **Type:** Manual | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.21[a] | use of organizational portable storage devices containing CUI on external systems is identified and documented. | No |
| 3.1.21[b] | limits on the use of organizational portable storage devices containing CUI on external systems are defined. | No |
| 3.1.21[c] | use of organizational portable storage devices containing CUI on external systems is limited as defined. | No |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.21-aws-001` | AWS | S3 Block Public Access enabled at account level | S3 | `s3control.get_public_access_block` | high |  |
| `ac-3.1.21-azure-001` | AZURE | Storage accounts block public blob access | Storage | `storage.storage_accounts.list` | high |  |
| `ac-3.1.21-gcp-001` | GCP | Uniform bucket-level access org policy enforced | OrgPolicy | `orgpolicy.projects.policies.get` | high |  |

**Documentation Requirements:**

- **3.1.21[a]**: use of organizational portable storage devices containing CUI on external systems is identified and documented. — *Provide documentation showing that use of organizational portable storage devices containing cui on external systems are identified and documented.*
- **3.1.21[b]**: limits on the use of organizational portable storage devices containing CUI on external systems are defined. — *Provide documentation showing that limits on the use of organizational portable storage devices containing cui on external systems are defined.*
- **3.1.21[c]**: use of organizational portable storage devices containing CUI on external systems is limited as defined. — *Provide documentation or process evidence: use of organizational portable storage devices containing CUI on external systems is limited as defined.*

**CCA Manual Assessment Guidance:** Review policies restricting use of USB drives and portable storage on external systems. Verify endpoint DLP controls for removable media.


#### 3.1.22 — Control CUI posted or processed on publicly accessible information systems.

**Level:** L1 | **Type:** Automated | **Objectives:** 5
 | **FAR 52.204-21:** b.1.iv

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.1.22[a] | individuals authorized to post or process information on publicly accessible systems are identified. | Partial |
| 3.1.22[b] | procedures to ensure CUI is not posted or processed on publicly accessible systems are identified. | Partial |
| 3.1.22[c] | a review process in in place prior to posting of any content to publicly accessible systems. | Partial |
| 3.1.22[d] | content on publicly accessible information systems is reviewed to ensure that it does not include CUI. | Partial |
| 3.1.22[e] | mechanisms are in place to remove and address improper posting of CUI. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ac-3.1.22-aws-001` | AWS | No S3 buckets publicly accessible | S3 | `s3.get_bucket_policy_status` | critical | [a], [b], [c], [d], [e] |
| `ac-3.1.22-aws-002` | AWS | No EC2 instances with public IPs in CUI subnets | EC2 | `ec2.describe_instances` | high | [a], [b], [c], [d], [e] |
| `ac-3.1.22-azure-001` | AZURE | No storage accounts with public blob access | Storage | `storage.storage_accounts.list` | critical | [a], [b], [c], [d], [e] |
| `ac-3.1.22-gcp-001` | GCP | No Cloud Storage buckets publicly accessible | Storage | `storage.buckets.getIamPolicy` | critical | [a], [b], [c], [d], [e] |


### AT — Awareness and Training

**Practices:** 3 | **Automated:** 0 | **Manual:** 3 | **Objectives:** 9 | **Checks:** AWS 0, Azure 0, GCP 0

#### 3.2.1 — Ensure that managers, systems administrators, and users of organizational information systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of organizational information systems.

**Level:** L2 | **Type:** Manual | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.2.1[a] | security risks associated with organizational activities involving CUI are identified. | No |
| 3.2.1[b] | policies, standards, and procedures related to the security of the system are identified. | No |
| 3.2.1[c] | managers, systems administrators, and users of the system are made aware of the security risks associated with their act | No |
| 3.2.1[d] | managers, systems administrators, and users of the system are made aware of the applicable policies, standards, and proc | No |

**Documentation Requirements:**

- **3.2.1[a]**: security risks associated with organizational activities involving CUI are identified. — *Provide documentation showing that security risks associated with organizational activities involving cui are identified and documented.*
- **3.2.1[b]**: policies, standards, and procedures related to the security of the system are identified. — *Provide documentation showing that policies, standards, and procedures related to the security of the system are identified and documented.*
- **3.2.1[c]**: managers, systems administrators, and users of the system are made aware of the security risks associated with their activities. — *Provide documentation or process evidence: managers, systems administrators, and users of the system are made aware of the security risks associated with their activities.*
- **3.2.1[d]**: managers, systems administrators, and users of the system are made aware of the applicable policies, standards, and procedures related to the security of the system. — *Provide documentation or process evidence: managers, systems administrators, and users of the system are made aware of the applicable policies, standards, and procedures related to the security of the system.*

**CCA Manual Assessment Guidance:** Request security awareness training records and completion certificates. Verify training covers CUI handling, phishing, social engineering, and organizational security policies.


#### 3.2.2 — Ensure that organizational personnel are adequately trained to carry out their assigned information security-related duties and responsibilities.

**Level:** L2 | **Type:** Manual | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.2.2[a] | information security-related duties, roles, and responsibilities are defined. | No |
| 3.2.2[b] | information security-related duties, roles, and responsibilities are assigned to designated personnel. | No |
| 3.2.2[c] | personnel are adequately trained to carry out their assigned information security-related duties, roles, and responsibil | No |

**Documentation Requirements:**

- **3.2.2[a]**: information security-related duties, roles, and responsibilities are defined. — *Provide documentation showing that information security-related duties, roles, and responsibilities are defined.*
- **3.2.2[b]**: information security-related duties, roles, and responsibilities are assigned to designated personnel. — *Provide personnel records: information security-related duties, roles, and responsibilities are assigned to designated personnel.*
- **3.2.2[c]**: personnel are adequately trained to carry out their assigned information security-related duties, roles, and responsibilities. — *Provide personnel records: personnel are adequately trained to carry out their assigned information security-related duties, roles, and responsibilities.*

**CCA Manual Assessment Guidance:** Request role-based training records for IT/security staff. Verify training covers specific duties such as incident response, system administration, and security monitoring.


#### 3.2.3 — Provide security awareness training on recognizing and reporting potential indicators of insider threat.

**Level:** L2 | **Type:** Manual | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.2.3[a] | potential indicators associated with insider threats are identified. | No |
| 3.2.3[b] | security awareness training on recognizing and reporting potential indicators of insider threat is provided to managers  | No |

**Documentation Requirements:**

- **3.2.3[a]**: potential indicators associated with insider threats are identified. — *Provide documentation showing that potential indicators associated with insider threats are identified and documented.*
- **3.2.3[b]**: security awareness training on recognizing and reporting potential indicators of insider threat is provided to managers and employees. — *Provide training records: security awareness training on recognizing and reporting potential indicators of insider threat is provided to managers and employees.*

**CCA Manual Assessment Guidance:** Request insider threat training records. Verify training includes indicators of insider threat, reporting procedures, and is completed annually by all personnel with CUI access.


### AU — Audit and Accountability

**Practices:** 9 | **Automated:** 8 | **Manual:** 1 | **Objectives:** 29 | **Checks:** AWS 18, Azure 11, GCP 11

#### 3.3.1 — Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.

**Level:** L2 | **Type:** Automated | **Objectives:** 6

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.3.1[a] | audit logs needed (i.e., event types to be logged) to enable the monitoring, analysis, investigation, and reporting of u | Partial |
| 3.3.1[b] | the content of audit records needed to support monitoring, analysis, investigation, and reporting of unlawful or unautho | Partial |
| 3.3.1[c] | audit records are created (generated). | Yes |
| 3.3.1[d] | audit records, once created, contain the defined content. | Yes |
| 3.3.1[e] | retention requirements for audit records are defined. | Partial |
| 3.3.1[f] | audit records are retained as defined. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-3.3.1-aws-001` | AWS | CloudTrail enabled in all regions | CloudTrail | `cloudtrail.describe_trails` | critical | [a], [b], [c], [d], [e], [f] |
| `au-3.3.1-aws-002` | AWS | CloudTrail log file validation enabled | CloudTrail | `cloudtrail.get_trail_status` | high | [a], [b], [c], [d], [e], [f] |
| `au-3.3.1-aws-003` | AWS | CloudTrail logs retained for at least 365 days | S3 | `s3.get_bucket_lifecycle_configuration` | high | [a], [b], [c], [d], [e], [f] |
| `au-3.3.1-aws-004` | AWS | CloudTrail data events enabled for S3 and Lambda | CloudTrail | `cloudtrail.get_event_selectors` | medium | [a], [b], [c], [d], [e], [f] |
| `au-3.3.1-azure-001` | AZURE | Azure Activity Log retention configured | Monitor | `monitor.diagnostic_settings.list` | critical | [a], [b], [c], [d], [e], [f] |
| `au-3.3.1-azure-002` | AZURE | Azure AD audit logs retained | Azure AD | `graph.audit_logs.list` | high | [a], [b], [c], [d], [e], [f] |
| `au-3.3.1-azure-003` | AZURE | Resource diagnostic settings enabled | Monitor | `monitor.diagnostic_settings.list` | high | [a], [b], [c], [d], [e], [f] |
| `au-3.3.1-gcp-001` | GCP | Admin Activity audit logs active | Logging | `logging.projects.logs.list` | critical | [a], [b], [c], [d], [e], [f] |
| `au-3.3.1-gcp-002` | GCP | Data Access audit logs enabled | Logging | `cloudresourcemanager.projects.getIamPolicy` | high | [a], [b], [c], [d], [e], [f] |
| `au-3.3.1-gcp-003` | GCP | Audit log sink to long-term storage | Logging | `logging.projects.sinks.list` | high | [a], [b], [c], [d], [e], [f] |


#### 3.3.2 — Ensure that the actions of individual system users can be uniquely traced to those users so they can be held accountable for their actions.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.3.2[a] | the content of the audit records needed to support the ability to uniquely trace users to their actions is defined. | Partial |
| 3.3.2[b] | audit records, once created, contain the defined content. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-3.3.2-aws-001` | AWS | CloudTrail records user identity | CloudTrail | `cloudtrail.describe_trails` | high | [a], [b] |
| `au-3.3.2-aws-002` | AWS | No shared IAM user accounts | IAM | `iam.generate_credential_report` | high | [a], [b] |
| `au-3.3.2-azure-001` | AZURE | Azure AD sign-in logs available | Azure AD | `graph.sign_in_logs.list` | high | [a], [b] |
| `au-3.3.2-gcp-001` | GCP | Audit logs include principal identity | Logging | `logging.entries.list` | high | [a], [b] |


#### 3.3.3 — Review and update logged events.

**Level:** L2 | **Type:** Manual | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.3.3[a] | a process for determining when to review logged events is defined. | No |
| 3.3.3[b] | event types being logged are reviewed in accordance with the defined review process. | No |
| 3.3.3[c] | event types being logged are updated based on the review. | No |

**Documentation Requirements:**

- **3.3.3[a]**: a process for determining when to review logged events is defined. — *Provide documentation showing that a process for determining when to review logged events are defined.*
- **3.3.3[b]**: event types being logged are reviewed in accordance with the defined review process. — *Provide evidence of periodic review: event types being logged are reviewed in accordance with the defined review process.*
- **3.3.3[c]**: event types being logged are updated based on the review. — *Provide documentation or process evidence: event types being logged are updated based on the review.*

**CCA Manual Assessment Guidance:** Review audit logging configuration to ensure events of interest are captured. Verify periodic review process for updating which events are logged based on current threat landscape.


#### 3.3.4 — Alert in the event of an audit logging process failure.

**Level:** L2 | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.3.4[a] | personnel or roles to be alerted in the event of an audit logging process failure are identified. | Partial |
| 3.3.4[b] | types of audit logging process failures for which alert will be generated are defined. | Partial |
| 3.3.4[c] | identified personnel or roles are alerted in the event of an audit logging process failure. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-3.3.4-aws-001` | AWS | CloudWatch alarm for CloudTrail logging changes | CloudWatch | `cloudwatch.describe_alarms` | high | [a], [b], [c] |
| `au-3.3.4-aws-002` | AWS | SNS topic configured for audit failure notifications | SNS | `sns.list_subscriptions_by_topic` | medium | [a], [b], [c] |
| `au-3.3.4-azure-001` | AZURE | Activity log alert for diagnostic settings changes | Monitor | `monitor.activity_log_alerts.list` | high | [a], [b], [c] |
| `au-3.3.4-gcp-001` | GCP | Alert policy for log sink changes | Monitoring | `monitoring.projects.alertPolicies.list` | high | [a], [b], [c] |


#### 3.3.5 — Correlate audit record review, analysis, and reporting processes to support organizational processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.3.5[a] | audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauth | Partial |
| 3.3.5[b] | defined audit record review, analysis, and reporting processes are correlated. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-3.3.5-aws-001` | AWS | AWS Security Hub enabled | Security Hub | `securityhub.describe_hub` | high | [a], [b] |
| `au-3.3.5-aws-002` | AWS | CloudTrail integrated with CloudWatch Logs | CloudTrail | `cloudtrail.describe_trails` | high | [a], [b] |
| `au-3.3.5-azure-001` | AZURE | Microsoft Sentinel enabled | Sentinel | `securityinsight.sentinel_onboarding_states.list` | high | [a], [b] |
| `au-3.3.5-gcp-001` | GCP | Security Command Center enabled | SCC | `securitycenter.organizations.sources.list` | high | [a], [b] |


#### 3.3.6 — Provide audit record reduction and report generation to support on-demand analysis and reporting.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.3.6[a] | an audit record reduction capability that supports on-demand analysis is provided. | Partial |
| 3.3.6[b] | a report generation capability that supports on-demand reporting is provided. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-3.3.6-aws-001` | AWS | CloudWatch Logs Insights available | CloudWatch | `logs.describe_log_groups` | medium | [a], [b] |
| `au-3.3.6-aws-002` | AWS | Athena table configured for CloudTrail analysis | Athena | `athena.list_named_queries` | low | [a], [b] |
| `au-3.3.6-azure-001` | AZURE | Log Analytics workspace configured | Monitor | `operationalinsights.workspaces.list` | medium | [a], [b] |
| `au-3.3.6-gcp-001` | GCP | Log Analytics enabled in Cloud Logging | Logging | `logging.projects.locations.buckets.list` | medium | [a], [b] |


#### 3.3.7 — Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records.

**Level:** L2 | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.3.7[a] | internal system clocks are used to generate time stamps for audit records. | Yes |
| 3.3.7[b] | an authoritative source with which to compare and synchronize internal system clocks is specified. | Partial |
| 3.3.7[c] | internal system clocks used to generate time stamps for audit records are compared to and synchronized with the specifie | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-3.3.7-aws-001` | AWS | NTP configured on EC2 instances | EC2 | `ssm.send_command` | medium | [a], [b], [c] |
| `au-3.3.7-azure-001` | AZURE | Azure VMs use platform time sync | Compute | `compute.virtual_machines.list` | medium | [a], [b], [c] |
| `au-3.3.7-gcp-001` | GCP | GCE instances use Google NTP | Compute | `compute.instances.list` | medium | [a], [b], [c] |


#### 3.3.8 — Protect audit information and audit logging tools from unauthorized access, modification, and deletion.

**Level:** L2 | **Type:** Automated | **Objectives:** 6

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.3.8[a] | audit information is protected from unauthorized access. | Yes |
| 3.3.8[b] | audit information is protected from unauthorized modification. | Yes |
| 3.3.8[c] | audit information is protected from unauthorized deletion. | Yes |
| 3.3.8[d] | audit logging tools are protected from unauthorized access. | Yes |
| 3.3.8[e] | audit logging tools are protected from unauthorized modification. | Yes |
| 3.3.8[f] | audit logging tools are protected from unauthorized deletion. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-3.3.8-aws-001` | AWS | CloudTrail S3 bucket has access logging | S3 | `s3.get_bucket_logging` | high | [a], [b], [c], [d], [e], [f] |
| `au-3.3.8-aws-002` | AWS | CloudTrail S3 bucket encrypted | S3 | `s3.get_bucket_encryption` | high | [a], [b], [c], [d], [e], [f] |
| `au-3.3.8-aws-003` | AWS | CloudTrail S3 bucket MFA Delete enabled | S3 | `s3.get_bucket_versioning` | medium | [a], [b], [c], [d], [e], [f] |
| `au-3.3.8-azure-001` | AZURE | Log Analytics workspace access controlled | Monitor | `operationalinsights.workspaces.list` | high | [a], [b], [c], [d], [e], [f] |
| `au-3.3.8-azure-002` | AZURE | Audit log storage uses immutable blobs | Storage | `storage.blob_containers.get_immutability_policy` | high | [a], [b], [c], [d], [e], [f] |
| `au-3.3.8-gcp-001` | GCP | Audit log bucket has retention policy | Storage | `storage.buckets.get` | high | [a], [b], [c], [d], [e], [f] |
| `au-3.3.8-gcp-002` | GCP | Audit log bucket access restricted | Storage | `storage.buckets.getIamPolicy` | high | [a], [b], [c], [d], [e], [f] |


#### 3.3.9 — Limit management of audit logging functionality to a subset of privileged users.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.3.9[a] | a subset of privileged users granted access to manage audit logging functionality is defined. | Partial |
| 3.3.9[b] | management of audit logging functionality is limited to the defined subset of privileged users. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `au-3.3.9-aws-001` | AWS | CloudTrail management restricted to security team | IAM | `iam.list_entities_for_policy` | high | [a], [b] |
| `au-3.3.9-aws-002` | AWS | SCP prevents non-security users from modifying audit config | Organizations | `organizations.list_policies` | high | [a], [b] |
| `au-3.3.9-azure-001` | AZURE | Diagnostic settings management restricted | Authorization | `authorization.role_assignments.list` | high | [a], [b] |
| `au-3.3.9-gcp-001` | GCP | Logging admin role restricted | IAM | `cloudresourcemanager.projects.getIamPolicy` | high | [a], [b] |


### CM — Configuration Management

**Practices:** 9 | **Automated:** 8 | **Manual:** 1 | **Objectives:** 44 | **Checks:** AWS 15, Azure 10, GCP 10

#### 3.4.1 — Establish and maintain baseline configurations and inventories of organizational information systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.

**Level:** L2 | **Type:** Automated | **Objectives:** 6

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.4.1[a] | a baseline configuration is established. | Partial |
| 3.4.1[b] | the baseline configuration includes hardware, software, firmware, and documentation. | No |
| 3.4.1[c] | the baseline configuration is maintained (reviewed and updated) throughout the system development life cycle. | Partial |
| 3.4.1[d] | a system inventory is established. | Partial |
| 3.4.1[e] | the system inventory includes hardware, software, firmware, and documentation. | No |
| 3.4.1[f] | the inventory is maintained (reviewed and updated) throughout the system development life cycle. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-3.4.1-aws-001` | AWS | AWS Config enabled in all regions | Config | `config.describe_configuration_recorders` | critical | [a], [c], [d], [f] |
| `cm-3.4.1-aws-002` | AWS | Systems Manager Inventory enabled | SSM | `ssm.describe_instance_information` | high | [a], [c], [d], [f] |
| `cm-3.4.1-aws-003` | AWS | AMI baseline documented and maintained | EC2 | `ec2.describe_images` | medium | [a], [c], [d], [f] |
| `cm-3.4.1-azure-001` | AZURE | Azure Resource Graph inventory available | Resource Graph | `resourcegraph.resources` | high | [a], [c], [d], [f] |
| `cm-3.4.1-azure-002` | AZURE | Azure Policy Guest Configuration enabled | Policy | `guestconfiguration.guest_configuration_assignments.list` | high | [a], [c], [d], [f] |
| `cm-3.4.1-gcp-001` | GCP | Cloud Asset Inventory enabled | Asset Inventory | `cloudasset.assets.list` | high | [a], [c], [d], [f] |
| `cm-3.4.1-gcp-002` | GCP | OS Config inventory management enabled | OS Config | `osconfig.projects.locations.instances.inventories.get` | medium | [a], [c], [d], [f] |

**Documentation Requirements:**

- **3.4.1[b]**: the baseline configuration includes hardware, software, firmware, and documentation. — *Provide documentation or process evidence: the baseline configuration includes hardware, software, firmware, and documentation.*
- **3.4.1[e]**: the system inventory includes hardware, software, firmware, and documentation. — *Provide documentation or process evidence: the system inventory includes hardware, software, firmware, and documentation.*


#### 3.4.2 — Establish and enforce security configuration settings for information technology products employed in organizational information systems.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.4.2[a] | security configuration settings for information technology products employed in the system are established and included  | Partial |
| 3.4.2[b] | security configuration settings for information technology products employed in the system are enforced. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-3.4.2-aws-001` | AWS | AWS Config rules for CIS Benchmark | Config | `config.describe_config_rules` | high | [a], [b] |
| `cm-3.4.2-aws-002` | AWS | Security Hub CIS standard enabled | Security Hub | `securityhub.describe_standards_subscriptions` | high | [a], [b] |
| `cm-3.4.2-azure-001` | AZURE | Azure Policy assignments for security baseline | Policy | `policy.policy_assignments.list` | high | [a], [b] |
| `cm-3.4.2-azure-002` | AZURE | Defender for Cloud secure score reviewed | Security Center | `security.secure_scores.list` | medium | [a], [b] |
| `cm-3.4.2-gcp-001` | GCP | Organization policies configured | Organization Policy | `orgpolicy.projects.policies.list` | high | [a], [b] |
| `cm-3.4.2-gcp-002` | GCP | SCC findings for CIS compliance | SCC | `securitycenter.organizations.sources.findings.list` | high | [a], [b] |


#### 3.4.3 — Track, review, approve or disapprove, and log changes to organizational information systems.

**Level:** L2 | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.4.3[a] | changes to the system are tracked. | Partial |
| 3.4.3[b] | changes to the system are reviewed. | Partial |
| 3.4.3[c] | changes to the system are approved or disapproved. | Partial |
| 3.4.3[d] | changes to the system are logged. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-3.4.3-aws-001` | AWS | AWS Config configuration history enabled | Config | `config.describe_delivery_channels` | high | [a], [b], [c], [d] |
| `cm-3.4.3-aws-002` | AWS | CloudTrail captures config changes | CloudTrail | `cloudtrail.describe_trails` | high | [a], [b], [c], [d] |
| `cm-3.4.3-azure-001` | AZURE | Activity Log captures resource changes | Monitor | `monitor.activity_logs.list` | high | [a], [b], [c], [d] |
| `cm-3.4.3-gcp-001` | GCP | Admin Activity logs capture changes | Logging | `logging.entries.list` | high | [a], [b], [c], [d] |


#### 3.4.4 — Analyze the security impact of changes prior to implementation.

**Level:** L2 | **Type:** Manual | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.4.4[a] | the security impact of changes to each organizational system is analyzed prior to implementation. | No |

**Documentation Requirements:**

- **3.4.4[a]**: the security impact of changes to each organizational system is analyzed prior to implementation. — *Provide documentation or process evidence: the security impact of changes to each organizational system is analyzed prior to implementation.*

**CCA Manual Assessment Guidance:** Review change management process documentation. Verify that security impact analysis is performed as part of the change approval process before implementation.


#### 3.4.5 — Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational information systems.

**Level:** L2 | **Type:** Automated | **Objectives:** 8

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.4.5[a] | physical access restrictions associated with changes to the system are defined. | Partial |
| 3.4.5[b] | physical access restrictions associated with changes to the system are documented. | No |
| 3.4.5[c] | physical access restrictions associated with changes to the system are approved. | Partial |
| 3.4.5[d] | physical access restrictions associated with changes to the system are enforced. | Yes |
| 3.4.5[e] | logical access restrictions associated with changes to the system are defined. | Partial |
| 3.4.5[f] | logical access restrictions associated with changes to the system are documented. | No |
| 3.4.5[g] | logical access restrictions associated with changes to the system are approved. | Partial |
| 3.4.5[h] | logical access restrictions associated with changes to the system are enforced. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-3.4.5-aws-001` | AWS | CI/CD pipeline has approval gates | CodePipeline | `codepipeline.list_pipelines` | high | [a], [c], [d], [e], [g], [h] |
| `cm-3.4.5-aws-002` | AWS | IAM roles for deployment are scoped | IAM | `iam.list_roles` | high | [a], [c], [d], [e], [g], [h] |
| `cm-3.4.5-azure-001` | AZURE | Resource locks on critical resources | Resources | `resources.management_locks.list` | medium | [a], [c], [d], [e], [g], [h] |
| `cm-3.4.5-gcp-001` | GCP | Project lien configured for critical projects | Resource Manager | `cloudresourcemanager.liens.list` | medium | [a], [c], [d], [e], [g], [h] |

**Documentation Requirements:**

- **3.4.5[b]**: physical access restrictions associated with changes to the system are documented. — *Provide physical security evidence: physical access restrictions associated with changes to the system are documented.*
- **3.4.5[f]**: logical access restrictions associated with changes to the system are documented. — *Provide documentation or process evidence: logical access restrictions associated with changes to the system are documented.*


#### 3.4.6 — Employ the principle of least functionality by configuring organizational information systems to provide only essential capabilities.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.4.6[a] | essential system capabilities are defined based on the principle of least functionality. | Partial |
| 3.4.6[b] | the system is configured to provide only the defined essential capabilities. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-3.4.6-aws-001` | AWS | Unused security groups identified | EC2 | `ec2.describe_security_groups` | medium | [a], [b] |
| `cm-3.4.6-aws-002` | AWS | Unused IAM roles identified | IAM | `iam.list_roles` | medium | [a], [b] |
| `cm-3.4.6-azure-001` | AZURE | Unused resources identified | Advisor | `advisor.recommendations.list` | medium | [a], [b] |
| `cm-3.4.6-gcp-001` | GCP | Unused firewall rules identified | VPC | `compute.firewalls.list` | medium | [a], [b] |


#### 3.4.7 — Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services.

**Level:** L2 | **Type:** Automated | **Objectives:** 15

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.4.7[a] | essential programs are defined. | Partial |
| 3.4.7[b] | the use of nonessential programs is defined. | Partial |
| 3.4.7[c] | the use of nonessential programs is restricted, disabled, or prevented as defined. | Yes |
| 3.4.7[d] | essential functions are defined. | Partial |
| 3.4.7[e] | the use of nonessential functions is defined. | Partial |
| 3.4.7[f] | the use of nonessential functions is restricted, disabled, or prevented as defined. | Yes |
| 3.4.7[g] | essential ports are defined. | Partial |
| 3.4.7[h] | the use of nonessential ports is defined. | Partial |
| 3.4.7[i] | the use of nonessential ports is restricted, disabled, or prevented as defined. | Yes |
| 3.4.7[j] | essential protocols are defined. | Partial |
| 3.4.7[k] | the use of nonessential protocols is defined. | Partial |
| 3.4.7[l] | the use of nonessential protocols is restricted, disabled, or prevented as defined. | Yes |
| 3.4.7[m] | essential services are defined. | Partial |
| 3.4.7[n] | the use of nonessential services is defined. | Partial |
| 3.4.7[o] | the use of nonessential services is restricted, disabled, or prevented as defined. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-3.4.7-aws-001` | AWS | Security groups restrict unnecessary ports | EC2 | `ec2.describe_security_groups` | high | [a], [b], [c], [d], [e], [f], [g], [h], [i], [j], [k], [l], [m], [n], [o] |
| `cm-3.4.7-aws-002` | AWS | Unnecessary AWS services restricted via SCP | Organizations | `organizations.list_policies` | medium | [a], [b], [c], [d], [e], [f], [g], [h], [i], [j], [k], [l], [m], [n], [o] |
| `cm-3.4.7-azure-001` | AZURE | NSG rules restrict unnecessary ports | Network | `network.network_security_groups.list` | high | [a], [b], [c], [d], [e], [f], [g], [h], [i], [j], [k], [l], [m], [n], [o] |
| `cm-3.4.7-gcp-001` | GCP | Firewall rules restrict unnecessary ports | VPC | `compute.firewalls.list` | high | [a], [b], [c], [d], [e], [f], [g], [h], [i], [j], [k], [l], [m], [n], [o] |


#### 3.4.8 — Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software.

**Level:** L2 | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.4.8[a] | a policy specifying whether whitelisting or blacklisting is to be implemented is specified. | Partial |
| 3.4.8[b] | the software allowed to execute under whitelisting or denied use under blacklisting is specified. | Partial |
| 3.4.8[c] | whitelisting to allow the execution of authorized software or blacklisting to prevent the use of unauthorized software i | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-3.4.8-aws-001` | AWS | SSM AppManager or application control configured | SSM | `ssm.list_documents` | medium | [a], [b], [c] |
| `cm-3.4.8-azure-001` | AZURE | Adaptive application controls enabled | Security Center | `security.adaptive_application_controls.list` | medium | [a], [b], [c] |
| `cm-3.4.8-gcp-001` | GCP | Binary Authorization enabled | Binary Authorization | `binaryauthorization.projects.getPolicy` | medium | [a], [b], [c] |


#### 3.4.9 — Control and monitor user-installed software.

**Level:** L2 | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.4.9[a] | a policy for controlling the installation of software by users is established. | Partial |
| 3.4.9[b] | installation of software by users is controlled based on the established policy. | Yes |
| 3.4.9[c] | installation of software by users is monitored. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `cm-3.4.9-aws-001` | AWS | SSM software inventory collected | SSM | `ssm.list_inventory_entries` | medium | [a], [b], [c] |
| `cm-3.4.9-azure-001` | AZURE | Change Tracking and Inventory enabled | Automation | `automation.automation_accounts.list` | medium | [a], [b], [c] |
| `cm-3.4.9-gcp-001` | GCP | OS Config patch and inventory management | OS Config | `osconfig.projects.locations.instances.inventories.list` | medium | [a], [b], [c] |


### IA — Identification and Authentication

**Practices:** 11 | **Automated:** 10 | **Manual:** 1 | **Objectives:** 25 | **Checks:** AWS 18, Azure 13, GCP 12

#### 3.5.1 — Identify information system users, processes acting on behalf of users, or devices.

**Level:** L1 | **Type:** Automated | **Objectives:** 3
 | **FAR 52.204-21:** b.1.v

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.5.1[a] | system users are identified. | Partial |
| 3.5.1[b] | processes acting on behalf of users are identified. | Partial |
| 3.5.1[c] | devices accessing the system are identified. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-3.5.1-aws-001` | AWS | All IAM users uniquely identified | IAM | `iam.list_users` | high | [a], [b], [c] |
| `ia-3.5.1-aws-002` | AWS | Service accounts have descriptive names | IAM | `iam.list_roles` | medium | [a], [b], [c] |
| `ia-3.5.1-aws-003` | AWS | EC2 instances use instance profiles | EC2 | `ec2.describe_instances` | high | [a], [b], [c] |
| `ia-3.5.1-azure-001` | AZURE | All Azure AD users uniquely identified | Azure AD | `graph.users.list` | high | [a], [b], [c] |
| `ia-3.5.1-azure-002` | AZURE | Managed identities used for service authentication | Compute | `compute.virtual_machines.list` | high | [a], [b], [c] |
| `ia-3.5.1-gcp-001` | GCP | All users identified via Google Cloud Identity | IAM | `cloudresourcemanager.projects.getIamPolicy` | high | [a], [b], [c] |
| `ia-3.5.1-gcp-002` | GCP | Service accounts clearly identified | IAM | `iam.projects.serviceAccounts.list` | medium | [a], [b], [c] |


#### 3.5.2 — Authenticate (or verify) the identities of those users, processes, or devices, as a prerequisite to allowing access to organizational information systems.

**Level:** L1 | **Type:** Automated | **Objectives:** 3
 | **FAR 52.204-21:** b.1.vi

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.5.2[a] | the identity of each user is authenticated or verified as a prerequisite to system access. | Partial |
| 3.5.2[b] | the identity of each process acting on behalf of a user is authenticated or verified as a prerequisite to system access. | Partial |
| 3.5.2[c] | the identity of each device accessing or connecting to the system is authenticated or verified as a prerequisite to syst | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-3.5.2-aws-001` | AWS | Root account has MFA enabled | IAM | `iam.get_account_summary` | critical | [a], [b], [c] |
| `ia-3.5.2-aws-002` | AWS | All IAM users with console access have MFA | IAM | `iam.generate_credential_report` | critical | [a], [b], [c] |
| `ia-3.5.2-azure-001` | AZURE | MFA registration required for all users | Azure AD | `graph.reports.credential_user_registration_details.list` | critical | [a], [b], [c] |
| `ia-3.5.2-azure-002` | AZURE | Legacy authentication blocked | Azure AD | `graph.conditional_access_policies.list` | high | [a], [b], [c] |
| `ia-3.5.2-gcp-001` | GCP | 2-Step Verification enforced | Workspace Admin | `admin.directory.users.list` | critical | [a], [b], [c] |


#### 3.5.3 — Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.

**Level:** L2 | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.5.3[a] | privileged accounts are identified. | Partial |
| 3.5.3[b] | multifactor authentication is implemented for local access to privileged accounts. | Yes |
| 3.5.3[c] | multifactor authentication is implemented for network access to privileged accounts. | Yes |
| 3.5.3[d] | multifactor authentication is implemented for network access to non-privileged accounts. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-3.5.3-aws-001` | AWS | MFA enforced for all console access | IAM | `iam.generate_credential_report` | critical | [a], [b], [c], [d] |
| `ia-3.5.3-aws-002` | AWS | MFA required for privileged API actions | IAM | `iam.get_policy_version` | high | [a], [b], [c], [d] |
| `ia-3.5.3-aws-003` | AWS | Hardware MFA used for root account | IAM | `iam.list_virtual_mfa_devices` | high | [a], [b], [c], [d] |
| `ia-3.5.3-azure-001` | AZURE | MFA required via Conditional Access | Azure AD | `graph.conditional_access_policies.list` | critical | [a], [b], [c], [d] |
| `ia-3.5.3-azure-002` | AZURE | MFA required for Azure management | Azure AD | `graph.conditional_access_policies.list` | critical | [a], [b], [c], [d] |
| `ia-3.5.3-gcp-001` | GCP | 2-Step Verification enforced organization-wide | Workspace Admin | `admin.directory.users.list` | critical | [a], [b], [c], [d] |
| `ia-3.5.3-gcp-002` | GCP | Security key required for admin accounts | Workspace Admin | `admin.directory.users.list` | high | [a], [b], [c], [d] |


#### 3.5.4 — Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts.

**Level:** L2 | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.5.4[a] | replay-resistant authentication mechanisms are implemented for all network account access to privileged and non-privileg | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-3.5.4-aws-001` | AWS | FIDO2/WebAuthn supported for MFA | IAM | `iam.list_mfa_devices` | medium | [a] |
| `ia-3.5.4-aws-002` | AWS | STS tokens are time-limited | STS | `iam.list_roles` | medium | [a] |
| `ia-3.5.4-azure-001` | AZURE | FIDO2 authentication method enabled | Azure AD | `graph.authentication_method_configurations.get` | medium | [a] |
| `ia-3.5.4-gcp-001` | GCP | Security key enforcement available | Workspace Admin | `admin.directory.users.list` | medium | [a] |


#### 3.5.5 — Prevent reuse of identifiers for a defined period.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.5.5[a] | a period within which identifiers cannot be reused is defined. | Partial |
| 3.5.5[b] | reuse of identifiers is prevented within the defined period. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-3.5.5-aws-001` | AWS | Deleted IAM user names not reused within 90 days | IAM | `iam.list_users` | medium | [a], [b] |
| `ia-3.5.5-azure-001` | AZURE | Soft-deleted user accounts not reused | Azure AD | `graph.deleted_users.list` | medium | [a], [b] |
| `ia-3.5.5-gcp-001` | GCP | User account identifiers not reused | Workspace Admin | `admin.directory.users.list` | medium | [a], [b] |


#### 3.5.6 — Disable identifiers after a defined period of inactivity.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.5.6[a] | a period of inactivity after which an identifier is disabled is defined. | Partial |
| 3.5.6[b] | identifiers are disabled after the defined period of inactivity. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-3.5.6-aws-001` | AWS | IAM users inactive for 90 days identified | IAM | `iam.generate_credential_report` | high | [a], [b] |
| `ia-3.5.6-aws-002` | AWS | Access keys inactive for 90 days identified | IAM | `iam.generate_credential_report` | high | [a], [b] |
| `ia-3.5.6-azure-001` | AZURE | Inactive Azure AD accounts identified | Azure AD | `graph.users.list` | high | [a], [b] |
| `ia-3.5.6-gcp-001` | GCP | Inactive service account keys identified | IAM | `iam.projects.serviceAccounts.keys.list` | high | [a], [b] |


#### 3.5.7 — Enforce a minimum password complexity and change of characters when new passwords are created.

**Level:** L2 | **Type:** Automated | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.5.7[a] | password complexity requirements are defined. | Partial |
| 3.5.7[b] | password change of character requirements are defined. | Partial |
| 3.5.7[c] | minimum password complexity requirements as defined are enforced when new passwords are created. | Yes |
| 3.5.7[d] | minimum password change of character requirements as defined are enforced when new passwords are created. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-3.5.7-aws-001` | AWS | IAM password policy enforces complexity | IAM | `iam.get_account_password_policy` | high | [a], [b], [c], [d] |
| `ia-3.5.7-azure-001` | AZURE | Azure AD password protection enabled | Azure AD | `graph.settings.list` | high | [a], [b], [c], [d] |
| `ia-3.5.7-gcp-001` | GCP | Password policy enforced in Workspace | Workspace Admin | `admin.directory.users.list` | high | [a], [b], [c], [d] |


#### 3.5.8 — Prohibit password reuse for a specified number of generations.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.5.8[a] | the number of generations during which a password cannot be reused is specified. | Partial |
| 3.5.8[b] | reuse of passwords is prohibited during the specified number of generations. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-3.5.8-aws-001` | AWS | Password reuse prevention configured | IAM | `iam.get_account_password_policy` | high | [a], [b] |
| `ia-3.5.8-azure-001` | AZURE | Password history enforced | Azure AD | `graph.settings.list` | high | [a], [b] |
| `ia-3.5.8-gcp-001` | GCP | Password reuse restricted in Workspace | Workspace Admin | `admin.directory.users.list` | high | [a], [b] |


#### 3.5.9 — Allow temporary password use for system logons with an immediate change to a permanent password.

**Level:** L2 | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.5.9[a] | an immediate change to a permanent password is required when a temporary password is used for system logon. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-3.5.9-aws-001` | AWS | IAM Identity Center force password change on first login | IAM Identity Center | `identitystore.describe_user` | medium | [a] |
| `ia-3.5.9-azure-001` | AZURE | Force password change on new accounts | Azure AD | `graph.users.list` | medium | [a] |
| `ia-3.5.9-gcp-001` | GCP | Force password change for new users | Workspace Admin | `admin.directory.users.list` | medium | [a] |


#### 3.5.10 — Store and transmit only cryptographically-protected passwords.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.5.10[a] | passwords are cryptographically protected in storage. | Yes |
| 3.5.10[b] | passwords are cryptographically protected in transit. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ia-3.5.10-aws-001` | AWS | TLS enforced for all API communication | IAM | `iam.get_account_password_policy` | high | [a], [b] |
| `ia-3.5.10-aws-002` | AWS | Database passwords encrypted in transit | RDS | `rds.describe_db_instances` | high | [a], [b] |
| `ia-3.5.10-azure-001` | AZURE | HTTPS-only access enforced | App Service | `web.web_apps.list` | high | [a], [b] |
| `ia-3.5.10-gcp-001` | GCP | SSL enforced on Cloud SQL instances | Cloud SQL | `sqladmin.instances.list` | high | [a], [b] |


#### 3.5.11 — Obscure feedback of authentication information.

**Level:** L2 | **Type:** Manual | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.5.11[a] | authentication information is obscured during the authentication process. | No |

**Documentation Requirements:**

- **3.5.11[a]**: authentication information is obscured during the authentication process. — *Provide documentation or process evidence: authentication information is obscured during the authentication process.*

**CCA Manual Assessment Guidance:** Verify that authentication interfaces mask password input. Check that error messages do not reveal whether the username or password was incorrect.


### IR — Incident Response

**Practices:** 3 | **Automated:** 1 | **Manual:** 2 | **Objectives:** 14 | **Checks:** AWS 4, Azure 3, GCP 3

#### 3.6.1 — Establish an operational incident-handling capability for organizational information systems that includes preparation, detection, analysis, containment, recovery, and user response activities.

**Level:** L2 | **Type:** Automated | **Objectives:** 7

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.6.1[a] | an operational incident-handling capability is established. | Partial |
| 3.6.1[b] | the operational incident-handling capability includes preparation. | Partial |
| 3.6.1[c] | the operational incident-handling capability includes detection. | Partial |
| 3.6.1[d] | the operational incident-handling capability includes analysis. | Partial |
| 3.6.1[e] | the operational incident-handling capability includes containment. | Partial |
| 3.6.1[f] | the operational incident-handling capability includes recovery. | Partial |
| 3.6.1[g] | the operational incident-handling capability includes user response activities. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ir-3.6.1-aws-001` | AWS | GuardDuty enabled in all regions | GuardDuty | `guardduty.list_detectors` | critical | [a], [b], [c], [d], [e], [f], [g] |
| `ir-3.6.1-aws-002` | AWS | Security Hub enabled with automated findings | Security Hub | `securityhub.describe_hub` | high | [a], [b], [c], [d], [e], [f], [g] |
| `ir-3.6.1-aws-003` | AWS | EventBridge rules for security events | EventBridge | `events.list_rules` | high | [a], [b], [c], [d], [e], [f], [g] |
| `ir-3.6.1-aws-004` | AWS | IR playbooks documented in SSM Automation | SSM | `ssm.list_documents` | medium | [a], [b], [c], [d], [e], [f], [g] |
| `ir-3.6.1-azure-001` | AZURE | Microsoft Defender for Cloud enabled | Security Center | `security.pricings.list` | critical | [a], [b], [c], [d], [e], [f], [g] |
| `ir-3.6.1-azure-002` | AZURE | Microsoft Sentinel deployed | Sentinel | `securityinsight.sentinel_onboarding_states.list` | high | [a], [b], [c], [d], [e], [f], [g] |
| `ir-3.6.1-azure-003` | AZURE | Sentinel automation rules configured | Sentinel | `securityinsight.automation_rules.list` | medium | [a], [b], [c], [d], [e], [f], [g] |
| `ir-3.6.1-gcp-001` | GCP | Security Command Center Premium enabled | SCC | `securitycenter.organizations.getOrganizationSettings` | critical | [a], [b], [c], [d], [e], [f], [g] |
| `ir-3.6.1-gcp-002` | GCP | Event Threat Detection enabled | SCC | `securitycenter.organizations.sources.list` | high | [a], [b], [c], [d], [e], [f], [g] |
| `ir-3.6.1-gcp-003` | GCP | Pub/Sub notifications for SCC findings | SCC | `securitycenter.organizations.notificationConfigs.list` | high | [a], [b], [c], [d], [e], [f], [g] |


#### 3.6.2 — Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.

**Level:** L2 | **Type:** Manual | **Objectives:** 6

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.6.2[a] | incidents are tracked. | No |
| 3.6.2[b] | incidents are documented. | No |
| 3.6.2[c] | authorities to whom incidents are to be reported are identified. | No |
| 3.6.2[d] | organizational officials to whom incidents are to be reported are identified. | No |
| 3.6.2[e] | identified authorities are notified of incidents. | No |
| 3.6.2[f] | identified organizational officials are notified of incidents. | No |

**Documentation Requirements:**

- **3.6.2[a]**: incidents are tracked. — *Provide documentation or process evidence: incidents are tracked.*
- **3.6.2[b]**: incidents are documented. — *Provide documentation or process evidence: incidents are documented.*
- **3.6.2[c]**: authorities to whom incidents are to be reported are identified. — *Provide documentation showing that authorities to whom incidents are to be reported are identified and documented.*
- **3.6.2[d]**: organizational officials to whom incidents are to be reported are identified. — *Provide documentation showing that organizational officials to whom incidents are to be reported are identified and documented.*
- **3.6.2[e]**: identified authorities are notified of incidents. — *Provide documentation or process evidence: identified authorities are notified of incidents.*
- **3.6.2[f]**: identified organizational officials are notified of incidents. — *Provide documentation or process evidence: identified organizational officials are notified of incidents.*

**CCA Manual Assessment Guidance:** Review incident tracking system and reporting procedures. Verify incident reports include required data elements and are communicated to appropriate authorities within required timeframes.


#### 3.6.3 — Test the organizational incident response capability.

**Level:** L2 | **Type:** Manual | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.6.3[a] | the incident response capability is tested. | No |

**Documentation Requirements:**

- **3.6.3[a]**: the incident response capability is tested. — *Provide documentation or process evidence: the incident response capability is tested.*

**CCA Manual Assessment Guidance:** Request records of incident response tests and tabletop exercises. Verify testing occurs at least annually and results are documented with lessons learned.


### MA — Maintenance

**Practices:** 6 | **Automated:** 2 | **Manual:** 4 | **Objectives:** 10 | **Checks:** AWS 5, Azure 3, GCP 3

#### 3.7.1 — Perform maintenance on organizational information systems.

**Level:** L2 | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.7.1[a] | system maintenance is performed. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ma-3.7.1-aws-001` | AWS | SSM Patch Manager configured | SSM | `ssm.describe_patch_baselines` | high | [a] |
| `ma-3.7.1-aws-002` | AWS | Patch compliance monitored | SSM | `ssm.describe_instance_patch_states` | high | [a] |
| `ma-3.7.1-aws-003` | AWS | RDS automatic minor version upgrade enabled | RDS | `rds.describe_db_instances` | medium | [a] |
| `ma-3.7.1-azure-001` | AZURE | Azure Update Management configured | Automation | `automation.software_update_configurations.list` | high | [a] |
| `ma-3.7.1-azure-002` | AZURE | VM patch assessment enabled | Compute | `compute.virtual_machines.list` | high | [a] |
| `ma-3.7.1-gcp-001` | GCP | OS Config patch management configured | OS Config | `osconfig.projects.patchDeployments.list` | high | [a] |
| `ma-3.7.1-gcp-002` | GCP | Container image vulnerability scanning | Artifact Registry | `containeranalysis.projects.occurrences.list` | high | [a] |


#### 3.7.2 — Provide controls on the tools, techniques, mechanisms, and personnel used to conduct information system maintenance.

**Level:** L2 | **Type:** Manual | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.7.2[a] | tools used to conduct system maintenance are controlled. | No |
| 3.7.2[b] | techniques used to conduct system maintenance are controlled. | No |
| 3.7.2[c] | mechanisms used to conduct system maintenance are controlled. | No |
| 3.7.2[d] | personnel used to conduct system maintenance are controlled. | No |

**Documentation Requirements:**

- **3.7.2[a]**: tools used to conduct system maintenance are controlled. — *Provide documentation or process evidence: tools used to conduct system maintenance are controlled.*
- **3.7.2[b]**: techniques used to conduct system maintenance are controlled. — *Provide documentation or process evidence: techniques used to conduct system maintenance are controlled.*
- **3.7.2[c]**: mechanisms used to conduct system maintenance are controlled. — *Provide documentation or process evidence: mechanisms used to conduct system maintenance are controlled.*
- **3.7.2[d]**: personnel used to conduct system maintenance are controlled. — *Provide personnel records: personnel used to conduct system maintenance are controlled.*

**CCA Manual Assessment Guidance:** Review maintenance tool inventory and authorization records. Verify that maintenance personnel are vetted and that maintenance tools are inspected and sanitized before use.


#### 3.7.3 — Ensure equipment removed for off-site maintenance is sanitized of any CUI.

**Level:** L2 | **Type:** Manual | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.7.3[a] | equipment to be removed from organizational spaces for off-site maintenance is sanitized of any CUI. | No |

**Documentation Requirements:**

- **3.7.3[a]**: equipment to be removed from organizational spaces for off-site maintenance is sanitized of any CUI. — *Provide documentation or process evidence: equipment to be removed from organizational spaces for off-site maintenance is sanitized of any CUI.*

**CCA Manual Assessment Guidance:** Review media sanitization procedures for equipment sent off-site. Verify sanitization records exist for all equipment removed for maintenance.


#### 3.7.4 — Check media containing diagnostic and test programs for malicious code before the media are used in organizational information systems.

**Level:** L2 | **Type:** Manual | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.7.4[a] | media containing diagnostic and test programs are checked for malicious code before being used in organizational systems | No |

**Documentation Requirements:**

- **3.7.4[a]**: media containing diagnostic and test programs are checked for malicious code before being used in organizational systems that process, store, or transmit CUI. — *Provide documentation or process evidence: media containing diagnostic and test programs are checked for malicious code before being used in organizational systems that process, store, or transmit CUI.*

**CCA Manual Assessment Guidance:** Review procedures for scanning maintenance media. Verify that anti-malware scans are performed on all diagnostic media before connection to production systems.


#### 3.7.5 — Require multifactor authentication to establish nonlocal maintenance sessions via external network connections and terminate such connections when nonlocal maintenance is complete.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.7.5[a] | multifactor authentication is required to establish nonlocal maintenance sessions via external network connections. | Partial |
| 3.7.5[b] | nonlocal maintenance sessions established via external network connections are terminated when nonlocal maintenance is c | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ma-3.7.5-aws-001` | AWS | Session Manager requires MFA for remote maintenance | SSM | `iam.get_policy_version` | high | [a], [b] |
| `ma-3.7.5-aws-002` | AWS | VPN connections require MFA | VPC | `ec2.describe_client_vpn_endpoints` | high | [a], [b] |
| `ma-3.7.5-azure-001` | AZURE | MFA required for Azure Bastion access | Azure AD | `graph.conditional_access_policies.list` | high | [a], [b] |
| `ma-3.7.5-gcp-001` | GCP | 2SV required for admin console access | Workspace Admin | `admin.directory.users.list` | high | [a], [b] |


#### 3.7.6 — Supervise the maintenance activities of maintenance personnel without required access authorization.

**Level:** L2 | **Type:** Manual | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.7.6[a] | maintenance personnel without required access authorization are supervised during maintenance activities. | No |

**Documentation Requirements:**

- **3.7.6[a]**: maintenance personnel without required access authorization are supervised during maintenance activities. — *Provide personnel records: maintenance personnel without required access authorization are supervised during maintenance activities.*

**CCA Manual Assessment Guidance:** Review escort and supervision procedures for maintenance personnel. Verify that session recording or direct observation is used for uncleared maintenance staff.


### MP — Media Protection

**Practices:** 9 | **Automated:** 3 | **Manual:** 6 | **Objectives:** 15 | **Checks:** AWS 9, Azure 6, GCP 5

#### 3.8.1 — Protect (i.e., physically control and securely store) information system media containing CUI, both paper and digital.

**Level:** L2 | **Type:** Manual | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.8.1[a] | paper media containing CUI is physically controlled. | No |
| 3.8.1[b] | digital media containing CUI is physically controlled. | No |
| 3.8.1[c] | paper media containing CUI is securely stored. | No |
| 3.8.1[d] | digital media containing CUI is securely stored. | No |

**Documentation Requirements:**

- **3.8.1[a]**: paper media containing CUI is physically controlled. — *Provide physical security evidence: paper media containing CUI is physically controlled.*
- **3.8.1[b]**: digital media containing CUI is physically controlled. — *Provide physical security evidence: digital media containing CUI is physically controlled.*
- **3.8.1[c]**: paper media containing CUI is securely stored. — *Provide documentation or process evidence: paper media containing CUI is securely stored.*
- **3.8.1[d]**: digital media containing CUI is securely stored. — *Provide documentation or process evidence: digital media containing CUI is securely stored.*

**CCA Manual Assessment Guidance:** Review media storage and handling procedures. Verify physical security controls for media storage areas and digital media access controls.


#### 3.8.2 — Limit access to CUI on information system media to authorized users.

**Level:** L2 | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.8.2[a] | access to CUI on system media is limited to authorized users. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `mp-3.8.2-aws-001` | AWS | S3 bucket policies restrict CUI access | S3 | `s3.get_bucket_policy` | high | [a] |
| `mp-3.8.2-aws-002` | AWS | EBS volumes encrypted | EC2 | `ec2.describe_volumes` | high | [a] |
| `mp-3.8.2-aws-003` | AWS | EBS default encryption enabled | EC2 | `ec2.get_ebs_encryption_by_default` | high | [a] |
| `mp-3.8.2-azure-001` | AZURE | Storage account access restricted | Storage | `storage.storage_accounts.list` | high | [a] |
| `mp-3.8.2-azure-002` | AZURE | Managed disk encryption enabled | Compute | `compute.disks.list` | high | [a] |
| `mp-3.8.2-gcp-001` | GCP | Cloud Storage bucket access restricted | Storage | `storage.buckets.getIamPolicy` | high | [a] |
| `mp-3.8.2-gcp-002` | GCP | Persistent disk encryption with CMEK | Compute | `compute.disks.list` | high | [a] |


#### 3.8.3 — Sanitize or destroy information system media containing CUI before disposal or release for reuse.

**Level:** L1 | **Type:** Manual | **Objectives:** 2
 | **FAR 52.204-21:** b.1.vii

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.8.3[a] | system media containing CUI is sanitized or destroyed before disposal. | No |
| 3.8.3[b] | system media containing CUI is sanitized before it is released for reuse. | No |

**Documentation Requirements:**

- **3.8.3[a]**: system media containing CUI is sanitized or destroyed before disposal. — *Provide documentation or process evidence: system media containing CUI is sanitized or destroyed before disposal.*
- **3.8.3[b]**: system media containing CUI is sanitized before it is released for reuse. — *Provide documentation or process evidence: system media containing CUI is sanitized before it is released for reuse.*

**CCA Manual Assessment Guidance:** Review media sanitization procedures and records. Verify NIST 800-88 compliant sanitization methods are used. Check disposal vendor certifications and certificates of destruction.


#### 3.8.4 — Mark media with necessary CUI markings and distribution limitations.

**Level:** L2 | **Type:** Manual | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.8.4[a] | media containing CUI is marked with applicable CUI markings. | No |
| 3.8.4[b] | media containing CUI is marked with distribution limitations. | No |

**Documentation Requirements:**

- **3.8.4[a]**: media containing CUI is marked with applicable CUI markings. — *Provide documentation or process evidence: media containing CUI is marked with applicable CUI markings.*
- **3.8.4[b]**: media containing CUI is marked with distribution limitations. — *Provide documentation or process evidence: media containing CUI is marked with distribution limitations.*

**CCA Manual Assessment Guidance:** Verify CUI marking procedures exist and are followed. Check that digital and physical media containing CUI are marked with appropriate CUI designations and distribution statements.


#### 3.8.5 — Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas.

**Level:** L2 | **Type:** Manual | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.8.5[a] | access to media containing CUI is controlled. | No |
| 3.8.5[b] | accountability for media containing CUI is maintained during transport outside of controlled areas. | No |

**Documentation Requirements:**

- **3.8.5[a]**: access to media containing CUI is controlled. — *Provide documentation or process evidence: access to media containing CUI is controlled.*
- **3.8.5[b]**: accountability for media containing CUI is maintained during transport outside of controlled areas. — *Provide documentation or process evidence: accountability for media containing CUI is maintained during transport outside of controlled areas.*

**CCA Manual Assessment Guidance:** Review media transport procedures and chain-of-custody records. Verify encryption requirements for media in transit and accountability tracking mechanisms.


#### 3.8.6 — Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport unless otherwise protected by alternative physical safeguards.

**Level:** L2 | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.8.6[a] | the confidentiality of CUI stored on digital media is protected during transport using cryptographic mechanisms or alter | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `mp-3.8.6-aws-001` | AWS | S3 buckets encrypted with KMS | S3 | `s3.get_bucket_encryption` | high | [a] |
| `mp-3.8.6-aws-002` | AWS | RDS instances encrypted | RDS | `rds.describe_db_instances` | high | [a] |
| `mp-3.8.6-aws-003` | AWS | EFS file systems encrypted | EFS | `efs.describe_file_systems` | high | [a] |
| `mp-3.8.6-azure-001` | AZURE | Storage accounts enforce encryption | Storage | `storage.storage_accounts.list` | high | [a] |
| `mp-3.8.6-azure-002` | AZURE | SQL Database TDE enabled | SQL | `sql.transparent_data_encryptions.get` | high | [a] |
| `mp-3.8.6-gcp-001` | GCP | Cloud Storage buckets use CMEK | Storage | `storage.buckets.get` | high | [a] |
| `mp-3.8.6-gcp-002` | GCP | Cloud SQL instances encrypted | Cloud SQL | `sqladmin.instances.list` | high | [a] |


#### 3.8.7 — Control the use of removable media on information system components.

**Level:** L2 | **Type:** Manual | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.8.7[a] | the use of removable media on system components containing CUI is controlled. | No |

**Documentation Requirements:**

- **3.8.7[a]**: the use of removable media on system components containing CUI is controlled. — *Provide documentation or process evidence: the use of removable media on system components containing CUI is controlled.*

**CCA Manual Assessment Guidance:** Review removable media policies and endpoint DLP configurations. Verify USB device restrictions and authorized device whitelists.


#### 3.8.8 — Prohibit the use of portable storage devices when such devices have no identifiable owner.

**Level:** L2 | **Type:** Manual | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.8.8[a] | the use of portable storage devices is prohibited when such devices have no identifiable owner. | No |

**Documentation Requirements:**

- **3.8.8[a]**: the use of portable storage devices is prohibited when such devices have no identifiable owner. — *Provide documentation or process evidence: the use of portable storage devices is prohibited when such devices have no identifiable owner.*

**CCA Manual Assessment Guidance:** Review portable storage device policies. Verify that all authorized portable storage devices are registered and assigned to specific individuals.


#### 3.8.9 — Protect the confidentiality of backup CUI at storage locations.

**Level:** L2 | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.8.9[a] | the confidentiality of backup CUI is protected at storage locations. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `mp-3.8.9-aws-001` | AWS | Backup vault encrypted with KMS | Backup | `backup.list_backup_vaults` | high | [a] |
| `mp-3.8.9-aws-002` | AWS | Backup vault access policy restricts access | Backup | `backup.get_backup_vault_access_policy` | high | [a] |
| `mp-3.8.9-aws-003` | AWS | S3 cross-region replication encrypted | S3 | `s3.get_bucket_replication` | medium | [a] |
| `mp-3.8.9-azure-001` | AZURE | Recovery Services vault encrypted | Recovery Services | `recoveryservices.vaults.list` | high | [a] |
| `mp-3.8.9-azure-002` | AZURE | Backup vault soft delete enabled | Recovery Services | `recoveryservices.backup_resource_vault_configs.get` | medium | [a] |
| `mp-3.8.9-gcp-001` | GCP | Backup encrypted with CMEK | Backup and DR | `backupdr.projects.locations.backupVaults.list` | high | [a] |


### PS — Personnel Security

**Practices:** 2 | **Automated:** 0 | **Manual:** 2 | **Objectives:** 4 | **Checks:** AWS 0, Azure 0, GCP 0

#### 3.9.1 — Screen individuals prior to authorizing access to organizational information systems containing CUI.

**Level:** L2 | **Type:** Manual | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.9.1[a] | individuals are screened prior to authorizing access to organizational systems. | No |

**Documentation Requirements:**

- **3.9.1[a]**: individuals are screened prior to authorizing access to organizational systems. — *Provide documentation or process evidence: individuals are screened prior to authorizing access to organizational systems.*

**CCA Manual Assessment Guidance:** Review personnel screening procedures and records. Verify background checks are completed before granting access to CUI systems. Check screening criteria meet organizational and regulatory requirements.


#### 3.9.2 — Ensure that organizational information systems containing CUI are protected during and after personnel actions such as terminations and transfers.

**Level:** L2 | **Type:** Manual | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.9.2[a] | a policy and/or process for terminating system access authorization and any credentials coincident with personnel action | No |
| 3.9.2[b] | system access and credentials are terminated consistent with personnel actions such as termination or transfer. | No |
| 3.9.2[c] | the system is protected during and after personnel transfer actions. | No |

**Documentation Requirements:**

- **3.9.2[a]**: a policy and/or process for terminating system access authorization and any credentials coincident with personnel actions is established. — *Provide personnel records: a policy and/or process for terminating system access authorization and any credentials coincident with personnel actions is established.*
- **3.9.2[b]**: system access and credentials are terminated consistent with personnel actions such as termination or transfer. — *Provide personnel records: system access and credentials are terminated consistent with personnel actions such as termination or transfer.*
- **3.9.2[c]**: the system is protected during and after personnel transfer actions. — *Provide personnel records: the system is protected during and after personnel transfer actions.*

**CCA Manual Assessment Guidance:** Review termination and transfer procedures. Verify that access is revoked promptly upon termination, credentials are disabled, and equipment/media are recovered. Check for automated deprovisioning workflows.


### PE — Physical Protection

**Practices:** 6 | **Automated:** 0 | **Manual:** 6 | **Objectives:** 16 | **Checks:** AWS 0, Azure 0, GCP 0

#### 3.10.1 — Limit physical access to organizational information systems, equipment, and the respective operating environments to authorized individuals.

**Level:** L1 | **Type:** Manual | **Objectives:** 4
 | **FAR 52.204-21:** b.1.viii

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.10.1[a] | authorized individuals allowed physical access are identified. | No |
| 3.10.1[b] | physical access to organizational systems is limited to authorized individuals. | No |
| 3.10.1[c] | physical access to equipment is limited to authorized individuals. | No |
| 3.10.1[d] | physical access to operating environments is limited to authorized individuals. | No |

**Documentation Requirements:**

- **3.10.1[a]**: authorized individuals allowed physical access are identified. — *Provide documentation showing that authorized individuals allowed physical access are identified and documented.*
- **3.10.1[b]**: physical access to organizational systems is limited to authorized individuals. — *Provide physical security evidence: physical access to organizational systems is limited to authorized individuals.*
- **3.10.1[c]**: physical access to equipment is limited to authorized individuals. — *Provide physical security evidence: physical access to equipment is limited to authorized individuals.*
- **3.10.1[d]**: physical access to operating environments is limited to authorized individuals. — *Provide physical security evidence: physical access to operating environments is limited to authorized individuals.*

**CCA Manual Assessment Guidance:** Review physical access control mechanisms (badge readers, biometrics, locks). Verify authorized access lists are current and physical access logs are maintained.


#### 3.10.2 — Protect and monitor the physical facility and support infrastructure for organizational information systems.

**Level:** L2 | **Type:** Manual | **Objectives:** 4

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.10.2[a] | the physical facility where that system resides is protected. | No |
| 3.10.2[b] | the support infrastructure for that system is protected. | No |
| 3.10.2[c] | the physical facility where that system resides is monitored. | No |
| 3.10.2[d] | the support infrastructure for that system is monitored. | No |

**Documentation Requirements:**

- **3.10.2[a]**: the physical facility where that system resides is protected. — *Provide physical security evidence: the physical facility where that system resides is protected.*
- **3.10.2[b]**: the support infrastructure for that system is protected. — *Provide documentation or process evidence: the support infrastructure for that system is protected.*
- **3.10.2[c]**: the physical facility where that system resides is monitored. — *Provide physical security evidence: the physical facility where that system resides is monitored.*
- **3.10.2[d]**: the support infrastructure for that system is monitored. — *Provide documentation or process evidence: the support infrastructure for that system is monitored.*

**CCA Manual Assessment Guidance:** Review physical security monitoring systems (cameras, alarms, environmental controls). Verify monitoring coverage of server rooms, network closets, and other sensitive areas.


#### 3.10.3 — Escort visitors and monitor visitor activity.

**Level:** L1 | **Type:** Manual | **Objectives:** 2
 | **FAR 52.204-21:** b.1.ix

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.10.3[a] | visitors are escorted. | No |
| 3.10.3[b] | visitor activity is monitored. | No |

**Documentation Requirements:**

- **3.10.3[a]**: visitors are escorted. — *Provide documentation or process evidence: visitors are escorted.*
- **3.10.3[b]**: visitor activity is monitored. — *Provide documentation or process evidence: visitor activity is monitored.*

**CCA Manual Assessment Guidance:** Review visitor management procedures. Verify visitor logs, escort requirements, and badge/identification procedures. Check that visitors are escorted in areas with CUI access.


#### 3.10.4 — Maintain audit logs of physical access.

**Level:** L1 | **Type:** Manual | **Objectives:** 1
 | **FAR 52.204-21:** b.1.x

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.10.4[a] | audit logs of physical access are maintained. | No |

**Documentation Requirements:**

- **3.10.4[a]**: audit logs of physical access are maintained. — *Provide physical security evidence: audit logs of physical access are maintained.*

**CCA Manual Assessment Guidance:** Review physical access logs and retention periods. Verify logs capture entry/exit times, individual identity, and are retained per organizational policy.


#### 3.10.5 — Control and manage physical access devices.

**Level:** L1 | **Type:** Manual | **Objectives:** 3
 | **FAR 52.204-21:** b.1.xi

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.10.5[a] | physical access devices are identified. | No |
| 3.10.5[b] | physical access devices are controlled. | No |
| 3.10.5[c] | physical access devices are managed. | No |

**Documentation Requirements:**

- **3.10.5[a]**: physical access devices are identified. — *Provide documentation showing that physical access devices are identified and documented.*
- **3.10.5[b]**: physical access devices are controlled. — *Provide physical security evidence: physical access devices are controlled.*
- **3.10.5[c]**: physical access devices are managed. — *Provide physical security evidence: physical access devices are managed.*

**CCA Manual Assessment Guidance:** Review inventory and management of physical access devices (keys, badges, combinations, PINs). Verify devices are inventoried, changed when compromised, and deactivated for separated personnel.


#### 3.10.6 — Enforce safeguarding measures for CUI at alternate work sites.

**Level:** L2 | **Type:** Manual | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.10.6[a] | safeguarding measures for CUI are defined for alternate work sites. | No |
| 3.10.6[b] | safeguarding measures for CUI are enforced for alternate work sites. | No |

**Documentation Requirements:**

- **3.10.6[a]**: safeguarding measures for CUI are defined for alternate work sites. — *Provide documentation showing that safeguarding measures for cui are defined.*
- **3.10.6[b]**: safeguarding measures for CUI are enforced for alternate work sites. — *Provide documentation or process evidence: safeguarding measures for CUI are enforced for alternate work sites.*

**CCA Manual Assessment Guidance:** Review telework and alternate work site policies. Verify requirements for securing CUI at home offices and temporary work locations including physical security and network requirements.


### RA — Risk Assessment

**Practices:** 3 | **Automated:** 2 | **Manual:** 1 | **Objectives:** 9 | **Checks:** AWS 5, Azure 5, GCP 5

#### 3.11.1 — Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational information systems and the associated processing, storage, or transmission of CUI.

**Level:** L2 | **Type:** Manual | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.11.1[a] | the frequency to assess risk to organizational operations, organizational assets, and individuals is defined. | No |
| 3.11.1[b] | risk to organizational operations, organizational assets, and individuals resulting from the operation of an organizatio | No |

**Documentation Requirements:**

- **3.11.1[a]**: the frequency to assess risk to organizational operations, organizational assets, and individuals is defined. — *Provide documentation showing that the frequency to assess risk to organizational operations, organizational assets, and individuals are defined.*
- **3.11.1[b]**: risk to organizational operations, organizational assets, and individuals resulting from the operation of an organizational system that processes, stores, or transmits CUI is assessed with the defined frequency. — *Provide documentation or process evidence: risk to organizational operations, organizational assets, and individuals resulting from the operation of an organizational system that processes, stores, or transmits CUI is assessed with the defined frequency.*

**CCA Manual Assessment Guidance:** Request the most recent risk assessment report. Verify it covers CUI systems, is updated at least annually, and addresses threats, vulnerabilities, likelihood, and impact.


#### 3.11.2 — Scan for vulnerabilities in organizational information systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified.

**Level:** L2 | **Type:** Automated | **Objectives:** 5

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.11.2[a] | the frequency to scan for vulnerabilities in an organizational system and its applications that process, store, or trans | Partial |
| 3.11.2[b] | vulnerability scans are performed in an organizational system that processes, stores, or transmits CUI with the defined  | Partial |
| 3.11.2[c] | vulnerability scans are performed in an application that contains CUI with the defined frequency. | Partial |
| 3.11.2[d] | vulnerability scans are performed in an organizational system that processes, stores, or transmits CUI when new vulnerab | Partial |
| 3.11.2[e] | vulnerability scans are performed in an application that contains CUI when new vulnerabilities are identified. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ra-3.11.2-aws-001` | AWS | Amazon Inspector enabled | Inspector | `inspector2.list_account_permissions` | high | [a], [b], [c], [d], [e] |
| `ra-3.11.2-aws-002` | AWS | ECR image scanning enabled | ECR | `ecr.describe_repositories` | high | [a], [b], [c], [d], [e] |
| `ra-3.11.2-aws-003` | AWS | Vulnerability findings reviewed regularly | Inspector | `inspector2.list_findings` | high | [a], [b], [c], [d], [e] |
| `ra-3.11.2-azure-001` | AZURE | Defender for Cloud vulnerability assessment enabled | Security Center | `security.sub_assessments.list` | high | [a], [b], [c], [d], [e] |
| `ra-3.11.2-azure-002` | AZURE | Container vulnerability scanning enabled | Security Center | `security.pricings.get` | high | [a], [b], [c], [d], [e] |
| `ra-3.11.2-azure-003` | AZURE | SQL vulnerability assessment enabled | SQL | `sql.server_vulnerability_assessments.get` | high | [a], [b], [c], [d], [e] |
| `ra-3.11.2-gcp-001` | GCP | Web Security Scanner enabled | SCC | `websecurityscanner.projects.scanConfigs.list` | high | [a], [b], [c], [d], [e] |
| `ra-3.11.2-gcp-002` | GCP | Container Analysis vulnerability scanning | Container Analysis | `containeranalysis.projects.occurrences.list` | high | [a], [b], [c], [d], [e] |
| `ra-3.11.2-gcp-003` | GCP | Security Health Analytics enabled | SCC | `securitycenter.organizations.sources.findings.list` | high | [a], [b], [c], [d], [e] |


#### 3.11.3 — Remediate vulnerabilities in accordance with risk assessments.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.11.3[a] | vulnerabilities are identified. | Partial |
| 3.11.3[b] | vulnerabilities are remediated in accordance with risk assessments. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ra-3.11.3-aws-001` | AWS | SSM Patch Manager compliance monitored | SSM | `ssm.describe_instance_patch_states` | high | [a], [b] |
| `ra-3.11.3-aws-002` | AWS | Inspector critical findings remediated | Inspector | `inspector2.list_findings` | high | [a], [b] |
| `ra-3.11.3-azure-001` | AZURE | Update Management compliance tracked | Automation | `automation.software_update_configurations.list` | high | [a], [b] |
| `ra-3.11.3-azure-002` | AZURE | Defender recommendations addressed | Security Center | `security.assessments.list` | high | [a], [b] |
| `ra-3.11.3-gcp-001` | GCP | OS Config patch compliance monitored | OS Config | `osconfig.projects.locations.instances.vulnerabilityReports.get` | high | [a], [b] |
| `ra-3.11.3-gcp-002` | GCP | SCC critical findings remediated | SCC | `securitycenter.organizations.sources.findings.list` | high | [a], [b] |


### CA — Security Assessment

**Practices:** 4 | **Automated:** 1 | **Manual:** 3 | **Objectives:** 13 | **Checks:** AWS 3, Azure 2, GCP 2

#### 3.12.1 — Periodically assess the security controls in organizational information systems to determine if the controls are effective in their application.

**Level:** L2 | **Type:** Manual | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.12.1[a] | the frequency of security control assessments is defined. | No |
| 3.12.1[b] | security controls are assessed with the defined frequency to determine if the controls are effective in their applicatio | No |

**Documentation Requirements:**

- **3.12.1[a]**: the frequency of security control assessments is defined. — *Provide documentation showing that the frequency of security control assessments are defined.*
- **3.12.1[b]**: security controls are assessed with the defined frequency to determine if the controls are effective in their application. — *Provide documentation or process evidence: security controls are assessed with the defined frequency to determine if the controls are effective in their application.*

**CCA Manual Assessment Guidance:** Request security assessment reports. Verify assessments are conducted at least annually, cover all security controls, and identify control effectiveness with findings and recommendations.


#### 3.12.2 — Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational information systems.

**Level:** L2 | **Type:** Manual | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.12.2[a] | deficiencies and vulnerabilities to be addressed by the plan of action are identified. | No |
| 3.12.2[b] | a plan of action is developed to correct identified deficiencies and reduce or eliminate identified vulnerabilities. | No |
| 3.12.2[c] | the plan of action is implemented to correct identified deficiencies and reduce or eliminate identified vulnerabilities. | No |

**Documentation Requirements:**

- **3.12.2[a]**: deficiencies and vulnerabilities to be addressed by the plan of action are identified. — *Provide documentation showing that deficiencies and vulnerabilities to be addressed by the plan of action are identified and documented.*
- **3.12.2[b]**: a plan of action is developed to correct identified deficiencies and reduce or eliminate identified vulnerabilities. — *Provide documentation or process evidence: a plan of action is developed to correct identified deficiencies and reduce or eliminate identified vulnerabilities.*
- **3.12.2[c]**: the plan of action is implemented to correct identified deficiencies and reduce or eliminate identified vulnerabilities. — *Provide documentation or process evidence: the plan of action is implemented to correct identified deficiencies and reduce or eliminate identified vulnerabilities.*

**CCA Manual Assessment Guidance:** Request the Plan of Action and Milestones (POA&M). Verify it documents known deficiencies, planned corrective actions, responsible parties, and target completion dates.


#### 3.12.3 — Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls.

**Level:** L2 | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.12.3[a] | security controls are monitored on an ongoing basis to ensure the continued effectiveness of those controls. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `ca-3.12.3-aws-001` | AWS | Security Hub continuous monitoring active | Security Hub | `securityhub.describe_hub` | high | [a] |
| `ca-3.12.3-aws-002` | AWS | Config rules continuously evaluating | Config | `config.describe_compliance_by_config_rule` | high | [a] |
| `ca-3.12.3-aws-003` | AWS | GuardDuty continuous threat monitoring | GuardDuty | `guardduty.get_detector` | high | [a] |
| `ca-3.12.3-azure-001` | AZURE | Defender for Cloud continuous assessment | Security Center | `security.assessments.list` | high | [a] |
| `ca-3.12.3-azure-002` | AZURE | Azure Policy compliance continuously monitored | Policy | `policy.policy_states.list` | high | [a] |
| `ca-3.12.3-gcp-001` | GCP | Security Command Center continuous monitoring | SCC | `securitycenter.organizations.getOrganizationSettings` | high | [a] |
| `ca-3.12.3-gcp-002` | GCP | Organization policy compliance monitored | Organization Policy | `orgpolicy.projects.policies.list` | high | [a] |


#### 3.12.4 — Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems.

**Level:** L2 | **Type:** Manual | **Objectives:** 7

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.12.4[a] | a system security plan is developed. | No |
| 3.12.4[b] | the system boundary is described and documented in the system security plan. | No |
| 3.12.4[c] | the system environment of operation is described and documented in the system security plan. | No |
| 3.12.4[d] | the security requirements identified and approved by the designated authority as non-applicable are identified. | No |
| 3.12.4[e] | the method of security requirement implementation is described and documented in the system security plan. | No |
| 3.12.4[f] | the relationship with or connection to other systems is described and documented in the system security plan. | No |
| 3.12.4[g] | the frequency to update the system security plan is defined. | No |

**Documentation Requirements:**

- **3.12.4[a]**: a system security plan is developed. — *Provide documentation or process evidence: a system security plan is developed.*
- **3.12.4[b]**: the system boundary is described and documented in the system security plan. — *Provide documentation or process evidence: the system boundary is described and documented in the system security plan.*
- **3.12.4[c]**: the system environment of operation is described and documented in the system security plan. — *Provide documentation or process evidence: the system environment of operation is described and documented in the system security plan.*
- **3.12.4[d]**: the security requirements identified and approved by the designated authority as non-applicable are identified. — *Provide documentation showing that the security requirements identified and approved by the designated authority as non-applicable are identified and documented.*
- **3.12.4[e]**: the method of security requirement implementation is described and documented in the system security plan. — *Provide documentation or process evidence: the method of security requirement implementation is described and documented in the system security plan.*
- **3.12.4[f]**: the relationship with or connection to other systems is described and documented in the system security plan. — *Provide documentation or process evidence: the relationship with or connection to other systems is described and documented in the system security plan.*
- **3.12.4[g]**: the frequency to update the system security plan is defined. — *Provide documentation showing that the frequency to update the system security plan are defined.*

**CCA Manual Assessment Guidance:** Request the System Security Plan (SSP). Verify it documents system boundaries, operating environment, security control implementation, and interconnections. Check for annual review and updates.


### SC — System and Communications Protection

**Practices:** 16 | **Automated:** 13 | **Manual:** 3 | **Objectives:** 41 | **Checks:** AWS 31, Azure 21, GCP 21

#### 3.13.1 — Monitor, control, and protect organizational communications (i.e., information transmitted or received by organizational information systems) at the external boundaries and key internal boundaries of the information systems.

**Level:** L1 | **Type:** Automated | **Objectives:** 8
 | **FAR 52.204-21:** b.1.xii

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.1[a] | the external system boundary is defined. | Partial |
| 3.13.1[b] | key internal system boundaries are defined. | Partial |
| 3.13.1[c] | communications are monitored at the external system boundary. | Yes |
| 3.13.1[d] | communications are monitored at key internal boundaries. | Yes |
| 3.13.1[e] | communications are controlled at the external system boundary. | Yes |
| 3.13.1[f] | communications are controlled at key internal boundaries. | Yes |
| 3.13.1[g] | communications are protected at the external system boundary. | Yes |
| 3.13.1[h] | communications are protected at key internal boundaries. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-3.13.1-aws-001` | AWS | WAF deployed on internet-facing resources | WAFv2 | `wafv2.list_web_acls` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-3.13.1-aws-002` | AWS | VPC Flow Logs enabled for all VPCs | VPC | `ec2.describe_flow_logs` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-3.13.1-aws-003` | AWS | Network Firewall deployed for CUI VPCs | Network Firewall | `network-firewall.list_firewalls` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-3.13.1-aws-004` | AWS | GuardDuty monitors network anomalies | GuardDuty | `guardduty.get_detector` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-3.13.1-azure-001` | AZURE | Azure Firewall or NVA deployed | Network | `network.azure_firewalls.list` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-3.13.1-azure-002` | AZURE | NSG flow logs enabled | Network | `network.flow_logs.list` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-3.13.1-azure-003` | AZURE | Azure WAF deployed | Network | `network.web_application_firewall_policies.list` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-3.13.1-gcp-001` | GCP | Cloud Armor WAF deployed | Cloud Armor | `compute.securityPolicies.list` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-3.13.1-gcp-002` | GCP | VPC Flow Logs enabled | VPC | `compute.subnetworks.list` | high | [a], [b], [c], [d], [e], [f], [g], [h] |
| `sc-3.13.1-gcp-003` | GCP | Packet Mirroring or IDS configured | VPC | `compute.packetMirrorings.list` | medium | [a], [b], [c], [d], [e], [f], [g], [h] |


#### 3.13.2 — Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational information systems.

**Level:** L2 | **Type:** Manual | **Objectives:** 6

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.2[a] | architectural designs that promote effective information security are identified. | No |
| 3.13.2[b] | software development techniques that promote effective information security are identified. | No |
| 3.13.2[c] | systems engineering principles that promote effective information security are identified. | No |
| 3.13.2[d] | identified architectural designs that promote effective information security are employed. | No |
| 3.13.2[e] | identified software development techniques that promote effective information security are employed. | No |
| 3.13.2[f] | identified systems engineering principles that promote effective information security are employed. | No |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-3.13.2-aws-001` | AWS | Defense-in-depth architecture layers present | Multiple | `ec2/guardduty/cloudtrail/kms` | high |  |
| `sc-3.13.2-azure-001` | AZURE | Defense-in-depth architecture layers present | Multiple | `network/keyvault/monitor/security` | high |  |
| `sc-3.13.2-gcp-001` | GCP | Defense-in-depth architecture layers present | Multiple | `compute/kms/logging/orgpolicy` | high |  |

**Documentation Requirements:**

- **3.13.2[a]**: architectural designs that promote effective information security are identified. — *Provide documentation showing that architectural designs that promote effective information security are identified and documented.*
- **3.13.2[b]**: software development techniques that promote effective information security are identified. — *Provide documentation showing that software development techniques that promote effective information security are identified and documented.*
- **3.13.2[c]**: systems engineering principles that promote effective information security are identified. — *Provide documentation showing that systems engineering principles that promote effective information security are identified and documented.*
- **3.13.2[d]**: identified architectural designs that promote effective information security are employed. — *Provide documentation or process evidence: identified architectural designs that promote effective information security are employed.*
- **3.13.2[e]**: identified software development techniques that promote effective information security are employed. — *Provide documentation or process evidence: identified software development techniques that promote effective information security are employed.*
- **3.13.2[f]**: identified systems engineering principles that promote effective information security are employed. — *Provide documentation or process evidence: identified systems engineering principles that promote effective information security are employed.*

**CCA Manual Assessment Guidance:** Review system architecture documentation. Verify defense-in-depth design, network segmentation, and secure development practices are documented and implemented.


#### 3.13.3 — Separate user functionality from information system management functionality.

**Level:** L2 | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.3[a] | user functionality is identified. | Partial |
| 3.13.3[b] | system management functionality is identified. | Partial |
| 3.13.3[c] | user functionality is separated from system management functionality. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-3.13.3-aws-001` | AWS | Management and data plane separated | VPC | `ec2.describe_subnets` | high | [a], [b], [c] |
| `sc-3.13.3-aws-002` | AWS | Systems Manager for management access | SSM | `ssm.describe_instance_information` | high | [a], [b], [c] |
| `sc-3.13.3-azure-001` | AZURE | Management network isolated | Network | `network.virtual_networks.list` | high | [a], [b], [c] |
| `sc-3.13.3-gcp-001` | GCP | Management network segmented | VPC | `compute.subnetworks.list` | high | [a], [b], [c] |


#### 3.13.4 — Prevent unauthorized and unintended information transfer via shared system resources.

**Level:** L2 | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.4[a] | unauthorized and unintended information transfer via shared system resources is prevented. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-3.13.4-aws-001` | AWS | EBS volumes not shared across accounts | EC2 | `ec2.describe_snapshot_attribute` | high | [a] |
| `sc-3.13.4-aws-002` | AWS | AMIs not publicly shared | EC2 | `ec2.describe_image_attribute` | high | [a] |
| `sc-3.13.4-azure-001` | AZURE | Shared disks restricted | Compute | `compute.disks.list` | medium | [a] |
| `sc-3.13.4-gcp-001` | GCP | Images not publicly shared | Compute | `compute.images.getIamPolicy` | high | [a] |


#### 3.13.5 — Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.

**Level:** L1 | **Type:** Automated | **Objectives:** 2
 | **FAR 52.204-21:** b.1.xiii

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.5[a] | publicly accessible system components are identified. | Partial |
| 3.13.5[b] | subnetworks for publicly accessible system components are physically or logically separated from internal networks. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-3.13.5-aws-001` | AWS | Public subnets isolated from private subnets | VPC | `ec2.describe_subnets` | high | [a], [b] |
| `sc-3.13.5-aws-002` | AWS | NAT Gateway used for private subnet outbound | VPC | `ec2.describe_nat_gateways` | high | [a], [b] |
| `sc-3.13.5-azure-001` | AZURE | DMZ subnet implemented | Network | `network.virtual_networks.list` | high | [a], [b] |
| `sc-3.13.5-gcp-001` | GCP | Public-facing resources in dedicated subnets | VPC | `compute.subnetworks.list` | high | [a], [b] |


#### 3.13.6 — Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.6[a] | network communications traffic is denied by default. | Partial |
| 3.13.6[b] | network communications traffic is allowed by exception. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-3.13.6-aws-001` | AWS | Default security group restricts all traffic | EC2 | `ec2.describe_security_groups` | high | [a], [b] |
| `sc-3.13.6-aws-002` | AWS | NACLs implement deny-by-default | VPC | `ec2.describe_network_acls` | medium | [a], [b] |
| `sc-3.13.6-azure-001` | AZURE | NSG default deny rules active | Network | `network.network_security_groups.list` | high | [a], [b] |
| `sc-3.13.6-azure-002` | AZURE | Azure Firewall default deny configured | Network | `network.azure_firewalls.list` | high | [a], [b] |
| `sc-3.13.6-gcp-001` | GCP | Default deny ingress firewall rule | VPC | `compute.firewalls.list` | high | [a], [b] |
| `sc-3.13.6-gcp-002` | GCP | Default allow egress reviewed | VPC | `compute.firewalls.list` | medium | [a], [b] |


#### 3.13.7 — Prevent remote devices from simultaneously establishing non-remote connections with organizational information systems and communicating via some other connection to resources in external networks (i.e., split tunneling).

**Level:** L2 | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.7[a] | remote devices are prevented from simultaneously establishing non-remote connections with the system and communicating v | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-3.13.7-aws-001` | AWS | Client VPN full tunnel enforced | VPC | `ec2.describe_client_vpn_endpoints` | high | [a] |
| `sc-3.13.7-azure-001` | AZURE | VPN forced tunneling configured | Network | `network.virtual_network_gateways.list` | high | [a] |
| `sc-3.13.7-gcp-001` | GCP | VPN full tunnel policy enforced | VPN | `compute.vpnTunnels.list` | high | [a] |


#### 3.13.8 — Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards.

**Level:** L2 | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.8[a] | cryptographic mechanisms intended to prevent unauthorized disclosure of CUI are identified. | Partial |
| 3.13.8[b] | alternative physical safeguards intended to prevent unauthorized disclosure of CUI are identified. | Partial |
| 3.13.8[c] | either cryptographic mechanisms or alternative physical safeguards are implemented to prevent unauthorized disclosure of | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-3.13.8-aws-001` | AWS | ALB/NLB listeners use TLS 1.2+ | ELB | `elbv2.describe_listeners` | high | [a], [b], [c] |
| `sc-3.13.8-aws-002` | AWS | CloudFront uses TLS 1.2+ | CloudFront | `cloudfront.list_distributions` | high | [a], [b], [c] |
| `sc-3.13.8-aws-003` | AWS | S3 bucket policy enforces TLS | S3 | `s3.get_bucket_policy` | high | [a], [b], [c] |
| `sc-3.13.8-azure-001` | AZURE | Minimum TLS 1.2 enforced on App Services | App Service | `web.web_apps.list` | high | [a], [b], [c] |
| `sc-3.13.8-azure-002` | AZURE | Storage accounts enforce TLS 1.2+ | Storage | `storage.storage_accounts.list` | high | [a], [b], [c] |
| `sc-3.13.8-gcp-001` | GCP | SSL policies enforce TLS 1.2+ | Compute | `compute.sslPolicies.list` | high | [a], [b], [c] |
| `sc-3.13.8-gcp-002` | GCP | Cloud SQL requires SSL | Cloud SQL | `sqladmin.instances.list` | high | [a], [b], [c] |


#### 3.13.9 — Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity.

**Level:** L2 | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.9[a] | a period of inactivity to terminate network connections associated with communications sessions is defined. | Partial |
| 3.13.9[b] | network connections associated with communications sessions are terminated at the end of the sessions. | Yes |
| 3.13.9[c] | network connections associated with communications sessions are terminated after the defined period of inactivity. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-3.13.9-aws-001` | AWS | ALB idle timeout configured | ELB | `elbv2.describe_load_balancer_attributes` | medium | [a], [b], [c] |
| `sc-3.13.9-aws-002` | AWS | API Gateway timeout configured | API Gateway | `apigateway.get_rest_apis` | medium | [a], [b], [c] |
| `sc-3.13.9-azure-001` | AZURE | Application Gateway idle timeout configured | Network | `network.application_gateways.list` | medium | [a], [b], [c] |
| `sc-3.13.9-gcp-001` | GCP | Load balancer timeout configured | Compute | `compute.backendServices.list` | medium | [a], [b], [c] |


#### 3.13.10 — Establish and manage cryptographic keys for cryptography employed in organizational information systems.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.10[a] | cryptographic keys are established whenever cryptography is employed. | Yes |
| 3.13.10[b] | cryptographic keys are managed whenever cryptography is employed. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-3.13.10-aws-001` | AWS | KMS key rotation enabled | KMS | `kms.get_key_rotation_status` | high | [a], [b] |
| `sc-3.13.10-aws-002` | AWS | KMS key policies restrict access | KMS | `kms.get_key_policy` | high | [a], [b] |
| `sc-3.13.10-aws-003` | AWS | ACM certificates managed and auto-renewed | ACM | `acm.list_certificates` | medium | [a], [b] |
| `sc-3.13.10-azure-001` | AZURE | Key Vault key rotation configured | Key Vault | `keyvault.keys.list` | high | [a], [b] |
| `sc-3.13.10-azure-002` | AZURE | Key Vault access policies follow least privilege | Key Vault | `keyvault.vaults.list` | high | [a], [b] |
| `sc-3.13.10-gcp-001` | GCP | Cloud KMS key rotation configured | KMS | `cloudkms.projects.locations.keyRings.cryptoKeys.list` | high | [a], [b] |
| `sc-3.13.10-gcp-002` | GCP | Cloud KMS IAM bindings restricted | KMS | `cloudkms.projects.locations.keyRings.getIamPolicy` | high | [a], [b] |


#### 3.13.11 — Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.

**Level:** L2 | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.11[a] | FIPS-validated cryptography is employed to protect the confidentiality of CUI. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-3.13.11-aws-001` | AWS | FIPS endpoints used in GovCloud | IAM | `sts.get_caller_identity` | high | [a] |
| `sc-3.13.11-aws-002` | AWS | S3 uses FIPS-validated encryption | S3 | `s3.get_bucket_encryption` | high | [a] |
| `sc-3.13.11-azure-001` | AZURE | Azure Government FIPS-validated services used | Compute | `compute.virtual_machines.list` | high | [a] |
| `sc-3.13.11-gcp-001` | GCP | CMEK uses FIPS-validated Cloud KMS | KMS | `cloudkms.projects.locations.keyRings.cryptoKeys.list` | high | [a] |


#### 3.13.12 — Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device.

**Level:** L2 | **Type:** Manual | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.12[a] | collaborative computing devices are identified. | No |
| 3.13.12[b] | collaborative computing devices provide indication to users of devices in use. | No |
| 3.13.12[c] | remote activation of collaborative computing devices is prohibited. | No |

**Documentation Requirements:**

- **3.13.12[a]**: collaborative computing devices are identified. — *Provide documentation showing that collaborative computing devices are identified and documented.*
- **3.13.12[b]**: collaborative computing devices provide indication to users of devices in use. — *Provide documentation or process evidence: collaborative computing devices provide indication to users of devices in use.*
- **3.13.12[c]**: remote activation of collaborative computing devices is prohibited. — *Provide documentation or process evidence: remote activation of collaborative computing devices is prohibited.*

**CCA Manual Assessment Guidance:** Review policies for collaborative computing devices (cameras, microphones, conferencing systems). Verify remote activation is disabled and indicators of active use are enabled.


#### 3.13.13 — Control and monitor the use of mobile code.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.13[a] | use of mobile code is controlled. | Yes |
| 3.13.13[b] | use of mobile code is monitored. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-3.13.13-aws-001` | AWS | WAF rules block malicious scripts | WAFv2 | `wafv2.list_web_acls` | high | [a], [b] |
| `sc-3.13.13-azure-001` | AZURE | WAF OWASP rules enabled | Network | `network.web_application_firewall_policies.list` | high | [a], [b] |
| `sc-3.13.13-gcp-001` | GCP | Cloud Armor preconfigured WAF rules | Cloud Armor | `compute.securityPolicies.list` | high | [a], [b] |


#### 3.13.14 — Control and monitor the use of Voice over Internet Protocol (VoIP) technologies.

**Level:** L2 | **Type:** Manual | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.14[a] | use of Voice over Internet Protocol (VoIP) technologies is controlled. | No |
| 3.13.14[b] | use of Voice over Internet Protocol (VoIP) technologies is monitored. | No |

**Documentation Requirements:**

- **3.13.14[a]**: use of Voice over Internet Protocol (VoIP) technologies is controlled. — *Provide documentation or process evidence: use of Voice over Internet Protocol (VoIP) technologies is controlled.*
- **3.13.14[b]**: use of Voice over Internet Protocol (VoIP) technologies is monitored. — *Provide documentation or process evidence: use of Voice over Internet Protocol (VoIP) technologies is monitored.*

**CCA Manual Assessment Guidance:** Review VoIP security policies and configurations. Verify VoIP traffic is encrypted, segregated on dedicated VLANs, and monitored for anomalous activity.


#### 3.13.15 — Protect the authenticity of communications sessions.

**Level:** L2 | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.15[a] | the authenticity of communications sessions is protected. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-3.13.15-aws-001` | AWS | ACM certificates valid and not expired | ACM | `acm.list_certificates` | high | [a] |
| `sc-3.13.15-aws-002` | AWS | DNSSEC enabled on Route 53 hosted zones | Route 53 | `route53.list_hosted_zones` | medium | [a] |
| `sc-3.13.15-azure-001` | AZURE | App Service certificates valid | App Service | `web.certificates.list` | high | [a] |
| `sc-3.13.15-gcp-001` | GCP | Managed SSL certificates valid | Compute | `compute.sslCertificates.list` | high | [a] |


#### 3.13.16 — Protect the confidentiality of CUI at rest.

**Level:** L2 | **Type:** Automated | **Objectives:** 1

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.13.16[a] | the confidentiality of CUI at rest is protected. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `sc-3.13.16-aws-001` | AWS | S3 default encryption enabled | S3 | `s3.get_bucket_encryption` | high | [a] |
| `sc-3.13.16-aws-002` | AWS | RDS encryption at rest enabled | RDS | `rds.describe_db_instances` | high | [a] |
| `sc-3.13.16-aws-003` | AWS | DynamoDB encryption enabled | DynamoDB | `dynamodb.describe_table` | high | [a] |
| `sc-3.13.16-aws-004` | AWS | EBS encryption by default enabled | EC2 | `ec2.get_ebs_encryption_by_default` | high | [a] |
| `sc-3.13.16-azure-001` | AZURE | Storage account encryption with CMK | Storage | `storage.storage_accounts.list` | high | [a] |
| `sc-3.13.16-azure-002` | AZURE | Azure SQL TDE with CMK | SQL | `sql.transparent_data_encryptions.get` | high | [a] |
| `sc-3.13.16-azure-003` | AZURE | VM disk encryption enabled | Compute | `compute.disks.list` | high | [a] |
| `sc-3.13.16-gcp-001` | GCP | Cloud Storage CMEK encryption | Storage | `storage.buckets.get` | high | [a] |
| `sc-3.13.16-gcp-002` | GCP | Cloud SQL CMEK encryption | Cloud SQL | `sqladmin.instances.list` | high | [a] |
| `sc-3.13.16-gcp-003` | GCP | BigQuery CMEK encryption | BigQuery | `bigquery.datasets.list` | high | [a] |


### SI — System and Information Integrity

**Practices:** 7 | **Automated:** 7 | **Manual:** 0 | **Objectives:** 20 | **Checks:** AWS 21, Azure 16, GCP 16

#### 3.14.1 — Identify, report, and correct information and information system flaws in a timely manner.

**Level:** L1 | **Type:** Automated | **Objectives:** 6
 | **FAR 52.204-21:** b.1.xiv

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.14.1[a] | the time within which to identify system flaws is specified. | Partial |
| 3.14.1[b] | system flaws are identified within the specified time frame. | Partial |
| 3.14.1[c] | the time within which to report system flaws is specified. | Partial |
| 3.14.1[d] | system flaws are reported within the specified time frame. | Partial |
| 3.14.1[e] | the time within which to correct system flaws is specified. | Partial |
| 3.14.1[f] | system flaws are corrected within the specified time frame. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `si-3.14.1-aws-001` | AWS | SSM Patch Manager deployed | SSM | `ssm.describe_patch_baselines` | high | [a], [b], [c], [d], [e], [f] |
| `si-3.14.1-aws-002` | AWS | Patch compliance within SLA | SSM | `ssm.describe_instance_patch_states` | high | [a], [b], [c], [d], [e], [f] |
| `si-3.14.1-aws-003` | AWS | Amazon Inspector vulnerability findings addressed | Inspector | `inspector2.list_findings` | high | [a], [b], [c], [d], [e], [f] |
| `si-3.14.1-aws-004` | AWS | RDS automatic minor version upgrade enabled | RDS | `rds.describe_db_instances` | medium | [a], [b], [c], [d], [e], [f] |
| `si-3.14.1-azure-001` | AZURE | Azure Update Manager configured | Compute | `compute.virtual_machines.list` | high | [a], [b], [c], [d], [e], [f] |
| `si-3.14.1-azure-002` | AZURE | Defender vulnerability assessment findings addressed | Security Center | `security.sub_assessments.list` | high | [a], [b], [c], [d], [e], [f] |
| `si-3.14.1-azure-003` | AZURE | App Service platform version current | App Service | `web.web_apps.list` | medium | [a], [b], [c], [d], [e], [f] |
| `si-3.14.1-gcp-001` | GCP | OS Config patch management active | OS Config | `osconfig.projects.patchDeployments.list` | high | [a], [b], [c], [d], [e], [f] |
| `si-3.14.1-gcp-002` | GCP | GKE cluster auto-upgrade enabled | GKE | `container.projects.locations.clusters.list` | high | [a], [b], [c], [d], [e], [f] |
| `si-3.14.1-gcp-003` | GCP | Container vulnerability findings addressed | Container Analysis | `containeranalysis.projects.occurrences.list` | high | [a], [b], [c], [d], [e], [f] |


#### 3.14.2 — Provide protection from malicious code at appropriate locations within organizational information systems.

**Level:** L1 | **Type:** Automated | **Objectives:** 2
 | **FAR 52.204-21:** b.1.xv

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.14.2[a] | designated locations for malicious code protection are identified. | Partial |
| 3.14.2[b] | protection from malicious code at designated locations is provided. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `si-3.14.2-aws-001` | AWS | GuardDuty malware protection enabled | GuardDuty | `guardduty.get_detector` | high | [a], [b] |
| `si-3.14.2-aws-002` | AWS | EC2 instances have endpoint protection | SSM | `ssm.list_inventory_entries` | high | [a], [b] |
| `si-3.14.2-aws-003` | AWS | S3 Malware Scanning configured | GuardDuty | `guardduty.get_malware_scan_settings` | medium | [a], [b] |
| `si-3.14.2-azure-001` | AZURE | Defender for Endpoint deployed | Security Center | `security.pricings.get` | high | [a], [b] |
| `si-3.14.2-azure-002` | AZURE | Microsoft Antimalware extension deployed | Compute | `compute.virtual_machine_extensions.list` | high | [a], [b] |
| `si-3.14.2-gcp-001` | GCP | Endpoint protection deployed on GCE instances | Compute | `compute.instances.list` | high | [a], [b] |
| `si-3.14.2-gcp-002` | GCP | Malware scanning enabled for Cloud Storage | Storage | `storage.buckets.list` | medium | [a], [b] |


#### 3.14.3 — Monitor information system security alerts and advisories and take action in response.

**Level:** L2 | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.14.3[a] | response actions to system security alerts and advisories are identified. | Partial |
| 3.14.3[b] | system security alerts and advisories are monitored. | Yes |
| 3.14.3[c] | actions in response to system security alerts and advisories are taken. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `si-3.14.3-aws-001` | AWS | Security Hub findings notifications configured | Security Hub | `securityhub.describe_hub` | high | [a], [b], [c] |
| `si-3.14.3-aws-002` | AWS | GuardDuty findings alerting configured | GuardDuty | `guardduty.list_detectors` | high | [a], [b], [c] |
| `si-3.14.3-aws-003` | AWS | AWS Health Dashboard alerts configured | Health | `health.describe_events` | medium | [a], [b], [c] |
| `si-3.14.3-azure-001` | AZURE | Defender for Cloud email notifications | Security Center | `security.security_contacts.list` | high | [a], [b], [c] |
| `si-3.14.3-azure-002` | AZURE | Service Health alerts configured | Monitor | `monitor.activity_log_alerts.list` | medium | [a], [b], [c] |
| `si-3.14.3-gcp-001` | GCP | SCC notification config for critical findings | SCC | `securitycenter.organizations.notificationConfigs.list` | high | [a], [b], [c] |
| `si-3.14.3-gcp-002` | GCP | Cloud Monitoring alerting for security events | Monitoring | `monitoring.projects.alertPolicies.list` | high | [a], [b], [c] |


#### 3.14.4 — Update malicious code protection mechanisms when new releases are available.

**Level:** L1 | **Type:** Automated | **Objectives:** 1
 | **FAR 52.204-21:** b.1.xvi

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.14.4[a] | malicious code protection mechanisms are updated when new releases are available. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `si-3.14.4-aws-001` | AWS | Endpoint protection auto-update enabled | SSM | `ssm.list_inventory_entries` | high | [a] |
| `si-3.14.4-aws-002` | AWS | GuardDuty threat intelligence auto-updated | GuardDuty | `guardduty.get_detector` | medium | [a] |
| `si-3.14.4-azure-001` | AZURE | Defender for Endpoint signature updates current | Security Center | `security.pricings.get` | high | [a] |
| `si-3.14.4-gcp-001` | GCP | Endpoint protection auto-update configured | Compute | `compute.instances.list` | high | [a] |


#### 3.14.5 — Perform periodic scans of the information system and real-time scans of files from external sources as files are downloaded, opened, or executed.

**Level:** L1 | **Type:** Automated | **Objectives:** 3
 | **FAR 52.204-21:** b.1.xvii

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.14.5[a] | the frequency for malicious code scans is defined. | Partial |
| 3.14.5[b] | malicious code scans are performed with the defined frequency. | Partial |
| 3.14.5[c] | real-time malicious code scans of files from external sources as files are downloaded, opened, or executed are performed | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `si-3.14.5-aws-001` | AWS | Periodic vulnerability scanning configured | Inspector | `inspector2.list_account_permissions` | high | [a], [b], [c] |
| `si-3.14.5-aws-002` | AWS | GuardDuty real-time malware scanning | GuardDuty | `guardduty.get_detector` | high | [a], [b], [c] |
| `si-3.14.5-aws-003` | AWS | S3 object scanning for uploads | GuardDuty | `guardduty.get_malware_scan_settings` | medium | [a], [b], [c] |
| `si-3.14.5-azure-001` | AZURE | Scheduled VM vulnerability scans configured | Security Center | `security.pricings.get` | high | [a], [b], [c] |
| `si-3.14.5-azure-002` | AZURE | Real-time protection enabled on endpoints | Compute | `compute.virtual_machine_extensions.list` | high | [a], [b], [c] |
| `si-3.14.5-gcp-001` | GCP | Container vulnerability scanning continuous | Container Analysis | `containeranalysis.projects.occurrences.list` | high | [a], [b], [c] |
| `si-3.14.5-gcp-002` | GCP | Web Security Scanner periodic scans | SCC | `websecurityscanner.projects.scanConfigs.list` | medium | [a], [b], [c] |


#### 3.14.6 — Monitor organizational information systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.

**Level:** L2 | **Type:** Automated | **Objectives:** 3

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.14.6[a] | the system is monitored to detect attacks and indicators of potential attacks. | Yes |
| 3.14.6[b] | inbound communications traffic is monitored to detect attacks and indicators of potential attacks. | Yes |
| 3.14.6[c] | outbound communications traffic is monitored to detect attacks and indicators of potential attacks. | Yes |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `si-3.14.6-aws-001` | AWS | GuardDuty monitors network traffic | GuardDuty | `guardduty.get_detector` | high | [a], [b], [c] |
| `si-3.14.6-aws-002` | AWS | VPC Flow Logs analyzed for anomalies | VPC | `ec2.describe_flow_logs` | high | [a], [b], [c] |
| `si-3.14.6-aws-003` | AWS | Network Firewall IDS/IPS rules configured | Network Firewall | `network-firewall.list_firewall_policies` | high | [a], [b], [c] |
| `si-3.14.6-azure-001` | AZURE | Defender for Network deployed | Security Center | `security.pricings.get` | high | [a], [b], [c] |
| `si-3.14.6-azure-002` | AZURE | Azure Firewall IDPS enabled | Network | `network.azure_firewalls.list` | high | [a], [b], [c] |
| `si-3.14.6-azure-003` | AZURE | NSG flow log analytics enabled | Network | `network.flow_logs.list` | high | [a], [b], [c] |
| `si-3.14.6-gcp-001` | GCP | Cloud IDS deployed for network monitoring | Cloud IDS | `ids.projects.locations.endpoints.list` | high | [a], [b], [c] |
| `si-3.14.6-gcp-002` | GCP | VPC Flow Logs analyzed | VPC | `compute.subnetworks.list` | high | [a], [b], [c] |
| `si-3.14.6-gcp-003` | GCP | Event Threat Detection monitors for attacks | SCC | `securitycenter.organizations.sources.list` | high | [a], [b], [c] |


#### 3.14.7 — Identify unauthorized use of organizational information systems.

**Level:** L2 | **Type:** Automated | **Objectives:** 2

**Assessment Objectives:**

| ID | Objective | Automatable |
|----|-----------|-------------|
| 3.14.7[a] | authorized use of the system is defined. | Partial |
| 3.14.7[b] | unauthorized use of the system is identified. | Partial |

**Automated Checks:**

| Check ID | Cloud | Name | Service | API Call | Severity | Objectives |
|----------|-------|------|---------|---------|----------|------------|
| `si-3.14.7-aws-001` | AWS | GuardDuty UnauthorizedAccess findings monitored | GuardDuty | `guardduty.list_findings` | high | [a], [b] |
| `si-3.14.7-aws-002` | AWS | CloudWatch anomaly detection configured | CloudWatch | `cloudwatch.describe_anomaly_detectors` | medium | [a], [b] |
| `si-3.14.7-aws-003` | AWS | CloudTrail Insights enabled | CloudTrail | `cloudtrail.get_insight_selectors` | medium | [a], [b] |
| `si-3.14.7-azure-001` | AZURE | Azure AD Identity Protection configured | Azure AD | `graph.identity_protection.risk_detections.list` | high | [a], [b] |
| `si-3.14.7-azure-002` | AZURE | Sentinel UEBA enabled | Sentinel | `securityinsight.settings.list` | medium | [a], [b] |
| `si-3.14.7-azure-003` | AZURE | Anomalous login alerts configured | Azure AD | `graph.identity_protection.risky_users.list` | high | [a], [b] |
| `si-3.14.7-gcp-001` | GCP | Event Threat Detection for unauthorized access | SCC | `securitycenter.organizations.sources.findings.list` | high | [a], [b] |
| `si-3.14.7-gcp-002` | GCP | Anomaly detection alerts configured | Monitoring | `monitoring.projects.alertPolicies.list` | medium | [a], [b] |
| `si-3.14.7-gcp-003` | GCP | Access Transparency logs monitored | Logging | `logging.entries.list` | medium | [a], [b] |


---

## 7. CCA Manual Assessment Guide

### 7.1 How to Use This Guide

For the 39 controls classified as **Manual Review Required**, the scanner cannot make an automated determination. The CCA must independently assess these practices using the guidance below.

For each manual practice, this guide provides:

1. **Assessment Objectives** — The exact 800-53A "determine if" statements the CCA must evaluate
2. **Assessment Guidance** — Specific steps, interview topics, and configuration areas to examine
3. **Evidence Artifacts** — Documents, records, and artifacts the CCA should request from the OSC
4. **Determination Criteria** — What constitutes a Met vs. Not Met finding

**Note:** Some "manual" practices have automated checks that provide *supporting evidence* (e.g., cloud configurations). These checks do not determine compliance but give the CCA baseline data to inform their manual assessment.

### 7.2 Manual Practice Reference

#### AC — Access Control (Manual Practices)

##### Practice 3.1.9: Provide privacy and security notices consistent with applicable CUI rules.

**FedRAMP Baseline:** L2 | **Domain:** AC

**Assessment Objectives (NIST SP 800-53A):**

- **3.1.9[a]**: Determine if privacy and security notices required by CUI-specified rules are identified, consistent, and associated with the specific CUI category
- **3.1.9[b]**: Determine if privacy and security notices are displayed.

**CCA Assessment Guidance:**

> Verify login banners and system use notification messages are configured on all systems processing CUI.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.1.9[a] | Provide documentation showing that privacy and security notices required by cui-specified rules are identified and documented. |
| 3.1.9[b] | Provide documentation or process evidence: privacy and security notices are displayed. |

**Determination Criteria:**

- **Met:** All 2 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.1.16: Authorize wireless access prior to allowing such connections.

**FedRAMP Baseline:** L2 | **Domain:** AC

**Assessment Objectives (NIST SP 800-53A):**

- **3.1.16[a]**: Determine if wireless access points are identified.
- **3.1.16[b]**: Determine if wireless access is authorized prior to allowing such connections.

**CCA Assessment Guidance:**

> Review wireless access policies and verify that wireless connections require explicit authorization. Check for rogue access point detection.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.1.16[a] | Provide documentation showing that wireless access points are identified and documented. |
| 3.1.16[b] | Provide documentation or process evidence: wireless access is authorized prior to allowing such connections. |

**Supporting Automated Checks** (provide baseline data for CCA review):

| Cloud | Check | API Call | What It Evaluates |
|-------|-------|---------|-------------------|
| AWS | ac-3.1.16-aws-001 | `ec2.describe_vpn_connections/describe_client_vpn_endpoints` | VPN infrastructure for remote access authorization |
| AZURE | ac-3.1.16-azure-001 | `network.virtual_network_gateways.list` | VPN gateway for remote access authorization |
| GCP | ac-3.1.16-gcp-001 | `compute.vpnGateways.list/vpnTunnels.list` | Cloud VPN for remote access authorization |

**Determination Criteria:**

- **Met:** All 2 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.1.17: Protect wireless access using authentication and encryption.

**FedRAMP Baseline:** L2 | **Domain:** AC

**Assessment Objectives (NIST SP 800-53A):**

- **3.1.17[a]**: Determine if wireless access to the system is protected using encryption.
- **3.1.17[b]**: Determine if wireless access to the system is protected using authentication.

**CCA Assessment Guidance:**

> Verify wireless networks use WPA2/WPA3-Enterprise with 802.1X authentication. Check encryption standards meet FIPS 140-2 requirements.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.1.17[a] | Provide documentation or process evidence: wireless access to the system is protected using encryption. |
| 3.1.17[b] | Provide documentation or process evidence: wireless access to the system is protected using authentication. |

**Determination Criteria:**

- **Met:** All 2 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.1.18: Control connection of mobile devices.

**FedRAMP Baseline:** L2 | **Domain:** AC

**Assessment Objectives (NIST SP 800-53A):**

- **3.1.18[a]**: Determine if mobile devices that process, store, or transmit CUI are identified.
- **3.1.18[b]**: Determine if the connection of mobile devices is authorized.
- **3.1.18[c]**: Determine if mobile device connections are monitored and logged.

**CCA Assessment Guidance:**

> Review mobile device management (MDM) policies. Verify enrollment requirements, device compliance checks, and connection restrictions for mobile devices accessing CUI.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.1.18[a] | Provide documentation showing that mobile devices that process, store, or transmit cui are identified and documented. |
| 3.1.18[b] | Provide documentation or process evidence: the connection of mobile devices is authorized. |
| 3.1.18[c] | Provide documentation or process evidence: mobile device connections are monitored and logged. |

**Supporting Automated Checks** (provide baseline data for CCA review):

| Cloud | Check | API Call | What It Evaluates |
|-------|-------|---------|-------------------|
| AWS | ac-3.1.18-aws-001 | `iam.list_saml_providers/list_open_id_connect_providers` | Centralized identity providers for device control |
| AZURE | ac-3.1.18-azure-001 | `resource_client.providers.get/auth_client.role_assignments.list` | Defender for Cloud and managed identity for device control |
| GCP | ac-3.1.18-gcp-001 | `orgpolicy.projects.policies.get` | OS Login and device security org policies |

**Determination Criteria:**

- **Met:** All 3 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.1.19: Encrypt CUI on mobile devices and mobile computing platforms.

**FedRAMP Baseline:** L2 | **Domain:** AC

**Assessment Objectives (NIST SP 800-53A):**

- **3.1.19[a]**: Determine if mobile devices and mobile computing platforms that process, store, or transmit CUI are identified.
- **3.1.19[b]**: Determine if encryption is employed to protect CUI on identified mobile devices and mobile computing platforms.

**CCA Assessment Guidance:**

> Verify MDM enforces full-device encryption on mobile devices. Check that CUI storage on mobile devices uses FIPS-validated encryption.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.1.19[a] | Provide documentation showing that mobile devices and mobile computing platforms that process, store, or transmit cui are identified and documented. |
| 3.1.19[b] | Provide documentation or process evidence: encryption is employed to protect CUI on identified mobile devices and mobile computing platforms. |

**Supporting Automated Checks** (provide baseline data for CCA review):

| Cloud | Check | API Call | What It Evaluates |
|-------|-------|---------|-------------------|
| AWS | ac-3.1.19-aws-001 | `ec2.get_ebs_encryption_by_default` | EBS default encryption enabled for compute platforms |
| AZURE | ac-3.1.19-azure-001 | `compute.disks.list` | All managed disks encrypted |
| GCP | ac-3.1.19-gcp-001 | `orgpolicy/compute.disks.list` | CMEK org policy or disk-level CMEK enforced |

**Determination Criteria:**

- **Met:** All 2 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.1.21: Limit use of organizational portable storage devices on external information systems.

**FedRAMP Baseline:** L2 | **Domain:** AC

**Assessment Objectives (NIST SP 800-53A):**

- **3.1.21[a]**: Determine if use of organizational portable storage devices containing CUI on external systems is identified and documented.
- **3.1.21[b]**: Determine if limits on the use of organizational portable storage devices containing CUI on external systems are defined.
- **3.1.21[c]**: Determine if use of organizational portable storage devices containing CUI on external systems is limited as defined.

**CCA Assessment Guidance:**

> Review policies restricting use of USB drives and portable storage on external systems. Verify endpoint DLP controls for removable media.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.1.21[a] | Provide documentation showing that use of organizational portable storage devices containing cui on external systems are identified and documented. |
| 3.1.21[b] | Provide documentation showing that limits on the use of organizational portable storage devices containing cui on external systems are defined. |
| 3.1.21[c] | Provide documentation or process evidence: use of organizational portable storage devices containing CUI on external systems is limited as defined. |

**Supporting Automated Checks** (provide baseline data for CCA review):

| Cloud | Check | API Call | What It Evaluates |
|-------|-------|---------|-------------------|
| AWS | ac-3.1.21-aws-001 | `s3control.get_public_access_block` | S3 Block Public Access enabled at account level |
| AZURE | ac-3.1.21-azure-001 | `storage.storage_accounts.list` | Storage accounts block public blob access |
| GCP | ac-3.1.21-gcp-001 | `orgpolicy.projects.policies.get` | Uniform bucket-level access org policy enforced |

**Determination Criteria:**

- **Met:** All 3 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### AT — Awareness and Training (Manual Practices)

##### Practice 3.2.1: Ensure that managers, systems administrators, and users of organizational information systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of organizational information systems.

**FedRAMP Baseline:** L2 | **Domain:** AT

**Assessment Objectives (NIST SP 800-53A):**

- **3.2.1[a]**: Determine if security risks associated with organizational activities involving CUI are identified.
- **3.2.1[b]**: Determine if policies, standards, and procedures related to the security of the system are identified.
- **3.2.1[c]**: Determine if managers, systems administrators, and users of the system are made aware of the security risks associated with their activities.
- **3.2.1[d]**: Determine if managers, systems administrators, and users of the system are made aware of the applicable policies, standards, and procedures related to the security of the system.

**CCA Assessment Guidance:**

> Request security awareness training records and completion certificates. Verify training covers CUI handling, phishing, social engineering, and organizational security policies.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.2.1[a] | Provide documentation showing that security risks associated with organizational activities involving cui are identified and documented. |
| 3.2.1[b] | Provide documentation showing that policies, standards, and procedures related to the security of the system are identified and documented. |
| 3.2.1[c] | Provide documentation or process evidence: managers, systems administrators, and users of the system are made aware of the security risks associated with their activities. |
| 3.2.1[d] | Provide documentation or process evidence: managers, systems administrators, and users of the system are made aware of the applicable policies, standards, and procedures related to the security of the system. |

**Determination Criteria:**

- **Met:** All 4 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.2.2: Ensure that organizational personnel are adequately trained to carry out their assigned information security-related duties and responsibilities.

**FedRAMP Baseline:** L2 | **Domain:** AT

**Assessment Objectives (NIST SP 800-53A):**

- **3.2.2[a]**: Determine if information security-related duties, roles, and responsibilities are defined.
- **3.2.2[b]**: Determine if information security-related duties, roles, and responsibilities are assigned to designated personnel.
- **3.2.2[c]**: Determine if personnel are adequately trained to carry out their assigned information security-related duties, roles, and responsibilities.

**CCA Assessment Guidance:**

> Request role-based training records for IT/security staff. Verify training covers specific duties such as incident response, system administration, and security monitoring.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.2.2[a] | Provide documentation showing that information security-related duties, roles, and responsibilities are defined. |
| 3.2.2[b] | Provide personnel records: information security-related duties, roles, and responsibilities are assigned to designated personnel. |
| 3.2.2[c] | Provide personnel records: personnel are adequately trained to carry out their assigned information security-related duties, roles, and responsibilities. |

**Determination Criteria:**

- **Met:** All 3 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.2.3: Provide security awareness training on recognizing and reporting potential indicators of insider threat.

**FedRAMP Baseline:** L2 | **Domain:** AT

**Assessment Objectives (NIST SP 800-53A):**

- **3.2.3[a]**: Determine if potential indicators associated with insider threats are identified.
- **3.2.3[b]**: Determine if security awareness training on recognizing and reporting potential indicators of insider threat is provided to managers and employees.

**CCA Assessment Guidance:**

> Request insider threat training records. Verify training includes indicators of insider threat, reporting procedures, and is completed annually by all personnel with CUI access.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.2.3[a] | Provide documentation showing that potential indicators associated with insider threats are identified and documented. |
| 3.2.3[b] | Provide training records: security awareness training on recognizing and reporting potential indicators of insider threat is provided to managers and employees. |

**Determination Criteria:**

- **Met:** All 2 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### AU — Audit and Accountability (Manual Practices)

##### Practice 3.3.3: Review and update logged events.

**FedRAMP Baseline:** L2 | **Domain:** AU

**Assessment Objectives (NIST SP 800-53A):**

- **3.3.3[a]**: Determine if a process for determining when to review logged events is defined.
- **3.3.3[b]**: Determine if event types being logged are reviewed in accordance with the defined review process.
- **3.3.3[c]**: Determine if event types being logged are updated based on the review.

**CCA Assessment Guidance:**

> Review audit logging configuration to ensure events of interest are captured. Verify periodic review process for updating which events are logged based on current threat landscape.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.3.3[a] | Provide documentation showing that a process for determining when to review logged events are defined. |
| 3.3.3[b] | Provide evidence of periodic review: event types being logged are reviewed in accordance with the defined review process. |
| 3.3.3[c] | Provide documentation or process evidence: event types being logged are updated based on the review. |

**Determination Criteria:**

- **Met:** All 3 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### CM — Configuration Management (Manual Practices)

##### Practice 3.4.4: Analyze the security impact of changes prior to implementation.

**FedRAMP Baseline:** L2 | **Domain:** CM

**Assessment Objectives (NIST SP 800-53A):**

- **3.4.4[a]**: Determine if the security impact of changes to each organizational system is analyzed prior to implementation.

**CCA Assessment Guidance:**

> Review change management process documentation. Verify that security impact analysis is performed as part of the change approval process before implementation.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.4.4[a] | Provide documentation or process evidence: the security impact of changes to each organizational system is analyzed prior to implementation. |

**Determination Criteria:**

- **Met:** All 1 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### IA — Identification and Authentication (Manual Practices)

##### Practice 3.5.11: Obscure feedback of authentication information.

**FedRAMP Baseline:** L2 | **Domain:** IA

**Assessment Objectives (NIST SP 800-53A):**

- **3.5.11[a]**: Determine if authentication information is obscured during the authentication process.

**CCA Assessment Guidance:**

> Verify that authentication interfaces mask password input. Check that error messages do not reveal whether the username or password was incorrect.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.5.11[a] | Provide documentation or process evidence: authentication information is obscured during the authentication process. |

**Determination Criteria:**

- **Met:** All 1 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### IR — Incident Response (Manual Practices)

##### Practice 3.6.2: Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.

**FedRAMP Baseline:** L2 | **Domain:** IR

**Assessment Objectives (NIST SP 800-53A):**

- **3.6.2[a]**: Determine if incidents are tracked.
- **3.6.2[b]**: Determine if incidents are documented.
- **3.6.2[c]**: Determine if authorities to whom incidents are to be reported are identified.
- **3.6.2[d]**: Determine if organizational officials to whom incidents are to be reported are identified.
- **3.6.2[e]**: Determine if identified authorities are notified of incidents.
- **3.6.2[f]**: Determine if identified organizational officials are notified of incidents.

**CCA Assessment Guidance:**

> Review incident tracking system and reporting procedures. Verify incident reports include required data elements and are communicated to appropriate authorities within required timeframes.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.6.2[a] | Provide documentation or process evidence: incidents are tracked. |
| 3.6.2[b] | Provide documentation or process evidence: incidents are documented. |
| 3.6.2[c] | Provide documentation showing that authorities to whom incidents are to be reported are identified and documented. |
| 3.6.2[d] | Provide documentation showing that organizational officials to whom incidents are to be reported are identified and documented. |
| 3.6.2[e] | Provide documentation or process evidence: identified authorities are notified of incidents. |
| 3.6.2[f] | Provide documentation or process evidence: identified organizational officials are notified of incidents. |

**Determination Criteria:**

- **Met:** All 6 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.6.3: Test the organizational incident response capability.

**FedRAMP Baseline:** L2 | **Domain:** IR

**Assessment Objectives (NIST SP 800-53A):**

- **3.6.3[a]**: Determine if the incident response capability is tested.

**CCA Assessment Guidance:**

> Request records of incident response tests and tabletop exercises. Verify testing occurs at least annually and results are documented with lessons learned.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.6.3[a] | Provide documentation or process evidence: the incident response capability is tested. |

**Determination Criteria:**

- **Met:** All 1 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### MA — Maintenance (Manual Practices)

##### Practice 3.7.2: Provide controls on the tools, techniques, mechanisms, and personnel used to conduct information system maintenance.

**FedRAMP Baseline:** L2 | **Domain:** MA

**Assessment Objectives (NIST SP 800-53A):**

- **3.7.2[a]**: Determine if tools used to conduct system maintenance are controlled.
- **3.7.2[b]**: Determine if techniques used to conduct system maintenance are controlled.
- **3.7.2[c]**: Determine if mechanisms used to conduct system maintenance are controlled.
- **3.7.2[d]**: Determine if personnel used to conduct system maintenance are controlled.

**CCA Assessment Guidance:**

> Review maintenance tool inventory and authorization records. Verify that maintenance personnel are vetted and that maintenance tools are inspected and sanitized before use.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.7.2[a] | Provide documentation or process evidence: tools used to conduct system maintenance are controlled. |
| 3.7.2[b] | Provide documentation or process evidence: techniques used to conduct system maintenance are controlled. |
| 3.7.2[c] | Provide documentation or process evidence: mechanisms used to conduct system maintenance are controlled. |
| 3.7.2[d] | Provide personnel records: personnel used to conduct system maintenance are controlled. |

**Determination Criteria:**

- **Met:** All 4 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.7.3: Ensure equipment removed for off-site maintenance is sanitized of any CUI.

**FedRAMP Baseline:** L2 | **Domain:** MA

**Assessment Objectives (NIST SP 800-53A):**

- **3.7.3[a]**: Determine if equipment to be removed from organizational spaces for off-site maintenance is sanitized of any CUI.

**CCA Assessment Guidance:**

> Review media sanitization procedures for equipment sent off-site. Verify sanitization records exist for all equipment removed for maintenance.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.7.3[a] | Provide documentation or process evidence: equipment to be removed from organizational spaces for off-site maintenance is sanitized of any CUI. |

**Determination Criteria:**

- **Met:** All 1 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.7.4: Check media containing diagnostic and test programs for malicious code before the media are used in organizational information systems.

**FedRAMP Baseline:** L2 | **Domain:** MA

**Assessment Objectives (NIST SP 800-53A):**

- **3.7.4[a]**: Determine if media containing diagnostic and test programs are checked for malicious code before being used in organizational systems that process, store, or transmit CUI.

**CCA Assessment Guidance:**

> Review procedures for scanning maintenance media. Verify that anti-malware scans are performed on all diagnostic media before connection to production systems.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.7.4[a] | Provide documentation or process evidence: media containing diagnostic and test programs are checked for malicious code before being used in organizational systems that process, store, or transmit CUI. |

**Determination Criteria:**

- **Met:** All 1 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.7.6: Supervise the maintenance activities of maintenance personnel without required access authorization.

**FedRAMP Baseline:** L2 | **Domain:** MA

**Assessment Objectives (NIST SP 800-53A):**

- **3.7.6[a]**: Determine if maintenance personnel without required access authorization are supervised during maintenance activities.

**CCA Assessment Guidance:**

> Review escort and supervision procedures for maintenance personnel. Verify that session recording or direct observation is used for uncleared maintenance staff.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.7.6[a] | Provide personnel records: maintenance personnel without required access authorization are supervised during maintenance activities. |

**Determination Criteria:**

- **Met:** All 1 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### MP — Media Protection (Manual Practices)

##### Practice 3.8.1: Protect (i.e., physically control and securely store) information system media containing CUI, both paper and digital.

**FedRAMP Baseline:** L2 | **Domain:** MP

**Assessment Objectives (NIST SP 800-53A):**

- **3.8.1[a]**: Determine if paper media containing CUI is physically controlled.
- **3.8.1[b]**: Determine if digital media containing CUI is physically controlled.
- **3.8.1[c]**: Determine if paper media containing CUI is securely stored.
- **3.8.1[d]**: Determine if digital media containing CUI is securely stored.

**CCA Assessment Guidance:**

> Review media storage and handling procedures. Verify physical security controls for media storage areas and digital media access controls.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.8.1[a] | Provide physical security evidence: paper media containing CUI is physically controlled. |
| 3.8.1[b] | Provide physical security evidence: digital media containing CUI is physically controlled. |
| 3.8.1[c] | Provide documentation or process evidence: paper media containing CUI is securely stored. |
| 3.8.1[d] | Provide documentation or process evidence: digital media containing CUI is securely stored. |

**Determination Criteria:**

- **Met:** All 4 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.8.3: Sanitize or destroy information system media containing CUI before disposal or release for reuse.

**FedRAMP Baseline:** L1 | **Domain:** MP

**Assessment Objectives (NIST SP 800-53A):**

- **3.8.3[a]**: Determine if system media containing CUI is sanitized or destroyed before disposal.
- **3.8.3[b]**: Determine if system media containing CUI is sanitized before it is released for reuse.

**CCA Assessment Guidance:**

> Review media sanitization procedures and records. Verify NIST 800-88 compliant sanitization methods are used. Check disposal vendor certifications and certificates of destruction.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.8.3[a] | Provide documentation or process evidence: system media containing CUI is sanitized or destroyed before disposal. |
| 3.8.3[b] | Provide documentation or process evidence: system media containing CUI is sanitized before it is released for reuse. |

**Determination Criteria:**

- **Met:** All 2 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.8.4: Mark media with necessary CUI markings and distribution limitations.

**FedRAMP Baseline:** L2 | **Domain:** MP

**Assessment Objectives (NIST SP 800-53A):**

- **3.8.4[a]**: Determine if media containing CUI is marked with applicable CUI markings.
- **3.8.4[b]**: Determine if media containing CUI is marked with distribution limitations.

**CCA Assessment Guidance:**

> Verify CUI marking procedures exist and are followed. Check that digital and physical media containing CUI are marked with appropriate CUI designations and distribution statements.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.8.4[a] | Provide documentation or process evidence: media containing CUI is marked with applicable CUI markings. |
| 3.8.4[b] | Provide documentation or process evidence: media containing CUI is marked with distribution limitations. |

**Determination Criteria:**

- **Met:** All 2 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.8.5: Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas.

**FedRAMP Baseline:** L2 | **Domain:** MP

**Assessment Objectives (NIST SP 800-53A):**

- **3.8.5[a]**: Determine if access to media containing CUI is controlled.
- **3.8.5[b]**: Determine if accountability for media containing CUI is maintained during transport outside of controlled areas.

**CCA Assessment Guidance:**

> Review media transport procedures and chain-of-custody records. Verify encryption requirements for media in transit and accountability tracking mechanisms.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.8.5[a] | Provide documentation or process evidence: access to media containing CUI is controlled. |
| 3.8.5[b] | Provide documentation or process evidence: accountability for media containing CUI is maintained during transport outside of controlled areas. |

**Determination Criteria:**

- **Met:** All 2 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.8.7: Control the use of removable media on information system components.

**FedRAMP Baseline:** L2 | **Domain:** MP

**Assessment Objectives (NIST SP 800-53A):**

- **3.8.7[a]**: Determine if the use of removable media on system components containing CUI is controlled.

**CCA Assessment Guidance:**

> Review removable media policies and endpoint DLP configurations. Verify USB device restrictions and authorized device whitelists.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.8.7[a] | Provide documentation or process evidence: the use of removable media on system components containing CUI is controlled. |

**Determination Criteria:**

- **Met:** All 1 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.8.8: Prohibit the use of portable storage devices when such devices have no identifiable owner.

**FedRAMP Baseline:** L2 | **Domain:** MP

**Assessment Objectives (NIST SP 800-53A):**

- **3.8.8[a]**: Determine if the use of portable storage devices is prohibited when such devices have no identifiable owner.

**CCA Assessment Guidance:**

> Review portable storage device policies. Verify that all authorized portable storage devices are registered and assigned to specific individuals.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.8.8[a] | Provide documentation or process evidence: the use of portable storage devices is prohibited when such devices have no identifiable owner. |

**Determination Criteria:**

- **Met:** All 1 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### PS — Personnel Security (Manual Practices)

##### Practice 3.9.1: Screen individuals prior to authorizing access to organizational information systems containing CUI.

**FedRAMP Baseline:** L2 | **Domain:** PS

**Assessment Objectives (NIST SP 800-53A):**

- **3.9.1[a]**: Determine if individuals are screened prior to authorizing access to organizational systems.

**CCA Assessment Guidance:**

> Review personnel screening procedures and records. Verify background checks are completed before granting access to CUI systems. Check screening criteria meet organizational and regulatory requirements.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.9.1[a] | Provide documentation or process evidence: individuals are screened prior to authorizing access to organizational systems. |

**Determination Criteria:**

- **Met:** All 1 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.9.2: Ensure that organizational information systems containing CUI are protected during and after personnel actions such as terminations and transfers.

**FedRAMP Baseline:** L2 | **Domain:** PS

**Assessment Objectives (NIST SP 800-53A):**

- **3.9.2[a]**: Determine if a policy and/or process for terminating system access authorization and any credentials coincident with personnel actions is established.
- **3.9.2[b]**: Determine if system access and credentials are terminated consistent with personnel actions such as termination or transfer.
- **3.9.2[c]**: Determine if the system is protected during and after personnel transfer actions.

**CCA Assessment Guidance:**

> Review termination and transfer procedures. Verify that access is revoked promptly upon termination, credentials are disabled, and equipment/media are recovered. Check for automated deprovisioning workflows.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.9.2[a] | Provide personnel records: a policy and/or process for terminating system access authorization and any credentials coincident with personnel actions is established. |
| 3.9.2[b] | Provide personnel records: system access and credentials are terminated consistent with personnel actions such as termination or transfer. |
| 3.9.2[c] | Provide personnel records: the system is protected during and after personnel transfer actions. |

**Determination Criteria:**

- **Met:** All 3 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### PE — Physical Protection (Manual Practices)

##### Practice 3.10.1: Limit physical access to organizational information systems, equipment, and the respective operating environments to authorized individuals.

**FedRAMP Baseline:** L1 | **Domain:** PE

**Assessment Objectives (NIST SP 800-53A):**

- **3.10.1[a]**: Determine if authorized individuals allowed physical access are identified.
- **3.10.1[b]**: Determine if physical access to organizational systems is limited to authorized individuals.
- **3.10.1[c]**: Determine if physical access to equipment is limited to authorized individuals.
- **3.10.1[d]**: Determine if physical access to operating environments is limited to authorized individuals.

**CCA Assessment Guidance:**

> Review physical access control mechanisms (badge readers, biometrics, locks). Verify authorized access lists are current and physical access logs are maintained.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.10.1[a] | Provide documentation showing that authorized individuals allowed physical access are identified and documented. |
| 3.10.1[b] | Provide physical security evidence: physical access to organizational systems is limited to authorized individuals. |
| 3.10.1[c] | Provide physical security evidence: physical access to equipment is limited to authorized individuals. |
| 3.10.1[d] | Provide physical security evidence: physical access to operating environments is limited to authorized individuals. |

**Determination Criteria:**

- **Met:** All 4 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.10.2: Protect and monitor the physical facility and support infrastructure for organizational information systems.

**FedRAMP Baseline:** L2 | **Domain:** PE

**Assessment Objectives (NIST SP 800-53A):**

- **3.10.2[a]**: Determine if the physical facility where that system resides is protected.
- **3.10.2[b]**: Determine if the support infrastructure for that system is protected.
- **3.10.2[c]**: Determine if the physical facility where that system resides is monitored.
- **3.10.2[d]**: Determine if the support infrastructure for that system is monitored.

**CCA Assessment Guidance:**

> Review physical security monitoring systems (cameras, alarms, environmental controls). Verify monitoring coverage of server rooms, network closets, and other sensitive areas.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.10.2[a] | Provide physical security evidence: the physical facility where that system resides is protected. |
| 3.10.2[b] | Provide documentation or process evidence: the support infrastructure for that system is protected. |
| 3.10.2[c] | Provide physical security evidence: the physical facility where that system resides is monitored. |
| 3.10.2[d] | Provide documentation or process evidence: the support infrastructure for that system is monitored. |

**Determination Criteria:**

- **Met:** All 4 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.10.3: Escort visitors and monitor visitor activity.

**FedRAMP Baseline:** L1 | **Domain:** PE

**Assessment Objectives (NIST SP 800-53A):**

- **3.10.3[a]**: Determine if visitors are escorted.
- **3.10.3[b]**: Determine if visitor activity is monitored.

**CCA Assessment Guidance:**

> Review visitor management procedures. Verify visitor logs, escort requirements, and badge/identification procedures. Check that visitors are escorted in areas with CUI access.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.10.3[a] | Provide documentation or process evidence: visitors are escorted. |
| 3.10.3[b] | Provide documentation or process evidence: visitor activity is monitored. |

**Determination Criteria:**

- **Met:** All 2 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.10.4: Maintain audit logs of physical access.

**FedRAMP Baseline:** L1 | **Domain:** PE

**Assessment Objectives (NIST SP 800-53A):**

- **3.10.4[a]**: Determine if audit logs of physical access are maintained.

**CCA Assessment Guidance:**

> Review physical access logs and retention periods. Verify logs capture entry/exit times, individual identity, and are retained per organizational policy.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.10.4[a] | Provide physical security evidence: audit logs of physical access are maintained. |

**Determination Criteria:**

- **Met:** All 1 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.10.5: Control and manage physical access devices.

**FedRAMP Baseline:** L1 | **Domain:** PE

**Assessment Objectives (NIST SP 800-53A):**

- **3.10.5[a]**: Determine if physical access devices are identified.
- **3.10.5[b]**: Determine if physical access devices are controlled.
- **3.10.5[c]**: Determine if physical access devices are managed.

**CCA Assessment Guidance:**

> Review inventory and management of physical access devices (keys, badges, combinations, PINs). Verify devices are inventoried, changed when compromised, and deactivated for separated personnel.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.10.5[a] | Provide documentation showing that physical access devices are identified and documented. |
| 3.10.5[b] | Provide physical security evidence: physical access devices are controlled. |
| 3.10.5[c] | Provide physical security evidence: physical access devices are managed. |

**Determination Criteria:**

- **Met:** All 3 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.10.6: Enforce safeguarding measures for CUI at alternate work sites.

**FedRAMP Baseline:** L2 | **Domain:** PE

**Assessment Objectives (NIST SP 800-53A):**

- **3.10.6[a]**: Determine if safeguarding measures for CUI are defined for alternate work sites.
- **3.10.6[b]**: Determine if safeguarding measures for CUI are enforced for alternate work sites.

**CCA Assessment Guidance:**

> Review telework and alternate work site policies. Verify requirements for securing CUI at home offices and temporary work locations including physical security and network requirements.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.10.6[a] | Provide documentation showing that safeguarding measures for cui are defined. |
| 3.10.6[b] | Provide documentation or process evidence: safeguarding measures for CUI are enforced for alternate work sites. |

**Determination Criteria:**

- **Met:** All 2 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### RA — Risk Assessment (Manual Practices)

##### Practice 3.11.1: Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational information systems and the associated processing, storage, or transmission of CUI.

**FedRAMP Baseline:** L2 | **Domain:** RA

**Assessment Objectives (NIST SP 800-53A):**

- **3.11.1[a]**: Determine if the frequency to assess risk to organizational operations, organizational assets, and individuals is defined.
- **3.11.1[b]**: Determine if risk to organizational operations, organizational assets, and individuals resulting from the operation of an organizational system that processes, stores, or transmits CUI is assessed with the defined frequency.

**CCA Assessment Guidance:**

> Request the most recent risk assessment report. Verify it covers CUI systems, is updated at least annually, and addresses threats, vulnerabilities, likelihood, and impact.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.11.1[a] | Provide documentation showing that the frequency to assess risk to organizational operations, organizational assets, and individuals are defined. |
| 3.11.1[b] | Provide documentation or process evidence: risk to organizational operations, organizational assets, and individuals resulting from the operation of an organizational system that processes, stores, or transmits CUI is assessed with the defined frequency. |

**Determination Criteria:**

- **Met:** All 2 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### CA — Security Assessment (Manual Practices)

##### Practice 3.12.1: Periodically assess the security controls in organizational information systems to determine if the controls are effective in their application.

**FedRAMP Baseline:** L2 | **Domain:** CA

**Assessment Objectives (NIST SP 800-53A):**

- **3.12.1[a]**: Determine if the frequency of security control assessments is defined.
- **3.12.1[b]**: Determine if security controls are assessed with the defined frequency to determine if the controls are effective in their application.

**CCA Assessment Guidance:**

> Request security assessment reports. Verify assessments are conducted at least annually, cover all security controls, and identify control effectiveness with findings and recommendations.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.12.1[a] | Provide documentation showing that the frequency of security control assessments are defined. |
| 3.12.1[b] | Provide documentation or process evidence: security controls are assessed with the defined frequency to determine if the controls are effective in their application. |

**Determination Criteria:**

- **Met:** All 2 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.12.2: Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational information systems.

**FedRAMP Baseline:** L2 | **Domain:** CA

**Assessment Objectives (NIST SP 800-53A):**

- **3.12.2[a]**: Determine if deficiencies and vulnerabilities to be addressed by the plan of action are identified.
- **3.12.2[b]**: Determine if a plan of action is developed to correct identified deficiencies and reduce or eliminate identified vulnerabilities.
- **3.12.2[c]**: Determine if the plan of action is implemented to correct identified deficiencies and reduce or eliminate identified vulnerabilities.

**CCA Assessment Guidance:**

> Request the Plan of Action and Milestones (POA&M). Verify it documents known deficiencies, planned corrective actions, responsible parties, and target completion dates.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.12.2[a] | Provide documentation showing that deficiencies and vulnerabilities to be addressed by the plan of action are identified and documented. |
| 3.12.2[b] | Provide documentation or process evidence: a plan of action is developed to correct identified deficiencies and reduce or eliminate identified vulnerabilities. |
| 3.12.2[c] | Provide documentation or process evidence: the plan of action is implemented to correct identified deficiencies and reduce or eliminate identified vulnerabilities. |

**Determination Criteria:**

- **Met:** All 3 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.12.4: Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems.

**FedRAMP Baseline:** L2 | **Domain:** CA

**Assessment Objectives (NIST SP 800-53A):**

- **3.12.4[a]**: Determine if a system security plan is developed.
- **3.12.4[b]**: Determine if the system boundary is described and documented in the system security plan.
- **3.12.4[c]**: Determine if the system environment of operation is described and documented in the system security plan.
- **3.12.4[d]**: Determine if the security requirements identified and approved by the designated authority as non-applicable are identified.
- **3.12.4[e]**: Determine if the method of security requirement implementation is described and documented in the system security plan.
- **3.12.4[f]**: Determine if the relationship with or connection to other systems is described and documented in the system security plan.
- **3.12.4[g]**: Determine if the frequency to update the system security plan is defined.

**CCA Assessment Guidance:**

> Request the System Security Plan (SSP). Verify it documents system boundaries, operating environment, security control implementation, and interconnections. Check for annual review and updates.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.12.4[a] | Provide documentation or process evidence: a system security plan is developed. |
| 3.12.4[b] | Provide documentation or process evidence: the system boundary is described and documented in the system security plan. |
| 3.12.4[c] | Provide documentation or process evidence: the system environment of operation is described and documented in the system security plan. |
| 3.12.4[d] | Provide documentation showing that the security requirements identified and approved by the designated authority as non-applicable are identified and documented. |
| 3.12.4[e] | Provide documentation or process evidence: the method of security requirement implementation is described and documented in the system security plan. |
| 3.12.4[f] | Provide documentation or process evidence: the relationship with or connection to other systems is described and documented in the system security plan. |
| 3.12.4[g] | Provide documentation showing that the frequency to update the system security plan are defined. |

**Determination Criteria:**

- **Met:** All 7 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

#### SC — System and Communications Protection (Manual Practices)

##### Practice 3.13.2: Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational information systems.

**FedRAMP Baseline:** L2 | **Domain:** SC

**Assessment Objectives (NIST SP 800-53A):**

- **3.13.2[a]**: Determine if architectural designs that promote effective information security are identified.
- **3.13.2[b]**: Determine if software development techniques that promote effective information security are identified.
- **3.13.2[c]**: Determine if systems engineering principles that promote effective information security are identified.
- **3.13.2[d]**: Determine if identified architectural designs that promote effective information security are employed.
- **3.13.2[e]**: Determine if identified software development techniques that promote effective information security are employed.
- **3.13.2[f]**: Determine if identified systems engineering principles that promote effective information security are employed.

**CCA Assessment Guidance:**

> Review system architecture documentation. Verify defense-in-depth design, network segmentation, and secure development practices are documented and implemented.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.13.2[a] | Provide documentation showing that architectural designs that promote effective information security are identified and documented. |
| 3.13.2[b] | Provide documentation showing that software development techniques that promote effective information security are identified and documented. |
| 3.13.2[c] | Provide documentation showing that systems engineering principles that promote effective information security are identified and documented. |
| 3.13.2[d] | Provide documentation or process evidence: identified architectural designs that promote effective information security are employed. |
| 3.13.2[e] | Provide documentation or process evidence: identified software development techniques that promote effective information security are employed. |
| 3.13.2[f] | Provide documentation or process evidence: identified systems engineering principles that promote effective information security are employed. |

**Supporting Automated Checks** (provide baseline data for CCA review):

| Cloud | Check | API Call | What It Evaluates |
|-------|-------|---------|-------------------|
| AWS | sc-3.13.2-aws-001 | `ec2/guardduty/cloudtrail/kms` | Defense-in-depth architecture layers present |
| AZURE | sc-3.13.2-azure-001 | `network/keyvault/monitor/security` | Defense-in-depth architecture layers present |
| GCP | sc-3.13.2-gcp-001 | `compute/kms/logging/orgpolicy` | Defense-in-depth architecture layers present |

**Determination Criteria:**

- **Met:** All 6 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.13.12: Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device.

**FedRAMP Baseline:** L2 | **Domain:** SC

**Assessment Objectives (NIST SP 800-53A):**

- **3.13.12[a]**: Determine if collaborative computing devices are identified.
- **3.13.12[b]**: Determine if collaborative computing devices provide indication to users of devices in use.
- **3.13.12[c]**: Determine if remote activation of collaborative computing devices is prohibited.

**CCA Assessment Guidance:**

> Review policies for collaborative computing devices (cameras, microphones, conferencing systems). Verify remote activation is disabled and indicators of active use are enabled.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.13.12[a] | Provide documentation showing that collaborative computing devices are identified and documented. |
| 3.13.12[b] | Provide documentation or process evidence: collaborative computing devices provide indication to users of devices in use. |
| 3.13.12[c] | Provide documentation or process evidence: remote activation of collaborative computing devices is prohibited. |

**Determination Criteria:**

- **Met:** All 3 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---

##### Practice 3.13.14: Control and monitor the use of Voice over Internet Protocol (VoIP) technologies.

**FedRAMP Baseline:** L2 | **Domain:** SC

**Assessment Objectives (NIST SP 800-53A):**

- **3.13.14[a]**: Determine if use of Voice over Internet Protocol (VoIP) technologies is controlled.
- **3.13.14[b]**: Determine if use of Voice over Internet Protocol (VoIP) technologies is monitored.

**CCA Assessment Guidance:**

> Review VoIP security policies and configurations. Verify VoIP traffic is encrypted, segregated on dedicated VLANs, and monitored for anomalous activity.

**Evidence Artifacts to Request:**

| Objective | Evidence Needed |
|-----------|----------------|
| 3.13.14[a] | Provide documentation or process evidence: use of Voice over Internet Protocol (VoIP) technologies is controlled. |
| 3.13.14[b] | Provide documentation or process evidence: use of Voice over Internet Protocol (VoIP) technologies is monitored. |

**Determination Criteria:**

- **Met:** All 2 assessment objectives are satisfied with documented evidence
- **Not Met:** One or more objectives lack sufficient evidence or are demonstrably not implemented

---


---

## 8. Appendix A — API Call Reference

Complete list of unique cloud API calls made by the scanner, organized by provider.

### AWS (93 unique API calls across 33 services)

| Service | API Call | Used By (Practices) |
|---------|---------|---------------------|
| ACM | `acm.list_certificates` | 3.13.10, 3.13.15 |
| API Gateway | `apigateway.get_rest_apis` | 3.13.9 |
| Athena | `athena.list_named_queries` | 3.3.6 |
| Backup | `backup.get_backup_vault_access_policy` | 3.8.9 |
| Backup | `backup.list_backup_vaults` | 3.8.9 |
| CloudFront | `cloudfront.list_distributions` | 3.13.8 |
| CloudTrail | `cloudtrail.describe_trails` | 3.1.7, 3.3.1, 3.3.2, 3.3.5, 3.4.3 |
| CloudTrail | `cloudtrail.get_event_selectors` | 3.3.1 |
| CloudTrail | `cloudtrail.get_insight_selectors` | 3.14.7 |
| CloudTrail | `cloudtrail.get_trail_status` | 3.3.1 |
| CloudWatch | `cloudwatch.describe_alarms` | 3.3.4 |
| CloudWatch | `cloudwatch.describe_anomaly_detectors` | 3.14.7 |
| CloudWatch | `logs.describe_log_groups` | 3.3.6 |
| CodePipeline | `codepipeline.list_pipelines` | 3.4.5 |
| Config | `config.describe_compliance_by_config_rule` | 3.12.3 |
| Config | `config.describe_config_rules` | 3.4.2 |
| Config | `config.describe_configuration_recorders` | 3.4.1 |
| Config | `config.describe_delivery_channels` | 3.4.3 |
| DynamoDB | `dynamodb.describe_table` | 3.13.16 |
| EC2 | `ec2.describe_image_attribute` | 3.13.4 |
| EC2 | `ec2.describe_images` | 3.4.1 |
| EC2 | `ec2.describe_instances` | 3.1.22, 3.5.1 |
| EC2 | `ec2.describe_security_groups` | 3.1.14, 3.4.6, 3.4.7, 3.13.6 |
| EC2 | `ec2.describe_snapshot_attribute` | 3.13.4 |
| EC2 | `ec2.describe_volumes` | 3.8.2 |
| EC2 | `ec2.get_ebs_encryption_by_default` | 3.1.19, 3.8.2, 3.13.16 |
| EC2 | `ssm.send_command` | 3.3.7 |
| ECR | `ecr.describe_repositories` | 3.11.2 |
| EFS | `efs.describe_file_systems` | 3.8.6 |
| ELB | `elbv2.describe_listeners` | 3.13.8 |
| ELB | `elbv2.describe_load_balancer_attributes` | 3.13.9 |
| ELB | `elbv2.describe_ssl_policies` | 3.1.13 |
| EventBridge | `events.list_rules` | 3.6.1 |
| GuardDuty | `guardduty.get_detector` | 3.12.3, 3.13.1, 3.14.2, 3.14.4, 3.14.5 (+1 more) |
| GuardDuty | `guardduty.get_malware_scan_settings` | 3.14.2, 3.14.5 |
| GuardDuty | `guardduty.list_detectors` | 3.1.8, 3.6.1, 3.14.3 |
| GuardDuty | `guardduty.list_findings` | 3.14.7 |
| Health | `health.describe_events` | 3.14.3 |
| IAM | `accessanalyzer.list_analyzers` | 3.1.5 |
| IAM | `iam.generate_credential_report` | 3.1.1, 3.3.2, 3.5.2, 3.5.3, 3.5.6 |
| IAM | `iam.get_account_password_policy` | 3.1.1, 3.5.7, 3.5.8, 3.5.10 |
| IAM | `iam.get_account_summary` | 3.1.1, 3.5.2 |
| IAM | `iam.get_policy_version` | 3.1.4, 3.5.3 |
| IAM | `iam.get_role` | 3.1.10 |
| IAM | `iam.list_entities_for_policy` | 3.1.5, 3.3.9 |
| IAM | `iam.list_mfa_devices` | 3.5.4 |
| IAM | `iam.list_policies` | 3.1.2 |
| IAM | `iam.list_roles` | 3.1.4, 3.1.6, 3.1.11, 3.4.5, 3.4.6 (+1 more) |
| IAM | `iam.list_saml_providers/list_open_id_connect_providers` | 3.1.18 |
| IAM | `iam.list_user_policies` | 3.1.5 |
| IAM | `iam.list_users` | 3.1.2, 3.5.1, 3.5.5 |
| IAM | `iam.list_virtual_mfa_devices` | 3.5.3 |
| IAM | `sts.get_caller_identity` | 3.13.11 |
| IAM Identity Center | `identitystore.describe_user` | 3.5.9 |
| IAM Identity Center | `sso-admin.describe_instance` | 3.1.11 |
| IAM Identity Center | `sso-admin.describe_instance_access_control_attribute_configuration` | 3.1.8 |
| Inspector | `inspector2.list_account_permissions` | 3.11.2, 3.14.5 |
| Inspector | `inspector2.list_findings` | 3.11.2, 3.11.3, 3.14.1 |
| KMS | `kms.get_key_policy` | 3.13.10 |
| KMS | `kms.get_key_rotation_status` | 3.13.10 |
| Multiple | `ec2/guardduty/cloudtrail/kms` | 3.13.2 |
| Network Firewall | `network-firewall.list_firewall_policies` | 3.14.6 |
| Network Firewall | `network-firewall.list_firewalls` | 3.13.1 |
| Organizations | `organizations.list_policies` | 3.1.7, 3.3.9, 3.4.7 |
| RDS | `rds.describe_db_instances` | 3.5.10, 3.7.1, 3.8.6, 3.13.16, 3.14.1 |
| Route 53 | `route53.list_hosted_zones` | 3.13.15 |
| S3 | `s3.get_bucket_encryption` | 3.3.8, 3.8.6, 3.13.11, 3.13.16 |
| S3 | `s3.get_bucket_lifecycle_configuration` | 3.3.1 |
| S3 | `s3.get_bucket_logging` | 3.3.8 |
| S3 | `s3.get_bucket_policy` | 3.8.2, 3.13.8 |
| S3 | `s3.get_bucket_policy_status` | 3.1.22 |
| S3 | `s3.get_bucket_replication` | 3.8.9 |
| S3 | `s3.get_bucket_versioning` | 3.3.8 |
| S3 | `s3control.get_public_access_block` | 3.1.3, 3.1.21 |
| SNS | `sns.list_subscriptions_by_topic` | 3.3.4 |
| SSM | `iam.get_policy_version` | 3.7.5 |
| SSM | `ssm.describe_document` | 3.1.12 |
| SSM | `ssm.describe_instance_information` | 3.1.15, 3.4.1, 3.13.3 |
| SSM | `ssm.describe_instance_patch_states` | 3.7.1, 3.11.3, 3.14.1 |
| SSM | `ssm.describe_patch_baselines` | 3.7.1, 3.14.1 |
| SSM | `ssm.list_documents` | 3.4.8, 3.6.1 |
| SSM | `ssm.list_inventory_entries` | 3.4.9, 3.14.2, 3.14.4 |
| STS | `iam.list_roles` | 3.5.4 |
| Security Hub | `securityhub.describe_hub` | 3.3.5, 3.6.1, 3.12.3, 3.14.3 |
| Security Hub | `securityhub.describe_standards_subscriptions` | 3.4.2 |
| VPC | `ec2.describe_client_vpn_endpoints` | 3.1.14, 3.7.5, 3.13.7 |
| VPC | `ec2.describe_flow_logs` | 3.1.3, 3.13.1, 3.14.6 |
| VPC | `ec2.describe_nat_gateways` | 3.13.5 |
| VPC | `ec2.describe_network_acls` | 3.13.6 |
| VPC | `ec2.describe_subnets` | 3.13.3, 3.13.5 |
| VPC | `ec2.describe_transit_gateway_attachments` | 3.1.20 |
| VPC | `ec2.describe_vpc_peering_connections` | 3.1.20 |
| VPC | `ec2.describe_vpn_connections` | 3.1.12, 3.1.13 |
| VPC | `ec2.describe_vpn_connections/describe_client_vpn_endpoints` | 3.1.16 |
| WAFv2 | `wafv2.list_web_acls` | 3.13.1, 3.13.13 |

### Azure (65 unique API calls across 19 services)

| Service | API Call | Used By (Practices) |
|---------|---------|---------------------|
| Advisor | `advisor.recommendations.list` | 3.4.6 |
| App Service | `web.certificates.list` | 3.13.15 |
| App Service | `web.web_apps.list` | 3.5.10, 3.13.8, 3.14.1 |
| Authorization | `authorization.role_assignments.list` | 3.1.4, 3.3.9 |
| Authorization | `authorization.role_definitions.list` | 3.1.2 |
| Automation | `automation.automation_accounts.list` | 3.4.9 |
| Automation | `automation.software_update_configurations.list` | 3.7.1, 3.11.3 |
| Azure AD | `graph.audit_logs.list` | 3.3.1 |
| Azure AD | `graph.authentication_method_configurations.get` | 3.5.4 |
| Azure AD | `graph.authorization_policy.get` | 3.1.1 |
| Azure AD | `graph.conditional_access_policies.list` | 3.1.1, 3.1.10, 3.1.15, 3.5.2, 3.5.3 (+1 more) |
| Azure AD | `graph.deleted_users.list` | 3.5.5 |
| Azure AD | `graph.directory_roles.members.list` | 3.1.5 |
| Azure AD | `graph.identity_protection.risk_detections.list` | 3.14.7 |
| Azure AD | `graph.identity_protection.risky_users.list` | 3.14.7 |
| Azure AD | `graph.identity_security_defaults_enforcement_policy.get` | 3.1.1 |
| Azure AD | `graph.privileged_access.list` | 3.1.2 |
| Azure AD | `graph.reports.credential_user_registration_details.list` | 3.5.2 |
| Azure AD | `graph.settings.list` | 3.1.8, 3.5.7, 3.5.8 |
| Azure AD | `graph.sign_in_logs.list` | 3.3.2 |
| Azure AD | `graph.token_lifetime_policies.list` | 3.1.11 |
| Azure AD | `graph.users.list` | 3.1.6, 3.5.1, 3.5.6, 3.5.9 |
| Compute | `compute.disks.list` | 3.1.19, 3.8.2, 3.13.4, 3.13.16 |
| Compute | `compute.virtual_machine_extensions.list` | 3.14.2, 3.14.5 |
| Compute | `compute.virtual_machines.list` | 3.3.7, 3.5.1, 3.7.1, 3.13.11, 3.14.1 |
| Key Vault | `keyvault.keys.list` | 3.13.10 |
| Key Vault | `keyvault.vaults.list` | 3.13.10 |
| Monitor | `monitor.activity_log_alerts.list` | 3.1.7, 3.3.4, 3.14.3 |
| Monitor | `monitor.activity_logs.list` | 3.4.3 |
| Monitor | `monitor.diagnostic_settings.list` | 3.3.1 |
| Monitor | `operationalinsights.workspaces.list` | 3.3.6, 3.3.8 |
| Multiple | `network/keyvault/monitor/security` | 3.13.2 |
| Network | `network.application_gateways.list` | 3.13.9 |
| Network | `network.azure_firewalls.list` | 3.1.3, 3.13.1, 3.13.6, 3.14.6 |
| Network | `network.bastion_hosts.list` | 3.1.12 |
| Network | `network.flow_logs.list` | 3.1.3, 3.13.1, 3.14.6 |
| Network | `network.network_security_groups.list` | 3.1.14, 3.4.7, 3.13.6 |
| Network | `network.virtual_network_gateway_connections.list` | 3.1.13 |
| Network | `network.virtual_network_gateways.list` | 3.1.16, 3.13.7 |
| Network | `network.virtual_network_peerings.list` | 3.1.20 |
| Network | `network.virtual_networks.list` | 3.13.3, 3.13.5 |
| Network | `network.web_application_firewall_policies.list` | 3.13.1, 3.13.13 |
| Policy | `guestconfiguration.guest_configuration_assignments.list` | 3.4.1 |
| Policy | `policy.policy_assignments.list` | 3.4.2 |
| Policy | `policy.policy_states.list` | 3.12.3 |
| Recovery Services | `recoveryservices.backup_resource_vault_configs.get` | 3.8.9 |
| Recovery Services | `recoveryservices.vaults.list` | 3.8.9 |
| Resource Graph | `resourcegraph.resources` | 3.4.1 |
| Resources | `resources.management_locks.list` | 3.4.5 |
| SQL | `sql.server_vulnerability_assessments.get` | 3.11.2 |
| SQL | `sql.transparent_data_encryptions.get` | 3.8.6, 3.13.16 |
| Security Center | `security.adaptive_application_controls.list` | 3.4.8 |
| Security Center | `security.assessments.list` | 3.11.3, 3.12.3 |
| Security Center | `security.jit_network_access_policies.list` | 3.1.5 |
| Security Center | `security.pricings.get` | 3.11.2, 3.14.2, 3.14.4, 3.14.5, 3.14.6 |
| Security Center | `security.pricings.list` | 3.6.1 |
| Security Center | `security.secure_scores.list` | 3.4.2 |
| Security Center | `security.security_contacts.list` | 3.14.3 |
| Security Center | `security.sub_assessments.list` | 3.11.2, 3.14.1 |
| Security/Authorization | `resource_client.providers.get/auth_client.role_assignments.list` | 3.1.18 |
| Sentinel | `securityinsight.automation_rules.list` | 3.6.1 |
| Sentinel | `securityinsight.sentinel_onboarding_states.list` | 3.3.5, 3.6.1 |
| Sentinel | `securityinsight.settings.list` | 3.14.7 |
| Storage | `storage.blob_containers.get_immutability_policy` | 3.3.8 |
| Storage | `storage.storage_accounts.list` | 3.1.21, 3.1.22, 3.8.2, 3.8.6, 3.13.8 (+1 more) |

### GCP (54 unique API calls across 28 services)

| Service | API Call | Used By (Practices) |
|---------|---------|---------------------|
| Artifact Registry | `containeranalysis.projects.occurrences.list` | 3.7.1 |
| Asset Inventory | `cloudasset.assets.list` | 3.4.1 |
| Backup and DR | `backupdr.projects.locations.backupVaults.list` | 3.8.9 |
| BeyondCorp | `beyondcorp.projects.locations.appConnections.list` | 3.1.10 |
| BigQuery | `bigquery.datasets.list` | 3.13.16 |
| Binary Authorization | `binaryauthorization.projects.getPolicy` | 3.4.8 |
| Cloud Armor | `compute.securityPolicies.list` | 3.13.1, 3.13.13 |
| Cloud IDS | `ids.projects.locations.endpoints.list` | 3.14.6 |
| Cloud SQL | `sqladmin.instances.list` | 3.5.10, 3.8.6, 3.13.8, 3.13.16 |
| Compute | `compute.backendServices.list` | 3.13.9 |
| Compute | `compute.disks.list` | 3.8.2 |
| Compute | `compute.images.getIamPolicy` | 3.13.4 |
| Compute | `compute.instances.list` | 3.3.7, 3.14.2, 3.14.4 |
| Compute | `compute.projects.get` | 3.1.15 |
| Compute | `compute.sslCertificates.list` | 3.13.15 |
| Compute | `compute.sslPolicies.list` | 3.13.8 |
| Container Analysis | `containeranalysis.projects.occurrences.list` | 3.11.2, 3.14.1, 3.14.5 |
| GKE | `container.projects.locations.clusters.list` | 3.14.1 |
| IAM | `cloudresourcemanager.projects.getIamPolicy` | 3.1.1, 3.1.2, 3.1.4, 3.1.5, 3.1.6 (+2 more) |
| IAM | `compute.instances.list` | 3.1.1 |
| IAM | `iam.projects.roles.list` | 3.1.2 |
| IAM | `iam.projects.serviceAccounts.keys.list` | 3.1.1, 3.5.6 |
| IAM | `iam.projects.serviceAccounts.list` | 3.1.11, 3.5.1 |
| IAM | `recommender.projects.locations.recommenders.recommendations.list` | 3.1.5 |
| IAP | `iap.projects.iap_tunnel.locations.destGroups.list` | 3.1.12 |
| KMS | `cloudkms.projects.locations.keyRings.cryptoKeys.list` | 3.13.10, 3.13.11 |
| KMS | `cloudkms.projects.locations.keyRings.getIamPolicy` | 3.13.10 |
| Logging | `cloudresourcemanager.projects.getIamPolicy` | 3.3.1 |
| Logging | `logging.entries.list` | 3.3.2, 3.4.3, 3.14.7 |
| Logging | `logging.projects.locations.buckets.list` | 3.3.6 |
| Logging | `logging.projects.logs.list` | 3.1.7, 3.3.1 |
| Logging | `logging.projects.sinks.list` | 3.3.1 |
| Monitoring | `monitoring.projects.alertPolicies.list` | 3.1.7, 3.3.4, 3.14.3, 3.14.7 |
| Multiple | `compute/kms/logging/orgpolicy` | 3.13.2 |
| OS Config | `osconfig.projects.locations.instances.inventories.get` | 3.4.1 |
| OS Config | `osconfig.projects.locations.instances.inventories.list` | 3.4.9 |
| OS Config | `osconfig.projects.locations.instances.vulnerabilityReports.get` | 3.11.3 |
| OS Config | `osconfig.projects.patchDeployments.list` | 3.7.1, 3.14.1 |
| OrgPolicy | `orgpolicy.projects.policies.get` | 3.1.18, 3.1.21 |
| OrgPolicy/Compute | `orgpolicy/compute.disks.list` | 3.1.19 |
| Organization Policy | `orgpolicy.projects.policies.list` | 3.4.2, 3.12.3 |
| Resource Manager | `cloudresourcemanager.liens.list` | 3.4.5 |
| SCC | `securitycenter.organizations.getOrganizationSettings` | 3.6.1, 3.12.3 |
| SCC | `securitycenter.organizations.notificationConfigs.list` | 3.6.1, 3.14.3 |
| SCC | `securitycenter.organizations.sources.findings.list` | 3.4.2, 3.11.2, 3.11.3, 3.14.7 |
| SCC | `securitycenter.organizations.sources.list` | 3.3.5, 3.6.1, 3.14.6 |
| SCC | `websecurityscanner.projects.scanConfigs.list` | 3.11.2, 3.14.5 |
| Storage | `storage.buckets.get` | 3.3.8, 3.8.6, 3.13.16 |
| Storage | `storage.buckets.getIamPolicy` | 3.1.22, 3.3.8, 3.8.2 |
| Storage | `storage.buckets.list` | 3.14.2 |
| VPC | `compute.firewalls.list` | 3.1.3, 3.1.14, 3.4.6, 3.4.7, 3.13.6 |
| VPC | `compute.networks.listPeering` | 3.1.20 |
| VPC | `compute.packetMirrorings.list` | 3.13.1 |
| VPC | `compute.subnetworks.list` | 3.1.3, 3.13.1, 3.13.3, 3.13.5, 3.14.6 |
| VPN | `compute.vpnGateways.list/vpnTunnels.list` | 3.1.16 |
| VPN | `compute.vpnTunnels.list` | 3.1.13, 3.13.7 |
| Workspace Admin | `admin.directory.users.list` | 3.1.8, 3.5.2, 3.5.3, 3.5.4, 3.5.5 (+4 more) |

---

## 9. Appendix B — Glossary

| Term | Definition |
|------|-----------|
| **CCA** | Certified FedRAMP Assessor — individual authorized to conduct FedRAMP assessments |
| **3PAO** | FedRAMP Third-Party Assessment Organization — accredited organization that employs CCAs |
| **OSC** | Organization Seeking Certification — the CSP being assessed |
| **CUI** | Controlled Unclassified Information — sensitive government information requiring protection |
| **FCI** | Federal Contract Information — information provided by or generated for the government under contract |
| **CSP** | Defense Industrial Base — companies that supply products/services to the DoD |
| **CSP** | Cloud Service Provider — AWS, Azure, or GCP |
| **Met** | The practice/objective is fully implemented based on automated or manual evidence |
| **Not Met** | The practice/objective is not implemented or has deficiencies |
| **Manual Review** | The practice requires CCA manual assessment — cannot be determined by automated checks alone |
| **Assessment Objective** | A specific "determine if" statement from NIST SP 800-53A that must be evaluated |
| **POA&M** | Plan of Action and Milestones — remediation plan for Not Met findings |
| **SSP** | System Security Plan — document describing the system boundary, environment, and security controls |
| **STS** | Security Token Service — AWS service for assuming cross-account roles |
| **IAM** | Identity and Access Management — cloud service for managing users, roles, and permissions |

---

## Document Information

This methodology reference is auto-generated from the scanner's configuration files (`config/nist_800_53_controls.json` and `config/checks/*.json`). All check definitions, objective mappings, and coverage data are derived directly from the scanner's authoritative data sources.

For the interactive version of this document, see the **Assessment Methodology** tab in the scanner's Help blade.
