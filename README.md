# CMMC Cloud Compliance Scanner

A web-based platform that scans client cloud environments against CMMC 2.0 requirements and produces automated Met/Not-Met assessment reports. Built by [Securitybricks](https://securitybricks.com) (a C3PAO, powered by Aprio) for DIB contractor CMMC readiness assessments.

---

## Table of Contents

- [1. Introduction](#1-introduction)
  - [1.1 Overview](#11-overview)
  - [1.2 How It Works](#12-how-it-works)
- [2. CMMC Framework Reference](#2-cmmc-framework-reference)
  - [2.1 Supported Cloud Environments](#21-supported-cloud-environments)
  - [2.2 CMMC Certification Levels](#22-cmmc-certification-levels)
  - [2.3 CMMC Domains and Check Coverage](#23-cmmc-domains-and-check-coverage)
    - [Level 1 — FAR 52.204-21](#level-1--far-52204-21-17-practices)
    - [Level 2 — NIST SP 800-171](#level-2--nist-sp-800-171-110-practices)
    - [Level 3 — NIST SP 800-172](#level-3--nist-sp-800-172-enhanced-practices)
- [3. Getting Started](#3-getting-started)
  - [3.1 Prerequisites](#31-prerequisites)
  - [3.2 Local Development](#32-local-development)
    - [3.2.1 Option A — Automated Setup](#321-option-a--automated-setup)
    - [3.2.2 Option B — Manual Setup](#322-option-b--manual-setup)
    - [3.2.3 Option C — Docker](#323-option-c--docker)
  - [3.3 Client Environment Deployment (for Securitybricks Engineers)](#33-client-environment-deployment-for-securitybricks-engineers)
    - [3.3.1 VM Requirements](#331-vm-requirements)
    - [3.3.2 Step 1 — Provision the VM](#332-step-1--provision-the-vm)
    - [3.3.3 Step 2 — Install Prerequisites](#333-step-2--install-prerequisites)
    - [3.3.4 Step 3 — Download and Set Up](#334-step-3--download-and-set-up)
    - [3.3.5 Step 4 — Configure for VM Access](#335-step-4--configure-for-vm-access)
    - [3.3.6 Step 5 — Start the Scanner](#336-step-5--start-the-scanner)
    - [3.3.7 Step 6 — Connect and Scan](#337-step-6--connect-and-scan)
    - [3.3.8 Docker Alternative](#338-docker-alternative)
    - [3.3.9 Teardown](#339-teardown)
  - [3.4 API Documentation](#34-api-documentation)
  - [3.5 Demo Reports](#35-demo-reports)
  - [3.6 Environment Variables](#36-environment-variables)
- [4. API Reference](#4-api-reference)
  - [4.1 Authentication](#41-authentication)
  - [4.2 Clients](#42-clients)
  - [4.3 Scans](#43-scans)
  - [4.4 Reports](#44-reports)
- [5. Deployment](#5-deployment)
  - [5.1 Azure Commercial (Bicep)](#51-azure-commercial-bicep)
    - [5.1.1 Infrastructure Overview](#511-infrastructure-overview)
    - [5.1.2 Prerequisites](#512-prerequisites)
    - [5.1.3 Create Resource Group and Deploy Infrastructure](#513-create-resource-group-and-deploy-infrastructure)
    - [5.1.4 Get Deployment Outputs](#514-get-deployment-outputs)
    - [5.1.5 Build and Push Docker Image to ACR](#515-build-and-push-docker-image-to-acr)
    - [5.1.6 Register ACR Credentials and Update Container App](#516-register-acr-credentials-and-update-container-app)
    - [5.1.7 Upload Frontend to Blob Storage](#517-upload-frontend-to-blob-storage)
    - [5.1.8 Verify Deployment](#518-verify-deployment)
    - [5.1.9 Custom Domain (Optional)](#519-custom-domain-optional)
    - [5.1.10 Subsequent Deployments](#5110-subsequent-deployments)
    - [5.1.11 Client Onboarding (Azure)](#5111-client-onboarding-azure)
    - [5.1.12 Troubleshooting](#5112-troubleshooting)
  - [5.2 AWS Commercial (CloudFormation)](#52-aws-commercial-cloudformation)
    - [5.2.1 Infrastructure Overview](#521-infrastructure-overview)
    - [5.2.2 Prerequisites](#522-prerequisites)
    - [5.2.3 Deploy Infrastructure](#523-deploy-infrastructure)
    - [5.2.4 Build and Push Docker Image](#524-build-and-push-docker-image)
    - [5.2.5 Upload Frontend to S3](#525-upload-frontend-to-s3)
    - [5.2.6 Update ECS Service](#526-update-ecs-service)
    - [5.2.7 Verify Deployment](#527-verify-deployment)
    - [5.2.8 Subsequent Deployments](#528-subsequent-deployments)
    - [5.2.9 Client Onboarding (AWS)](#529-client-onboarding-aws)
    - [5.2.10 Troubleshooting](#5210-troubleshooting)
  - [5.3 GCP Commercial (gcloud CLI)](#53-gcp-commercial-gcloud-cli)
    - [5.3.1 Infrastructure Overview](#531-infrastructure-overview)
    - [5.3.2 Prerequisites](#532-prerequisites)
    - [5.3.3 Create Project and Enable APIs](#533-create-project-and-enable-apis)
    - [5.3.4 Deploy Cloud SQL (PostgreSQL)](#534-deploy-cloud-sql-postgresql)
    - [5.3.5 Build and Push Docker Image to Artifact Registry](#535-build-and-push-docker-image-to-artifact-registry)
    - [5.3.6 Deploy Cloud Run Service](#536-deploy-cloud-run-service)
    - [5.3.7 Upload Frontend to Cloud Storage](#537-upload-frontend-to-cloud-storage)
    - [5.3.8 Verify Deployment](#538-verify-deployment)
    - [5.3.9 Subsequent Deployments](#539-subsequent-deployments)
    - [5.3.10 Client Onboarding (GCP)](#5310-client-onboarding-gcp)
    - [5.3.11 Troubleshooting](#5311-troubleshooting)
- [6. Architecture](#6-architecture)
  - [6.1 Project Structure](#61-project-structure)
  - [6.2 Technology Stack](#62-technology-stack)
  - [6.3 Data Model](#63-data-model)
  - [6.4 Key Design Decisions](#64-key-design-decisions)
- [7. License](#7-license)

---

## 1. Introduction

### 1.1 Overview

The CMMC Cloud Compliance Scanner connects to client cloud environments via read-only IAM roles, evaluates security configurations against NIST 800-171/800-172 practices, and generates professional HTML and XLSX reports.

The scanner is designed for Securitybricks assessors performing CMMC readiness consulting for Defense Industrial Base (DIB) contractors. It automates the evaluation of approximately 71 of the 110 NIST 800-171 practices and flags the remaining 39 policy/process controls as "Manual Review Required."

### 1.2 How It Works

```
Client's Cloud                        Securitybricks Platform
IAM Role (read-only) <── assumes ──── Scan Engine
                                        │
                                        ▼
                                      Results DB (PostgreSQL)
                                      Report Generator (HTML + XLSX)
                                      Web UI (dashboard)
```

The workflow proceeds through five stages:

1. **Client onboarding** — The client grants a read-only cross-account role (AWS IAM role, Azure service principal, or GCP service account) using the provided template.
2. **Scan execution** — A Securitybricks consultant triggers a scan from the Web UI, selecting the client, environment, and CMMC level.
3. **Automated checks** — The scan engine connects to the client's cloud via the read-only role and evaluates ~71 automated practices across all 14 CMMC domains.
4. **Manual review markers** — ~39 policy/process controls that cannot be automated are flagged as "Manual Review Required."
5. **Report generation** — Professional HTML and XLSX reports are produced with executive summary, per-domain breakdown, detailed findings, and remediation guidance.

> **Scan scope:** Each client entry scans a single cloud account (AWS account, Azure subscription, or GCP project). If a client has multiple accounts or subscriptions in scope for CMMC assessment, onboard each one as a separate client entry. Reports are generated per scan, so each account/subscription gets its own assessment report.

---

## 2. CMMC Framework Reference

### 2.1 Supported Cloud Environments

| # | Environment | Tier | CMMC Levels | FedRAMP Baseline |
|---|-------------|------|-------------|------------------|
| 1 | AWS Commercial | Commercial | L1, L2 | Moderate |
| 2 | AWS GovCloud | Government | L1, L2, L3 | High |
| 3 | Azure Commercial | Commercial | L1, L2 | Moderate |
| 4 | Azure Government | Government | L1, L2, L3 | High |
| 5 | GCP Commercial | Commercial | L1, L2 | Moderate |
| 6 | GCP Assured Workloads | Government | L1, L2, L3 | High |

### 2.2 CMMC Certification Levels

| Level | Framework | Practices | Data Type | Assessment |
|-------|-----------|-----------|-----------|------------|
| L1 | FAR 52.204-21 | 17 | FCI | Self-assessment |
| L2 | NIST SP 800-171 Rev 2 | 110 | CUI | C3PAO assessment |
| L3 | NIST SP 800-172 (enhanced) | 110 + enhanced | CUI (APT-focused) | DIBCAC assessment |

### 2.3 CMMC Domains and Check Coverage

#### Level 1 — FAR 52.204-21 (17 practices)

L1 covers basic safeguarding of Federal Contract Information (FCI). The 17 FAR practices map to a subset of NIST 800-171 across 6 domains:

| Domain | Family | Automated | Manual |
|--------|--------|-----------|--------|
| AC | Access Control | 4 | 0 |
| IA | Identification and Authentication | 2 | 0 |
| MP | Media Protection | 0 | 1 |
| PE | Physical Protection | 0 | 4 |
| SC | System & Comms Protection | 2 | 0 |
| SI | System & Info Integrity | 4 | 0 |
| **Total** | | **12 automated** | **5 manual** |

#### Level 2 — NIST SP 800-171 (110 practices)

L2 covers all 110 NIST 800-171 practices (which include the 17 L1 practices) across all 14 CMMC domains:

| Domain | Family | Automated | Manual |
|--------|--------|-----------|--------|
| AC | Access Control | 16 | 6 |
| AT | Awareness and Training | 0 | 3 |
| AU | Audit and Accountability | 8 | 1 |
| CM | Configuration Management | 8 | 1 |
| IA | Identification and Authentication | 10 | 1 |
| IR | Incident Response | 1 | 2 |
| MA | Maintenance | 2 | 4 |
| MP | Media Protection | 3 | 6 |
| PS | Personnel Security | 0 | 2 |
| PE | Physical Protection | 0 | 6 |
| RA | Risk Assessment | 2 | 1 |
| CA | Security Assessment | 1 | 3 |
| SC | System & Comms Protection | 13 | 3 |
| SI | System & Info Integrity | 7 | 0 |
| **Total** | | **71 automated** | **39 manual** |

#### Level 3 — NIST SP 800-172 (enhanced practices)

L3 adds enhanced security requirements from NIST 800-172 on top of the 110 L2 practices, targeting protection against Advanced Persistent Threats (APTs). L3 checks are available only for Government environments (AWS GovCloud, Azure Government, GCP Assured Workloads).

> **Status:** L3 enhanced practice checks are planned but not yet implemented. The scanner currently supports L1 and L2 assessments.

Each automated practice has cloud-specific check implementations for AWS, Azure, and GCP.

---

## 3. Getting Started

### 3.1 Prerequisites

- Python 3.12
- PostgreSQL (production) or SQLite (development — used by default, no setup required)

### 3.2 Local Development

#### 3.2.1 Option A — Automated Setup

```bash
git clone <repo-url>
cd CMMC-Scanner
bash scripts/setup.sh
```

This creates a virtual environment, installs dependencies, initializes a local SQLite database, and generates a `.env` file with random secrets.

After setup:

```bash
source .venv/bin/activate
cd backend
uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000 in your browser. The backend serves the frontend via `/static/`.

**Dev mode** uses password login (default: `admin` / `admin`). **Production** uses Microsoft Entra ID SSO — see [Section 3.6](#36-environment-variables).

> **Note:** The server must be started from the `backend/` directory so that `uvicorn` can resolve `app.main:app`. The `config/` directory is located at the project root and is referenced via relative path from `engine.py`.

#### 3.2.2 Option B — Manual Setup

```bash
git clone <repo-url>
cd CMMC-Scanner

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Start the server (must run from backend/ directory)
cd backend
uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000 in your browser. The backend serves the frontend via `/static/`.

**Dev mode** uses password login (default: `admin` / `admin`). **Production** uses Microsoft Entra ID SSO — see [Section 3.6](#36-environment-variables).

> **Note:** The server must be started from the `backend/` directory so that `uvicorn` can resolve `app.main:app`. The `config/` directory is located at the project root and is referenced via relative path from `engine.py`.

#### 3.2.3 Option C — Docker

```bash
# Build the image (on Apple Silicon, add --platform linux/amd64)
docker build -t cmmc-scanner:latest .

# Run with default SQLite database
docker run -p 8000:8000 cmmc-scanner:latest

# Or with a .env file for PostgreSQL / SSO configuration
docker run -p 8000:8000 --env-file .env cmmc-scanner:latest
```

Open http://localhost:8000 in your browser. The backend serves the frontend via `/static/`.

**Dev mode** uses password login (default: `admin` / `admin`). **Production** uses Microsoft Entra ID SSO — see [Section 3.6](#36-environment-variables).

### 3.3 Client Environment Deployment (for Securitybricks Engineers)

For CMMC L2 readiness assessments, Securitybricks engineers deploy the scanner on a VM inside the client's cloud environment. The VM runs the scanner locally, connects to the client's cloud via read-only credentials, and engineers access it from their AVD session at `http://<VM_IP>:8000`. After the assessment is complete, the VM is destroyed — no persistent infrastructure is left behind.

#### 3.3.1 VM Requirements

| Requirement | Specification |
|-------------|--------------|
| OS | Ubuntu 22.04 LTS (recommended), Amazon Linux 2023, or any Linux with Python 3.12+ |
| CPU / RAM | 2 vCPU, 4 GB RAM (sufficient for 1–2 concurrent users) |
| Disk | 20 GB |
| Inbound network | TCP 8000 from engineer workstation / AVD IP |
| Outbound network | HTTPS 443 to cloud provider APIs (AWS, Azure, or GCP endpoints) |
| Cloud access | Read-only role already granted per client onboarding ([Section 5.1.11](#5111-client-onboarding-azure), [5.2.9](#529-client-onboarding-aws), or [5.3.10](#5310-client-onboarding-gcp)) |

> **Tip:** Use a private IP if connecting via AVD within the same virtual network — no public IP needed.

#### 3.3.2 Step 1 — Provision the VM

**Azure:**
```bash
# Create resource group and VM with NSG rule for TCP 8000
az group create --name cmmc-scan-rg --location eastus2

az vm create \
  --resource-group cmmc-scan-rg \
  --name cmmc-scan-vm \
  --image Ubuntu2204 \
  --size Standard_B2s \
  --admin-username azureuser \
  --generate-ssh-keys

az vm open-port --resource-group cmmc-scan-rg --name cmmc-scan-vm --port 8000
```

**AWS:**
```bash
# Launch instance with security group allowing TCP 8000
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.small \
  --key-name <your-key-pair> \
  --security-group-ids <sg-with-port-8000>
```

**GCP:**
```bash
# Create instance with firewall rule for TCP 8000
gcloud compute instances create cmmc-scan-vm \
  --zone=us-central1-a \
  --machine-type=e2-medium \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud

gcloud compute firewall-rules create allow-scanner \
  --allow=tcp:8000 --source-ranges=<engineer-ip>/32
```

#### 3.3.3 Step 2 — Install Prerequisites

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y python3.12 python3.12-venv python3-pip git

# Amazon Linux / RHEL
sudo dnf install -y python3.12 git
```

#### 3.3.4 Step 3 — Download and Set Up

```bash
git clone https://github.com/nubaskar/CMMC-Scanner.git
cd CMMC-Scanner
bash scripts/setup.sh
```

#### 3.3.5 Step 4 — Configure for VM Access

```bash
VM_IP=$(hostname -I | awk '{print $1}')
echo "ALLOWED_ORIGINS=http://${VM_IP}:8000" >> .env
echo "FRONTEND_URL=http://${VM_IP}:8000" >> .env
```

#### 3.3.6 Step 5 — Start the Scanner

```bash
source .venv/bin/activate
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

> **Note:** `--host 0.0.0.0` is required to accept connections from other machines (the default `127.0.0.1` only accepts local connections).

#### 3.3.7 Step 6 — Connect and Scan

1. From your AVD session, open a browser and navigate to `http://<VM_IP>:8000`
2. Log in with `admin` / `admin`
3. Add the client (Clients → Add Client) with cloud credentials per the client onboarding guide ([Section 5.1.11](#5111-client-onboarding-azure), [5.2.9](#529-client-onboarding-aws), or [5.3.10](#5310-client-onboarding-gcp))
4. Run a scan (Scans → New Scan), select the client and CMMC level
5. Download reports (Reports → select scan → Export HTML / XLSX)

#### 3.3.8 Docker Alternative

If Docker is available on the VM:

```bash
docker build -t cmmc-scanner:latest .
docker run -p 8000:8000 --env-file .env cmmc-scanner:latest
```

On Apple Silicon or ARM-based VMs, add `--platform linux/amd64` to the build command.

#### 3.3.9 Teardown

After the assessment is complete, destroy the VM:

```bash
# Azure
az vm delete --name cmmc-scan-vm --resource-group cmmc-scan-rg --yes
az group delete --name cmmc-scan-rg --yes

# AWS
aws ec2 terminate-instances --instance-ids <instance-id>

# GCP
gcloud compute instances delete cmmc-scan-vm --zone=us-central1-a --quiet
```

> **Note:** The SQLite database is local to the VM — all scan data is destroyed with the VM. Download any reports you need before teardown.

### 3.4 API Documentation

Interactive API docs are available when the server is running:

- **Swagger UI:** http://localhost:8000/api/docs
- **ReDoc:** http://localhost:8000/api/redoc

### 3.5 Demo Reports

Preview report format without running a scan or configuring a database:

- **HTML Report:** http://localhost:8000/api/reports/demo/html
- **XLSX Report:** http://localhost:8000/api/reports/demo/xlsx

### 3.6 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | `sqlite:///./cmmc_scanner.db` |
| `JWT_SECRET_KEY` | Secret key for signing JWT tokens | Dev fallback (change in production) |
| `AZURE_AD_TENANT_ID` | Microsoft Entra ID tenant ID | _(empty — disables SSO)_ |
| `AZURE_AD_CLIENT_ID` | Entra ID application (client) ID | _(empty — disables SSO)_ |
| `AZURE_AD_CLIENT_SECRET` | Entra ID client secret | _(empty)_ |
| `FRONTEND_URL` | Redirect target after SSO callback | `http://localhost:8080` |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | `http://localhost:8080,http://localhost:8000` |
| `ENVIRONMENT` | Runtime environment | `dev` (`dev`, `staging`, or `prod`) |

When `AZURE_AD_TENANT_ID` and `AZURE_AD_CLIENT_ID` are set and `ENVIRONMENT=prod`, the login page shows the SSO button. Otherwise it falls back to password login.

---

## 4. API Reference

### 4.1 Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/auth/config` | Auth mode (SSO or password) |
| `POST` | `/api/auth/login` | Password login, returns JWT token |
| `GET` | `/api/auth/login` | Redirect to Microsoft Entra ID for SSO |
| `GET` | `/api/auth/callback` | Entra ID SSO callback (exchanges code for JWT) |
| `POST` | `/api/auth/logout` | Logout (returns Entra ID logout URL if SSO) |
| `GET` | `/api/auth/me` | Current user info from JWT claims |

### 4.2 Clients

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/clients` | Create client with cloud credentials |
| `GET` | `/api/clients` | List all clients |
| `GET` | `/api/clients/{id}` | Get client details |
| `PUT` | `/api/clients/{id}` | Update client |
| `DELETE` | `/api/clients/{id}` | Delete client and all scan data |
| `POST` | `/api/clients/verify` | Test client cloud credentials |

### 4.3 Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scans` | Start a new scan (async) |
| `GET` | `/api/scans` | List scans (optional `?client_id=` filter) |
| `GET` | `/api/scans/{id}` | Get scan with all findings |
| `GET` | `/api/scans/{id}/summary` | Compliance summary by status/domain |
| `GET` | `/api/scans/{id}/evidence/{practice_id}` | Live API evidence for a practice |
| `DELETE` | `/api/scans/{id}` | Delete scan and findings |

### 4.4 Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/reports` | List clients with completed scans |
| `GET` | `/api/reports/notifications` | Recent scan completions/failures |
| `GET` | `/api/reports/demo/html` | Demo HTML report (no auth required) |
| `GET` | `/api/reports/demo/xlsx` | Demo XLSX report (no auth required) |
| `GET` | `/api/reports/{scan_id}/html` | Download HTML report for a completed scan |
| `GET` | `/api/reports/{scan_id}/xlsx` | Download XLSX report for a completed scan |

> **Note:** Demo routes must be defined before `/{scan_id}` routes in `reports.py` to prevent FastAPI from matching "demo" as a scan_id.

---

## 5. Deployment

The CMMC Scanner supports deployment to all three major cloud providers. Each deployment follows the same pattern: provision managed infrastructure (container runtime, PostgreSQL database, static file hosting, secrets management), push the Docker image, and upload the frontend assets. Choose the platform that aligns with your organization's existing cloud footprint.

| Section | Cloud Provider | IaC Tool | Status |
|---------|---------------|----------|--------|
| [5.1](#51-azure-commercial-bicep) | Azure Commercial | Bicep | Deployed and battle-tested |
| [5.2](#52-aws-commercial-cloudformation) | AWS Commercial | CloudFormation | Template ready |
| [5.3](#53-gcp-commercial-gcloud-cli) | GCP Commercial | gcloud CLI | Deployment guide ready |

All three deployments use the same Docker image, the same backend codebase, and the same frontend static files. The only differences are the cloud-native services used for hosting, database, secrets, and static file delivery.

### 5.1 Azure Commercial (Bicep)

#### 5.1.1 Infrastructure Overview

| Component | Azure Service | Purpose |
|-----------|---------------|---------|
| Backend API | Container Apps | Runs the FastAPI Docker container |
| Database | PostgreSQL Flexible Server | Stores clients, scans, findings |
| Frontend UI | Blob Storage + Azure Front Door | Static website hosting with CDN |
| Secrets | Key Vault | DB password, JWT secret, encryption key |
| Container images | Container Registry (ACR) | Stores the Docker image |
| Networking | Virtual Network | Private connectivity between services |
| Logging | Log Analytics | Monitoring and diagnostics |

The Bicep template uses a **two-phase deployment** to solve the chicken-and-egg problem: ACR is created during deployment but has no images yet. Phase 1 deploys with a Microsoft placeholder container. Phase 2 (Steps 5.1.5–5.1.6) pushes your image and switches the Container App to use it.

#### 5.1.2 Prerequisites

Register required Azure resource providers (one-time):

```bash
az provider register --namespace Microsoft.App
az provider register --namespace Microsoft.DBforPostgreSQL
az provider register --namespace Microsoft.ContainerRegistry
```

#### 5.1.3 Create Resource Group and Deploy Infrastructure

```bash
# Create the resource group
az group create --name cmmc-scanner-rg --location eastus2

# Deploy infrastructure (first deployment uses a placeholder init container)
az deployment group create \
  --resource-group cmmc-scanner-rg \
  --template-file deploy/azure/main.bicep \
  --parameters \
    environment=prod \
    location=eastus2 \
    dbAdminPassword='<secure-password>' \
    jwtSecret='<secure-jwt-secret>' \
    encryptionKey='<secure-encryption-key>'
```

Valid `environment` values: `dev`, `staging`, `prod`.

> **Note:** The first deployment uses a Microsoft placeholder container image. The Container App will show a basic "hello" page until you push your Docker image in [Step 5.1.5](#515-build-and-push-docker-image-to-acr).

#### 5.1.4 Get Deployment Outputs

```bash
# Get all deployment outputs
az deployment group show \
  --resource-group cmmc-scanner-rg \
  --name main \
  --query properties.outputs -o json

# Save ACR name for later steps
ACR_NAME=$(az deployment group show \
  --resource-group cmmc-scanner-rg \
  --name main \
  --query properties.outputs.acrLoginServer.value -o tsv)

echo "ACR: $ACR_NAME"
```

#### 5.1.5 Build and Push Docker Image to ACR

Use ACR Tasks to build in the cloud (no local Docker needed, builds linux/amd64 by default):

```bash
az acr build \
  --registry ${ACR_NAME%%.*} \
  --image cmmc-scanner:v1 \
  --platform linux/amd64 \
  .
```

> **Important:** Run this from the project root directory (where the `Dockerfile` is). If building locally on Apple Silicon (M1/M2/M3), you must use `docker build --platform linux/amd64` — Container Apps requires linux/amd64 images.

#### 5.1.6 Register ACR Credentials and Update Container App

```bash
# Register ACR credentials with the Container App (required after first deployment)
az containerapp registry set \
  --name cmmc-scanner-prod-api \
  --resource-group cmmc-scanner-rg \
  --server $ACR_NAME \
  --username $(az acr credential show --name ${ACR_NAME%%.*} --query username -o tsv) \
  --password $(az acr credential show --name ${ACR_NAME%%.*} --query "passwords[0].value" -o tsv)

# Update the Container App with the real image
az containerapp update \
  --name cmmc-scanner-prod-api \
  --resource-group cmmc-scanner-rg \
  --image $ACR_NAME/cmmc-scanner:v1

# Fix ingress port (init container used port 80, our app uses 8000)
az containerapp ingress update \
  --name cmmc-scanner-prod-api \
  --resource-group cmmc-scanner-rg \
  --target-port 8000
```

#### 5.1.7 Upload Frontend to Blob Storage

```bash
# Get storage account name
STORAGE_ACCOUNT=$(az storage account list \
  --resource-group cmmc-scanner-rg \
  --query "[0].name" -o tsv)

# Enable static website hosting
az storage blob service-properties update \
  --account-name $STORAGE_ACCOUNT \
  --static-website \
  --index-document index.html \
  --404-document index.html

# Upload frontend files
az storage blob upload-batch \
  --account-name $STORAGE_ACCOUNT \
  --destination '$web' \
  --source frontend/ \
  --overwrite
```

#### 5.1.8 Verify Deployment

```bash
# Backend health check
curl https://<container-app-url>/health

# Frontend — open in browser
echo "Frontend: https://$STORAGE_ACCOUNT.z20.web.core.windows.net/"
echo "Backend:  $(az containerapp show --name cmmc-scanner-prod-api \
  --resource-group cmmc-scanner-rg \
  --query properties.configuration.ingress.fqdn -o tsv)"
```

> **Note:** Production uses Entra ID SSO for login, not password auth. Ensure `AZURE_AD_TENANT_ID`, `AZURE_AD_CLIENT_ID`, `AZURE_AD_CLIENT_SECRET`, and `FRONTEND_URL` are set in the Container App environment variables, and the redirect URI `https://<container-app-url>/api/auth/callback` is registered in the Entra ID app registration.

#### 5.1.9 Custom Domain (Optional)

```bash
# Add custom domain to Container App
az containerapp hostname add \
  --name cmmc-scanner-prod-api \
  --resource-group cmmc-scanner-rg \
  --hostname scanner.securitybricks.com

# Bind managed TLS certificate
az containerapp hostname bind \
  --name cmmc-scanner-prod-api \
  --resource-group cmmc-scanner-rg \
  --hostname scanner.securitybricks.com \
  --environment cmmc-scanner-prod-env \
  --validation-method CNAME
```

Point your DNS CNAME record to the Container App's auto-generated URL before binding.

#### 5.1.10 Subsequent Deployments

After making code changes, rebuild and push a new image version:

```bash
# Build new version (always increment the tag — never reuse v1, v2, etc.)
az acr build \
  --registry ${ACR_NAME%%.*} \
  --image cmmc-scanner:v2 \
  --platform linux/amd64 \
  .

# Update Container App
az containerapp update \
  --name cmmc-scanner-prod-api \
  --resource-group cmmc-scanner-rg \
  --image $ACR_NAME/cmmc-scanner:v2

# Re-upload frontend if changed
az storage blob upload-batch \
  --account-name $STORAGE_ACCOUNT \
  --destination '$web' \
  --source frontend/ \
  --overwrite
```

> **Important:** Always use a new tag for each build (v1, v2, v3...). Container Apps caches images by tag, so reusing the same tag will not pick up changes.

#### 5.1.11 Client Onboarding (Azure)

Register an App in Microsoft Entra ID (Azure AD) in the client's tenant and grant it read-only access to the target subscription.

##### Via Azure CLI

```bash
# Run in the client's Azure tenant

# 1. Create an app registration
az ad app create --display-name "CMMC Scanner" \
  --sign-in-audience AzureADMyOrg

# 2. Create a service principal
APP_ID=$(az ad app list --display-name "CMMC Scanner" \
  --query "[0].appId" -o tsv)
az ad sp create --id $APP_ID

# 3. Create a client secret (save the output)
az ad app credential reset --id $APP_ID --append \
  --display-name "cmmc-scanner-secret" --years 1

# 4. Assign Reader role on the target subscription
SUB_ID=$(az account show --query id -o tsv)
az role assignment create --assignee $APP_ID \
  --role "Reader" --scope /subscriptions/$SUB_ID

# 5. Assign Security Reader role
az role assignment create --assignee $APP_ID \
  --role "Security Reader" --scope /subscriptions/$SUB_ID
```

##### Via Azure Portal

1. **Entra ID** > **App registrations** > **New registration** > Name: "CMMC Scanner", Single tenant > **Register**
2. **Certificates & secrets** > **New client secret** > set expiry > copy the **Value** immediately
3. **Subscriptions** > select subscription > **Access control (IAM)** > **Add role assignment**:
   - Add **Reader** role > assign to the CMMC Scanner app
   - Add **Security Reader** role > assign to the CMMC Scanner app

##### Required Microsoft Graph API Permissions

The scanner queries Microsoft Graph for Entra ID security checks (conditional access, MFA, sign-in logs, identity protection). All 8 permissions below are **Application** type (not Delegated) and require **admin consent**.

| # | Permission | Graph API Endpoints | CMMC Checks |
|---|-----------|-------------------|-------------|
| 1 | **Policy.Read.All** | `policies/authorizationPolicy`, `policies/identitySecurityDefaultsEnforcementPolicy`, `identity/conditionalAccess/policies`, `policies/tokenLifetimePolicies`, `policies/authenticationMethodsPolicy/*` | Guest access, Security Defaults, Conditional Access, MFA, FIDO2, token lifetime |
| 2 | **Directory.Read.All** | `settings`, `directoryRoles`, `directoryRoles/{id}/members` | Smart lockout, password protection, global admin count, admin account separation |
| 3 | **RoleManagement.Read.Directory** | `roleManagement/directory/roleAssignmentScheduleInstances` | Privileged Identity Management (PIM) |
| 4 | **User.Read.All** | `users`, `directory/deletedItems/microsoft.graph.user` | Unique users, inactive users, force password change, deleted users |
| 5 | **AuditLog.Read.All** | `auditLogs/directoryAudits`, `auditLogs/signIns` | Audit log retention, sign-in logs, user sign-in activity |
| 6 | **Reports.Read.All** | `reports/credentialUserRegistrationDetails` | MFA registration status |
| 7 | **IdentityRiskEvent.Read.All** | `identityProtection/riskDetections` | Identity Protection risk detections |
| 8 | **IdentityRiskyUser.Read.All** | `identityProtection/riskyUsers` | Risky users monitoring |

**Grant via CLI:**

```bash
APP_ID="<your-app-client-id>"

# Add all 8 Graph Application permissions (API ID: 00000003-0000-0000-c000-000000000000)
az ad app permission add --id $APP_ID --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions e2a3a72e-5f79-4c64-b1b1-878b674786c9=Role  # Policy.Read.All
az ad app permission add --id $APP_ID --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role  # Directory.Read.All
az ad app permission add --id $APP_ID --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 483bed4a-2ad3-4361-a73b-c83ccdbdc53c=Role  # RoleManagement.Read.Directory
az ad app permission add --id $APP_ID --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions df021288-bdef-4463-88db-98f22de89214=Role  # User.Read.All
az ad app permission add --id $APP_ID --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions b0afded3-3588-46d8-8b3d-9842eff778da=Role  # AuditLog.Read.All
az ad app permission add --id $APP_ID --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 230c1aed-a721-4c5d-9cb4-a90514e508ef=Role  # Reports.Read.All
az ad app permission add --id $APP_ID --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 6e472fd1-ad78-48da-a0f0-97ab2c6b769e=Role  # IdentityRiskEvent.Read.All
az ad app permission add --id $APP_ID --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions dc5007c0-2d7d-4c42-879c-2dab87571379=Role  # IdentityRiskyUser.Read.All

# Grant admin consent (REQUIRED — permissions are inactive without this)
az ad app permission admin-consent --id $APP_ID
```

**Grant via Azure Portal:**

1. **Entra ID** > **App registrations** > select your app
2. **API permissions** > **Add a permission** > **Microsoft Graph** > **Application permissions**
3. Search and add all 8 permissions listed above
4. Click **"Grant admin consent for [Tenant Name]"** — each permission must show a green checkmark

##### Required Azure RBAC Roles

The **Reader** and **Security Reader** roles (assigned above) cover all ARM resource checks:

| Azure Resource Provider | Operations | Covered By |
|------------------------|-----------|-----------|
| `Microsoft.Compute/*` | VMs, disks, managed identities | Reader |
| `Microsoft.Network/*` | VNets, NSGs, firewalls, private endpoints | Reader |
| `Microsoft.Storage/*` | Storage accounts, blob encryption | Reader |
| `Microsoft.KeyVault/*` | Key Vault access policies, network rules | Reader |
| `Microsoft.Sql/*` | SQL Server configurations, vulnerability assessments | Reader |
| `Microsoft.Web/*` | App Service certificates, platform versions | Reader |
| `Microsoft.Monitor/*` | Diagnostic settings, Log Analytics | Reader |
| `Microsoft.Authorization/*` | RBAC role assignments, resource locks, policy | Reader |
| `Microsoft.Security/*` | Defender for Cloud, secure score, assessments | Security Reader |
| `Microsoft.RecoveryServices/*` | Backup vaults, encryption, soft delete | Reader |
| `Microsoft.PolicyInsights/*` | Policy compliance monitoring | Reader |
| `Microsoft.Advisor/*` | Unused resource recommendations | Reader |
| `Microsoft.OperationalInsights/*` | Log Analytics workspaces, Sentinel | Reader |
| `Microsoft.SecurityInsights/*` | Microsoft Sentinel, automation rules | Security Reader |

##### Client Credentials

The client provides the following values to Securitybricks for onboarding:

| Value | Source |
|-------|--------|
| Tenant ID | `az account show --query tenantId` |
| Client ID (App ID) | App registration overview page |
| Client Secret | Created in step 3 |
| Subscription ID | `az account show --query id` |

The Securitybricks consultant enters these in the "Add Client" form, selecting **Azure Commercial** or **Azure Government** as the environment.

> **Multi-subscription scope:** Each client entry scans a single Azure subscription. If the client has multiple subscriptions in scope for CMMC, the same App registration can be reused — assign the Reader and Security Reader roles on each additional subscription and create a separate client entry with the same Tenant ID, Client ID, and Client Secret but a different Subscription ID.

#### 5.1.12 Troubleshooting

| Issue | Resolution |
|-------|------------|
| Key Vault name conflict on redeploy | Run `az keyvault list-deleted -o tsv` then `az keyvault purge --name <name>` (only works if purge protection was not enabled). |
| Container image not found | Verify tags: `az acr repository show-tags --name <acr> --repository cmmc-scanner -o tsv`. |
| App crash-looping | Check logs: `az containerapp logs show --name cmmc-scanner-prod-api --resource-group cmmc-scanner-rg --tail 50`. |
| PostgreSQL restricted in region | Use `eastus2` instead of `eastus`; register providers with `az provider register`. |
| CORS errors on frontend | Set `ALLOWED_ORIGINS` env var on the Container App to include the frontend URL. |
| ARM64 image error | Use `--platform linux/amd64` when building; Container Apps only supports amd64. |
| Reused image tag ignored | Always increment the tag (v2, v3...); Container Apps caches old tags. |
| Ingress port mismatch | After first deploy, run `az containerapp ingress update --target-port 8000`. |
| Graph API checks show "manual" with permission error | The service principal is missing one or more Microsoft Graph permissions. See the [Permission Audit](#permission-audit) section below. Most common: `Policy.Read.All` missing, which blocks all Conditional Access checks. |
| Scan detail shows "error" on Security Center checks | Verify the service principal has the **Security Reader** RBAC role on the subscription. Reader alone does not cover `Microsoft.Security/*` operations. |

##### Permission Audit

Use this checklist to verify the service principal has exactly the required permissions (no more, no less).

**Step 1: Check Azure RBAC roles**

```bash
APP_ID="<your-app-client-id>"
SUB_ID="<subscription-id>"
SP_OBJECT_ID=$(az ad sp show --id $APP_ID --query id -o tsv)

# List role assignments
az role assignment list --assignee $SP_OBJECT_ID --scope /subscriptions/$SUB_ID -o table
```

Expected output: exactly **Reader** and **Security Reader** on the subscription scope.

**Step 2: Check Microsoft Graph API permissions**

```bash
# List current Graph permissions
az ad app permission list --id $APP_ID --query "[?resourceAppId=='00000003-0000-0000-c000-000000000000'].resourceAccess[].id" -o tsv
```

Cross-reference with the 8 required permission IDs:

| Permission | GUID | Required |
|---|---|---|
| `Policy.Read.All` | `e2a3a72e-5f79-4c64-b1b1-878b674786c9` | Yes |
| `Directory.Read.All` | `7ab1d382-f21e-4acd-a863-ba3e13f7da61` | Yes |
| `RoleManagement.Read.Directory` | `483bed4a-2ad3-4361-a73b-c83ccdbdc53c` | Yes |
| `User.Read.All` | `df021288-bdef-4463-88db-98f22de89214` | Yes |
| `AuditLog.Read.All` | `b0afded3-3588-46d8-8b3d-9842eff778da` | Yes |
| `Reports.Read.All` | `230c1aed-a721-4c5d-9cb4-a90514e508ef` | Yes |
| `IdentityRiskEvent.Read.All` | `6e472fd1-ad78-48da-a0f0-97ab2c6b769e` | Yes |
| `IdentityRiskyUser.Read.All` | `dc5007c0-2d7d-4c42-879c-2dab87571379` | Yes |

**Step 3: Add missing permissions**

```bash
# Add Policy.Read.All (most commonly missing)
az ad app permission add --id $APP_ID --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions e2a3a72e-5f79-4c64-b1b1-878b674786c9=Role

# Grant admin consent (required after adding permissions)
az ad app permission admin-consent --id $APP_ID
```

**Step 4: Remove unnecessary permissions (least privilege)**

The following permissions are NOT required by the scanner and should be removed if present:

| Permission | Reason to Remove |
|---|---|
| `Mail.ReadWrite` | Scanner never accesses mail |
| `RoleManagement.ReadWrite.Directory` | Only `RoleManagement.Read.Directory` is needed (read-only) |
| `PrivilegedAccess.Read.AzureAD` | Deprecated API, not used by scanner |

```bash
# Remove via Azure Portal:
# Entra ID > App registrations > select app > API permissions >
# click "..." next to unnecessary permission > Remove permission

# Remove duplicate permissions the same way
```

> **Note:** Duplicate permissions (same permission listed twice) are harmless but should be cleaned up. Remove duplicates via the Azure Portal API permissions blade.

---

### 5.2 AWS Commercial (CloudFormation)

#### 5.2.1 Infrastructure Overview

| Component | AWS Service | Purpose |
|-----------|-------------|---------|
| Backend API | ECS Fargate | Runs the FastAPI Docker container |
| Database | RDS PostgreSQL | Stores clients, scans, findings |
| Frontend UI | S3 + CloudFront | Static website hosting with CDN |
| Secrets | Secrets Manager | DB credentials, JWT secret, encryption key |
| Container images | ECR | Stores the Docker image |
| Networking | VPC (2 AZs) | Public/private subnets, NAT Gateway |
| Load Balancer | ALB | HTTPS termination, routing to Fargate |
| Logging | CloudWatch | Container logs and monitoring |

The CloudFormation template provisions the full stack in a single deployment. Secrets (DB password, JWT secret, encryption key) are auto-generated in Secrets Manager.

#### 5.2.2 Prerequisites

- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) installed and configured (`aws configure`)
- An ACM certificate ARN for HTTPS (request via AWS Certificate Manager in the target region)
- IAM permissions to create CloudFormation stacks, ECS clusters, RDS instances, and ECR repositories

#### 5.2.3 Deploy Infrastructure

```bash
aws cloudformation deploy \
  --template-file deploy/aws/cloudformation.yaml \
  --stack-name cmmc-scanner \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    Environment=production \
    CertificateArn=<acm-certificate-arn>
```

#### 5.2.4 Build and Push Docker Image

```bash
# Get ECR repository URI from stack output
ECR_URI=$(aws cloudformation describe-stacks \
  --stack-name cmmc-scanner \
  --query 'Stacks[0].Outputs[?OutputKey==`ECRRepositoryURI`].OutputValue' \
  --output text)

# Login to ECR
aws ecr get-login-password | docker login --username AWS --password-stdin $ECR_URI

# Build and push (use --platform linux/amd64 on Apple Silicon)
docker build --platform linux/amd64 -t $ECR_URI:v1 .
docker push $ECR_URI:v1
```

> **Important:** Run this from the project root directory (where the `Dockerfile` is). Always use `--platform linux/amd64` when building on Apple Silicon — ECS Fargate requires linux/amd64 images.

#### 5.2.5 Upload Frontend to S3

```bash
# Get frontend bucket name from stack output
BUCKET=$(aws cloudformation describe-stacks \
  --stack-name cmmc-scanner \
  --query 'Stacks[0].Outputs[?OutputKey==`FrontendBucketName`].OutputValue' \
  --output text)

# Upload frontend files
aws s3 sync frontend/ s3://$BUCKET/
```

#### 5.2.6 Update ECS Service

```bash
# Force new deployment to pick up the latest image
aws ecs update-service \
  --cluster cmmc-scanner-cluster \
  --service cmmc-scanner-service \
  --force-new-deployment
```

#### 5.2.7 Verify Deployment

```bash
# Get ALB endpoint from stack output
ALB_URL=$(aws cloudformation describe-stacks \
  --stack-name cmmc-scanner \
  --query 'Stacks[0].Outputs[?OutputKey==`ALBEndpoint`].OutputValue' \
  --output text)

# Backend health check
curl https://$ALB_URL/health

# Show endpoints
echo "Backend:  https://$ALB_URL"
echo "Frontend: $(aws cloudformation describe-stacks \
  --stack-name cmmc-scanner \
  --query 'Stacks[0].Outputs[?OutputKey==`CloudFrontURL`].OutputValue' \
  --output text)"
```

> **Note:** Production uses Entra ID SSO for login. Ensure `AZURE_AD_TENANT_ID`, `AZURE_AD_CLIENT_ID`, `AZURE_AD_CLIENT_SECRET`, and `FRONTEND_URL` are set in the ECS task definition environment variables, and the redirect URI `https://<alb-url>/api/auth/callback` is registered in the Entra ID app registration.

#### 5.2.8 Subsequent Deployments

After making code changes, rebuild and push a new image version:

```bash
# Build new version (always increment the tag — never reuse v1, v2, etc.)
docker build --platform linux/amd64 -t $ECR_URI:v2 .
docker push $ECR_URI:v2

# Force ECS to pick up the new image
aws ecs update-service \
  --cluster cmmc-scanner-cluster \
  --service cmmc-scanner-service \
  --force-new-deployment

# Re-upload frontend if changed
aws s3 sync frontend/ s3://$BUCKET/

# Invalidate CloudFront cache if frontend changed
aws cloudfront create-invalidation \
  --distribution-id <distribution-id> \
  --paths "/*"
```

> **Important:** Always use a new tag for each build (v1, v2, v3...). Update the ECS task definition to reference the new tag, then force a new deployment.

#### 5.2.9 Client Onboarding (AWS)

Provide clients with the cross-account role template to grant read-only access.

##### Via CloudFormation (Recommended)

```bash
# Run in the client's AWS account
aws cloudformation deploy \
  --template-file deploy/aws/client-role-template.yaml \
  --stack-name cmmc-scanner-role \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    ScannerAccountId=<securitybricks-aws-account-id> \
    ExternalId=<unique-external-id>
```

This creates a read-only IAM role with SecurityAudit policy and explicit deny on all write operations.

##### Via AWS Console

1. **IAM** > **Roles** > **Create role** > **Another AWS account**
2. Enter the Securitybricks AWS Account ID and check **Require external ID**
3. Attach the **SecurityAudit** managed policy
4. Add an inline policy with the custom permissions below
5. Name the role `CMMCScannerRole` > **Create role**
6. Copy the **Role ARN** from the role summary page

##### Required IAM Permissions

The scanner uses the **SecurityAudit** managed policy plus these additional actions. The CloudFormation template includes all of these. If onboarding manually, create a custom inline policy:

| AWS Service | IAM Actions | CMMC Checks |
|------------|-------------|-------------|
| **IAM** | `iam:GenerateCredentialReport`, `iam:GetCredentialReport`, `iam:GetAccountSummary`, `iam:GetAccountPasswordPolicy`, `iam:ListUsers`, `iam:ListRoles`, `iam:ListPolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListAttachedUserPolicies`, `iam:ListAttachedRolePolicies`, `iam:ListUserPolicies`, `iam:GetUserPolicy`, `iam:ListEntitiesForPolicy`, `iam:ListVirtualMFADevices`, `iam:ListMFADevices`, `iam:ListSAMLProviders`, `iam:ListOpenIDConnectProviders` | Root access keys, MFA, password policy, least privilege, account separation |
| **STS** | `sts:GetCallerIdentity` | Account identity verification |
| **CloudTrail** | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors`, `cloudtrail:GetInsightSelectors` | Audit logging, multi-region trails, log validation |
| **S3** | `s3:GetAccountPublicAccessBlock` | Public access block |
| **KMS** | `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyRotationStatus`, `kms:GetKeyPolicy` | Encryption key rotation, key policies |
| **GuardDuty** | `guardduty:ListDetectors`, `guardduty:GetDetector` | Threat detection enabled |
| **SSM** | `ssm:DescribeInstanceInformation`, `ssm:DescribePatchBaselines`, `ssm:DescribeInstancePatchStates`, `ssm:ListDocuments`, `ssm:GetDocument`, `ssm:ListInventoryEntries` | Patch management, SSM compliance |
| **Config** | `config:DescribeConfigurationRecorders`, `config:DescribeConfigurationRecorderStatus`, `config:DescribeConfigRules`, `config:DescribeDeliveryChannels`, `config:DescribeComplianceByConfigRule` | Configuration monitoring |
| **Security Hub** | `securityhub:DescribeHub`, `securityhub:GetEnabledStandards`, `securityhub:GetFindings` | Security standards compliance |
| **RDS** | `rds:DescribeDBInstances` | Database auto-upgrade |
| **EFS** | `efs:DescribeFileSystems` | Encrypted file systems |
| **Backup** | `backup:ListBackupVaults`, `backup:GetBackupVaultAccessPolicy` | Backup vault policies |
| **Network Firewall** | `network-firewall:ListFirewalls`, `network-firewall:ListFirewallPolicies`, `network-firewall:DescribeFirewallPolicy` | Network boundary protection |
| **Organizations** | `organizations:ListPolicies`, `organizations:DescribePolicy` | SCP guardrails (if applicable) |
| **SSO Admin** | `sso-admin:ListInstances` | Identity Center configuration |
| **CodePipeline** | `codepipeline:ListPipelines`, `codepipeline:GetPipeline` | CI/CD approval gates |
| **CloudWatch** | `cloudwatch:DescribeAlarms`, `cloudwatch:DescribeAnomalyDetectors` | Monitoring alerts |
| **CloudWatch Logs** | `logs:DescribeLogGroups` | Log retention |
| **SNS** | `sns:ListTopics` | Notification topics |
| **ECR** | `ecr:DescribeRepositories` | Container image scanning |
| **ACM** | `acm:ListCertificates` | Certificate management |
| **CloudFront** | `cloudfront:ListDistributions` | CDN security |
| **API Gateway** | `apigateway:GetRestApis` | API security |
| **EventBridge** | `events:ListRules` | Event monitoring |
| **DynamoDB** | `dynamodb:ListTables`, `dynamodb:DescribeTable` | Database encryption |
| **Inspector** | `inspector2:BatchGetAccountStatus`, `inspector2:ListFindings` | Vulnerability scanning |

##### Client Credentials

The client provides the resulting **Role ARN** and **External ID** to Securitybricks for onboarding. The Securitybricks consultant enters these in the "Add Client" form, selecting **AWS Commercial** or **AWS GovCloud** as the environment.

> **Security note:** The External ID prevents the [confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html). Generate a unique External ID per client.

> **Multi-account scope:** Each client entry scans a single AWS account. If the client has multiple AWS accounts in scope for CMMC (e.g. production, staging, shared services), deploy the cross-account role template in each account and create a separate client entry for each.

#### 5.2.10 Troubleshooting

| Issue | Resolution |
|-------|------------|
| Stack creation fails with IAM capability error | Ensure `--capabilities CAPABILITY_IAM` is included in the deploy command. |
| ECR push access denied | Run `aws ecr get-login-password \| docker login --username AWS --password-stdin $ECR_URI` to refresh credentials. |
| ECS tasks fail to start | Check CloudWatch logs: `aws logs get-log-events --log-group-name /ecs/cmmc-scanner --log-stream-name <stream>`. |
| ALB health check failing | Verify the target group health check path is `/health` and the container is listening on port 8000. |
| ARM64 image on Fargate | Use `docker build --platform linux/amd64` when building on Apple Silicon. |
| CloudFront serving stale frontend | Create an invalidation: `aws cloudfront create-invalidation --distribution-id <id> --paths "/*"`. |
| RDS connection refused | Verify the security group allows inbound on port 5432 from the Fargate task security group. |
| Secrets not available to ECS | Ensure the task execution role has `secretsmanager:GetSecretValue` permission for the created secrets. |

---

### 5.3 GCP Commercial (gcloud CLI)

#### 5.3.1 Infrastructure Overview

| Component | GCP Service | Purpose |
|-----------|-------------|---------|
| Backend API | Cloud Run | Runs the FastAPI Docker container (serverless) |
| Database | Cloud SQL (PostgreSQL) | Stores clients, scans, findings |
| Frontend UI | Cloud Storage + Cloud CDN | Static website hosting with CDN |
| Secrets | Secret Manager | DB password, JWT secret, encryption key |
| Container images | Artifact Registry | Stores the Docker image |
| Networking | VPC + Serverless VPC Connector | Private connectivity to Cloud SQL |
| Logging | Cloud Logging | Container logs and monitoring |

Cloud Run is a fully managed serverless container platform that scales to zero when idle and auto-scales under load, making it cost-efficient for assessment workloads that are bursty in nature.

#### 5.3.2 Prerequisites

- [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) (`gcloud` CLI) installed and authenticated
- A GCP billing account linked to the project
- Project Owner or Editor role

#### 5.3.3 Create Project and Enable APIs

```bash
# Set your project ID (replace with your own)
PROJECT_ID="cmmc-scanner-prod"
REGION="us-central1"

# Create project (or use an existing one)
gcloud projects create $PROJECT_ID --name="CMMC Scanner"
gcloud config set project $PROJECT_ID

# Link billing account (required for resource creation)
# gcloud billing accounts list
# gcloud billing projects link $PROJECT_ID --billing-account=<BILLING_ACCOUNT_ID>

# Enable required APIs
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  vpcaccess.googleapis.com \
  cloudbuild.googleapis.com \
  compute.googleapis.com
```

#### 5.3.4 Deploy Cloud SQL (PostgreSQL)

```bash
# Create a Cloud SQL PostgreSQL instance
gcloud sql instances create cmmc-scanner-db \
  --database-version=POSTGRES_15 \
  --tier=db-f1-micro \
  --region=$REGION \
  --storage-size=10GB \
  --storage-auto-increase \
  --no-assign-ip \
  --network=default

# Set the database password
gcloud sql users set-password postgres \
  --instance=cmmc-scanner-db \
  --password='<secure-db-password>'

# Create the application database
gcloud sql databases create cmmc_scanner \
  --instance=cmmc-scanner-db
```

Store secrets in Secret Manager:

```bash
# Create secrets
echo -n '<secure-db-password>' | gcloud secrets create db-password --data-file=-
echo -n '<secure-jwt-secret>' | gcloud secrets create jwt-secret --data-file=-
echo -n '<secure-encryption-key>' | gcloud secrets create encryption-key --data-file=-
```

#### 5.3.5 Build and Push Docker Image to Artifact Registry

```bash
# Create Artifact Registry repository
gcloud artifacts repositories create cmmc-scanner \
  --repository-format=docker \
  --location=$REGION \
  --description="CMMC Scanner container images"

# Build using Cloud Build (no local Docker needed, builds linux/amd64)
gcloud builds submit \
  --tag $REGION-docker.pkg.dev/$PROJECT_ID/cmmc-scanner/cmmc-scanner:v1 \
  .
```

> **Note:** Run this from the project root directory (where the `Dockerfile` is). Cloud Build runs in the cloud and produces linux/amd64 images by default.

#### 5.3.6 Deploy Cloud Run Service

```bash
# Create a Serverless VPC Connector for Cloud SQL access
gcloud compute networks vpc-access connectors create cmmc-connector \
  --region=$REGION \
  --range=10.8.0.0/28

# Get the Cloud SQL connection name
SQL_CONNECTION=$(gcloud sql instances describe cmmc-scanner-db \
  --format='value(connectionName)')

# Deploy to Cloud Run
gcloud run deploy cmmc-scanner-api \
  --image=$REGION-docker.pkg.dev/$PROJECT_ID/cmmc-scanner/cmmc-scanner:v1 \
  --region=$REGION \
  --platform=managed \
  --port=8000 \
  --memory=1Gi \
  --cpu=1 \
  --min-instances=0 \
  --max-instances=3 \
  --vpc-connector=cmmc-connector \
  --add-cloudsql-instances=$SQL_CONNECTION \
  --set-env-vars="ENVIRONMENT=prod" \
  --set-env-vars="DATABASE_URL=postgresql://postgres:<secure-db-password>@/cmmc_scanner?host=/cloudsql/$SQL_CONNECTION" \
  --set-secrets="JWT_SECRET_KEY=jwt-secret:latest" \
  --set-secrets="ENCRYPTION_KEY=encryption-key:latest" \
  --allow-unauthenticated
```

> **Note:** The `--allow-unauthenticated` flag makes the Cloud Run service publicly accessible. The application handles its own authentication via JWT. For additional network-level security, configure Cloud Armor or IAP.

#### 5.3.7 Upload Frontend to Cloud Storage

```bash
# Create a Cloud Storage bucket for the frontend
BUCKET_NAME="${PROJECT_ID}-frontend"
gcloud storage buckets create gs://$BUCKET_NAME \
  --location=$REGION \
  --uniform-bucket-level-access

# Enable public access for static website hosting
gcloud storage buckets update gs://$BUCKET_NAME \
  --web-main-page-suffix=index.html \
  --web-not-found-page=index.html

# Make bucket publicly readable
gcloud storage buckets add-iam-policy-binding gs://$BUCKET_NAME \
  --member=allUsers \
  --role=roles/storage.objectViewer

# Upload frontend files
gcloud storage cp -r frontend/* gs://$BUCKET_NAME/
```

The frontend is accessible at `https://storage.googleapis.com/$BUCKET_NAME/index.html`. For a custom domain with HTTPS and CDN, configure a Cloud CDN-backed external HTTPS load balancer pointing to the bucket.

#### 5.3.8 Verify Deployment

```bash
# Get the Cloud Run service URL
SERVICE_URL=$(gcloud run services describe cmmc-scanner-api \
  --region=$REGION \
  --format='value(status.url)')

# Backend health check
curl $SERVICE_URL/health

# Show endpoints
echo "Backend:  $SERVICE_URL"
echo "Frontend: https://storage.googleapis.com/$BUCKET_NAME/index.html"
```

> **Note:** Update `FRONTEND_URL` and `ALLOWED_ORIGINS` environment variables on the Cloud Run service to match the actual frontend URL. If using Entra ID SSO in production, add `$SERVICE_URL/api/auth/callback` as a redirect URI in the Entra ID app registration.

#### 5.3.9 Subsequent Deployments

```bash
# Build new version (always increment the tag)
gcloud builds submit \
  --tag $REGION-docker.pkg.dev/$PROJECT_ID/cmmc-scanner/cmmc-scanner:v2 \
  .

# Update Cloud Run service
gcloud run deploy cmmc-scanner-api \
  --image=$REGION-docker.pkg.dev/$PROJECT_ID/cmmc-scanner/cmmc-scanner:v2 \
  --region=$REGION

# Re-upload frontend if changed
gcloud storage cp -r frontend/* gs://$BUCKET_NAME/
```

#### 5.3.10 Client Onboarding (GCP)

Each client creates a service account with read-only access on their GCP project and provides the key to Securitybricks:

```bash
# Run in the client's GCP project
PROJECT_ID="<client-project-id>"

# Create a read-only service account
gcloud iam service-accounts create cmmc-scanner-readonly \
  --project=$PROJECT_ID \
  --display-name="CMMC Scanner Read-Only"

# Grant Viewer role on the project
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:cmmc-scanner-readonly@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/viewer"

# Grant Security Reviewer role for deeper security config reads
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:cmmc-scanner-readonly@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/iam.securityReviewer"

# Create and download the service account key
gcloud iam service-accounts keys create sa-key.json \
  --iam-account=cmmc-scanner-readonly@${PROJECT_ID}.iam.gserviceaccount.com
```

The client provides the **service account key JSON file** and **Project ID** to Securitybricks for onboarding. The consultant enters these in the "Add Client" form, selecting **GCP Commercial** or **GCP Assured Workloads** as the environment.

> **Security note:** The `roles/viewer` role provides read-only access. The `roles/iam.securityReviewer` role adds visibility into IAM policies and security configurations needed for CMMC checks. Neither role permits any write operations.

> **Multi-project scope:** Each client entry scans a single GCP project. If the client has multiple projects in scope for CMMC, create a service account in each project and add each as a separate client entry.

#### 5.3.11 Troubleshooting

| Issue | Resolution |
|-------|------------|
| Cloud SQL connection refused from Cloud Run | Ensure the `--add-cloudsql-instances` flag is set and the VPC Connector is in the same region as Cloud SQL. |
| `Permission denied` on Cloud Build | Grant `roles/cloudbuild.builds.builder` to the Cloud Build service account, or enable the Cloud Build API. |
| Cloud Run returns 503 after deploy | Check logs: `gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=cmmc-scanner-api" --limit 50`. |
| Artifact Registry push denied | Run `gcloud auth configure-docker $REGION-docker.pkg.dev` to configure Docker credentials. |
| Cloud Storage bucket not publicly accessible | Verify `allUsers` has `roles/storage.objectViewer` and uniform bucket-level access is enabled. |
| Secret Manager access denied from Cloud Run | Grant `roles/secretmanager.secretAccessor` to the Cloud Run service account. |
| VPC Connector creation fails | Ensure the Serverless VPC Access API is enabled and the IP range (`10.8.0.0/28`) doesn't conflict with existing subnets. |
| Cloud Run cold start timeout | Increase `--memory` to `2Gi` and set `--min-instances=1` to keep one instance warm. |

---

## 6. Architecture

### 6.1 Project Structure

```
CMMC-Scanner/
├── README.md                     # This document
├── Dockerfile                    # Multi-stage container build (python:3.12-slim)
├── config/
│   ├── environments.json         # 6 cloud environment definitions
│   ├── nist_practices.json       # All 110 NIST 800-171 + 17 FAR practices
│   └── checks/                   # Check definitions per CMMC domain (14 JSON files)
│       ├── ac.json               # Access Control (3.1.x)
│       ├── at.json               # Awareness & Training (3.2.x)
│       ├── au.json               # Audit & Accountability (3.3.x)
│       ├── cm.json               # Configuration Management (3.4.x)
│       ├── ia.json               # Identification & Authentication (3.5.x)
│       ├── ir.json               # Incident Response (3.6.x)
│       ├── ma.json               # Maintenance (3.7.x)
│       ├── mp.json               # Media Protection (3.8.x)
│       ├── ps.json               # Personnel Security (3.9.x)
│       ├── pe.json               # Physical Protection (3.10.x)
│       ├── ra.json               # Risk Assessment (3.11.x)
│       ├── ca.json               # Security Assessment (3.12.x)
│       ├── sc.json               # System & Comms Protection (3.13.x)
│       └── si.json               # System & Info Integrity (3.14.x)
├── backend/
│   ├── requirements.txt          # Python dependencies
│   └── app/
│       ├── main.py               # FastAPI entry point (serves /api/docs)
│       ├── api/
│       │   ├── auth.py           # Entra ID SSO + JWT password auth
│       │   ├── clients.py        # Client CRUD + credential verification
│       │   ├── scans.py          # Scan execution, status, and evidence
│       │   └── reports.py        # Report generation, demo, and notifications
│       ├── scanner/
│       │   ├── base.py           # Base scanner interface
│       │   ├── engine.py         # Scan orchestrator
│       │   ├── aws_scanner.py    # AWS checks (boto3)
│       │   ├── azure_scanner.py  # Azure checks (azure-mgmt-*)
│       │   └── gcp_scanner.py    # GCP checks (google-cloud-*)
│       ├── reports/
│       │   ├── html_report.py    # Self-contained HTML report (Jinja2)
│       │   └── xlsx_report.py    # Multi-tab XLSX report (openpyxl)
│       ├── models/
│       │   └── schemas.py        # SQLAlchemy ORM + Pydantic models
│       └── db/
│           └── database.py       # Database connection and session
├── frontend/
│   ├── index.html                # SPA shell with login overlay
│   ├── css/
│   │   └── styles.css            # All styles (Securitybricks branded)
│   ├── js/
│   │   ├── app.js                # Router, auth, and shared utilities
│   │   ├── dashboard.js          # Dashboard view
│   │   ├── clients.js            # Client management view
│   │   ├── scans.js              # Scan execution and detail view
│   │   ├── reports.js            # Reports and scan comparison view
│   │   └── help.js               # Help & documentation view
│   └── assets/
│       └── sb-icon.png           # Securitybricks logo
├── deploy/
│   ├── aws/
│   │   ├── cloudformation.yaml   # AWS infrastructure (ECS Fargate)
│   │   └── client-role-template.yaml  # Client cross-account IAM role
│   └── azure/
│       └── main.bicep            # Azure infrastructure (Container Apps)
├── diagrams/
│   └── cmmc-scanner-architecture.drawio  # Architecture diagrams (2 pages)
└── scripts/
    └── setup.sh                  # Local development setup
```

### 6.2 Technology Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.12, FastAPI, SQLAlchemy |
| Database | PostgreSQL (production) / SQLite (development) |
| Authentication | Microsoft Entra ID SSO (authlib/OIDC), JWT (python-jose), bcrypt (passlib) |
| Cloud SDKs | boto3 (AWS), azure-identity + azure-mgmt-* (Azure), google-cloud-* (GCP) |
| Reports | Jinja2 (HTML), openpyxl (XLSX) |
| Frontend | Vanilla HTML/CSS/JS (no framework, SPA with hash routing) |
| Container | Docker multi-stage build (python:3.12-slim, non-root user) |
| Infrastructure as Code | CloudFormation (AWS), Bicep (Azure) |

### 6.3 Data Model

| Entity | Description | Key Fields |
|--------|-------------|------------|
| **Client** | Organization with cloud credentials | UUID PK, name, environment, cmmc_level, credentials_config (JSON) |
| **Scan** | Single assessment run against a client's environment | UUID PK, client_id FK, status (`pending`/`running`/`completed`/`failed`), summary (JSON) |
| **Finding** | Individual check result | UUID PK, scan_id FK, practice_id, status (`met`/`not_met`/`manual`/`error`), evidence, remediation |

Relationships: Client has many Scans (cascade delete). Scan has many Findings (cascade delete).

### 6.4 Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Flexible deployment model** | Scanner runs on Securitybricks infrastructure or as a local dev instance in the client's environment. Connects to client cloud via cross-account read-only roles. |
| **Scan results are metadata** | Config states, Met/Not-Met statuses, resource ARNs — not CUI. No FedRAMP/CMMC certification needed for the platform. |
| **~71 of 110 practices automated** | Remaining ~39 are policy/process controls marked "Manual Review Required." |
| **HTML + XLSX reports** | Professional, well-formatted, client-facing deliverables suitable for audit. |
| **Scan comparison** | Side-by-side delta reports to track remediation progress between scans. |
| **Triple deployment support** | Azure Commercial (Bicep), AWS Commercial (CloudFormation), or GCP Commercial (gcloud CLI). |
| **Check definitions in JSON** | All check logic is config-driven via `config/checks/*.json`, not hardcoded. |
| **Dual auth modes** | Entra ID SSO for production, password fallback for development. |

---

## 7. License

Internal tool — Securitybricks, Inc. All rights reserved.
