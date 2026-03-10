"""
Clients API — CRUD operations for CSP client records.

Each client represents a cloud service provider with an environment that
will be scanned for FedRAMP compliance.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.schemas import (
    Client,
    ClientCreate,
    ClientList,
    ClientResponse,
    ClientUpdate,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/clients", tags=["clients"])


# ---------------------------------------------------------------------------
# POST / — Create a new client
# ---------------------------------------------------------------------------
@router.post("/", response_model=ClientResponse, status_code=status.HTTP_201_CREATED)
def create_client(payload: ClientCreate, db: Session = Depends(get_db)):
    """Register a new CSP client."""
    client = Client(
        name=payload.name,
        environment=payload.environment,
        fedramp_baseline=payload.fedramp_baseline,
        credentials_config=payload.credentials_config,
    )
    db.add(client)
    db.commit()
    db.refresh(client)
    return client


# ---------------------------------------------------------------------------
# POST /verify — Test cloud credentials before saving
# ---------------------------------------------------------------------------

class VerifyRequest(BaseModel):
    environment: str
    credentials_config: dict


@router.post("/verify")
def verify_credentials(payload: VerifyRequest):
    """Test cloud connection without saving anything."""
    env = payload.environment
    creds = payload.credentials_config

    try:
        if env in ("aws_commercial", "aws_govcloud"):
            import boto3

            role_arn = creds.get("role_arn", "")
            external_id = creds.get("external_id", "")
            region = creds.get("region", "us-east-1")

            if not role_arn:
                raise ValueError("Role ARN is required")

            sts = boto3.client("sts", region_name=region)
            params = {
                "RoleArn": role_arn,
                "RoleSessionName": "fedramp-verify-session",
                "DurationSeconds": 900,
            }
            if external_id:
                params["ExternalId"] = external_id

            response = sts.assume_role(**params)
            account_id = response["AssumedRoleUser"]["Arn"].split(":")[4]
            return {"status": "ok", "message": f"Connected to AWS account {account_id}"}

        elif env in ("azure_commercial", "azure_government"):
            from azure.identity import ClientSecretCredential
            from azure.mgmt.resource import ResourceManagementClient

            tenant_id = creds.get("tenant_id", "")
            client_id = creds.get("client_id", "")
            client_secret = creds.get("client_secret", "")
            subscription_id = creds.get("subscription_id", "")

            if not all([tenant_id, client_id, client_secret, subscription_id]):
                raise ValueError("All Azure credential fields are required")

            credential = ClientSecretCredential(tenant_id, client_id, client_secret)
            rm_client = ResourceManagementClient(credential, subscription_id)
            # List one resource group to verify
            rgs = list(rm_client.resource_groups.list())
            return {"status": "ok", "message": f"Connected to Azure subscription ({len(rgs)} resource groups)"}

        elif env in ("gcp_commercial", "gcp_assured_workloads"):
            from google.cloud import resource_manager_v3
            from google.oauth2 import service_account

            sa_key = creds.get("service_account_key", {})
            project_id = creds.get("project_id", "")

            if not sa_key or not project_id:
                raise ValueError("Service account key and project ID are required")

            credentials = service_account.Credentials.from_service_account_info(sa_key)
            client = resource_manager_v3.ProjectsClient(credentials=credentials)
            project = client.get_project(name=f"projects/{project_id}")
            return {"status": "ok", "message": f"Connected to GCP project {project.display_name}"}

        else:
            raise ValueError(f"Unsupported environment: {env}")

    except Exception as e:
        logger.warning("Credential verification failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


# ---------------------------------------------------------------------------
# GET / — List all clients
# ---------------------------------------------------------------------------
@router.get("/", response_model=ClientList)
def list_clients(db: Session = Depends(get_db)):
    """Return all registered clients."""
    clients = db.query(Client).order_by(Client.created_at.desc()).all()
    return ClientList(
        clients=[ClientResponse.model_validate(c) for c in clients],
        total=len(clients),
    )


# ---------------------------------------------------------------------------
# GET /{client_id} — Get a single client
# ---------------------------------------------------------------------------
@router.get("/{client_id}", response_model=ClientResponse)
def get_client(client_id: str, db: Session = Depends(get_db)):
    """Return a specific client by ID."""
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")
    return client


# ---------------------------------------------------------------------------
# PUT /{client_id} — Update a client
# ---------------------------------------------------------------------------
@router.put("/{client_id}", response_model=ClientResponse)
def update_client(client_id: str, payload: ClientUpdate, db: Session = Depends(get_db)):
    """Update an existing client's details."""
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(client, field, value)

    client.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(client)
    return client


# ---------------------------------------------------------------------------
# DELETE /{client_id} — Delete a client and all associated scans
# ---------------------------------------------------------------------------
@router.delete("/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_client(client_id: str, db: Session = Depends(get_db)):
    """Delete a client and cascade-delete all associated scans and findings."""
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    db.delete(client)
    db.commit()
    return None
