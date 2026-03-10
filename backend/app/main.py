"""
FedRAMP Cloud Compliance Scanner — FastAPI application entry point.

Provides REST API for managing clients, running compliance scans, and
generating Met/Not-Met reports across AWS GovCloud, Azure Government,
and GCP Assured Workloads.
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root before any other imports read env vars
_env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(_env_path)

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.api import auth, clients, reports, scans
from app.api.auth import get_current_user
from app.db.database import Base, SessionLocal, engine

logger = logging.getLogger(__name__)


def _apply_missing_columns():
    """Add any columns defined in ORM models but missing from the database.

    SQLAlchemy's create_all() creates missing tables but does NOT alter
    existing ones.  This lightweight migration checks each table for
    missing columns and issues ALTER TABLE ADD COLUMN as needed.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    for table_name, table_obj in Base.metadata.tables.items():
        if not inspector.has_table(table_name):
            continue  # create_all() will handle it
        existing = {col["name"] for col in inspector.get_columns(table_name)}
        for col in table_obj.columns:
            if col.name not in existing:
                col_type = col.type.compile(engine.dialect)
                stmt = f"ALTER TABLE {table_name} ADD COLUMN {col.name} {col_type}"
                with engine.begin() as conn:
                    conn.execute(text(stmt))
                logger.info("Added missing column %s.%s (%s)", table_name, col.name, col_type)


def _widen_narrow_columns():
    """Widen VARCHAR columns that are too small for full NIST practice text.

    PostgreSQL enforces VARCHAR limits strictly. This checks the actual
    column size and issues ALTER TABLE ... TYPE VARCHAR(n) if needed.
    SQLite ignores VARCHAR lengths, so this is a no-op there.
    """
    from sqlalchemy import inspect, text

    if engine.dialect.name != "postgresql":
        return

    _fixes = [
        ("findings", "check_name", 500),
    ]

    inspector = inspect(engine)
    for table_name, col_name, target_len in _fixes:
        if not inspector.has_table(table_name):
            continue
        cols = {c["name"]: c for c in inspector.get_columns(table_name)}
        col_info = cols.get(col_name)
        if col_info is None:
            continue
        current_len = getattr(col_info.get("type"), "length", None)
        if current_len is not None and current_len < target_len:
            with engine.begin() as conn:
                conn.execute(text(
                    f"ALTER TABLE {table_name} ALTER COLUMN {col_name} TYPE VARCHAR({target_len})"
                ))
            logger.info("Widened %s.%s from VARCHAR(%s) to VARCHAR(%s)",
                        table_name, col_name, current_len, target_len)


def _cleanup_orphaned_scans():
    """Mark any 'running' or 'pending' scans as 'failed' on startup.

    A fresh process cannot have legitimately running scans, so these are
    leftovers from a previous crash or restart.
    """
    from datetime import datetime, timezone

    from app.models.schemas import Scan

    db = SessionLocal()
    try:
        orphans = db.query(Scan).filter(Scan.status.in_(["running", "pending"])).all()
        for scan in orphans:
            scan.status = "failed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.summary = {"error": "Scan interrupted — server restarted before completion."}
            logger.warning("Marked orphaned scan %s as failed", scan.id)
        if orphans:
            db.commit()
    except Exception as e:
        logger.error("Failed to clean up orphaned scans: %s", e)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create database tables and perform startup housekeeping."""
    Base.metadata.create_all(bind=engine)
    _apply_missing_columns()
    _widen_narrow_columns()
    _cleanup_orphaned_scans()
    yield


app = FastAPI(
    title="FedRAMP Cloud Compliance Scanner",
    description=(
        "Automated compliance scanning for CSPs across "
        "AWS, Azure, and GCP cloud environments. "
        "Validates FedRAMP Low/Moderate/High controls and generates Met/Not-Met reports."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# ---------------------------------------------------------------------------
# Session Middleware — required by authlib for OIDC state/nonce storage.
# Must be added BEFORE CORSMiddleware.
# ---------------------------------------------------------------------------
SESSION_SECRET = os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production-9f8a7b6c5d4e3f2a1b0c")
ENVIRONMENT = os.getenv("ENVIRONMENT", "dev")

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=ENVIRONMENT in ("prod", "staging"),
    same_site="lax",
)

# ---------------------------------------------------------------------------
# CORS — restrict origins; defaults allow localhost for dev
# ---------------------------------------------------------------------------
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:8080,http://localhost:8000,http://localhost:3000",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in ALLOWED_ORIGINS],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# API Routers
# ---------------------------------------------------------------------------
app.include_router(auth.router)
app.include_router(clients.router, dependencies=[Depends(get_current_user)])
app.include_router(scans.router, dependencies=[Depends(get_current_user)])
# Reports router left unprotected so demo endpoints remain accessible
app.include_router(reports.router)

# ---------------------------------------------------------------------------
# Static file serving — mount frontend directory
# ---------------------------------------------------------------------------
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
if FRONTEND_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="static")


# ---------------------------------------------------------------------------
# Root redirect
# ---------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
async def root():
    """Redirect root URL to the frontend."""
    return RedirectResponse(url="/static/index.html")


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/health", tags=["system"])
async def health_check():
    """Simple health check endpoint."""
    return {"status": "ok", "version": app.version}
