"""
Authentication API — dual-mode auth:
  - Dev (ENVIRONMENT != prod): password-based login (admin/admin)
  - Prod (ENVIRONMENT == prod): Microsoft Entra ID SSO via OIDC

Both modes issue the same application JWT for API access.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production-9f8a7b6c5d4e3f2a1b0c")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 hours
ENVIRONMENT = os.getenv("ENVIRONMENT", "dev")

AZURE_AD_TENANT_ID = os.getenv("AZURE_AD_TENANT_ID", "")
AZURE_AD_CLIENT_ID = os.getenv("AZURE_AD_CLIENT_ID", "")
AZURE_AD_CLIENT_SECRET = os.getenv("AZURE_AD_CLIENT_SECRET", "")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:8080")

IS_SSO_MODE = ENVIRONMENT == "prod" and AZURE_AD_TENANT_ID and AZURE_AD_CLIENT_ID

# ---------------------------------------------------------------------------
# Password auth (dev mode only)
# ---------------------------------------------------------------------------

DEV_USERS = {
    "admin": {
        "username": "admin",
        "hashed_password": None,  # set below
        "full_name": "System Administrator",
        "role": "admin",
    }
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__truncate_error=True)
DEV_USERS["admin"]["hashed_password"] = pwd_context.hash("admin")

# ---------------------------------------------------------------------------
# OAuth / OIDC setup (authlib) — only when SSO vars are set
# ---------------------------------------------------------------------------

oauth = OAuth()

if AZURE_AD_TENANT_ID and AZURE_AD_CLIENT_ID:
    oauth.register(
        name="entra",
        client_id=AZURE_AD_CLIENT_ID,
        client_secret=AZURE_AD_CLIENT_SECRET,
        server_metadata_url=(
            f"https://login.microsoftonline.com/{AZURE_AD_TENANT_ID}"
            "/v2.0/.well-known/openid-configuration"
        ),
        client_kwargs={
            "scope": "openid email profile",
        },
    )

# ---------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------

security = HTTPBearer(auto_error=False)

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60


class UserResponse(BaseModel):
    username: str
    full_name: str
    role: str
    email: Optional[str] = None


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def _create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def _verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def _authenticate_user(username: str, password: str) -> Optional[dict]:
    user = DEV_USERS.get(username)
    if user and _verify_password(password, user["hashed_password"]):
        return user
    return None


# ---------------------------------------------------------------------------
# Dependency — get current user from JWT
# ---------------------------------------------------------------------------

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> dict:
    """
    Extract and validate JWT from the Authorization header.
    Returns user dict or raises 401.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "username": username,
        "full_name": payload.get("name", username),
        "role": payload.get("role", "assessor"),
        "email": payload.get("email", ""),
    }


# ---------------------------------------------------------------------------
# Auth config endpoint — tells frontend which mode to use
# ---------------------------------------------------------------------------

@router.get("/config")
async def auth_config():
    """Return auth mode so the frontend shows the right login UI."""
    return {"mode": "sso" if IS_SSO_MODE else "password"}


# ---------------------------------------------------------------------------
# Password login (dev mode) — POST /api/auth/login
# ---------------------------------------------------------------------------

@router.post("/login", response_model=TokenResponse)
async def login_password(request: LoginRequest):
    """Authenticate with username/password."""
    user = _authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = _create_access_token(data={
        "sub": user["username"],
        "name": user["full_name"],
        "role": user["role"],
        "email": "",
        "auth_method": "password",
    })
    return TokenResponse(access_token=token)


# ---------------------------------------------------------------------------
# SSO login — GET /api/auth/login
# ---------------------------------------------------------------------------

@router.get("/login")
async def login_sso(request: Request):
    """Redirect user to Microsoft Entra ID for authentication."""
    if not AZURE_AD_TENANT_ID or not AZURE_AD_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SSO not configured. Set AZURE_AD_TENANT_ID and AZURE_AD_CLIENT_ID.",
        )
    callback_url = str(request.url_for("auth_callback"))
    return await oauth.entra.authorize_redirect(request, callback_url)


@router.get("/callback", name="auth_callback")
async def callback(request: Request):
    """Handle Entra ID callback: exchange code for tokens, issue app JWT."""
    try:
        token = await oauth.entra.authorize_access_token(request)
    except Exception as e:
        error_msg = str(e) or "Authentication failed"
        return RedirectResponse(
            url=f"{FRONTEND_URL}/#sso-error?message={urlencode({'m': error_msg})}"
        )

    userinfo = token.get("userinfo", {})

    username = (
        userinfo.get("preferred_username")
        or userinfo.get("email")
        or userinfo.get("sub", "unknown")
    )
    full_name = userinfo.get("name", username)
    email = userinfo.get("email") or userinfo.get("preferred_username", "")
    oid = userinfo.get("oid", "")

    app_token = _create_access_token(
        data={
            "sub": username,
            "name": full_name,
            "email": email,
            "oid": oid,
            "role": "assessor",
            "auth_method": "sso",
        }
    )

    return RedirectResponse(url=f"{FRONTEND_URL}/#sso-callback?token={app_token}")


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@router.post("/logout")
async def logout(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
):
    """Return the appropriate logout action based on how the user logged in."""
    auth_method = "password"
    if credentials:
        try:
            payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
            auth_method = payload.get("auth_method", "password")
        except JWTError:
            pass

    if auth_method == "sso" and AZURE_AD_TENANT_ID:
        logout_url = (
            f"https://login.microsoftonline.com/{AZURE_AD_TENANT_ID}"
            f"/oauth2/v2.0/logout?"
            f"post_logout_redirect_uri={FRONTEND_URL}"
        )
    else:
        logout_url = FRONTEND_URL
    return {"logout_url": logout_url, "auth_method": auth_method}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Return the currently authenticated user's info."""
    return UserResponse(
        username=current_user["username"],
        full_name=current_user["full_name"],
        role=current_user["role"],
        email=current_user.get("email"),
    )
