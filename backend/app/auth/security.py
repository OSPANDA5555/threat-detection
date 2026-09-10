import hmac
import hashlib
import base64
import json
import time
import secrets
from typing import Optional, Dict, Any, List, Callable
from fastapi import Request, HTTPException, status, Depends, Header, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.config import settings
from app.auth.models import UserRole, AuthUser, TokenPayload

# HTTP Bearer Scheme (auto_error=False allows falling back to API-Key or Query Tokens cleanly)
import os

security_bearer = HTTPBearer(auto_error=False)

def _get_user_password_hash(user_env_key: str, default_pwd: str) -> str:
    hash_val = os.environ.get(f"{user_env_key}_PASSWORD_HASH")
    if hash_val:
        return hash_val.strip()
    pwd = os.environ.get(f"{user_env_key}_PASSWORD", default_pwd)
    return hashlib.sha256(pwd.encode("utf-8")).hexdigest()

# Seeded default user credentials for enterprise demo operations (overridable via env)
DEFAULT_USERS: Dict[str, Dict[str, Any]] = {
    "admin": {
        "user_id": "usr-admin-01",
        "username": "admin",
        "email": "admin@threat-copilot.internal",
        "role": UserRole.ADMIN,
        "tenant_id": "soc-org-primary",
        "password_hash": _get_user_password_hash("ADMIN", "AdminSecret2026!"),
        "is_active": True
    },
    "analyst": {
        "user_id": "usr-analyst-01",
        "username": "analyst",
        "email": "analyst@threat-copilot.internal",
        "role": UserRole.ANALYST,
        "tenant_id": "soc-org-primary",
        "password_hash": _get_user_password_hash("ANALYST", "AnalystHunt2026!"),
        "is_active": True
    },
    "analyst2": {
        "user_id": "usr-analyst-02",
        "username": "analyst2",
        "email": "analyst2@threat-copilot.internal",
        "role": UserRole.ANALYST,
        "tenant_id": "soc-org-secondary",
        "password_hash": _get_user_password_hash("ANALYST2", "Analyst2Secret2026!"),
        "is_active": True
    }
}



def _b64_encode(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64_decode(data: str) -> bytes:
    """URL-safe base64 decode with padding restoration."""
    rem = len(data) % 4
    if rem > 0:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data.encode("utf-8"))


def create_access_token(
    user_id: str,
    username: str,
    role: UserRole,
    tenant_id: str = "default-org",
    expires_in_minutes: Optional[int] = None
) -> str:
    """
    Creates a signed HS256 JWT access token.
    """
    secret_key = getattr(settings, "JWT_SECRET_KEY", "threat-hunting-copilot-dev-jwt-secret-2026")
    exp_minutes = expires_in_minutes or getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 1440)
    
    now = int(time.time())
    payload = {
        "sub": user_id,
        "username": username,
        "role": role.value if isinstance(role, UserRole) else str(role),
        "tenant_id": tenant_id,
        "iat": now,
        "nbf": now,
        "exp": now + (exp_minutes * 60)
    }

    header = {"alg": "HS256", "typ": "JWT"}
    
    header_b64 = _b64_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_token(token: str) -> Optional[TokenPayload]:
    """
    Verifies a JWT token using constant-time signature comparison and expiration check.
    Returns TokenPayload if valid, None if invalid or expired.
    """
    if not token or not isinstance(token, str):
        return None

    parts = token.split(".")
    if len(parts) != 3:
        return None

    header_b64, payload_b64, sig_b64 = parts
    secret_key = getattr(settings, "JWT_SECRET_KEY", "threat-hunting-copilot-dev-jwt-secret-2026")

    try:
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected_sig = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
        actual_sig = _b64_decode(sig_b64)

        # Constant-time comparison to prevent timing attacks
        if not secrets.compare_digest(expected_sig, actual_sig):
            return None

        payload_bytes = _b64_decode(payload_b64)
        payload_dict = json.loads(payload_bytes.decode("utf-8"))

        now = int(time.time())
        if payload_dict.get("exp", 0) < now:
            return None
        if payload_dict.get("nbf", 0) > now:
            return None

        return TokenPayload(
            sub=payload_dict["sub"],
            username=payload_dict["username"],
            role=UserRole(payload_dict["role"]),
            tenant_id=payload_dict.get("tenant_id", "default-org"),
            exp=payload_dict["exp"],
            iat=payload_dict["iat"],
            nbf=payload_dict.get("nbf")
        )
    except Exception:
        return None


def authenticate_user(username: str, password: str) -> Optional[AuthUser]:
    """
    Validates username and password against configured users.
    Uses SHA-256 and constant-time digest comparison.
    """
    user_record = DEFAULT_USERS.get(username)
    if not user_record or not user_record.get("is_active"):
        return None

    provided_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    expected_hash = user_record["password_hash"]

    if secrets.compare_digest(provided_hash, expected_hash):
        return AuthUser(
            user_id=user_record["user_id"],
            username=user_record["username"],
            email=user_record.get("email"),
            role=user_record["role"],
            tenant_id=user_record.get("tenant_id", "default-org"),
            is_active=user_record.get("is_active", True)
        )
    return None


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    token_param: Optional[str] = Query(None, alias="token"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key")
) -> AuthUser:
    """
    FastAPI dependency that extracts and validates the caller's identity.
    Accepts:
    1. HTTP Bearer Token (Authorization: Bearer <jwt>)
    2. Query parameter token (?token=<jwt>)
    3. X-API-Key Header (maps to Agent or Admin service identity)
    """
    token = None
    if credentials and credentials.credentials:
        token = credentials.credentials
    elif token_param:
        token = token_param

    # 1. Check Bearer / JWT Token
    if token:
        payload = verify_token(token)
        if payload:
            return AuthUser(
                user_id=payload.sub,
                username=payload.username,
                role=payload.role,
                tenant_id=payload.tenant_id,
                is_active=True
            )

    # 2. Check X-API-Key or Agent API Key
    if x_api_key:
        configured_agent_key = getattr(settings, "SOC_AGENT_API_KEY", "SOC_AGENT_SECRET_KEY")
        if secrets.compare_digest(x_api_key, configured_agent_key):
            return AuthUser(
                user_id="agent-service-account",
                username="telemetry-agent",
                role=UserRole.AGENT,
                tenant_id="soc-org-primary",
                is_active=True
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )


def require_role(allowed_roles: List[UserRole]) -> Callable:
    """
    Dependency factory enforcing role-based authorization (RBAC).
    """
    async def role_checker(current_user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Insufficient privileges for this operation"
            )
        return current_user
    return role_checker


# Pre-built standard dependency shortcuts
require_admin = require_role([UserRole.ADMIN])
require_analyst_or_admin = require_role([UserRole.ANALYST, UserRole.ADMIN])


async def require_agent_or_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    token_param: Optional[str] = Query(None, alias="token")
) -> AuthUser:
    """
    Dedicated dependency for telemetry ingestion endpoints.
    Allows AGENT role, API Key, or ADMIN role.
    """
    # 1. Try standard user authentication
    try:
        user = await get_current_user(credentials=credentials, token_param=token_param, x_api_key=x_api_key)
        if user.role in [UserRole.AGENT, UserRole.ANALYST, UserRole.ADMIN]:
            return user
    except HTTPException:
        pass

    # 2. Try raw Bearer token matching configured SOC_AGENT_API_KEY directly
    if credentials and credentials.credentials:
        configured_agent_key = getattr(settings, "SOC_AGENT_API_KEY", "SOC_AGENT_SECRET_KEY")
        if secrets.compare_digest(credentials.credentials, configured_agent_key):
            return AuthUser(
                user_id="agent-service-account",
                username="telemetry-agent",
                role=UserRole.AGENT,
                tenant_id="soc-org-primary",
                is_active=True
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials for telemetry ingestion",
        headers={"WWW-Authenticate": "Bearer"}
    )
