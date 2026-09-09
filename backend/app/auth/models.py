from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field
import time

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    AGENT = "AGENT"
    DEMO_USER = "DEMO_USER"

class AuthUser(BaseModel):
    user_id: str
    username: str
    email: Optional[str] = None
    role: UserRole
    tenant_id: str = "default-org"
    is_active: bool = True
    created_at: float = Field(default_factory=time.time)

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: AuthUser

class TokenPayload(BaseModel):
    sub: str
    username: str
    role: UserRole
    tenant_id: str
    exp: int
    iat: int
    nbf: Optional[int] = None
