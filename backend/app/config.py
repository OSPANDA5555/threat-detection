import os
import json
from typing import List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "Autonomous Threat-Hunting Copilot"
    VERSION: str = "1.1.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    API_V1_STR: str = "/api/v1"

    # Tool Gateway Limits & Safety Caps
    # NOTE: MAX_TOOL_RESULT_COUNT must stay <= 500 — EventFilter caps at 500
    # (see test_telemetry.py::test_result_limit_caps).
    MAX_TOOL_RESULT_COUNT: int = Field(default=500, le=500)
    TOOL_TIMEOUT_SECONDS: float = Field(default=5.0, gt=0, le=60)
    ENFORCE_READ_ONLY: bool = True

    # Autonomous hunting safety bounds (overridable via .env)
    MAX_AUTONOMY_ITERATIONS: int = Field(default=5, ge=1, le=10)
    MAX_TOOL_CALLS_PER_HUNT: int = Field(default=10, ge=1, le=50)
    MAX_CONSECUTIVE_TOOL_ERRORS: int = Field(default=3, ge=1, le=10)
    HUNT_TIMEOUT_SECONDS: float = Field(default=300.0, gt=0, le=900)
    MAX_ACTIVE_HUNTS: int = Field(default=200, ge=10, le=2000)

    # Input bounds
    MAX_QUESTION_CHARS: int = Field(default=2000, ge=100, le=10000)
    MAX_STRING_ARG_CHARS: int = Field(default=500, ge=50, le=5000)

    # CORS — comma-separated list or JSON array in .env (CORS_ORIGINS).
    # Defaults to local dev origins; "*" must never be combined with credentials.
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173,http://localhost:8000,http://127.0.0.1:8000"

    # Rate limiting defaults for the HTTP middleware
    RATE_LIMIT_MAX_REQUESTS: int = Field(default=150, ge=1, le=10000)
    RATE_LIMIT_WINDOW_SECONDS: int = Field(default=60, ge=1, le=3600)

    # Adversarial report cache TTL (seconds) — avoids re-running the full
    # 8-hunt suite on every GET.
    ADVERSARIAL_CACHE_TTL_SECONDS: int = Field(default=300, ge=0, le=3600)

    # Authentication & Security Settings
    JWT_SECRET_KEY: str = Field(default="threat-hunting-copilot-dev-jwt-secret-2026")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=1440, ge=5, le=43200)
    SOC_AGENT_API_KEY: str = Field(default="SOC_AGENT_SECRET_KEY")
    MAX_UPLOAD_SIZE_MB: int = Field(default=25, ge=1, le=200)
    DEMO_MODE: bool = False

    # Optional external LLM provider (default: deterministic embedded engine)
    LLM_PROVIDER: str = "embedded"

    model_config = SettingsConfigDict(case_sensitive=True, env_file=".env", extra="ignore")

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _coerce_cors_origins(cls, v):
        # Accept JSON arrays (as in .env.example) as well as CSV strings.
        if isinstance(v, list):
            return ",".join(v)
        if isinstance(v, str) and v.strip().startswith("["):
            try:
                return ",".join(json.loads(v))
            except (ValueError, TypeError):
                return v
        return v

    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

settings = Settings()

