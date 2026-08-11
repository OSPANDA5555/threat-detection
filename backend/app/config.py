import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "Autonomous Threat-Hunting Copilot"
    VERSION: str = "1.0.0-phase1"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    API_V1_STR: str = "/api/v1"
    
    # Tool Gateway Limits & Safety Caps
    MAX_TOOL_RESULT_COUNT: int = 500
    TOOL_TIMEOUT_SECONDS: float = 5.0
    ENFORCE_READ_ONLY: bool = True
    
    model_config = SettingsConfigDict(case_sensitive=True)

settings = Settings()

