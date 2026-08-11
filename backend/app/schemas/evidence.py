from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field, field_validator, ConfigDict
from app.core.security import sanitize_input_string

class EvidenceSource(str, Enum):
    AUTHENTICATION = "auth"
    NETWORK = "network"
    DNS = "dns"
    PROCESS = "process"
    FILE = "file"
    ALERT = "alert"
    HOST_TIMELINE = "host_timeline"

class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: f"evd-{uuid.uuid4().hex[:10]}")
    source: EvidenceSource
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    host: Optional[str] = None
    user: Optional[str] = None
    sourceIp: Optional[str] = None
    destinationIp: Optional[str] = None
    eventType: str
    rawReference: str
    normalizedData: Dict[str, Any] = Field(default_factory=dict)
    relevance: str = Field(description="Explanation of why this evidence is relevant to the hunt hypothesis")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)

    @field_validator("host", "user", "eventType", "rawReference", "relevance")
    @classmethod
    def sanitize_strings(cls, v):
        if isinstance(v, str):
            return sanitize_input_string(v)
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "evd-8f92a11b01",
                "source": "auth",
                "timestamp": "2026-08-10T19:30:00Z",
                "host": "srv-prod-linux01",
                "user": "root",
                "sourceIp": "192.168.1.105",
                "destinationIp": "10.0.0.12",
                "eventType": "SSH_FAILED_PASSWORD",
                "rawReference": "auth.log:line_1482",
                "normalizedData": {"attempts": 14, "port": 22},
                "relevance": "14 failed SSH root password attempts within 30 seconds",
                "confidence": 0.95
            }
        }
    )

