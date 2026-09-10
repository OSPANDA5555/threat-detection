from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator
import time

MAX_EVENT_PAYLOAD_BYTES = 64 * 1024  # 64 KB per individual event

class AgentRegistration(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_\-\.]{1,128}$")
    hostname: str = Field(..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_\-\.]{1,128}$")
    platform: str = Field(default="Linux", max_length=64)
    os_release: Optional[str] = Field(default=None, max_length=128)
    ip_address: Optional[str] = Field(default=None, max_length=64)
    agent_version: str = Field(default="1.0.0", max_length=32)

class AgentStatus(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128)
    hostname: str = Field(..., min_length=1, max_length=128)
    platform: str = Field(default="Linux", max_length=64)
    ip_address: Optional[str] = Field(default=None, max_length=64)
    agent_version: str = Field(default="1.0.0", max_length=32)
    status: str = "ONLINE"  # ONLINE, OFFLINE, DEGRADED
    registered_at: str
    last_seen: str
    events_per_sec: float = 0.0
    total_events_sent: int = 0
    latest_sequence: int = 0

class AgentEventBatch(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_\-\.]{1,128}$")
    hostname: str = Field(..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_\-\.]{1,128}$")
    agent_version: str = Field(default="1.0.0", max_length=32)
    timestamp: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), max_length=64)
    sequence_number: int = Field(..., ge=0)
    events: List[Dict[str, Any]] = Field(default_factory=list, max_length=1000)

    @field_validator("events")
    @classmethod
    def validate_individual_events(cls, events_list):
        import json
        for idx, ev in enumerate(events_list):
            if not isinstance(ev, dict):
                raise ValueError(f"Event at index {idx} must be a dictionary object.")
            # Check serialized size limit per event (64 KB)
            ev_str = json.dumps(ev)
            if len(ev_str.encode("utf-8")) > MAX_EVENT_PAYLOAD_BYTES:
                raise ValueError(f"Event at index {idx} exceeds maximum allowed size of 64KB.")
        return events_list


class AgentIngestionResponse(BaseModel):
    status: str = "success"
    agent_id: str
    events_ingested: int
    latest_sequence: int
    server_time: str
