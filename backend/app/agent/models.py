from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import time

class AgentRegistration(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128)
    hostname: str = Field(..., min_length=1, max_length=128)
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
    agent_id: str = Field(..., min_length=1, max_length=128)
    hostname: str = Field(..., min_length=1, max_length=128)
    agent_version: str = Field(default="1.0.0", max_length=32)
    timestamp: str = Field(..., max_length=64)
    sequence_number: int = Field(..., ge=0)
    events: List[Dict[str, Any]] = Field(default_factory=list, max_length=1000)

class AgentIngestionResponse(BaseModel):
    status: str = "success"
    agent_id: str
    events_ingested: int
    latest_sequence: int
    server_time: str
