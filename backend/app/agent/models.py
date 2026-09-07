from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import time

class AgentRegistration(BaseModel):
    agent_id: str
    hostname: str
    platform: str = "Linux"
    os_release: Optional[str] = None
    ip_address: Optional[str] = None
    agent_version: str = "1.0.0"

class AgentStatus(BaseModel):
    agent_id: str
    hostname: str
    platform: str = "Linux"
    ip_address: Optional[str] = None
    agent_version: str = "1.0.0"
    status: str = "ONLINE"  # ONLINE, OFFLINE, DEGRADED
    registered_at: str
    last_seen: str
    events_per_sec: float = 0.0
    total_events_sent: int = 0
    latest_sequence: int = 0

class AgentEventBatch(BaseModel):
    agent_id: str
    hostname: str
    agent_version: str = "1.0.0"
    timestamp: str
    sequence_number: int
    events: List[Dict[str, Any]] = Field(default_factory=list)

class AgentIngestionResponse(BaseModel):
    status: str = "success"
    agent_id: str
    events_ingested: int
    latest_sequence: int
    server_time: str
