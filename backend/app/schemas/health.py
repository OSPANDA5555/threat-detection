from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

class SubsystemHealth(BaseModel):
    name: str
    status: str  # OK, DEGRADED, OFFLINE
    message: str
    metrics: Dict[str, Any] = Field(default_factory=dict)

class ComprehensiveHealthReport(BaseModel):
    overall_status: str  # HEALTHY, DEGRADED, UNHEALTHY
    timestamp: str
    version: str
    backend: SubsystemHealth
    database: SubsystemHealth
    event_stream: SubsystemHealth
    detection_engine: SubsystemHealth
    ai_investigator: SubsystemHealth
    connected_agents: SubsystemHealth
