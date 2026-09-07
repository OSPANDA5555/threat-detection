from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ConfigDict
from enum import Enum

class StreamConnectionState(str, Enum):
    CONNECTED = "CONNECTED"
    RECONNECTING = "RECONNECTING"
    DISCONNECTED = "DISCONNECTED"

class StreamedEvent(BaseModel):
    """
    Standardized payload for real-time streamed cybersecurity events.
    Includes global sequence number, event ID, and normalized event telemetry.
    """
    type: str = "event"
    sequence: int = Field(..., description="Monotonically increasing event sequence counter")
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: str = Field(..., description="Original event timestamp without modification")
    source_type: str = Field(default="generic", description="Telemetry source classification")
    source: Optional[str] = None
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    command: Optional[str] = None
    event_type: str = Field(default="security_event")
    action: Optional[str] = None
    status: Optional[str] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    severity: str = "INFO"
    label: str = "BENIGN"
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)

class StreamStats(BaseModel):
    connected_clients: int = 0
    total_events_streamed: int = 0
    latest_sequence: int = 0
    events_per_second: float = 0.0
    buffer_size: int = 0
