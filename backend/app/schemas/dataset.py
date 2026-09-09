from typing import Dict, Any, List, Optional, Literal
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field, ConfigDict

class NormalizedEvent(BaseModel):
    """
    Normalized internal cybersecurity event schema.
    Strictly adheres to the standardized field names.
    Values are null (None) when the original dataset does not provide them (no invented values).
    """
    timestamp: Optional[str] = Field(default=None, description="ISO-8601 formatted timestamp of the event")
    source_ip: Optional[str] = Field(default=None, description="Source IPv4 or IPv6 address")
    source_port: Optional[int] = Field(default=None, description="Source port (1-65535)")
    destination_ip: Optional[str] = Field(default=None, description="Destination IPv4 or IPv6 address")
    destination_port: Optional[int] = Field(default=None, description="Destination port (1-65535)")
    protocol: Optional[str] = Field(default=None, description="Network transport protocol (e.g. TCP, UDP, ICMP)")
    event_type: str = Field(default="network_flow", description="Categorized event type (network_flow, auth, process, alert)")
    action: Optional[str] = Field(default=None, description="Action taken (ALLOWED, DENIED, SUCCESS, FAILURE)")
    username: Optional[str] = Field(default=None, description="Associated user account name")
    hostname: Optional[str] = Field(default=None, description="Endpoint or host identifier")
    process: Optional[str] = Field(default=None, description="Process executable name or command")
    bytes_in: Optional[int] = Field(default=None, description="Total incoming bytes / forward packet length")
    bytes_out: Optional[int] = Field(default=None, description="Total outgoing bytes / backward packet length")
    duration: Optional[float] = Field(default=None, description="Flow or event duration in seconds")
    label: str = Field(default="BENIGN", description="Dataset label (BENIGN, attack category, or attack subtype)")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Original un-normalized raw event data")
    source: str = Field(default="dataset_import", description="Origin source tag (e.g. cic-ids2017, pcap, json_events)")

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "timestamp": "2017-07-07T08:30:00Z",
                "source_ip": "192.168.10.5",
                "source_port": 49152,
                "destination_ip": "192.168.10.50",
                "destination_port": 22,
                "protocol": "TCP",
                "event_type": "network_flow",
                "action": "ALLOWED",
                "username": None,
                "hostname": "web-server-01",
                "process": None,
                "bytes_in": 1284,
                "bytes_out": 4210,
                "duration": 0.042,
                "label": "SSH-Patator",
                "raw_data": {"Flow Duration": 42000, "Label": "SSH-Patator"},
                "source": "cic-ids2017"
            }
        }
    )

class ValidationErrorRecord(BaseModel):
    row_index: int
    field: str
    error_message: str
    raw_value: Optional[str] = None
    raw_snippet: Optional[str] = None

class DatasetMetadata(BaseModel):
    dataset_id: str = Field(default_factory=lambda: f"ds-{uuid.uuid4().hex[:10]}")
    dataset_name: str
    file_name: str
    import_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_events: int = 0
    benign_events: int = 0
    malicious_events: int = 0
    source_format: str = "CSV_NETWORK_FLOW"  # CSV_NETWORK_FLOW, JSON_EVENTS, PCAP
    available_labels: Dict[str, int] = Field(default_factory=dict)
    attack_categories: Dict[str, int] = Field(default_factory=dict)
    malformed_records_count: int = 0
    errors: List[ValidationErrorRecord] = Field(default_factory=list)
    owner_id: Optional[str] = Field(default="system-demo", description="Owner user ID for BOLA access control")
    tenant_id: Optional[str] = Field(default="soc-org-primary", description="Tenant organization ID")

class DatasetImportReport(BaseModel):
    dataset: DatasetMetadata
    sample_events: List[NormalizedEvent] = Field(default_factory=list)
    status: str = "SUCCESS"
    message: str = "Dataset imported and normalized successfully."

class DatasetQueryFilter(BaseModel):
    label: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    is_malicious: Optional[bool] = None
    offset: int = 0
    limit: int = Field(default=50, ge=1, le=500)
