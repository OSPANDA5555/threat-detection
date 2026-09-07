from enum import Enum
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import uuid
import hashlib
import json
from pydantic import BaseModel, Field, ConfigDict

class SourceType(str, Enum):
    NETWORK_FLOW = "network_flow"
    LINUX_AUTH = "linux_auth"
    LINUX_AUDIT = "linux_audit"
    WEB_LOG = "web_log"
    DNS = "dns"
    FIREWALL = "firewall"
    WINDOWS_SYSMON = "windows_sysmon"
    ALERT = "alert"
    GENERIC = "generic"

class SecurityEvent(BaseModel):
    """
    Canonical cybersecurity event representation used uniformly across
    investigation engine, indicator graph, evidence grounding, and evaluation lab.
    Strictly preserves raw data and never invents values for missing fields (uses None/null).
    """
    id: str = Field(default_factory=lambda: f"sec-evt-{uuid.uuid4().hex[:12]}")
    timestamp: Optional[str] = Field(default=None, description="ISO-8601 UTC timestamp")
    source_type: SourceType = Field(default=SourceType.GENERIC, description="Standardized source taxonomy category")
    source: Optional[str] = Field(default=None, description="Originating log source name (e.g. auth.log, audit.log, nginx, coredns, iptables)")
    hostname: Optional[str] = Field(default=None, description="Target or reporting host identifier")
    source_ip: Optional[str] = Field(default=None, description="Validated source IPv4 or IPv6 address")
    source_port: Optional[int] = Field(default=None, description="Source port (0-65535)")
    destination_ip: Optional[str] = Field(default=None, description="Validated destination IPv4 or IPv6 address")
    destination_port: Optional[int] = Field(default=None, description="Destination port (0-65535)")
    protocol: Optional[str] = Field(default=None, description="Transport protocol (TCP, UDP, ICMP, etc.)")
    username: Optional[str] = Field(default=None, description="User account identity")
    process_name: Optional[str] = Field(default=None, description="Process executable name")
    process_id: Optional[int] = Field(default=None, description="Process ID (PID)")
    command: Optional[str] = Field(default=None, description="Command line string or executed statement")
    event_type: str = Field(default="security_event", description="Fine-grained event type (e.g. SSH_FAILED_PASSWORD, EXECVE, DNS_QUERY)")
    action: Optional[str] = Field(default=None, description="Action taken (ALLOWED, DENIED, SUCCESS, FAILURE, BLOCK)")
    status: Optional[str] = Field(default=None, description="Outcome status (SUCCESS, FAILURE, ERROR)")
    bytes_in: Optional[int] = Field(default=None, description="Incoming byte length")
    bytes_out: Optional[int] = Field(default=None, description="Outgoing byte length")
    severity: Optional[str] = Field(default=None, description="Severity rating (INFO, LOW, MEDIUM, HIGH, CRITICAL)")
    label: str = Field(default="BENIGN", description="Dataset or alert classification label")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Original un-normalized raw log payload")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Extracted contextual metadata")

    @classmethod
    def generate_stable_id(cls, source: str, timestamp: Optional[str], raw_content: str) -> str:
        """Generates a stable, reproducible event ID based on event source, time, and content hash."""
        hash_seed = f"{source}:{timestamp or ''}:{raw_content}"
        digest = hashlib.sha256(hash_seed.encode("utf-8", errors="ignore")).hexdigest()[:12]
        return f"sec-evt-{digest}"

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "id": "sec-evt-8f912a10b4c2",
                "timestamp": "2026-08-10T19:30:15Z",
                "source_type": "linux_auth",
                "source": "auth.log",
                "hostname": "web-server-01",
                "source_ip": "192.168.100.99",
                "source_port": 49152,
                "destination_ip": "10.0.1.10",
                "destination_port": 22,
                "protocol": "TCP",
                "username": "root",
                "process_name": "sshd",
                "process_id": 1482,
                "command": None,
                "event_type": "SSH_FAILED_PASSWORD",
                "action": "FAILURE",
                "status": "FAILURE",
                "bytes_in": None,
                "bytes_out": None,
                "severity": "HIGH",
                "label": "SSH-Patator",
                "raw_data": {"raw": "sshd[1482]: Failed password for root from 192.168.100.99 port 49152 ssh2"},
                "metadata": {"auth_method": "password", "pam_service": "sshd"}
            }
        }
    )

class NormalizationResult(BaseModel):
    """Report returned after parsing a batch of raw logs through the adapter pipeline."""
    total_records: int = 0
    successful_events: int = 0
    malformed_records: int = 0
    source_type: SourceType = SourceType.GENERIC
    events: List[SecurityEvent] = Field(default_factory=list)
    errors: List[Dict[str, Any]] = Field(default_factory=list)
