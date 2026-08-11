from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field, field_validator, ConfigDict
from app.core.security import sanitize_input_string

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class MitreAttackMapping(BaseModel):
    tactic: str = Field(description="MITRE ATT&CK Tactic (e.g., Credential Access, Privilege Escalation)")
    technique_name: str = Field(description="MITRE ATT&CK Technique Name (e.g., Brute Force: Password Spray)")
    technique_id: str = Field(description="MITRE ATT&CK Technique ID (e.g., T1110.001)")
    description: str = Field(description="Behavioral explanation grounded in evidence")
    evidence_ids: List[str] = Field(default_factory=list)

class Finding(BaseModel):
    id: str = Field(default_factory=lambda: f"fnd-{uuid.uuid4().hex[:10]}")
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    evidenceIds: List[str] = Field(min_length=1, description="List of evidence IDs backing this finding")
    affectedHosts: List[str] = Field(default_factory=list)
    sourceIps: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list, description="Chronological key events")
    mitreTechniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK Technique IDs (e.g. T1110.001)")
    mitreDetails: List[MitreAttackMapping] = Field(default_factory=list, description="Structured ATT&CK mappings grounded in evidence")
    recommendation: str

    @field_validator("title", "description", "recommendation")
    @classmethod
    def sanitize_text(cls, v):
        if isinstance(v, str):
            return sanitize_input_string(v)
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "fnd-9a2c419",
                "title": "SSH Credential Access Attempt via Brute Force",
                "severity": "HIGH",
                "confidence": 0.92,
                "description": "High frequency authentication failures detected against Linux host srv-prod-linux01.",
                "evidenceIds": ["evd-8f92a11b01"],
                "affectedHosts": ["srv-prod-linux01"],
                "sourceIps": ["192.168.1.105"],
                "timeline": [{"time": "2026-08-10T19:30:00Z", "event": "Brute force surge start"}],
                "mitreTechniques": ["T1110.001"],
                "mitreDetails": [
                    {
                        "tactic": "Credential Access",
                        "technique_name": "Brute Force: Password Spray",
                        "technique_id": "T1110.001",
                        "description": "25 authentication failures observed from IP 192.168.1.105",
                        "evidence_ids": ["evd-8f92a11b01"]
                    }
                ],
                "recommendation": "Block source IP 192.168.1.105 at edge firewall and enforce fail2ban."
            }
        }
    )
