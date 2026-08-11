from enum import Enum
from typing import Dict, Any, List, Optional, Literal
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field, ConfigDict
from app.core.security import sanitize_input_string

class EventType(str, Enum):
    AUTHENTICATION = "auth"
    SSH = "ssh"
    PROCESS = "process"
    NETWORK = "network"
    DNS = "dns"
    FILE = "file"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    WEB_ACCESS = "web_access"

class TelemetryEvent(BaseModel):
    eventId: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:10]}")
    timestamp: str
    host: str
    user: Optional[str] = None
    sourceIp: Optional[str] = None
    destinationIp: Optional[str] = None
    eventType: EventType
    action: str
    status: str  # "SUCCESS", "FAILURE", "DENIED", "ALLOWED"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    isSyntheticLabData: Literal[True] = Field(default=True)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "eventId": "evt-syn-88a91c",
                "timestamp": "2026-08-10T19:30:00Z",
                "host": "web-server-01",
                "user": "root",
                "sourceIp": "192.168.100.99",
                "destinationIp": "10.0.1.10",
                "eventType": "ssh",
                "action": "FAILED_LOGIN",
                "status": "FAILURE",
                "metadata": {"port": 22, "auth_method": "password", "raw": "sshd[1482]: Failed password for root"},
                "isSyntheticLabData": True
            }
        }
    )

class EventFilter(BaseModel):
    host: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    event_type: Optional[EventType] = None
    action: Optional[str] = None
    status: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=500)

class GroundTruth(BaseModel):
    scenarioId: str
    attackName: str
    description: str
    expectedTechniques: List[str]  # e.g. ["T1110", "T1078"]
    affectedHost: str
    attackerIp: str
    targetUser: str
    startTime: str
    endTime: str
    groundTruthEventIds: List[str]

class AttackScenario(BaseModel):
    id: str
    name: str
    description: str
    difficulty: str  # "EASY", "MEDIUM", "HARD"
    groundTruth: GroundTruth  # Hidden evaluation metadata

class EvaluationReport(BaseModel):
    scenarioId: str
    evaluatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    f1Score: float = Field(ge=0.0, le=1.0)
    falsePositivesCount: int
    falseNegativesCount: int
    evidenceCoveragePercent: float = Field(ge=0.0, le=100.0)
    matchedTechniques: List[str]
    missingTechniques: List[str]
    isAccurate: bool
    summaryNotes: str

class ScenarioResult(BaseModel):
    scenarioId: str
    attackName: str
    detected: bool
    precision: float
    recall: float
    f1Score: float
    falsePositiveRate: float
    falseNegativeRate: float
    evidenceCoveragePercent: float
    toolCallsCount: int
    stepsCount: int
    timeToFindingMs: float

class OverallLabMetrics(BaseModel):
    detectionRatePercent: float = Field(ge=0.0, le=100.0)
    averagePrecision: float = Field(ge=0.0, le=1.0)
    averageRecall: float = Field(ge=0.0, le=1.0)
    falsePositiveRatePercent: float = Field(ge=0.0, le=100.0)
    falseNegativeRatePercent: float = Field(ge=0.0, le=100.0)
    evidenceCoveragePercent: float = Field(ge=0.0, le=100.0)
    toolEfficiencyPercent: float = Field(ge=0.0, le=100.0)
    averageInvestigationSteps: float
    averageToolCalls: float
    averageTimeToFindingMs: float

class EvaluationRun(BaseModel):
    runId: str = Field(default_factory=lambda: f"eval-run-{uuid.uuid4().hex[:8]}")
    model: str = Field(default="mock-ai-provider-v1")
    configuration: Dict[str, Any] = Field(default_factory=lambda: {"mode": "AUTONOMOUS", "max_iterations": 5, "max_tool_calls": 10})
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    overallMetrics: OverallLabMetrics
    scenarioResults: List[ScenarioResult]
