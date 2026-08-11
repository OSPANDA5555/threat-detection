from enum import Enum
from typing import List, Optional, Dict, Any, Literal
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field, field_validator, ConfigDict
from app.core.security import sanitize_input_string
from .evidence import Evidence
from .finding import Finding

class HuntStatus(str, Enum):
    INITIALIZED = "INITIALIZED"
    PLANNING = "PLANNING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    CORRELATING = "CORRELATING"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class HypothesisState(str, Enum):
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"

class ExecutionMode(str, Enum):
    ASSISTED = "ASSISTED"
    AUTONOMOUS = "AUTONOMOUS"

class HuntPlanStep(BaseModel):
    step_number: int
    title: str
    description: str
    tool_suggested: str
    status: str = Field(default="PENDING")  # "PENDING", "AWAITING_APPROVAL", "COMPLETED", "REJECTED", "SKIPPED"

class StructuredHuntPlan(BaseModel):
    hypothesis: str
    objectives: List[str] = Field(min_length=1)
    steps: List[HuntPlanStep] = Field(min_length=1)
    requiredTools: List[str] = Field(min_length=1)
    expectedEvidence: List[str] = Field(default_factory=list)
    stopConditions: List[str] = Field(default_factory=list)

class ExecutionTraceStep(BaseModel):
    step_number: int
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resultCount: int = 0
    evidenceIds: List[str] = Field(default_factory=list)
    duration_ms: float = 0.0
    error: Optional[str] = None

class PendingToolApproval(BaseModel):
    approval_id: str = Field(default_factory=lambda: f"appr-{uuid.uuid4().hex[:8]}")
    step_number: int
    tool_name: str
    arguments: Dict[str, Any]
    reasoning: str

class HuntAutonomyLimits(BaseModel):
    max_iterations: int = 5
    max_tool_calls: int = 10
    max_events_per_tool_call: int = 1000
    max_timeout_seconds: float = 300.0
    max_consecutive_errors: int = 3

class AuditTrailEntry(BaseModel):
    audit_id: str = Field(default_factory=lambda: f"aud-tr-{uuid.uuid4().hex[:8]}")
    huntId: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ai_decision: str
    tool_selected: str
    arguments: Dict[str, Any]
    result_count: int
    evidence_ids: List[str]
    next_decision: str

class Hunt(BaseModel):
    id: str = Field(default_factory=lambda: f"hunt-{uuid.uuid4().hex[:10]}")
    question: str = Field(description="Original analyst threat-hunting question")
    hypothesis: Optional[str] = Field(default=None, description="Formulated hunting hypothesis")
    hypothesisState: HypothesisState = Field(default=HypothesisState.INCONCLUSIVE)
    mode: ExecutionMode = Field(default=ExecutionMode.AUTONOMOUS)
    pendingApproval: Optional[PendingToolApproval] = None
    toolCallsExecuted: int = 0
    currentIteration: int = Field(default=1, ge=1, le=5)
    maxIterations: Literal[5] = Field(default=5)
    autonomyLimits: HuntAutonomyLimits = Field(default_factory=HuntAutonomyLimits)
    status: HuntStatus = Field(default=HuntStatus.INITIALIZED)
    createdAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    structuredPlan: Optional[StructuredHuntPlan] = None
    huntPlan: List[HuntPlanStep] = Field(default_factory=list)
    executionTrace: List[ExecutionTraceStep] = Field(default_factory=list)
    auditTrail: List[AuditTrailEntry] = Field(default_factory=list)
    toolsUsed: List[str] = Field(default_factory=list)
    evidence: List[Evidence] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    mitreTechniques: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)

    @field_validator("question")
    @classmethod
    def sanitize_question(cls, v):
        return sanitize_input_string(v)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "hunt-a1b2c3d4e5",
                "question": "Find evidence of suspicious SSH activity.",
                "hypothesis": "An attacker may have attempted credential-based access against an internal Linux host.",
                "hypothesisState": "SUPPORTED",
                "mode": "AUTONOMOUS",
                "toolCallsExecuted": 3,
                "currentIteration": 1,
                "maxIterations": 5,
                "status": "COMPLETED",
                "createdAt": "2026-08-10T19:30:00Z",
                "updatedAt": "2026-08-10T19:32:00Z",
                "toolsUsed": ["search_authentication_events"],
                "evidence": [],
                "findings": [],
                "confidence": 0.85,
                "mitreTechniques": ["T1110.001"],
                "recommendations": ["Audit SSH access logs"]
            }
        }
    )



