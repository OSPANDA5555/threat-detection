from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime

class DetectionAlert(BaseModel):
    id: str
    detection: str
    severity: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float = 0.90
    tactic: str
    technique: str
    technique_id: str
    timestamp: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    evidenceEventIds: List[str] = Field(default_factory=list)
    reasoning: str

class AttackGraphNode(BaseModel):
    id: str
    type: str  # IP, USER, HOST, PROCESS, STAGE, FILE
    label: str
    value: str
    stage: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list)

class AttackGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: str
    evidence_ids: List[str] = Field(default_factory=list)

class AttackGraph(BaseModel):
    nodes: List[AttackGraphNode] = Field(default_factory=list)
    edges: List[AttackGraphEdge] = Field(default_factory=list)

class ActiveIncident(BaseModel):
    incident_id: str
    title: str
    status: str = "ACTIVE"
    severity: str = "HIGH"
    confidence: float = 0.85
    start_time: str
    last_seen: str
    affected_hosts: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    detections: List[DetectionAlert] = Field(default_factory=list)
    evidence_event_ids: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    attack_graph: AttackGraph = Field(default_factory=AttackGraph)

class EvaluationMetrics(BaseModel):
    total_labeled_events: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    accuracy: float = 0.0
    is_statistically_significant: bool = False
    notice: str = "Insufficient labeled events (< 10) for statistically significant evaluation metrics."
