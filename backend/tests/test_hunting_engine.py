import pytest
import asyncio
from app.schemas.hunt import Hunt, HypothesisState, StructuredHuntPlan, HuntPlanStep
from app.schemas.finding import Finding, Severity
from app.schemas.evidence import Evidence, EvidenceSource
from app.hunting.engine import AutonomousHuntingEngine
from app.hunting.grounding import EvidenceGroundingEngine

def test_structured_hunt_plan_validation():
    plan = StructuredHuntPlan(
        hypothesis="Attacker SSH password spray",
        objectives=["Search failures", "Isolate IP"],
        steps=[
            HuntPlanStep(
                step_number=1,
                title="Search Auth Failures",
                description="Query auth failures",
                tool_suggested="search_authentication_events"
            )
        ],
        requiredTools=["search_authentication_events"],
        expectedEvidence=["Failed auth logs"],
        stopConditions=["Confirmed threat"]
    )
    assert plan.hypothesis == "Attacker SSH password spray"
    assert len(plan.steps) == 1
    assert plan.requiredTools[0] == "search_authentication_events"

def test_grounding_valid_evidence():
    evd = Evidence(
        id="evd-grounded-01",
        source=EvidenceSource.AUTHENTICATION,
        timestamp="2026-08-10T19:30:00Z",
        host="web-server-01",
        user="root",
        sourceIp="192.168.100.99",
        eventType="SSH_FAIL",
        rawReference="ref",
        relevance="Failed root login",
        confidence=0.9
    )
    finding = Finding(
        title="SSH Brute Force",
        severity=Severity.HIGH,
        confidence=0.9,
        description="SSH failure",
        evidenceIds=["evd-grounded-01"],
        affectedHosts=["web-server-01"],
        sourceIps=["192.168.100.99"],
        recommendation="Block IP"
    )

    is_grounded, err, _ = EvidenceGroundingEngine.validate_finding_grounding(finding, [evd])
    assert is_grounded is True
    assert err is None

def test_grounding_detects_hallucinated_ip():
    evd = Evidence(
        id="evd-grounded-01",
        source=EvidenceSource.AUTHENTICATION,
        timestamp="2026-08-10T19:30:00Z",
        host="web-server-01",
        user="root",
        sourceIp="10.0.1.50",
        eventType="SSH_FAIL",
        rawReference="ref",
        relevance="Failed root login",
        confidence=0.9
    )
    finding = Finding(
        title="SSH Brute Force",
        severity=Severity.HIGH,
        confidence=0.9,
        description="SSH failure",
        evidenceIds=["evd-grounded-01"],
        affectedHosts=["web-server-01"],
        sourceIps=["199.199.199.199"],  # Hallucinated IP not in evidence!
        recommendation="Block IP"
    )

    is_grounded, err, _ = EvidenceGroundingEngine.validate_finding_grounding(finding, [evd])
    assert is_grounded is False
    assert "Hallucination Detected" in err
    assert "199.199.199.199" in err

def test_grounding_detects_non_existent_evidence_id():
    evd = Evidence(
        id="evd-grounded-01",
        source=EvidenceSource.AUTHENTICATION,
        timestamp="2026-08-10T19:30:00Z",
        host="web-server-01",
        user="root",
        sourceIp="10.0.1.50",
        eventType="SSH_FAIL",
        rawReference="ref",
        relevance="Failed root login",
        confidence=0.9
    )
    finding = Finding(
        title="SSH Brute Force",
        severity=Severity.HIGH,
        confidence=0.9,
        description="SSH failure",
        evidenceIds=["evd-fake-999"],  # Non-existent evidence ID!
        affectedHosts=["web-server-01"],
        sourceIps=["10.0.1.50"],
        recommendation="Block IP"
    )

    is_grounded, err, _ = EvidenceGroundingEngine.validate_finding_grounding(finding, [evd])
    assert is_grounded is False
    assert "evd-fake-999" in err

def test_autonomous_hunting_engine_execution():
    engine = AutonomousHuntingEngine()
    hunt = asyncio.run(engine.execute_hunt("Find evidence of suspicious SSH activity."))

    assert hunt.question == "Find evidence of suspicious SSH activity."
    assert hunt.structuredPlan is not None
    assert hunt.hypothesisState in [HypothesisState.SUPPORTED, HypothesisState.REFUTED, HypothesisState.INCONCLUSIVE]
    assert hunt.currentIteration <= 5
    assert len(hunt.executionTrace) > 0
    assert len(hunt.evidence) > 0
    assert len(hunt.findings) > 0
