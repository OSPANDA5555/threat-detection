import pytest
import asyncio
from app.schemas.hunt import Hunt, ExecutionMode, HuntStatus, HypothesisState
from app.hunting.engine import AutonomousHuntingEngine

def test_assisted_mode_approval_gate():
    engine = AutonomousHuntingEngine()
    hunt = asyncio.run(engine.execute_hunt(
        question="Find evidence of suspicious SSH activity.",
        mode=ExecutionMode.ASSISTED
    ))

    # In Assisted mode, the engine must pause at step 1 awaiting analyst approval
    assert hunt.mode == ExecutionMode.ASSISTED
    assert hunt.status == HuntStatus.AWAITING_APPROVAL
    assert hunt.pendingApproval is not None
    assert hunt.pendingApproval.step_number == 1
    assert hunt.pendingApproval.tool_name == "search_authentication_events"
    assert len(hunt.auditTrail) > 0
    assert "Assisted Mode approval requested" in hunt.auditTrail[0].ai_decision

def test_resume_assisted_mode_approval():
    engine = AutonomousHuntingEngine()
    
    # 1. Start Assisted Hunt (Pauses)
    hunt_paused = asyncio.run(engine.execute_hunt(
        question="Find evidence of suspicious SSH activity.",
        mode=ExecutionMode.ASSISTED
    ))
    assert hunt_paused.status == HuntStatus.AWAITING_APPROVAL

    # 2. Analyst approves step 1
    hunt_resumed = asyncio.run(engine.resume_assisted_hunt(
        hunt_id=hunt_paused.id,
        approved=True
    ))

    assert hunt_resumed.pendingApproval is None or hunt_resumed.status in [HuntStatus.AWAITING_APPROVAL, HuntStatus.COMPLETED]
    assert len(hunt_resumed.executionTrace) > 0
    assert hunt_resumed.executionTrace[0].step_number == 1

def test_autonomous_mode_execution_within_limits():
    engine = AutonomousHuntingEngine()
    hunt = asyncio.run(engine.execute_hunt(
        question="Find evidence of suspicious SSH activity.",
        mode=ExecutionMode.AUTONOMOUS
    ))

    assert hunt.mode == ExecutionMode.AUTONOMOUS
    assert hunt.status == HuntStatus.COMPLETED
    assert hunt.currentIteration <= 5
    assert hunt.toolCallsExecuted <= 10
    assert len(hunt.auditTrail) > 0

def test_audit_trail_reproducibility():
    engine = AutonomousHuntingEngine()
    hunt = asyncio.run(engine.execute_hunt(
        question="Find evidence of suspicious SSH activity.",
        mode=ExecutionMode.AUTONOMOUS
    ))

    assert len(hunt.auditTrail) >= len(hunt.executionTrace)
    for entry in hunt.auditTrail:
        assert entry.huntId == hunt.id
        assert entry.ai_decision != ""
        assert entry.tool_selected != ""
        assert isinstance(entry.arguments, dict)
        assert entry.next_decision != ""

def test_specific_claim_formatting_grounding():
    engine = AutonomousHuntingEngine()
    hunt = asyncio.run(engine.execute_hunt(
        question="Find evidence of suspicious SSH activity.",
        mode=ExecutionMode.AUTONOMOUS
    ))

    assert len(hunt.findings) > 0
    finding = hunt.findings[0]
    
    # Verify strict requirement: "Suspicious activity detected because [evidence]"
    assert "Suspicious" in finding.description
    assert "because" in finding.description
    assert len(finding.evidenceIds) > 0
    assert "Something suspicious happened." not in finding.description
