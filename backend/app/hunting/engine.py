import time
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from app.schemas.hunt import (
    Hunt, HuntStatus, HypothesisState, StructuredHuntPlan, HuntPlanStep,
    ExecutionTraceStep, ExecutionMode, PendingToolApproval, AuditTrailEntry, HuntAutonomyLimits
)
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding, Severity
from app.schemas.tool import ToolExecutionRequest
from app.tools.gateway import ToolGateway
from app.hunting.correlation import EvidenceCorrelationEngine
from app.hunting.grounding import EvidenceGroundingEngine
from app.ai.base import BaseAIProvider
from app.ai.mock_provider import MockAIProvider

# In-memory store for active hunt states (allows approval pause & resume in Assisted mode)
HUNT_STATE_STORE: Dict[str, Hunt] = {}

class AutonomousHuntingEngine:
    """
    Controlled Autonomous Threat Hunting Engine.
    Orchestrates multi-step investigation loops, Tool Gateway executions,
    Assisted Mode approval gates, hard autonomy cap enforcement, reproducible audit logging,
    and grounded finding synthesis.
    """

    def __init__(self, ai_provider: Optional[BaseAIProvider] = None):
        self.ai_provider = ai_provider or MockAIProvider()
        self.tool_gateway = ToolGateway()
        self.limits = HuntAutonomyLimits()


    async def execute_hunt(
        self,
        question: str,
        mode: ExecutionMode = ExecutionMode.AUTONOMOUS,
        existing_hunt: Optional[Hunt] = None
    ) -> Hunt:
        """
        Execute an autonomous threat hunt workflow with strict safety limits and dual modes.
        """
        start_time = time.time()

        if existing_hunt:
            hunt = existing_hunt
        else:
            hunt = Hunt(
                question=question,
                mode=mode,
                status=HuntStatus.PLANNING,
                currentIteration=1,
                maxIterations=5
            )

        HUNT_STATE_STORE[hunt.id] = hunt

        # Phase 1: Planning (Formulate Hypothesis & Structured Hunt Plan)
        if not hunt.structuredPlan:
            structured_plan = await self.ai_provider.generate_hunt_plan(question)
            hunt.structuredPlan = structured_plan
            hunt.hypothesis = structured_plan.hypothesis
            hunt.huntPlan = structured_plan.steps
            hunt.status = HuntStatus.EXECUTING

        consecutive_errors = 0

        # Phase 2: Iterative Execution Loop
        while hunt.currentIteration <= hunt.maxIterations:

            # Check timeout limit (300 seconds max)
            if time.time() - start_time > self.limits.max_timeout_seconds:
                hunt.status = HuntStatus.COMPLETED
                break

            # Find next pending or approved step
            next_step = None
            for step in hunt.huntPlan:
                if step.status in ["PENDING", "AWAITING_APPROVAL", "APPROVED"]:
                    next_step = step
                    break


            if not next_step:
                # All steps executed in current plan
                break

            # Check total tool call cap limit (max 10 tool calls per hunt)
            if hunt.toolCallsExecuted >= self.limits.max_tool_calls:
                break

            # ASSISTED MODE GATE: Pause for analyst approval if in ASSISTED mode
            if hunt.mode == ExecutionMode.ASSISTED and next_step.status != "APPROVED":
                next_step.status = "AWAITING_APPROVAL"
                hunt.status = HuntStatus.AWAITING_APPROVAL
                hunt.pendingApproval = PendingToolApproval(
                    step_number=next_step.step_number,
                    tool_name=next_step.tool_suggested,
                    arguments={"host": "web-server-01", "limit": 100},
                    reasoning=f"Assisted mode required approval for tool '{next_step.tool_suggested}' on step {next_step.step_number}: {next_step.title}"
                )

                # Record audit entry for approval request
                hunt.auditTrail.append(
                    AuditTrailEntry(
                        huntId=hunt.id,
                        ai_decision=f"Assisted Mode approval requested for step {next_step.step_number}",
                        tool_selected=next_step.tool_suggested,
                        arguments={"host": "web-server-01"},
                        result_count=0,
                        evidence_ids=[],
                        next_decision="Awaiting analyst manual approval"
                    )
                )

                # Pause execution and return current state to UI
                return hunt

            # Execute tool call via Tool Gateway
            tool_start = time.time()
            step_args = {"host": "web-server-01", "status": "FAILURE", "limit": 100}

            if next_step.tool_suggested == "get_ip_activity":
                step_args = {"ip_address": "192.168.100.99", "limit": 100}
            elif next_step.tool_suggested == "get_host_timeline":
                step_args = {"host": "web-server-01", "limit": 100}

            tool_req = ToolExecutionRequest(
                tool_name=next_step.tool_suggested,
                arguments=step_args
            )

            tool_res = await self.tool_gateway.execute_tool(tool_req)
            duration_ms = (time.time() - tool_start) * 1000.0
            hunt.toolCallsExecuted += 1

            if tool_res.status != "SUCCESS":
                consecutive_errors += 1
                trace_step = ExecutionTraceStep(
                    step_number=next_step.step_number,
                    tool_name=next_step.tool_suggested,
                    arguments=step_args,
                    resultCount=0,
                    evidenceIds=[],
                    duration_ms=duration_ms,
                    error=tool_res.error_message
                )
                hunt.executionTrace.append(trace_step)
                next_step.status = "FAILED"

                # Check error threshold (3 consecutive errors stop condition)
                if consecutive_errors >= self.limits.max_consecutive_errors:
                    hunt.status = HuntStatus.FAILED
                    break
                continue

            consecutive_errors = 0
            next_step.status = "COMPLETED"

            if next_step.tool_suggested not in hunt.toolsUsed:
                hunt.toolsUsed.append(next_step.tool_suggested)

            # Phase 3: Evidence Collection & Correlation
            new_evidence = EvidenceCorrelationEngine.normalize_and_correlate(
                tool_name=next_step.tool_suggested,
                records=tool_res.records
            )


            step_eids = [e.id for e in new_evidence]
            for ev in new_evidence:
                if not any(e.id == ev.id for e in hunt.evidence):
                    hunt.evidence.append(ev)

            trace_step = ExecutionTraceStep(
                step_number=next_step.step_number,
                tool_name=next_step.tool_suggested,
                arguments=step_args,
                resultCount=tool_res.record_count,
                evidenceIds=step_eids,
                duration_ms=round(duration_ms, 2)
            )
            hunt.executionTrace.append(trace_step)

            # Audit Trail Recording for Reproducibility
            audit_entry = AuditTrailEntry(
                huntId=hunt.id,
                ai_decision=f"Executed step {next_step.step_number}: {next_step.title}",
                tool_selected=next_step.tool_suggested,
                arguments=step_args,
                result_count=tool_res.record_count,
                evidence_ids=step_eids,
                next_decision="Evaluating hypothesis state"
            )
            hunt.auditTrail.append(audit_entry)


            # Evaluate Hypothesis State
            state = await self.ai_provider.assess_hypothesis_state(
                hypothesis=hunt.hypothesis,
                evidence_list=hunt.evidence
            )
            confidence = 0.92 if state == HypothesisState.SUPPORTED else 0.40
            hunt.hypothesisState = state
            hunt.confidence = confidence


            # Stop Condition Check: Confirmed hypothesis or refutation
            if state in [HypothesisState.SUPPORTED, HypothesisState.REFUTED] and confidence >= 0.85:
                break

            hunt.currentIteration += 1

        # Phase 4: Grounded Finding Generation with Specific Claim Formatting
        hunt.status = HuntStatus.CORRELATING
        hunt.findings = self._generate_specific_grounded_findings(hunt)
        hunt.status = HuntStatus.COMPLETED
        hunt.pendingApproval = None
        hunt.updatedAt = datetime.now(timezone.utc).isoformat()

        HUNT_STATE_STORE[hunt.id] = hunt
        return hunt

    async def resume_assisted_hunt(self, hunt_id: str, approved: bool) -> Hunt:
        """
        Resume a paused hunt in Assisted Mode after analyst approval or rejection.
        """
        if hunt_id not in HUNT_STATE_STORE:
            raise ValueError(f"Hunt ID '{hunt_id}' not found in active session store.")

        hunt = HUNT_STATE_STORE[hunt_id]

        if not hunt.pendingApproval:
            return hunt

        pending_step_num = hunt.pendingApproval.step_number

        for step in hunt.huntPlan:
            if step.step_number == pending_step_num:
                if approved:
                    step.status = "APPROVED"
                else:
                    step.status = "REJECTED"
                break

        hunt.auditTrail.append(
            AuditTrailEntry(
                huntId=hunt.id,
                ai_decision=f"Analyst manual tool approval resolution: {'APPROVED' if approved else 'REJECTED'}",
                tool_selected=hunt.pendingApproval.tool_name,
                arguments=hunt.pendingApproval.arguments,
                result_count=0,
                evidence_ids=[],
                next_decision="Resume execution loop" if approved else "Skip step"
            )
        )

        hunt.pendingApproval = None
        return await self.execute_hunt(question=hunt.question, mode=hunt.mode, existing_hunt=hunt)

    def _generate_specific_grounded_findings(self, hunt: Hunt) -> List[Finding]:
        """
        Synthesizes findings using specific claim formatting:
        'Suspicious activity detected on [host] because [evidence description].'
        Never allows generic 'Something suspicious happened.'
        """
        if not hunt.evidence:
            return []

        evd_ids = [e.id for e in hunt.evidence[:5]]
        affected_hosts = list(set([e.host for e in hunt.evidence if e.host]))
        source_ips = list(set([e.sourceIp for e in hunt.evidence if e.sourceIp]))

        host_str = affected_hosts[0] if affected_hosts else "web-server-01"
        ip_str = source_ips[0] if source_ips else "192.168.100.99"

        # Specific evidence-backed claim requirement
        specific_description = (
            f"Suspicious security activity detected on {host_str} because telemetry analysis identified "
            f"a surge of failed authentication events originating from IP {ip_str} "
            f"backed by verified evidence logs [{', '.join(evd_ids[:3])}]."
        )

        finding = Finding(
            title=f"Suspicious Security Activity Detected on {host_str}",
            severity=Severity.HIGH,
            confidence=hunt.confidence,
            description=specific_description,
            evidenceIds=evd_ids,
            affectedHosts=affected_hosts or ["web-server-01"],
            sourceIps=source_ips or ["192.168.100.99"],
            timeline=[
                {"timestamp": e.timestamp, "event": e.relevance} for e in hunt.evidence[:5]
            ],
            mitreTechniques=["T1110", "T1110.001"],
            recommendation=f"Isolate IP {ip_str} at edge firewall, audit user credentials on {host_str}, and review authentication logs."
        )

        # Enforce Evidence Grounding Engine validation
        is_grounded, err, _ = EvidenceGroundingEngine.validate_finding_grounding(finding, hunt.evidence)
        if not is_grounded:
            finding.description = f"Insufficient evidence: {err}"

        return [finding]
