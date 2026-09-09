import time
import asyncio
import re
import threading
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from app.config import settings
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
_HUNT_STORE_LOCK = threading.Lock()

# MITRE technique inference by evidence signal — keeps findings scenario-aware
# instead of hardcoding SSH brute-force techniques for every hunt.
MITRE_BY_SIGNAL = [
    (("DNS", "TUNNEL", "BEACON", "C2"), ["T1071.004"]),
    (("SUDO", "PRIVILEGE", "ESCALAT"), ["T1548.003"]),
    (("SCAN", "CONNECT", "SYN", "RECON"), ["T1046"]),
    (("EXFIL", "PG_DUMP", "DUMP"), ["T1041"]),
    (("PIVOT", "LATERAL"), ["T1021.004"]),
    (("CURL", "BASH", "PAYLOAD", "EXECUTE"), ["T1059.004"]),
    (("FAILED_LOGIN", "BRUTE", "PASSWORD", "SPRAY"), ["T1110", "T1110.001"]),
    (("LOGIN", "VALID_ACCOUNT", "COMPROMISED"), ["T1110", "T1078"]),
]

SEVERITY_BY_SIGNAL = [
    (("EXFIL", "DUMP", "BEACON"), Severity.CRITICAL),
    (("PRIVILEGE", "SUDO"), Severity.CRITICAL),
    (("BRUTE", "FAILED_LOGIN", "SPRAY"), Severity.HIGH),
    (("SCAN", "RECON"), Severity.MEDIUM),
]


def _prune_hunt_store() -> None:
    """Evict oldest hunts when the store exceeds MAX_ACTIVE_HUNTS (memory-leak guard)."""
    with _HUNT_STORE_LOCK:
        overflow = len(HUNT_STATE_STORE) - settings.MAX_ACTIVE_HUNTS
        if overflow > 0:
            oldest = sorted(HUNT_STATE_STORE.values(), key=lambda h: h.createdAt)[:overflow]
            for hunt in oldest:
                HUNT_STATE_STORE.pop(hunt.id, None)


def _signal_hit(blob: str, signal: str) -> bool:
    """Match an evidence signal. Short tokens (e.g. 'C2', 'SYN', 'DNS') use word
    boundaries so they don't false-positive inside IDs and field names like
    'EVT-SC2-FAIL-000' or 'isSyntheticLabData'."""
    if len(signal) <= 3:
        return re.search(rf"\b{re.escape(signal)}\b", blob) is not None
    return signal in blob


def _infer_mitre_techniques(evidence: List[Evidence]) -> List[str]:
    blob = " ".join(
        f"{e.eventType} {e.relevance} {e.normalizedData}" for e in evidence
    ).upper()
    for signals, techniques in MITRE_BY_SIGNAL:
        if any(_signal_hit(blob, sig) for sig in signals):
            return techniques
    return ["T1110", "T1110.001"]


def _infer_severity(evidence: List[Evidence]) -> Severity:
    blob = " ".join(
        f"{e.eventType} {e.relevance} {e.normalizedData}" for e in evidence
    ).upper()
    for signals, severity in SEVERITY_BY_SIGNAL:
        if any(_signal_hit(blob, sig) for sig in signals):
            return severity
    return Severity.HIGH

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
        existing_hunt: Optional[Hunt] = None,
        owner_id: Optional[str] = None,
        tenant_id: Optional[str] = None
    ) -> Hunt:
        """
        Execute an autonomous threat hunt workflow with strict safety limits and dual modes.
        """
        if len(question or "") > settings.MAX_QUESTION_CHARS:
            raise ValueError(
                f"Hunt question exceeds maximum length of {settings.MAX_QUESTION_CHARS} characters."
            )
        start_time = time.time()

        if existing_hunt:
            hunt = existing_hunt
        else:
            hunt = Hunt(
                question=question,
                mode=mode,
                status=HuntStatus.PLANNING,
                currentIteration=1,
                maxIterations=5,
                owner_id=owner_id or "system-demo",
                tenant_id=tenant_id or "soc-org-primary"
            )

        with _HUNT_STORE_LOCK:
            HUNT_STATE_STORE[hunt.id] = hunt
        _prune_hunt_store()

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
                approval_args = await self._resolve_step_args(next_step)
                hunt.pendingApproval = PendingToolApproval(
                    step_number=next_step.step_number,
                    tool_name=next_step.tool_suggested,
                    arguments=approval_args,
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
            # Prefer the AI provider's tool selection (question-aware arguments);
            # fall back to safe defaults if the provider yields nothing usable.
            step_args = await self._resolve_step_args(next_step)

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
        # Roll finding metadata up to the hunt level for API consumers.
        hunt.mitreTechniques = sorted({t for f in hunt.findings for t in f.mitreTechniques})
        hunt.recommendations = [f.recommendation for f in hunt.findings if f.recommendation][:5]
        hunt.status = HuntStatus.COMPLETED
        hunt.pendingApproval = None
        hunt.updatedAt = datetime.now(timezone.utc).isoformat()

        with _HUNT_STORE_LOCK:
            HUNT_STATE_STORE[hunt.id] = hunt
        return hunt

    async def _resolve_step_args(self, step: HuntPlanStep) -> Dict[str, Any]:
        """
        Resolve tool arguments for a plan step via the AI provider's tool
        selection, constrained to the gateway's registered parameters.
        Falls back to safe per-tool defaults when the provider yields nothing.
        """
        try:
            available = self.tool_gateway.get_registered_tools()
            selected = await self.ai_provider.select_tools(step, available)
            if selected:
                candidate = selected[0].arguments or {}
                tool_def = self.tool_gateway.get_tool_definition(step.tool_suggested)
                if tool_def:
                    allowed = {p.name for p in tool_def.parameters}
                    filtered = {k: v for k, v in candidate.items() if k in allowed}
                    # Repair the legacy `ip_address` alias the engine used to send.
                    if "ip" in allowed and "ip" not in filtered and "ip_address" in candidate:
                        filtered["ip"] = candidate["ip_address"]
                    required = {p.name for p in tool_def.parameters if p.required}
                    if required.issubset(filtered.keys()):
                        if "limit" in allowed and "limit" not in filtered:
                            filtered["limit"] = 100
                        return filtered
        except Exception:
            pass  # Fall through to safe defaults below.

        fallbacks: Dict[str, Dict[str, Any]] = {
            "search_authentication_events": {"status": "FAILURE", "limit": 100},
            "search_network_events": {"limit": 100},
            "search_dns_events": {"limit": 100},
            "search_process_events": {"limit": 100},
            "search_file_events": {"limit": 100},
            "get_host_timeline": {"host": "web-server-01", "limit": 100},
            "get_ip_activity": {"ip": "192.168.100.99", "limit": 100},
            "get_domain_activity": {"domain": "attacker-domain.com", "limit": 100},
            "get_alerts": {"limit": 100},
            "scan_open_ports": {"host": "web-server-01", "limit": 100},
            "collect_workstation_telemetry": {"hosts": "all", "limit": 100},
        }
        return dict(fallbacks.get(step.tool_suggested, {"limit": 100}))

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
        MITRE techniques and severity are inferred from the collected evidence
        so non-SSH scenarios (DNS, exfil, recon, ...) get accurate mappings.
        """
        if not hunt.evidence:
            return []

        evd_ids = [e.id for e in hunt.evidence[:5]]
        affected_hosts = list(set([e.host for e in hunt.evidence if e.host]))
        source_ips = list(set([e.sourceIp for e in hunt.evidence if e.sourceIp]))

        host_str = affected_hosts[0] if affected_hosts else "web-server-01"
        ip_str = source_ips[0] if source_ips else "192.168.100.99"
        techniques = _infer_mitre_techniques(hunt.evidence)
        severity = _infer_severity(hunt.evidence)
        signal = self._describe_dominant_signal(hunt.evidence)

        # Specific evidence-backed claim requirement
        specific_description = (
            f"Suspicious security activity detected on {host_str} because telemetry analysis identified "
            f"{signal} originating from IP {ip_str} "
            f"backed by verified evidence logs [{', '.join(evd_ids[:3])}]."
        )

        finding = Finding(
            title=f"Suspicious Security Activity Detected on {host_str}",
            severity=severity,
            confidence=hunt.confidence,
            description=specific_description,
            evidenceIds=evd_ids,
            affectedHosts=affected_hosts or ["web-server-01"],
            sourceIps=source_ips or ["192.168.100.99"],
            timeline=[
                {"timestamp": e.timestamp, "event": e.relevance} for e in hunt.evidence[:5]
            ],
            mitreTechniques=techniques,
            recommendation=f"Isolate IP {ip_str} at edge firewall, audit user credentials on {host_str}, and review authentication logs."
        )

        # Enforce Evidence Grounding Engine validation
        is_grounded, err, _ = EvidenceGroundingEngine.validate_finding_grounding(finding, hunt.evidence)
        if not is_grounded:
            finding.description = f"Insufficient evidence: {err}"

        return [finding]

    @staticmethod
    def _describe_dominant_signal(evidence: List[Evidence]) -> str:
        """Human-readable summary of the dominant evidence signal."""
        blob = " ".join(f"{e.eventType} {e.relevance}" for e in evidence).upper()
        if "DNS" in blob or "BEACON" in blob or "LOOKUP" in blob:
            return "a surge of suspicious DNS resolution events"
        if "SUDO" in blob or "PRIVILEGE" in blob:
            return "an attempted privilege escalation to root"
        if "CONNECT" in blob or "SCAN" in blob or "SYN" in blob:
            return "a pattern of anomalous network connection events"
        if "EXECUTE" in blob or "PAYLOAD" in blob or "CURL" in blob:
            return "a suspicious post-authentication command execution"
        if "DUMP" in blob or "EXFIL" in blob:
            return "a database dump followed by a large outbound transfer"
        if "LOGIN" in blob and "SUCCESS" in blob:
            return "a successful login following repeated authentication failures"
        return "a surge of failed authentication events"
