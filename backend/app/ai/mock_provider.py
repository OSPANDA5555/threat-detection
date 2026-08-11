from typing import List, Dict, Any, Optional
from app.schemas.hunt import StructuredHuntPlan, HuntPlanStep, HypothesisState
from app.schemas.tool import ToolDefinition, ToolExecutionRequest
from app.schemas.finding import Finding, Severity
from app.schemas.evidence import Evidence
from app.tools.gateway import ToolGateway
from app.ai.base import BaseAIProvider


class MockAIProvider(BaseAIProvider):
    """
    Model-agnostic AI provider producing structured JSON plans, queries,
    and hypothesis assessments based on analyst questions and available tools.
    """

    async def generate_hypothesis(self, question: str) -> str:
        q_lower = question.lower()
        if "ssh" in q_lower or "login" in q_lower or "password" in q_lower:
            return "An attacker may have attempted credential-based access against an internal Linux host via SSH password brute force."
        elif "privilege" in q_lower or "sudo" in q_lower or "root" in q_lower:
            return "An adversary may have abused sudo permissions to escalate privileges to root."
        elif "recon" in q_lower or "scan" in q_lower or "nmap" in q_lower:
            return "An internal or external host may be conducting network reconnaissance across enterprise subnets."
        elif "dns" in q_lower or "beacon" in q_lower or "c2" in q_lower:
            return "An infected endpoint may be establishing covert C2 communications via DNS tunneling."
        elif "exfil" in q_lower or "database" in q_lower or "dump" in q_lower:
            return "An attacker may have dumped database contents and exfiltrated sensitive data to an external IP."
        elif "pivot" in q_lower or "lateral" in q_lower:
            return "An attacker may have pivoted laterally from a compromised web host to internal database servers."
        return "An unauthorized user or automated script may be performing anomalous activity in the enterprise environment."

    async def generate_structured_plan(self, question: str, available_tools: Optional[List[ToolDefinition]] = None) -> StructuredHuntPlan:
        hypothesis = await self.generate_hypothesis(question)
        tools = available_tools or ToolGateway().get_registered_tools()
        tool_names = {t.name for t in tools}


        steps = []
        req_tools = []

        if "search_authentication_events" in tool_names:
            steps.append(HuntPlanStep(
                step_number=1,
                title="Search Authentication Failure Events",
                description="Query authentication logs for SSH and system password failures.",
                tool_suggested="search_authentication_events",
                status="PENDING"
            ))
            req_tools.append("search_authentication_events")

        if "get_ip_activity" in tool_names:
            steps.append(HuntPlanStep(
                step_number=2,
                title="Identify Suspicious Source IPs",
                description="Summarize IP network and authentication activity for failing source IPs.",
                tool_suggested="get_ip_activity",
                status="PENDING"
            ))
            req_tools.append("get_ip_activity")

        if "get_host_timeline" in tool_names:
            steps.append(HuntPlanStep(
                step_number=3,
                title="Inspect Host Event Timeline",
                description="Fetch unified event timeline for target host around failure timestamps.",
                tool_suggested="get_host_timeline",
                status="PENDING"
            ))
            req_tools.append("get_host_timeline")

        return StructuredHuntPlan(
            hypothesis=hypothesis,
            objectives=[
                "Identify authentication anomaly patterns",
                "Isolate suspicious source IP addresses",
                "Correlate evidence across host timelines"
            ],
            steps=steps,
            requiredTools=req_tools,
            expectedEvidence=[
                "High frequency failed login logs",
                "Suspicious IP network connections",
                "Host process execution timeline"
            ],
            stopConditions=[
                "Confirmed malicious pattern with high confidence evidence",
                "All planned steps completed",
                "Maximum 5 iterations reached"
            ]
        )

    async def generate_hunt_plan(self, question: str, hypothesis: Optional[str] = None, available_tools: Optional[List[ToolDefinition]] = None) -> StructuredHuntPlan:
        return await self.generate_structured_plan(question, available_tools)


    async def select_tools(self, current_step: HuntPlanStep, available_tools: List[ToolDefinition]) -> List[ToolExecutionRequest]:
        tool_name = current_step.tool_suggested
        tool_names = {t.name for t in available_tools}

        if tool_name not in tool_names:
            return []

        args = {"limit": 50}
        if tool_name == "search_authentication_events":
            args["status"] = "FAILURE"
            args["host"] = "web-server-01"
        elif tool_name == "get_ip_activity":
            args["ip"] = "192.168.100.99"
        elif tool_name == "get_host_timeline":
            args["host"] = "web-server-01"

        return [ToolExecutionRequest(tool_name=tool_name, arguments=args)]

    async def assess_hypothesis_state(self, hypothesis: str, evidence_list: List[Evidence]) -> HypothesisState:
        if not evidence_list:
            return HypothesisState.INCONCLUSIVE

        failures = [e for e in evidence_list if "FAILURE" in e.eventType.upper() or "FAILED" in e.relevance.upper()]
        if len(failures) >= 5 or len(evidence_list) >= 3:
            return HypothesisState.SUPPORTED
        return HypothesisState.REFUTED

    async def correlate_evidence(self, evidence_list: List[Evidence]) -> Dict[str, Any]:
        hosts = list({e.host for e in evidence_list if e.host})
        ips = list({e.sourceIp for e in evidence_list if e.sourceIp})
        return {"hosts": hosts, "source_ips": ips, "total_evidence": len(evidence_list)}

    async def generate_finding(self, hunt: Any) -> Optional[Finding]:
        if not hunt.evidence:
            return None

        primary_evd = hunt.evidence[0]
        host = primary_evd.host or "web-server-01"
        ip = primary_evd.sourceIp or "192.168.100.99"

        return Finding(
            title=f"Suspicious Security Activity Detected on {host}",
            severity=Severity.HIGH,
            confidence=0.92,
            description=f"Automated threat hunt identified suspicious telemetry events originating from IP {ip} targeting host {host}.",
            evidenceIds=[e.id for e in hunt.evidence[:3]],
            affectedHosts=[host],
            sourceIps=[ip],
            timeline=[{"timestamp": primary_evd.timestamp, "event": primary_evd.relevance}],
            mitreTechniques=hunt.mitreTechniques or ["T1110", "T1110.001"],
            recommendation=f"Isolate IP {ip} at edge firewall, audit user credentials on {host}, and review authentication logs."
        )
