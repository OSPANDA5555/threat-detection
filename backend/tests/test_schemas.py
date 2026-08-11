import pytest
import asyncio
from app.schemas import Hunt, Evidence, Finding, ToolDefinition, ToolExecutionRequest, EvidenceSource, Severity
from app.tools.gateway import ToolGateway

def test_evidence_schema_validation():
    evidence = Evidence(
        source=EvidenceSource.AUTHENTICATION,
        eventType="SSH_FAIL",
        rawReference="log.txt:1",
        relevance="Failed password attempt",
        confidence=0.9
    )
    assert evidence.id.startswith("evd-")
    assert evidence.source == EvidenceSource.AUTHENTICATION
    assert evidence.confidence == 0.9

def test_evidence_invalid_confidence():
    with pytest.raises(ValueError):
        Evidence(
            source=EvidenceSource.AUTHENTICATION,
            eventType="SSH_FAIL",
            rawReference="log.txt:1",
            relevance="Invalid confidence test",
            confidence=1.5  # Exceeds max 1.0
        )

def test_finding_schema_validation():
    finding = Finding(
        title="Suspicious SSH Activity",
        severity=Severity.HIGH,
        confidence=0.88,
        description="Multiple failed logins observed",
        evidenceIds=["evd-101"],
        recommendation="Isolate IP"
    )
    assert finding.id.startswith("fnd-")
    assert finding.severity == Severity.HIGH
    assert len(finding.evidenceIds) == 1

def test_tool_gateway_unregistered_tool_rejection():
    gateway = ToolGateway()
    req = ToolExecutionRequest(
        tool_name="unauthorized_shell_exec",
        arguments={"cmd": "rm -rf /"}
    )
    result = asyncio.run(gateway.execute_tool(req))
    assert result.status == "REJECTED"
    assert "NOT registered" in result.error_message

def test_tool_gateway_valid_execution():
    gateway = ToolGateway()
    req = ToolExecutionRequest(
        tool_name="search_authentication_events",
        arguments={"host": "web-server-01", "limit": 10}
    )
    result = asyncio.run(gateway.execute_tool(req))
    assert result.status == "SUCCESS"
    assert result.record_count > 0
    assert "web-server-01" in result.records[0]["host"]


def test_tool_gateway_limit_capping():
    gateway = ToolGateway()
    req = ToolExecutionRequest(
        tool_name="search_authentication_events",
        arguments={"limit": 10000}  # Excessive limit request
    )
    result = asyncio.run(gateway.execute_tool(req))
    assert result.status == "SUCCESS"
    # Should be capped to maximum 500 records
    assert len(result.records) <= 500

def test_tool_gateway_invalid_parameter_rejection():
    gateway = ToolGateway()
    req = ToolExecutionRequest(
        tool_name="search_authentication_events",
        arguments={"unsupported_param": "test"}
    )
    result = asyncio.run(gateway.execute_tool(req))
    assert result.status == "REJECTED"
    assert "Invalid Parameter" in result.error_message

def test_tool_gateway_shell_injection_detection():
    gateway = ToolGateway()
    req = ToolExecutionRequest(
        tool_name="search_authentication_events",
        arguments={"host": "srv01; rm -rf /"}
    )
    result = asyncio.run(gateway.execute_tool(req))
    assert result.status == "REJECTED"
    assert "Malicious input pattern detected" in result.error_message
