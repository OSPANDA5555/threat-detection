import pytest
import asyncio
from fastapi.testclient import TestClient
from app.main import app
from app.telemetry.generator import telemetry_engine
from app.telemetry.models import EventFilter, EventType, GroundTruth
from app.telemetry.evaluation import EvaluationEngine
from app.schemas.finding import Finding, Severity
from app.schemas.evidence import Evidence, EvidenceSource

client = TestClient(app)

def test_telemetry_generator_scenarios():
    scenarios = telemetry_engine.get_scenarios()
    assert len(scenarios) == 8
    scenario_ids = [sc["id"] for sc in scenarios]
    assert "ssh-bruteforce" in scenario_ids
    assert "lateral-movement" in scenario_ids
    assert "suspicious-exfil" in scenario_ids

def test_telemetry_event_filtering():
    # Filter by host web-server-01
    flt_host = EventFilter(host="web-server-01", limit=100)
    events = telemetry_engine.query_events(flt_host)
    assert len(events) > 0
    assert all("web-server-01" in evt.host for evt in events)

    # Filter by IP 192.168.100.99
    flt_ip = EventFilter(source_ip="192.168.100.99", limit=100)
    ip_events = telemetry_engine.query_events(flt_ip)
    assert len(ip_events) > 0
    assert all(evt.sourceIp == "192.168.100.99" for evt in ip_events)

def test_ground_truth_isolation():
    gt = telemetry_engine.get_ground_truth("ssh-bruteforce")
    assert gt is not None
    assert gt.scenarioId == "ssh-bruteforce"
    assert gt.affectedHost == "web-server-01"
    assert "T1110" in gt.expectedTechniques

    # Ensure ground truth is NOT returned in standard query_events call
    flt = EventFilter(limit=5)
    public_events = telemetry_engine.query_events(flt)
    for evt in public_events:
        assert not hasattr(evt, "expectedTechniques")
        assert not hasattr(evt, "groundTruthEventIds")

def test_result_limit_caps():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        EventFilter(limit=1000)  # Exceeds max schema limit 500
    
    # Valid filter up to 500
    flt = EventFilter(limit=500)
    events = telemetry_engine.query_events(flt)
    assert len(events) <= 500


def test_evaluation_engine():
    gt = telemetry_engine.get_ground_truth("ssh-bruteforce")
    finding = Finding(
        title="SSH Password Spray Detected",
        severity=Severity.HIGH,
        confidence=0.9,
        description="Brute force against web-server-01",
        evidenceIds=["evt-sc1-001"],
        affectedHosts=["web-server-01"],
        sourceIps=["192.168.100.99"],
        mitreTechniques=["T1110", "T1110.001"],
        recommendation="Block IP"
    )
    evidence = Evidence(
        id="evt-sc1-001",
        source=EvidenceSource.AUTHENTICATION,
        eventType="FAILED_LOGIN",
        rawReference="log",
        relevance="Failed login attempt evt-sc1-001",
        confidence=0.9
    )

    report = EvaluationEngine.evaluate_finding(finding, [evidence], gt)
    assert report.scenarioId == "ssh-bruteforce"
    assert report.precision > 0.5
    assert report.recall > 0.5
    assert report.isAccurate is True

def test_telemetry_rest_api_endpoints():
    # 1. GET /api/v1/telemetry/scenarios
    res_sc = client.get("/api/v1/telemetry/scenarios")
    assert res_sc.status_code == 200
    assert len(res_sc.json()) == 8

    # 2. GET /api/v1/telemetry/events
    res_ev = client.get("/api/v1/telemetry/events?host=web-server-01&limit=10")
    assert res_ev.status_code == 200
    events = res_ev.json()
    assert len(events) > 0

    # 3. POST /api/v1/telemetry/evaluate
    eval_payload = {
        "scenario_id": "ssh-bruteforce",
        "finding": {
            "title": "SSH Brute Force",
            "severity": "HIGH",
            "confidence": 0.95,
            "description": "Brute force attack",
            "evidenceIds": ["evt-sc1-001"],
            "affectedHosts": ["web-server-01"],
            "sourceIps": ["192.168.100.99"],
            "mitreTechniques": ["T1110"],
            "recommendation": "Block IP"
        },
        "evidence_list": []
    }
    res_eval = client.post("/api/v1/telemetry/evaluate", json=eval_payload)
    assert res_eval.status_code == 200
    report = res_eval.json()
    assert report["scenarioId"] == "ssh-bruteforce"
    assert "precision" in report
    assert "recall" in report
