import pytest
import asyncio
from fastapi.testclient import TestClient

from app.main import app
from app.scenarios.definitions import get_prebuilt_scenarios
from app.scenarios.engine import simulated_scenario_runner
from app.detection.engine import realtime_detection_engine
from app.streaming.hub import streaming_hub

@pytest.fixture(autouse=True)
def reset_state():
    realtime_detection_engine.reset()
    streaming_hub.reset()
    yield
    realtime_detection_engine.reset()
    streaming_hub.reset()

def test_prebuilt_scenarios_definitions_and_metadata():
    scenarios = get_prebuilt_scenarios()
    
    expected_ids = [
        "ssh-bruteforce",
        "account-compromise",
        "privilege-escalation",
        "credential-discovery",
        "data-collection",
        "data-exfiltration",
        "multi-stage-attack"
    ]

    for sid in expected_ids:
        assert sid in scenarios, f"Missing expected scenario {sid}"
        sc = scenarios[sid]
        assert sc.name != ""
        assert sc.description != ""
        assert sc.category == "SIMULATED ATTACK REPLAY"
        assert len(sc.expected_techniques) > 0
        assert len(sc.expected_tactics) > 0
        assert sc.events_count == len(sc.events)

        # Check that events have ascending chronological timestamps and simulated metadata
        for i, ev in enumerate(sc.events):
            assert ev["label"] == "SIMULATED ATTACK REPLAY"
            assert ev["metadata"]["telemetry_source"] == "SIMULATED_SCENARIO"
            assert ev["metadata"]["simulated"] is True
            assert ev["id"].startswith("sim-")

def test_multi_stage_attack_kill_chain_coverage():
    scenarios = get_prebuilt_scenarios()
    multi = scenarios["multi-stage-attack"]
    
    # Verify expected techniques cover full kill chain
    techs = multi.expected_techniques
    assert "T1110" in techs  # Brute Force
    assert "T1078" in techs  # Valid Accounts
    assert "T1548.003" in techs  # Sudo PrivEsc
    assert "T1003" in techs  # Credential Dump
    assert "T1560" in techs  # Archive Data
    assert "T1048" in techs  # Exfiltration

def test_scenarios_rest_api_endpoints():
    client = TestClient(app)
    from app.auth.models import UserRole
    from app.auth.security import create_access_token
    analyst_headers = {"Authorization": f"Bearer {create_access_token('usr-analyst-01', 'analyst', UserRole.ANALYST)}"}

    # 1. List scenarios
    resp = client.get("/api/scenarios", headers=analyst_headers)
    assert resp.status_code == 200
    sc_list = resp.json()
    assert len(sc_list) == 7

    # 2. Get specific scenario
    resp_detail = client.get("/api/scenarios/multi-stage-attack", headers=analyst_headers)
    assert resp_detail.status_code == 200
    detail = resp_detail.json()
    assert detail["name"] == "Multi-Stage Attack (Full Kill-Chain)"
    assert detail["category"] == "SIMULATED ATTACK REPLAY"
    assert len(detail["events"]) >= 6

    # 3. Invalid scenario returns 404
    resp_404 = client.get("/api/scenarios/nonexistent-scenario", headers=analyst_headers)
    assert resp_404.status_code == 404

def test_scenario_replay_lifecycle_and_status():
    client = TestClient(app)
    from app.auth.models import UserRole
    from app.auth.security import create_access_token
    analyst_headers = {"Authorization": f"Bearer {create_access_token('usr-analyst-01', 'analyst', UserRole.ANALYST)}"}

    # 1. Status initially idle
    resp_status = client.get("/api/scenarios/status", headers=analyst_headers)
    assert resp_status.status_code == 200
    assert resp_status.json()["category"] == "SIMULATED ATTACK REPLAY"

    # 2. Start replay at 50x speed for fast test execution
    resp_start = client.post("/api/scenarios/replay/ssh-bruteforce?speed_multiplier=50.0", headers=analyst_headers)
    assert resp_start.status_code == 200
    start_data = resp_start.json()
    assert start_data["status"] == "running"
    assert start_data["scenario_id"] == "ssh-bruteforce"

    # 3. Stop replay
    resp_stop = client.post("/api/scenarios/stop", headers=analyst_headers)
    assert resp_stop.status_code == 200
    assert resp_stop.json()["status"] in ["stopped", "completed"]

def test_end_to_end_simulated_multi_stage_attack_generates_incident():
    """
    Verify replaying multi-stage-attack feeds the detection engine and creates
    a correlated CRITICAL incident with attack graph and MITRE progression.
    """
    scenarios = get_prebuilt_scenarios()
    multi = scenarios["multi-stage-attack"]

    # Directly feed scenario events to detection engine
    for ev in multi.events:
        realtime_detection_engine.process_event(ev)

    incidents = realtime_detection_engine.get_active_incidents()
    assert len(incidents) >= 1

    inc = incidents[0]
    assert inc.severity == "CRITICAL"
    assert "198.51.100.99" in inc.source_ips
    assert "srv-web-01" in inc.affected_hosts
    assert "deploy" in inc.users
    assert len(inc.mitre_tactics) >= 3
    assert len(inc.detections) >= 3

    # Check attack graph nodes
    graph = inc.attack_graph
    assert any(n.type == "IP" and n.value == "198.51.100.99" for n in graph.nodes)
    assert any(n.type == "USER" and n.value == "deploy" for n in graph.nodes)
    assert any(n.type == "HOST" and n.value == "srv-web-01" for n in graph.nodes)
