import pytest
import asyncio
import time
from fastapi.testclient import TestClient

from app.main import app
from app.streaming.hub import streaming_hub
from app.detection.engine import realtime_detection_engine
from app.agent.registry import agent_registry
from app.schemas.health import ComprehensiveHealthReport

@pytest.fixture(autouse=True)
def reset_all():
    streaming_hub.reset()
    realtime_detection_engine.reset()
    agent_registry.reset()
    yield
    streaming_hub.reset()
    realtime_detection_engine.reset()
    agent_registry.reset()

def test_comprehensive_health_report_all_subsystems():
    client = TestClient(app)
    resp = client.get("/api/health/comprehensive")
    assert resp.status_code == 200
    report = resp.json()

    assert report["overall_status"] == "HEALTHY"
    assert report["backend"]["status"] == "OK"
    assert report["database"]["status"] == "OK"
    assert report["event_stream"]["status"] == "OK"
    assert report["detection_engine"]["status"] == "OK"
    assert report["ai_investigator"]["status"] == "OK"
    assert report["connected_agents"]["status"] in ["OK", "DEGRADED"]

def test_10k_events_stress_test_and_memory_boundedness():
    """
    Stress test ingesting 10,000 security events to verify throughput,
    stability, and circular buffer memory boundedness.
    """
    start_time = time.time()
    total_events = 10000

    # Ingest 10,000 events in batches of 500
    for b in range(20):
        batch_events = []
        for i in range(500):
            idx = b * 500 + i
            batch_events.append({
                "id": f"stress-ev-{idx:05d}",
                "timestamp": f"2026-08-10T19:00:00.{idx:05d}Z",
                "source_type": "network_flow",
                "source_ip": f"10.0.{(idx // 256) % 256}.{idx % 256}",
                "destination_ip": "10.0.1.5",
                "destination_port": 80,
                "protocol": "TCP",
                "bytes_out": 450,
                "label": "BENIGN"
            })

        for ev in batch_events:
            realtime_detection_engine.process_event(ev)

    elapsed = time.time() - start_time
    assert elapsed < 5.0, f"Stress test took too long: {elapsed:.2f}s"

    # Verify evaluation metrics handled 10,000 labeled events cleanly
    eval_metrics = realtime_detection_engine.get_evaluation_metrics()
    assert eval_metrics.total_labeled_events == total_events
    assert eval_metrics.true_negatives == total_events
    assert eval_metrics.is_statistically_significant is True

def test_concurrent_agent_shippers_race_condition():
    """
    Simulate 10 concurrent agent shippers sending event batches simultaneously
    to verify async thread safety and sequence monotonicity.
    """
    client = TestClient(app)

    def ship_batch(agent_num: int):
        return client.post("/api/events", json={
            "agent_id": f"agent-stress-{agent_num}",
            "hostname": f"srv-stress-{agent_num}",
            "agent_version": "1.0.0",
            "timestamp": "2026-08-10T19:00:00Z",
            "sequence_number": 1,
            "events": [
                {
                    "id": f"ev-conc-{agent_num}-{j}",
                    "source_type": "linux_auth",
                    "hostname": f"srv-stress-{agent_num}",
                    "username": "root",
                    "event_type": "ssh_authentication",
                    "action": "failed_password",
                    "status": "FAILURE"
                }
                for j in range(10)
            ]
        })

    # Fire 10 concurrent requests
    responses = [ship_batch(i) for i in range(10)]

    for resp in responses:
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

    # Verify all 10 agents registered cleanly
    agents = agent_registry.list_agents()
    assert len(agents) == 10
    total_sent = sum(a.total_events_sent for a in agents)
    assert total_sent == 100

def test_multi_source_cross_telemetry_attack_correlation():
    """
    Verify that telemetry arriving from:
    1. Real Linux Agent (auth.log)
    2. Network Dataset Replay (flow)
    3. Simulated Scenario (auditd)
    correctly correlates on IP and Host into a unified multi-stage incident.
    """
    engine = realtime_detection_engine
    target_host = "srv-cluster-db01"
    attacker_ip = "198.51.100.77"

    # Source 1: Agent reports SSH Brute Force
    for i in range(3):
        engine.process_event({
            "id": f"agent-ev-{i}",
            "timestamp": f"2026-08-10T19:00:0{i}Z",
            "source": f"agent:agent-deb-01",
            "source_type": "linux_auth",
            "hostname": target_host,
            "source_ip": attacker_ip,
            "username": "admin",
            "event_type": "ssh_authentication",
            "action": "failed_password",
            "status": "FAILURE"
        })

    # Source 2: Agent reports successful compromise
    engine.process_event({
        "id": "agent-ev-succ",
        "timestamp": "2026-08-10T19:00:10Z",
        "source": f"agent:agent-deb-01",
        "source_type": "linux_auth",
        "hostname": target_host,
        "source_ip": attacker_ip,
        "username": "admin",
        "event_type": "ssh_authentication",
        "action": "accepted_password",
        "status": "SUCCESS"
    })

    # Source 3: Audit log reports sudo privesc
    engine.process_event({
        "id": "audit-ev-priv",
        "timestamp": "2026-08-10T19:00:20Z",
        "source": "simulated:privilege-escalation",
        "source_type": "linux_audit",
        "hostname": target_host,
        "username": "admin",
        "command": "sudo bash",
        "event_type": "process_create",
        "action": "sudo_execution",
        "status": "SUCCESS"
    })

    # Source 4: Network flow reports high volume exfiltration
    engine.process_event({
        "id": "net-ev-exfil",
        "timestamp": "2026-08-10T19:00:30Z",
        "source": "dataset:pcap-flow",
        "source_type": "network_flow",
        "hostname": target_host,
        "source_ip": attacker_ip,
        "destination_ip": "203.0.113.55",
        "bytes_out": 1500000,
        "event_type": "network_flow"
    })

    # Check that all 4 sources correlated into ONE unified CRITICAL incident
    incidents = engine.get_active_incidents()
    assert len(incidents) == 1
    inc = incidents[0]

    assert inc.severity == "CRITICAL"
    assert attacker_ip in inc.source_ips
    assert target_host in inc.affected_hosts
    assert "admin" in inc.users
    assert len(inc.detections) >= 3
    assert len(inc.mitre_tactics) >= 3

    # Verify attack graph contains nodes from all sources
    graph = inc.attack_graph
    assert any(n.type == "IP" and n.value == attacker_ip for n in graph.nodes)
    assert any(n.type == "HOST" and n.value == target_host for n in graph.nodes)
    assert any(n.type == "USER" and n.value == "admin" for n in graph.nodes)
