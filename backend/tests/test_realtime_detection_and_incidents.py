import pytest
import json
from fastapi.testclient import TestClient

from app.main import app
from app.detection.engine import realtime_detection_engine
from app.detection.rules import BehavioralRuleEngine
from app.detection.incidents import IncidentStateManager
from app.detection.evaluation import RealTimeEvaluationTracker
from app.streaming.hub import streaming_hub

@pytest.fixture(autouse=True)
def reset_detection_state():
    realtime_detection_engine.reset()
    streaming_hub.reset()
    yield
    realtime_detection_engine.reset()
    streaming_hub.reset()

def test_behavioral_rule_brute_force_surge():
    engine = BehavioralRuleEngine()
    
    # Send 2 failed auth events (below threshold of 3)
    ev1 = {
        "id": "ev-fail-1",
        "timestamp": "2026-08-10T19:00:01Z",
        "source_ip": "192.168.1.50",
        "hostname": "srv-app-01",
        "username": "admin",
        "event_type": "ssh_authentication",
        "action": "failed_password",
        "status": "FAILURE"
    }
    ev2 = {
        "id": "ev-fail-2",
        "timestamp": "2026-08-10T19:00:10Z",
        "source_ip": "192.168.1.50",
        "hostname": "srv-app-01",
        "username": "admin",
        "event_type": "ssh_authentication",
        "action": "failed_password",
        "status": "FAILURE"
    }
    assert engine.evaluate_event(ev1) == []
    assert engine.evaluate_event(ev2) == []

    # 3rd failed auth triggers T1110
    ev3 = {
        "id": "ev-fail-3",
        "timestamp": "2026-08-10T19:00:20Z",
        "source_ip": "192.168.1.50",
        "hostname": "srv-app-01",
        "username": "admin",
        "event_type": "ssh_authentication",
        "action": "failed_password",
        "status": "FAILURE"
    }
    alerts = engine.evaluate_event(ev3)
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1110"
    assert alerts[0].severity == "HIGH"
    assert "ev-fail-1" in alerts[0].evidenceEventIds
    assert "ev-fail-2" in alerts[0].evidenceEventIds
    assert "ev-fail-3" in alerts[0].evidenceEventIds

def test_behavioral_rule_compromise_after_brute_force():
    engine = BehavioralRuleEngine()
    
    # 3 failed logins
    for i in range(1, 4):
        engine.evaluate_event({
            "id": f"ev-fail-{i}",
            "timestamp": f"2026-08-10T19:00:{10*i:02d}Z",
            "source_ip": "192.168.1.50",
            "hostname": "srv-app-01",
            "username": "admin",
            "event_type": "ssh_authentication",
            "action": "failed_password",
            "status": "FAILURE"
        })

    # Successful login from same attacker IP
    success_ev = {
        "id": "ev-succ-4",
        "timestamp": "2026-08-10T19:01:00Z",
        "source_ip": "192.168.1.50",
        "hostname": "srv-app-01",
        "username": "admin",
        "event_type": "ssh_authentication",
        "action": "accepted_password",
        "status": "SUCCESS"
    }
    alerts = engine.evaluate_event(success_ev)
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1078"
    assert alerts[0].severity == "CRITICAL"
    assert "ev-succ-4" in alerts[0].evidenceEventIds
    assert len(alerts[0].evidenceEventIds) == 4

def test_behavioral_rule_privilege_escalation_and_cred_dump():
    engine = BehavioralRuleEngine()

    # Privilege escalation
    priv_ev = {
        "id": "ev-priv-1",
        "timestamp": "2026-08-10T19:02:00Z",
        "hostname": "srv-app-01",
        "username": "user1",
        "command": "sudo bash",
        "event_type": "process_create",
        "action": "sudo_execution"
    }
    alerts = engine.evaluate_event(priv_ev)
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1548.003"
    assert alerts[0].tactic == "Privilege Escalation"

    # Credential dump
    cred_ev = {
        "id": "ev-cred-1",
        "timestamp": "2026-08-10T19:02:30Z",
        "hostname": "srv-app-01",
        "username": "root",
        "command": "cat /etc/shadow",
        "event_type": "file_access"
    }
    alerts = engine.evaluate_event(cred_ev)
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1003"
    assert alerts[0].tactic == "Credential Access"

def test_behavioral_rule_archive_and_exfiltration():
    engine = BehavioralRuleEngine()

    # Archive creation in /tmp
    arch_ev = {
        "id": "ev-arch-1",
        "timestamp": "2026-08-10T19:03:00Z",
        "hostname": "srv-app-01",
        "command": "tar -czf /tmp/backup.tar.gz /var/www/data",
        "event_type": "process_create"
    }
    alerts = engine.evaluate_event(arch_ev)
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1560"

    # High volume outbound exfiltration
    exfil_ev = {
        "id": "ev-exfil-1",
        "timestamp": "2026-08-10T19:04:00Z",
        "source_ip": "10.0.1.15",
        "destination_ip": "203.0.113.88",
        "bytes_out": 2500000,
        "event_type": "network_flow"
    }
    alerts = engine.evaluate_event(exfil_ev)
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1048"

def test_behavioral_rule_port_scanning():
    engine = BehavioralRuleEngine()
    src_ip = "192.168.1.99"
    
    # Probe ports 22, 80, 443
    for p, eid in [(22, "ev-scan-1"), (80, "ev-scan-2"), (443, "ev-scan-3")]:
        alerts = engine.evaluate_event({
            "id": eid,
            "timestamp": "2026-08-10T19:00:00Z",
            "source_ip": src_ip,
            "destination_ip": "10.0.1.5",
            "destination_port": p,
            "event_type": "network_flow"
        })
    
    # 3rd port scan triggers T1046
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1046"
    assert len(alerts[0].evidenceEventIds) == 3

def test_no_label_leakage_in_detections():
    """
    Ensure detections are based solely on behavior and indicators, NOT on dataset labels.
    """
    engine = BehavioralRuleEngine()

    # 1. Event labeled "FTP-Patator" but with completely harmless benign ping behavior
    harmless_labeled_malicious = {
        "id": "ev-leak-1",
        "timestamp": "2026-08-10T19:00:00Z",
        "source_ip": "192.168.1.10",
        "command": "ping -c 1 8.8.8.8",
        "event_type": "process_create",
        "status": "SUCCESS",
        "label": "FTP-Patator"  # Dataset label
    }
    # Must NOT detect because behavior is benign
    alerts = engine.evaluate_event(harmless_labeled_malicious)
    assert len(alerts) == 0

    # 2. Event labeled "BENIGN" but executing malicious privilege escalation command
    malicious_labeled_benign = {
        "id": "ev-leak-2",
        "timestamp": "2026-08-10T19:00:05Z",
        "hostname": "srv-web-01",
        "command": "sudo bash",
        "event_type": "process_create",
        "status": "SUCCESS",
        "label": "BENIGN"
    }
    # Must detect because behavior is malicious
    alerts = engine.evaluate_event(malicious_labeled_benign)
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1548.003"

def test_incident_correlation_and_dynamic_attack_graph():
    engine = realtime_detection_engine
    
    # Send multi-stage attack events for same IP / Host
    events = [
        # Stage 1: Brute force
        {"id": "ev-1", "timestamp": "2026-08-10T19:00:01Z", "source_ip": "198.51.100.20", "hostname": "srv-db-01", "username": "postgres", "event_type": "auth", "action": "failed_login", "status": "FAILURE"},
        {"id": "ev-2", "timestamp": "2026-08-10T19:00:05Z", "source_ip": "198.51.100.20", "hostname": "srv-db-01", "username": "postgres", "event_type": "auth", "action": "failed_login", "status": "FAILURE"},
        {"id": "ev-3", "timestamp": "2026-08-10T19:00:10Z", "source_ip": "198.51.100.20", "hostname": "srv-db-01", "username": "postgres", "event_type": "auth", "action": "failed_login", "status": "FAILURE"},
        # Stage 2: Successful auth
        {"id": "ev-4", "timestamp": "2026-08-10T19:00:15Z", "source_ip": "198.51.100.20", "hostname": "srv-db-01", "username": "postgres", "event_type": "auth", "action": "login_success", "status": "SUCCESS"},
        # Stage 3: Sudo privesc
        {"id": "ev-5", "timestamp": "2026-08-10T19:00:30Z", "source_ip": "198.51.100.20", "hostname": "srv-db-01", "username": "postgres", "command": "sudo bash", "event_type": "process_create"},
        # Stage 4: Outbound exfiltration
        {"id": "ev-6", "timestamp": "2026-08-10T19:01:00Z", "source_ip": "198.51.100.20", "destination_ip": "203.0.113.99", "hostname": "srv-db-01", "bytes_out": 1200000, "event_type": "network_flow"}
    ]

    for ev in events:
        engine.process_event(ev)

    incidents = engine.get_active_incidents()
    assert len(incidents) == 1
    inc = incidents[0]
    
    assert inc.severity == "CRITICAL"
    assert "198.51.100.20" in inc.source_ips
    assert "srv-db-01" in inc.affected_hosts
    assert "postgres" in inc.users
    assert len(inc.mitre_tactics) >= 3
    assert len(inc.timeline) >= 4

    # Verify attack graph structure
    graph = inc.attack_graph
    assert len(graph.nodes) >= 4
    assert any(n.type == "IP" and n.value == "198.51.100.20" for n in graph.nodes)
    assert any(n.type == "HOST" and n.value == "srv-db-01" for n in graph.nodes)
    assert any(n.type == "USER" and n.value == "postgres" for n in graph.nodes)
    assert len(graph.edges) >= 3

def test_online_evaluation_metrics_and_significance_barrier():
    tracker = RealTimeEvaluationTracker()
    
    # 1. Less than 10 events -> Insufficient notice
    tracker.record_event_evaluation("BENIGN", False)  # TN
    tracker.record_event_evaluation("SSH-Patator", True)  # TP
    
    metrics = tracker.get_metrics()
    assert metrics.total_labeled_events == 2
    assert not metrics.is_statistically_significant
    assert "Insufficient labeled events" in metrics.notice
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0

    # 2. Add more events to exceed 10
    for _ in range(8):
        tracker.record_event_evaluation("BENIGN", False) # 8 more TNs
    
    metrics = tracker.get_metrics()
    assert metrics.total_labeled_events == 10
    assert metrics.is_statistically_significant
    assert "Statistically valid" in metrics.notice
    assert metrics.true_positives == 1
    assert metrics.true_negatives == 9
    assert metrics.accuracy == 1.0

def test_realtime_detection_rest_endpoints():
    client = TestClient(app)

    # 1. Reset
    resp = client.post("/api/incidents/reset")
    assert resp.status_code == 200

    # 2. Check active incidents (empty initially)
    resp = client.get("/api/incidents/active")
    assert resp.status_code == 200
    assert resp.json() == []

    # 3. Trigger detection via engine
    realtime_detection_engine.process_event({
        "id": "ev-rest-1",
        "timestamp": "2026-08-10T19:00:00Z",
        "hostname": "srv-prod-01",
        "username": "root",
        "command": "cat /etc/shadow",
        "event_type": "file_access",
        "label": "MALICIOUS"
    })

    # 4. Check active incidents
    resp = client.get("/api/incidents/active")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    inc_id = data[0]["incident_id"]

    # 5. Get incident detail
    resp = client.get(f"/api/incidents/{inc_id}")
    assert resp.status_code == 200
    inc_data = resp.json()
    assert inc_data["incident_id"] == inc_id
    assert len(inc_data["detections"]) == 1

    # 6. Evaluation metrics
    resp = client.get("/api/incidents/evaluation")
    assert resp.status_code == 200
    eval_data = resp.json()
    assert eval_data["total_labeled_events"] == 1
    assert eval_data["true_positives"] == 1

def test_websocket_stream_broadcasts_detection_alerts():
    client = TestClient(app)
    with client.websocket_connect("/ws/events") as ws:
        # Handshake
        welcome = ws.receive_json()
        assert welcome["type"] == "connected"

        # Broadcast a malicious event via streaming hub
        import asyncio
        asyncio.run(streaming_hub.broadcast_event({
            "id": "ev-ws-priv-1",
            "timestamp": "2026-08-10T19:05:00Z",
            "hostname": "srv-web-01",
            "username": "www-data",
            "command": "sudo bash",
            "event_type": "process_create",
            "label": "MALICIOUS"
        }))

        # Client should receive standard event + detection alert
        msg1 = ws.receive_json()
        assert msg1["type"] == "event"
        assert msg1["event_id"] == "ev-ws-priv-1"

        msg2 = ws.receive_json()
        assert msg2["type"] == "detection_alert"
        assert msg2["detection"]["technique_id"] == "T1548.003"
        assert msg2["active_incidents_count"] == 1
