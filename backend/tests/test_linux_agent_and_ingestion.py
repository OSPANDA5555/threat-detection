import pytest
import os
import sys
import json
import tempfile
from fastapi.testclient import TestClient

# Add project root to sys.path so we can import the standalone agent
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.main import app
from app.agent.registry import agent_registry
from app.detection.engine import realtime_detection_engine
from app.streaming.hub import streaming_hub
from agent.linux_collector import (
    CredentialSanitizer,
    LinuxTelemetryParsers,
    CheckpointTracker,
    LinuxCollectorAgent
)

@pytest.fixture(autouse=True)
def reset_state():
    agent_registry.reset()
    realtime_detection_engine.reset()
    streaming_hub.reset()
    yield
    agent_registry.reset()
    realtime_detection_engine.reset()
    streaming_hub.reset()

def test_credential_sanitizer_redacts_passwords_and_private_keys():
    # 1. Password in command line
    raw_cmd = "mysql -u admin -p SecretPassword123! -h db.corp.internal"
    sanitized = CredentialSanitizer.sanitize(raw_cmd)
    assert "SecretPassword123!" not in sanitized
    assert "[REDACTED_PASSWORD]" in sanitized

    # 2. RSA private key
    raw_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...secretkeycontent...\n-----END RSA PRIVATE KEY-----"
    sanitized_key = CredentialSanitizer.sanitize(raw_key)
    assert "secretkeycontent" not in sanitized_key
    assert "[REDACTED_PRIVATE_KEY]" in sanitized_key

    # 3. Bearer token
    raw_token = "curl -H 'Authorization: Bearer my_super_secret_jwt_token_12345' https://api.corp"
    sanitized_token = CredentialSanitizer.sanitize(raw_token)
    assert "my_super_secret_jwt_token_12345" not in sanitized_token
    assert "Bearer [REDACTED_TOKEN]" in sanitized_token

def test_parse_auth_line_ssh_failed_password():
    line = "Oct 15 14:02:11 debian-srv sshd[4821]: Failed password for invalid user root from 192.168.1.100 port 54321 ssh2"
    ev = LinuxTelemetryParsers.parse_auth_line(line, hostname="debian-srv")
    assert ev is not None
    assert ev["source_type"] == "linux_auth"
    assert ev["source_ip"] == "192.168.1.100"
    assert ev["source_port"] == 54321
    assert ev["destination_port"] == 22
    assert ev["username"] == "root"
    assert ev["status"] == "FAILURE"
    assert ev["event_type"] == "ssh_authentication"

def test_parse_auth_line_sudo_execution():
    line = "Oct 15 14:03:00 debian-srv sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
    ev = LinuxTelemetryParsers.parse_auth_line(line, hostname="debian-srv")
    assert ev is not None
    assert ev["username"] == "alice"
    assert ev["process_name"] == "sudo"
    assert ev["command"] == "/bin/bash"
    assert ev["status"] == "SUCCESS"
    assert ev["severity"] == "HIGH"

def test_parse_audit_line_execve():
    line = 'type=EXECVE msg=audit(1691695800.123:456): argc=3 a0="cat" a1="/etc/shadow"'
    ev = LinuxTelemetryParsers.parse_audit_line(line, hostname="ubuntu-srv")
    assert ev is not None
    assert ev["source_type"] == "linux_audit"
    assert ev["command"] == "cat /etc/shadow"
    assert ev["process_name"] == "cat"
    assert ev["status"] == "SUCCESS"

def test_checkpoint_tracker_offset_persistence():
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        chk_path = f.name

    try:
        tracker = CheckpointTracker(chk_path)
        tracker.update_offset("/var/log/auth.log", 1024)
        tracker.update_offset("/var/log/audit/audit.log", 2048)

        # Reload from disk
        tracker2 = CheckpointTracker(chk_path)
        assert tracker2.get_offset("/var/log/auth.log") == 1024
        assert tracker2.get_offset("/var/log/audit/audit.log") == 2048
        assert tracker2.get_offset("/nonexistent.log") == 0
    finally:
        if os.path.exists(chk_path):
            os.remove(chk_path)

def test_agent_registry_lifecycle_and_status():
    registry = agent_registry
    
    # 1. Register agent
    status = registry.register_or_update(
        agent_id="agent-deb-01",
        hostname="srv-debian-01",
        agent_version="1.0.0",
        platform="Linux 6.8",
        ip_address="10.0.1.25"
    )
    assert status.agent_id == "agent-deb-01"
    assert status.status == "ONLINE"
    assert status.hostname == "srv-debian-01"

    # 2. Record ingestion
    status2 = registry.record_ingestion(
        agent_id="agent-deb-01",
        hostname="srv-debian-01",
        agent_version="1.0.0",
        sequence_number=1,
        events_count=10
    )
    assert status2.total_events_sent == 10
    assert status2.latest_sequence == 1

    # 3. Query list
    agents = registry.list_agents()
    assert len(agents) == 1
    assert agents[0].agent_id == "agent-deb-01"

def test_post_events_api_ingestion_and_heartbeat():
    client = TestClient(app)

    batch_payload = {
        "agent_id": "agent-linux-vm-01",
        "hostname": "test-vm-ubuntu",
        "agent_version": "1.0.0",
        "timestamp": "2026-08-10T19:00:00Z",
        "sequence_number": 1,
        "events": [
            {
                "source_type": "linux_auth",
                "source": "auth.log",
                "source_ip": "192.168.1.88",
                "source_port": 50123,
                "username": "root",
                "process_name": "sshd",
                "event_type": "ssh_authentication",
                "action": "failed_password",
                "status": "FAILURE"
            },
            {
                "source_type": "linux_auth",
                "source": "auth.log",
                "username": "alice",
                "process_name": "sudo",
                "command": "sudo -i",
                "event_type": "process_create",
                "action": "sudo_execution",
                "status": "SUCCESS"
            }
        ]
    }

    from app.config import settings
    from app.auth.models import UserRole
    from app.auth.security import create_access_token
    agent_headers = {"X-API-Key": settings.SOC_AGENT_API_KEY}
    analyst_headers = {"Authorization": f"Bearer {create_access_token('usr-analyst-01', 'analyst', UserRole.ANALYST)}"}

    resp = client.post("/api/events", json=batch_payload, headers=agent_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["agent_id"] == "agent-linux-vm-01"
    assert data["events_ingested"] == 2
    assert data["latest_sequence"] == 1

    # Verify agent appears in GET /api/agents
    resp_agents = client.get("/api/agents", headers=analyst_headers)
    assert resp_agents.status_code == 200
    agents_list = resp_agents.json()
    assert len(agents_list) == 1
    assert agents_list[0]["agent_id"] == "agent-linux-vm-01"
    assert agents_list[0]["status"] == "ONLINE"
    assert agents_list[0]["total_events_sent"] == 2

    # Verify specific agent status endpoint
    resp_detail = client.get("/api/agents/agent-linux-vm-01", headers=analyst_headers)
    assert resp_detail.status_code == 200
    assert resp_detail.json()["hostname"] == "test-vm-ubuntu"

def test_end_to_end_agent_telemetry_triggers_behavioral_detections():
    """
    Ensure events ingested from a Linux agent flow directly through the detection
    engine and trigger behavioral alerts and active incidents.
    """
    client = TestClient(app)
    from app.config import settings
    from app.auth.models import UserRole
    from app.auth.security import create_access_token
    agent_headers = {"X-API-Key": settings.SOC_AGENT_API_KEY}
    analyst_headers = {"Authorization": f"Bearer {create_access_token('usr-analyst-01', 'analyst', UserRole.ANALYST)}"}

    # Ingest 3 failed SSH auth events from same attacker IP
    for i in range(1, 4):
        client.post("/api/events", json={
            "agent_id": "agent-linux-vm-02",
            "hostname": "prod-web-01",
            "agent_version": "1.0.0",
            "timestamp": f"2026-08-10T19:00:{10*i:02d}Z",
            "sequence_number": i,
            "events": [
                {
                    "id": f"ev-agent-fail-{i}",
                    "timestamp": f"2026-08-10T19:00:{10*i:02d}Z",
                    "source_type": "linux_auth",
                    "source_ip": "203.0.113.77",
                    "destination_port": 22,
                    "username": "admin",
                    "event_type": "ssh_authentication",
                    "action": "failed_password",
                    "status": "FAILURE"
                }
            ]
        }, headers=agent_headers)

    # Ingest successful login following brute force
    client.post("/api/events", json={
        "agent_id": "agent-linux-vm-02",
        "hostname": "prod-web-01",
        "agent_version": "1.0.0",
        "timestamp": "2026-08-10T19:01:00Z",
        "sequence_number": 4,
        "events": [
            {
                "id": "ev-agent-succ-4",
                "timestamp": "2026-08-10T19:01:00Z",
                "source_type": "linux_auth",
                "source_ip": "203.0.113.77",
                "destination_port": 22,
                "username": "admin",
                "event_type": "ssh_authentication",
                "action": "accepted_password",
                "status": "SUCCESS"
            }
        ]
    }, headers=agent_headers)

    # Check that an active incident was created
    resp_inc = client.get("/api/incidents/active", headers=analyst_headers)
    assert resp_inc.status_code == 200
    incidents = resp_inc.json()
    assert len(incidents) == 1
    assert "203.0.113.77" in incidents[0]["source_ips"]
    assert "prod-web-01" in incidents[0]["affected_hosts"]
    assert incidents[0]["severity"] == "CRITICAL"
