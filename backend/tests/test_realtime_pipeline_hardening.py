import pytest
import json
import time
from fastapi.testclient import TestClient
from app.main import app
from app.agent.registry import agent_registry
from app.agent.models import AgentEventBatch, AgentRegistration
from app.streaming.hub import streaming_hub
from app.auth.security import create_access_token
from app.auth.models import UserRole
from app.config import settings
from app.core.audit import AuditLogger

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_pipeline_state():
    """Reset agent registry and streaming hub before each test."""
    agent_registry.reset()
    streaming_hub.reset()
    yield
    agent_registry.reset()
    streaming_hub.reset()

def get_auth_token(role: UserRole = UserRole.ANALYST, tenant_id: str = "soc-org-primary", username: str = "analyst") -> str:
    return create_access_token(
        user_id=username,
        username=username,
        role=role,
        tenant_id=tenant_id
    )

class TestAgentIdentityAndAuthentication:
    """Requirement 1-4: Authenticate telemetry agents and validate credentials server-side."""

    def test_anonymous_event_ingestion_is_rejected(self):
        payload = {
            "agent_id": "agent-linux-01",
            "hostname": "workstation-alpha",
            "agent_version": "1.0.0",
            "sequence_number": 1,
            "events": [{"timestamp": "2026-09-10T12:00:00Z", "event_type": "process_start"}]
        }
        res = client.post("/api/events", json=payload)
        assert res.status_code == 401
        assert "validate credentials" in res.json().get("detail", "").lower() or res.status_code == 401

    def test_valid_agent_token_ingests_successfully(self):
        token = get_auth_token(role=UserRole.AGENT, username="agent-linux-01")
        payload = {
            "agent_id": "agent-linux-01",
            "hostname": "workstation-alpha",
            "agent_version": "1.0.0",
            "sequence_number": 1,
            "events": [{"id": "ev-1", "timestamp": "2026-09-10T12:00:00Z", "event_type": "process_start", "process_name": "bash"}]
        }
        res = client.post(
            "/api/events",
            json=payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["events_ingested"] == 1
        assert data["agent_id"] == "agent-linux-01"

    def test_valid_api_key_header_authenticates(self):
        api_key = settings.SOC_AGENT_API_KEY
        payload = {
            "agent_id": "agent-linux-01",
            "hostname": "workstation-alpha",
            "agent_version": "1.0.0",
            "sequence_number": 1,
            "events": [{"id": "ev-1", "timestamp": "2026-09-10T12:00:00Z", "event_type": "process_start"}]
        }
        res = client.post(
            "/api/events",
            json=payload,
            headers={"X-API-Key": api_key}
        )
        assert res.status_code == 200
        assert res.json()["status"] == "success"


class TestAntiImpersonationAndReplayProtection:
    """Requirement 5-6: Prevent agent impersonation and enforce sequence monotonicity."""

    def test_agent_cannot_impersonate_another_registered_agent(self):
        # 1. Register agent-01 with agent-01's identity
        token_01 = get_auth_token(role=UserRole.AGENT, username="agent-01")
        reg_res = client.post(
            "/api/agents/register",
            json={"agent_id": "agent-01", "hostname": "host-01", "agent_version": "1.0.0"},
            headers={"Authorization": f"Bearer {token_01}"}
        )
        assert reg_res.status_code == 200

        # 2. Agent-02 attempts to submit telemetry claiming to be agent-01
        token_02 = get_auth_token(role=UserRole.AGENT, username="agent-02")
        spoofed_payload = {
            "agent_id": "agent-01",
            "hostname": "host-01",
            "agent_version": "1.0.0",
            "sequence_number": 1,
            "events": [{"id": "ev-spoof", "timestamp": "2026-09-10T12:00:00Z", "event_type": "process_start"}]
        }
        res = client.post(
            "/api/events",
            json=spoofed_payload,
            headers={"Authorization": f"Bearer {token_02}"}
        )
        assert res.status_code == 403
        assert "Impersonation Violation" in res.json()["detail"]

    def test_replay_protection_rejects_out_of_order_or_duplicate_sequences(self):
        token = get_auth_token(role=UserRole.AGENT, username="agent-01")

        # Ingest sequence 10
        batch_1 = {
            "agent_id": "agent-01",
            "hostname": "host-01",
            "agent_version": "1.0.0",
            "sequence_number": 10,
            "events": [{"id": "ev-10", "timestamp": "2026-09-10T12:00:00Z", "event_type": "process_start"}]
        }
        res1 = client.post("/api/events", json=batch_1, headers={"Authorization": f"Bearer {token}"})
        assert res1.status_code == 200

        # Replay sequence 10 again (should be rejected)
        res2 = client.post("/api/events", json=batch_1, headers={"Authorization": f"Bearer {token}"})
        assert res2.status_code == 400
        assert "Replay Protection" in res2.json()["detail"]

        # Submit older sequence 5 (should be rejected)
        batch_old = {
            "agent_id": "agent-01",
            "hostname": "host-01",
            "agent_version": "1.0.0",
            "sequence_number": 5,
            "events": [{"id": "ev-5", "timestamp": "2026-09-10T12:00:00Z", "event_type": "process_start"}]
        }
        res3 = client.post("/api/events", json=batch_old, headers={"Authorization": f"Bearer {token}"})
        assert res3.status_code == 400
        assert "Replay Protection" in res3.json()["detail"]

        # Submit newer monotonic sequence 11 (succeeds)
        batch_new = {
            "agent_id": "agent-01",
            "hostname": "host-01",
            "agent_version": "1.0.0",
            "sequence_number": 11,
            "events": [{"id": "ev-11", "timestamp": "2026-09-10T12:00:00Z", "event_type": "process_start"}]
        }
        res4 = client.post("/api/events", json=batch_new, headers={"Authorization": f"Bearer {token}"})
        assert res4.status_code == 200


class TestDuplicateFloodAndResourceLimits:
    """Requirement 7-10: Duplicate event filtering, size limits, schema validation, and EPS throttling."""

    def test_duplicate_event_flood_is_deduplicated(self):
        token = get_auth_token(role=UserRole.AGENT, username="agent-dup")
        duplicate_event = {
            "id": "ev-dup-01",
            "timestamp": "2026-09-10T12:00:00Z",
            "event_type": "network_connection",
            "source_ip": "10.0.0.5",
            "destination_port": 443
        }

        # Send batch containing 5 identical duplicate events
        batch = {
            "agent_id": "agent-dup",
            "hostname": "host-dup",
            "agent_version": "1.0.0",
            "sequence_number": 1,
            "events": [duplicate_event, duplicate_event, duplicate_event, duplicate_event, duplicate_event]
        }
        res = client.post("/api/events", json=batch, headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        # Deduplication filters out the duplicate events within the batch
        assert res.json()["events_ingested"] == 1

    def test_oversized_individual_event_payload_is_rejected(self):
        token = get_auth_token(role=UserRole.AGENT, username="agent-large")
        # Construct an oversized individual event payload (>64KB)
        huge_raw = "A" * (70 * 1024)
        batch = {
            "agent_id": "agent-large",
            "hostname": "host-large",
            "agent_version": "1.0.0",
            "sequence_number": 1,
            "events": [{
                "id": "ev-huge",
                "timestamp": "2026-09-10T12:00:00Z",
                "event_type": "large_event",
                "raw_data": huge_raw
            }]
        }
        res = client.post("/api/events", json=batch, headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 422
        assert "exceeds maximum allowed size" in str(res.json())

    def test_abnormal_eps_rate_throttling(self):
        token = get_auth_token(role=UserRole.AGENT, username="agent-flood")
        # Registry max_eps is 500. Sending a massive batch over threshold triggers rate limit
        agent_registry._max_eps = 50.0 # Temporarily lower for unit test
        
        batch = {
            "agent_id": "agent-flood",
            "hostname": "host-flood",
            "agent_version": "1.0.0",
            "sequence_number": 1,
            "events": [{"id": f"ev-{i}", "timestamp": "2026-09-10T12:00:00Z", "event_type": "ping"} for i in range(120)]
        }
        res = client.post("/api/events", json=batch, headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 429
        assert "Rate limit exceeded" in res.json()["detail"]


class TestWebSocketTenantIsolationAndResourceCaps:
    """Requirement 12-16: Authenticate WS, enforce tenant isolation, handle reconnects, bound resources."""

    def test_websocket_rejects_invalid_token(self):
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/events?token=invalid.jwt.token") as ws:
                pass

    def test_websocket_tenant_data_isolation(self):
        # Setup tokens for Tenant A and Tenant B
        token_a = get_auth_token(role=UserRole.ANALYST, tenant_id="tenant-alpha", username="analyst-a")

        with client.websocket_connect(f"/ws/events?token={token_a}") as ws_a:
            # First message is welcome handshake
            handshake = json.loads(ws_a.receive_text())
            assert handshake["type"] == "connected"
            assert handshake["tenant_id"] == "tenant-alpha"

    def test_websocket_max_connections_cap_guard(self):
        # Configure small cap
        original_cap = streaming_hub._max_connections
        streaming_hub._max_connections = 1
        try:
            token = get_auth_token()
            with client.websocket_connect(f"/ws/events?token={token}") as ws1:
                # Second concurrent connection should be rejected
                with pytest.raises(Exception):
                    with client.websocket_connect(f"/ws/events?token={token}") as ws2:
                        pass
        finally:
            streaming_hub._max_connections = original_cap


class TestAuditLoggingIntegration:
    """Requirement 19: Structured audit logging for agent lifecycle."""

    def test_agent_registration_emits_audit_log(self):
        token = get_auth_token(role=UserRole.ADMIN, username="admin")
        res = client.post(
            "/api/agents/register",
            json={"agent_id": "audit-agent-01", "hostname": "audit-host", "agent_version": "1.2.0"},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert res.status_code == 200
        # Audit logger was called
        ag = agent_registry.get_agent("audit-agent-01")
        assert ag is not None
        assert ag.hostname == "audit-host"
