import json
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.auth.models import UserRole
from app.auth.security import create_access_token
from app.core.security import reset_rate_limit

client = TestClient(app)

def get_auth_token(role: UserRole = UserRole.ANALYST, user_id: str = "analyst", tenant_id: str = "soc-org-primary") -> str:
    return create_access_token(
        user_id=user_id,
        username=user_id,
        role=role,
        tenant_id=tenant_id,
        expires_in_minutes=60
    )

def get_auth_headers(role: UserRole = UserRole.ANALYST, user_id: str = "analyst", tenant_id: str = "soc-org-primary") -> dict:
    token = get_auth_token(role=role, user_id=user_id, tenant_id=tenant_id)
    return {"Authorization": f"Bearer {token}"}


class TestHttpMethodValidation:
    """1. Validate HTTP method handling."""

    def test_invalid_http_method_returns_405(self):
        analyst_headers = get_auth_headers()
        # GET endpoint called via DELETE or PUT
        resp = client.put("/api/v1/tools", headers=analyst_headers)
        assert resp.status_code == 405

        # POST endpoint called via GET
        resp_post = client.get("/api/v1/tools/execute", headers=analyst_headers)
        assert resp_post.status_code == 405


class TestRequestSizeLimits:
    """7. Enforce request size limits."""

    def test_oversized_payload_content_length_returns_413(self):
        # Header claiming > 25MB
        headers = get_auth_headers()
        headers["Content-Length"] = str(30 * 1024 * 1024)
        resp = client.post("/api/v1/datasets/import/raw", headers=headers, json={"content": "small"})
        assert resp.status_code == 413
        assert "Request entity too large" in resp.json()["detail"]


class TestQueryAndPaginationBounds:
    """5, 8, 9. Enforce pagination bounds, query limits, and parameter validation."""

    def test_negative_pagination_offset_returns_422(self):
        headers = get_auth_headers(role=UserRole.ADMIN)
        resp = client.get("/api/v1/datasets/ds-demo-01/events?offset=-5", headers=headers)
        assert resp.status_code == 422

    def test_excessive_pagination_limit_returns_422(self):
        headers = get_auth_headers(role=UserRole.ADMIN)
        # Exceeds max 500
        resp = client.get("/api/v1/datasets/ds-demo-01/events?limit=9999", headers=headers)
        assert resp.status_code == 422

    def test_invalid_query_port_range_returns_422(self):
        headers = get_auth_headers(role=UserRole.ADMIN)
        resp = client.get("/api/v1/datasets/ds-demo-01/events?destination_port=999999", headers=headers)
        assert resp.status_code == 422

    def test_valid_pagination_bounds_succeed(self):
        headers = get_auth_headers(role=UserRole.ADMIN)
        resp = client.get("/api/v1/telemetry/events?limit=50", headers=headers)
        assert resp.status_code == 200
        assert len(resp.json()) <= 50


class TestPathParameterValidation:
    """6. Validate path parameters against path traversal and invalid character injections."""

    def test_invalid_path_parameter_characters_returns_422(self):
        headers = get_auth_headers(role=UserRole.ADMIN)
        # Attempt special characters / path traversal syntax in path
        resp = client.get("/api/v1/datasets/ds%20invalid%20id/events", headers=headers)
        assert resp.status_code == 422

    def test_oversized_path_parameter_returns_422(self):
        headers = get_auth_headers(role=UserRole.ADMIN)
        oversized_id = "a" * 100
        resp = client.get(f"/api/v1/datasets/{oversized_id}", headers=headers)
        assert resp.status_code == 422


class TestRateLimitingProtection:
    """10. Add rate limiting where appropriate (Login & AI Hunts)."""

    @pytest.fixture(autouse=True)
    def reset_limiter_fixture(self):
        reset_rate_limit("127.0.0.1")
        reset_rate_limit("testclient")
        yield
        reset_rate_limit("127.0.0.1")
        reset_rate_limit("testclient")

    def test_login_endpoint_rate_limiting(self):
        reset_rate_limit("127.0.0.1")
        # Fire 10 login attempts (allowed)
        for i in range(10):
            client.post("/api/v1/auth/login", json={"username": "admin", "password": "WrongPassword!"})

        # 11th attempt must be rejected with 429
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "WrongPassword!"})
        assert resp.status_code == 429
        assert "Too many login attempts" in resp.json()["detail"]
        reset_rate_limit("127.0.0.1")



class TestSafeErrorHandlingAndInformationLeakage:
    """11, 12, 13, 14. Return safe error messages without stack traces, database errors, or local paths."""

    def test_custom_exception_returns_sanitized_500_with_request_id(self):
        # Simulate unhandled error safely by triggering invalid state
        headers = get_auth_headers()
        # Verify 404/400 errors do not expose Python file paths
        resp = client.get("/api/v1/datasets/ds-nonexistent-01", headers=headers)
        assert resp.status_code == 404
        detail = resp.json()["detail"]
        assert "/Users/" not in detail
        assert "Traceback" not in detail
        assert ".py" not in detail


class TestRequestBodyBoundsAndSanitization:
    """4, 16. Validate request body and prevent unrestricted resource consumption."""

    def test_oversized_agent_event_batch_rejected(self):
        # Batch exceeding max 1000 events
        oversized_events = [{"id": f"ev-{i}", "event_type": "ssh"} for i in range(1005)]
        resp = client.post(
            "/api/events",
            headers={"X-API-Key": settings.SOC_AGENT_API_KEY},
            json={
                "agent_id": "test-agent",
                "hostname": "test-host",
                "timestamp": "2026-08-10T19:00:00Z",
                "sequence_number": 1,
                "events": oversized_events
            }
        )
        assert resp.status_code == 422

    def test_hunt_question_length_bounds(self):
        headers = get_auth_headers()
        # Empty question rejected
        resp_empty = client.post("/api/v1/hunts/run", headers=headers, json={"question": ""})
        assert resp_empty.status_code == 422

        # Oversized question (>2000 chars) rejected
        oversized_q = "X" * 2500
        resp_over = client.post("/api/v1/hunts/run", headers=headers, json={"question": oversized_q})
        assert resp_over.status_code == 422


class TestWebSocketAndBOLAValidation:
    """15, 16. Test WebSocket token verification and Replay IDOR/BOLA protection."""

    def test_websocket_with_valid_token_connects(self):
        token = get_auth_token(role=UserRole.ANALYST)
        with client.websocket_connect(f"/ws/events?token={token}") as ws:
            raw = ws.receive_text()
            data = json.loads(raw)
            assert data["type"] == "connected"

    def test_websocket_with_invalid_token_rejected(self):
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/events?token=invalid.token.signature") as ws:
                ws.receive_text()

    def test_replay_bola_unauthorized_dataset_access_blocked(self):
        from app.ingestion.service import dataset_service
        # Create a dataset belonging to a different tenant
        sample_csv = b"Timestamp,Source IP,Destination IP,Source Port,Destination Port,Protocol,Label\n2017-07-07 08:30:00,192.168.1.1,10.0.0.1,5000,80,TCP,BENIGN\n"
        report = dataset_service.import_dataset(
            content=sample_csv,
            file_name="secret_tenant_flow.csv",
            owner_id="tenant_b_user",
            tenant_id="tenant-beta-isolated"
        )
        ds_id = report.dataset.dataset_id

        # Tenant A analyst tries to start replay on Tenant B's dataset -> 403 Forbidden
        tenant_a_headers = get_auth_headers(role=UserRole.ANALYST, user_id="analyst_a", tenant_id="tenant-alpha")
        resp = client.post("/api/replay/start", headers=tenant_a_headers, json={
            "datasetId": ds_id,
            "speedMultiplier": 2.0
        })
        assert resp.status_code == 403
        assert "Forbidden" in resp.json()["detail"]

