import time
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.auth.models import UserRole
from app.auth.security import create_access_token

client = TestClient(app)

def get_auth_token(role: UserRole = UserRole.ANALYST, user_id: str = "analyst", tenant_id: str = "soc-org-primary", expires_in_minutes: int = 60) -> str:
    """Helper to generate signed test JWT tokens."""
    return create_access_token(
        user_id=user_id,
        username=user_id,
        role=role,
        tenant_id=tenant_id,
        expires_in_minutes=expires_in_minutes
    )

def get_auth_headers(role: UserRole = UserRole.ANALYST, user_id: str = "analyst", tenant_id: str = "soc-org-primary") -> dict:
    token = get_auth_token(role=role, user_id=user_id, tenant_id=tenant_id)
    return {"Authorization": f"Bearer {token}"}


class TestAuthenticationFlow:
    """Test login endpoint and credential verification."""

    def test_login_success_admin(self):
        resp = client.post("/api/v1/auth/login", json={
            "username": "admin",
            "password": "AdminSecret2026!"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["role"] == "ADMIN"
        assert data["user"]["username"] == "admin"

    def test_login_success_analyst(self):
        resp = client.post("/api/v1/auth/login", json={
            "username": "analyst",
            "password": "AnalystHunt2026!"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["user"]["role"] == "ANALYST"
        assert data["user"]["tenant_id"] == "soc-org-primary"

    def test_login_invalid_password_returns_401(self):
        resp = client.post("/api/v1/auth/login", json={
            "username": "admin",
            "password": "WrongPassword123!"
        })
        assert resp.status_code == 401
        assert "Invalid username or password" in resp.json()["detail"]

    def test_login_unknown_user_returns_401(self):
        resp = client.post("/api/v1/auth/login", json={
            "username": "nonexistent_user",
            "password": "SomePassword123!"
        })
        assert resp.status_code == 401
        assert "Invalid username or password" in resp.json()["detail"]

    def test_auth_me_with_valid_token(self):
        headers = get_auth_headers(role=UserRole.ANALYST, user_id="analyst")
        resp = client.get("/api/v1/auth/me", headers=headers)
        assert resp.status_code == 200
        user = resp.json()
        assert user["username"] == "analyst"
        assert user["role"] == "ANALYST"

    def test_auth_me_unauthenticated_returns_401(self):
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 401


class TestPublicVsProtectedEndpoints:
    """Verify public endpoints work unauthenticated and protected endpoints reject unauthenticated requests."""

    def test_public_root_endpoint(self):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_public_health_endpoints(self):
        resp1 = client.get("/api/v1/health")
        assert resp1.status_code == 200

        resp2 = client.get("/api/health/comprehensive")
        assert resp2.status_code == 200

    @pytest.mark.parametrize("method,path", [
        ("GET", "/api/v1/tools"),
        ("GET", "/api/v1/telemetry/events"),
        ("GET", "/api/v1/telemetry/scenarios"),
        ("GET", "/api/v1/telemetry/workstations"),
        ("GET", "/api/v1/datasets"),
        ("GET", "/api/incidents/active"),
        ("GET", "/api/incidents/evaluation"),
        ("GET", "/api/agents"),
        ("GET", "/api/scenarios"),
        ("GET", "/api/v1/hunts/sample"),
        ("POST", "/api/incidents/reset"),
        ("POST", "/api/v1/security/adversarial/run"),
        ("POST", "/api/events"),
        ("POST", "/api/agents/register"),
    ])
    def test_protected_endpoints_require_auth(self, method, path):
        if method == "GET":
            resp = client.get(path)
        elif method == "POST":
            resp = client.post(path, json={})
        assert resp.status_code == 401


class TestTokenSecurityAndValidation:
    """Verify expired, forged, and malformed tokens are rejected."""

    def test_expired_token_returns_401(self):
        # Create token that expired
        expired_token = create_access_token(
            user_id="usr-analyst-01",
            username="analyst",
            role=UserRole.ANALYST,
            expires_in_minutes=-10
        )
        resp = client.get("/api/v1/tools", headers={"Authorization": f"Bearer {expired_token}"})
        assert resp.status_code == 401
        assert "credentials" in resp.json()["detail"].lower()

    def test_forged_signature_token_returns_401(self):
        valid_token = get_auth_token(role=UserRole.ANALYST)
        # Tamper with token signature
        parts = valid_token.split(".")
        tampered_signature = "invalid_signature_xyz123"
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_signature}"

        resp = client.get("/api/v1/tools", headers={"Authorization": f"Bearer {tampered_token}"})
        assert resp.status_code == 401

    def test_malformed_authorization_header_returns_401(self):
        resp = client.get("/api/v1/tools", headers={"Authorization": "NotBearer abcdef"})
        assert resp.status_code == 401


class TestRoleBasedAccessControlAndPrivilegeEscalation:
    """Verify RBAC rules and privilege escalation defenses."""

    def test_analyst_can_access_tools_and_telemetry(self):
        analyst_headers = get_auth_headers(role=UserRole.ANALYST)
        resp = client.get("/api/v1/tools", headers=analyst_headers)
        assert resp.status_code == 200

        resp_sc = client.get("/api/v1/telemetry/scenarios", headers=analyst_headers)
        assert resp_sc.status_code == 200

    def test_analyst_cannot_reset_incidents_escalation_blocked(self):
        """Privilege escalation test: Analyst attempting Admin-only incident reset."""
        analyst_headers = get_auth_headers(role=UserRole.ANALYST)
        resp = client.post("/api/incidents/reset", headers=analyst_headers)
        assert resp.status_code == 403
        assert "Forbidden" in resp.json()["detail"]

    def test_admin_can_reset_incidents(self):
        admin_headers = get_auth_headers(role=UserRole.ADMIN)
        resp = client.post("/api/incidents/reset", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

    def test_analyst_cannot_run_adversarial_suite(self):
        analyst_headers = get_auth_headers(role=UserRole.ANALYST)
        resp = client.post("/api/v1/security/adversarial/run", headers=analyst_headers)
        assert resp.status_code == 403

    def test_admin_can_run_adversarial_suite(self):
        admin_headers = get_auth_headers(role=UserRole.ADMIN)
        resp = client.post("/api/v1/security/adversarial/run", headers=admin_headers)
        assert resp.status_code == 200


class TestMultiTenantBOLAIsolation:
    """Test Broken Object Level Authorization (BOLA) and multi-tenant resource access controls."""

    def test_analyst_cannot_access_other_tenant_dataset(self):
        # 1. Analyst 1 imports dataset under tenant-alpha
        analyst1_headers = get_auth_headers(role=UserRole.ANALYST, user_id="analyst-1", tenant_id="tenant-alpha")
        import_resp = client.post(
            "/api/v1/datasets/import/raw",
            headers=analyst1_headers,
            json={
                "dataset_name": "Tenant Alpha Dataset",
                "format_hint": "JSON_EVENTS",
                "content": '[{"timestamp": "2026-08-10T19:00:00Z", "source_type": "linux_auth", "username": "alpha_user", "event_type": "ssh_authentication"}]'
            }
        )
        assert import_resp.status_code == 200
        dataset_id = import_resp.json()["dataset"]["dataset_id"]

        # 2. Analyst 1 can view dataset metadata
        view_resp1 = client.get(f"/api/v1/datasets/{dataset_id}", headers=analyst1_headers)
        assert view_resp1.status_code == 200
        assert view_resp1.json()["dataset_name"] == "Tenant Alpha Dataset"

        # 3. Analyst 2 (tenant-beta) attempts to view dataset metadata -> MUST RETURN 403
        analyst2_headers = get_auth_headers(role=UserRole.ANALYST, user_id="analyst-2", tenant_id="tenant-beta")
        view_resp2 = client.get(f"/api/v1/datasets/{dataset_id}", headers=analyst2_headers)
        assert view_resp2.status_code == 403
        assert "Forbidden" in view_resp2.json()["detail"]

        # 4. Analyst 2 attempts to query dataset events -> MUST RETURN 403
        events_resp2 = client.get(f"/api/v1/datasets/{dataset_id}/events", headers=analyst2_headers)
        assert events_resp2.status_code == 403

        # 5. Analyst 2 attempts to delete dataset -> MUST RETURN 403 (Admin required anyway)
        del_resp2 = client.delete(f"/api/v1/datasets/{dataset_id}", headers=analyst2_headers)
        assert del_resp2.status_code == 403

        # 6. Admin can access dataset across any tenant
        admin_headers = get_auth_headers(role=UserRole.ADMIN, user_id="admin")
        view_admin = client.get(f"/api/v1/datasets/{dataset_id}", headers=admin_headers)
        assert view_admin.status_code == 200

        # Clean up
        del_admin = client.delete(f"/api/v1/datasets/{dataset_id}", headers=admin_headers)
        assert del_admin.status_code == 200


class TestAgentAuthentication:
    """Test Linux collector / agent token and API key authentication."""

    def test_agent_ingestion_with_valid_api_key_header(self):
        resp = client.post(
            "/api/events",
            headers={"X-API-Key": settings.SOC_AGENT_API_KEY},
            json={
                "agent_id": "agent-test-auth-01",
                "hostname": "srv-test-01",
                "agent_version": "1.0.0",
                "timestamp": "2026-08-10T19:00:00Z",
                "sequence_number": 1,
                "events": [
                    {
                        "id": "ev-auth-test-1",
                        "source_type": "linux_auth",
                        "username": "root",
                        "event_type": "ssh_authentication",
                        "action": "failed_password",
                        "status": "FAILURE"
                    }
                ]
            }
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

    def test_agent_ingestion_with_invalid_api_key_returns_401(self):
        resp = client.post(
            "/api/events",
            headers={"X-API-Key": "invalid_agent_secret_key_123"},
            json={
                "agent_id": "agent-test-auth-01",
                "hostname": "srv-test-01",
                "agent_version": "1.0.0",
                "timestamp": "2026-08-10T19:00:00Z",
                "sequence_number": 1,
                "events": []
            }
        )
        assert resp.status_code == 401

    def test_agent_registration_with_bearer_token(self):
        agent_token = get_auth_token(role=UserRole.AGENT, user_id="soc-linux-agent")
        resp = client.post(
            "/api/agents/register",
            headers={"Authorization": f"Bearer {agent_token}"},
            json={
                "agent_id": "agent-reg-test-01",
                "hostname": "sensor-01",
                "agent_version": "1.0.0",
                "platform": "Linux (Ubuntu 22.04)"
            }
        )
        assert resp.status_code == 200
        assert resp.json()["agent_id"] == "agent-reg-test-01"
