import pytest
from fastapi.testclient import TestClient
from app.main import app

from app.auth.models import UserRole
from app.auth.security import create_access_token

client = TestClient(app)
auth_headers = {
    "Authorization": f"Bearer {create_access_token('usr-analyst-01', 'analyst', UserRole.ANALYST)}"
}

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["project"] == "Autonomous Threat-Hunting Copilot"
    assert data["status"] == "ONLINE"

def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert data["tool_gateway"]["status"] == "ACTIVE"
    assert data["tool_gateway"]["registered_tools_count"] == 11
    assert data["tool_gateway"]["enforce_read_only"] is True

def test_list_tools_endpoint():
    # Unauthenticated returns 401
    unauth_res = client.get("/api/v1/tools")
    assert unauth_res.status_code == 401

    # Authenticated returns 200
    response = client.get("/api/v1/tools", headers=auth_headers)
    assert response.status_code == 200
    tools = response.json()
    assert len(tools) == 11
    tool_names = [t["name"] for t in tools]
    assert "search_authentication_events" in tool_names
    assert "get_host_timeline" in tool_names
    assert "scan_open_ports" in tool_names
    assert "collect_workstation_telemetry" in tool_names

def test_sample_hunt_endpoint():
    response = client.get("/api/v1/hunts/sample", headers=auth_headers)
    assert response.status_code == 200
    hunt = response.json()
    assert hunt["question"] == "Find evidence of suspicious SSH activity."
    assert len(hunt["evidence"]) > 0
    assert len(hunt["findings"]) > 0
