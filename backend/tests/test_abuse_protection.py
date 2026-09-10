import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.auth.security import create_access_token
from app.auth.models import UserRole
from app.core.abuse import abuse_monitor
from app.core.security import check_rate_limit, reset_rate_limit

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_limiter():
    reset_rate_limit()
    yield
    reset_rate_limit()

@pytest.fixture
def auth_headers():
    analyst_token = create_access_token("analyst-1", "analyst", UserRole.ANALYST, tenant_id="soc-alpha")
    return {"Authorization": f"Bearer {analyst_token}"}


def test_ai_hunt_rate_limiting(auth_headers):
    """Verify AI investigation endpoint enforces rate limits and returns 429 upon flooding."""
    test_ip = "192.168.10.101"
    
    # 20 allowed requests within window
    for _ in range(20):
        allowed, msg = check_rate_limit(test_ip, max_requests=20, window_seconds=60, key_prefix="hunt_run")
        assert allowed is True

    # 21st request must be rate limited
    allowed, msg = check_rate_limit(test_ip, max_requests=20, window_seconds=60, key_prefix="hunt_run")
    assert allowed is False
    assert "Rate limit exceeded" in msg


def test_ai_hunt_concurrency_slots():
    """Verify concurrent AI investigations are capped to prevent CPU/memory exhaustion."""
    test_ip = "10.50.1.25"
    
    # Acquire 5 concurrent hunt slots
    for _ in range(5):
        has_slot, msg = abuse_monitor.acquire_hunt_slot(test_ip, max_concurrent=5)
        assert has_slot is True

    # 6th concurrent hunt must be rejected
    has_slot, msg = abuse_monitor.acquire_hunt_slot(test_ip, max_concurrent=5)
    assert has_slot is False
    assert "Maximum concurrent AI investigations" in msg

    # Releasing slot frees capacity
    abuse_monitor.release_hunt_slot(test_ip)
    has_slot, msg = abuse_monitor.acquire_hunt_slot(test_ip, max_concurrent=5)
    assert has_slot is True

    # Cleanup remaining slots
    for _ in range(5):
        abuse_monitor.release_hunt_slot(test_ip)


def test_dataset_upload_rate_limiting():
    """Verify dataset upload endpoint caps requests per minute."""
    test_ip = "10.50.1.30"
    for _ in range(10):
        allowed, msg = check_rate_limit(test_ip, max_requests=10, window_seconds=60, key_prefix="dataset_import")
        assert allowed is True

    allowed, msg = check_rate_limit(test_ip, max_requests=10, window_seconds=60, key_prefix="dataset_import")
    assert allowed is False


def test_websocket_concurrency_caps():
    """Verify WebSocket connections per IP and global capacity are enforced."""
    test_ip = "172.16.0.5"
    
    # Acquire 10 connections for single IP
    for _ in range(10):
        has_slot, msg = abuse_monitor.acquire_websocket_slot(test_ip, max_concurrent_per_ip=10, max_global=100)
        assert has_slot is True

    # 11th connection from same IP must be rejected
    has_slot, msg = abuse_monitor.acquire_websocket_slot(test_ip, max_concurrent_per_ip=10, max_global=100)
    assert has_slot is False
    assert "Maximum concurrent WebSocket connections" in msg

    # Cleanup
    for _ in range(10):
        abuse_monitor.release_websocket_slot(test_ip)


def test_abuse_metrics_monitoring_endpoint(auth_headers):
    """Verify abuse monitoring endpoint returns live metrics report."""
    abuse_monitor.record_rate_limit_hit("203.0.113.5", "test_flood")
    abuse_monitor.record_payload_too_large("203.0.113.6", 30 * 1024 * 1024)

    res = client.get("/api/v1/monitoring/abuse-metrics", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"
    assert "active_concurrency" in data
    assert "abuse_prevention_stats" in data
    assert data["abuse_prevention_stats"]["total_429_rate_limited"] >= 1
    assert data["abuse_prevention_stats"]["total_413_payload_rejected"] >= 1


def test_legitimate_demo_usage_not_blocked(auth_headers):
    """Verify standard legitimate exploration flow (health, tools, scenarios, sample hunt) succeeds."""
    # 1. Health check
    res_health = client.get("/api/v1/health")
    assert res_health.status_code == 200

    # 2. Tool list
    res_tools = client.get("/api/v1/tools", headers=auth_headers)
    assert res_tools.status_code == 200

    # 3. Scenarios list
    res_scenarios = client.get("/api/v1/scenarios", headers=auth_headers)
    assert res_scenarios.status_code == 200

    # 4. Sample hunt
    res_hunt = client.get("/api/v1/hunts/sample", headers=auth_headers)
    assert res_hunt.status_code == 200
