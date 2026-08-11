import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.security import sanitize_input_string, is_valid_ip, check_rate_limit

client = TestClient(app)

def test_secure_http_headers():
    response = client.get("/api/v1/health")
    assert response.status_code == 200

    # Verify Secure HTTP Headers added by production middleware
    headers = response.headers
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert "Content-Security-Policy" in headers

def test_rate_limiting_middleware():
    test_ip = "192.168.1.50"
    # Trigger 10 allowed requests
    for _ in range(10):
        allowed, msg = check_rate_limit(test_ip, max_requests=10, window_seconds=60)
        assert allowed is True

    # 11th request must be rejected
    allowed, msg = check_rate_limit(test_ip, max_requests=10, window_seconds=60)
    assert allowed is False
    assert "Rate limit exceeded" in msg

def test_input_sanitization_and_ip_validation():
    malicious_input = "<script>alert('xss')</script>\x00admin"
    sanitized = sanitize_input_string(malicious_input)
    assert "<script>" not in sanitized
    assert "&lt;script&gt;" in sanitized
    assert "\x00" not in sanitized

    assert is_valid_ip("192.168.100.99") is True
    assert is_valid_ip("999.999.999.999") is False
