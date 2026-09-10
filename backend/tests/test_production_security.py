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
    assert "frame-ancestors 'none'" in headers.get("Content-Security-Policy", "")
    assert headers.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains; preload"
    assert "camera=()" in headers.get("Permissions-Policy", "")
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

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

def test_deleted_resource_cannot_be_accessed_via_stale_id():
    from app.ingestion.service import dataset_service
    from app.schemas.dataset import DatasetQueryFilter
    from app.auth.security import create_access_token
    from app.auth.models import UserRole

    # Ingest a temporary dataset
    report = dataset_service.import_dataset(
        content=b"Source IP,Destination IP,Protocol,Label\n10.0.0.1,10.0.0.2,TCP,BENIGN",
        file_name="temp_test_ds.csv",
        dataset_name="Temporary Stale ID Test"
    )
    ds_id = report.dataset.dataset_id
    assert dataset_service.get_dataset(ds_id) is not None

    # Delete dataset
    admin_token = create_access_token("admin-1", "admin", UserRole.ADMIN)
    del_res = client.delete(f"/api/v1/datasets/{ds_id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert del_res.status_code == 200

    # Querying deleted dataset with stale ID returns 404
    analyst_token = create_access_token("analyst-1", "analyst", UserRole.ANALYST)
    get_res = client.get(f"/api/v1/datasets/{ds_id}/events", headers={"Authorization": f"Bearer {analyst_token}"})
    assert get_res.status_code == 404
    assert dataset_service.get_dataset(ds_id) is None

def test_unbounded_query_limit_capping_and_pagination():
    from app.ingestion.service import dataset_service
    from app.schemas.dataset import DatasetQueryFilter

    csv_data = (
        "Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration, Total Length of Fwd Packets, Total Length of Bwd Packets, Label\n"
        "192.168.10.5, 49152, 192.168.10.50, 22, 6, 07/07/2017 08:30:00, 45000, 1280, 4200, BENIGN\n"
        "192.168.10.8, 51200, 192.168.10.50, 80, 6, 07/07/2017 08:45:00, 120000, 45000, 89000, BENIGN\n"
    ).encode("utf-8")
    report = dataset_service.import_dataset(
        content=csv_data,
        file_name="pagination_test.csv",
        dataset_name="Pagination Test Dataset"
    )
    ds_id = report.dataset.dataset_id


    # Request with limit=5000 (exceeding max 500) is rejected by schema validator
    import pytest
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        DatasetQueryFilter(limit=5000, offset=0)

    # Valid paginated query with limit=1 returns 1 event and total >= 2
    valid_flt = DatasetQueryFilter(limit=1, offset=0)
    events, total = dataset_service.get_dataset_events(ds_id, valid_flt)
    assert len(events) == 1
    assert total >= 2


def test_database_retention_pruning():
    from app.ingestion.service import dataset_service

    # Verify retention prune method runs safely
    pruned = dataset_service.prune_retention(max_datasets=100)
    assert isinstance(pruned, int)
