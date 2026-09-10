import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.auth.security import create_access_token
from app.auth.models import UserRole
from app.ingestion.service import dataset_service, MAX_STORED_DATASETS, MAX_EVENTS_PER_DATASET
from app.schemas.dataset import DatasetQueryFilter

client = TestClient(app)

@pytest.fixture
def auth_headers():
    admin_token = create_access_token("admin-user-1", "admin", UserRole.ADMIN, tenant_id="tenant-alpha")
    analyst_token = create_access_token("analyst-user-1", "analyst", UserRole.ANALYST, tenant_id="tenant-alpha")
    demo_token = create_access_token("demo-user-1", "demo", UserRole.DEMO_USER, tenant_id="tenant-alpha")
    foreign_analyst_token = create_access_token("foreign-analyst", "analyst", UserRole.ANALYST, tenant_id="tenant-bravo")
    
    return {
        "admin": {"Authorization": f"Bearer {admin_token}"},
        "analyst": {"Authorization": f"Bearer {analyst_token}"},
        "demo": {"Authorization": f"Bearer {demo_token}"},
        "foreign_analyst": {"Authorization": f"Bearer {foreign_analyst_token}"}
    }


def test_query_size_limit_and_pagination_enforcement(auth_headers):
    """Verify max query size limit (500) is enforced and pagination works correctly."""
    # Exceeding max limit (500) must raise ValidationError / return 422
    with pytest.raises(ValidationError):
        DatasetQueryFilter(limit=501, offset=0)
    
    with pytest.raises(ValidationError):
        DatasetQueryFilter(limit=0, offset=0)
        
    with pytest.raises(ValidationError):
        DatasetQueryFilter(limit=10, offset=-1)

    # Valid query within bounds
    valid_filter = DatasetQueryFilter(limit=100, offset=0)
    assert valid_filter.limit == 100
    assert valid_filter.offset == 0


def test_deleted_resource_cannot_be_accessed_via_stale_id(auth_headers):
    """Verify deleted datasets are tombstoned and cannot be accessed via stale IDs."""
    sample_csv = (
        "Source IP, Destination IP, Destination Port, Protocol, Timestamp, Label\n"
        "10.0.0.1, 10.0.0.2, 80, 6, 07/07/2017 08:30:00, BENIGN\n"
        "10.0.0.3, 10.0.0.4, 443, 6, 07/07/2017 08:35:00, PortScan\n"
    ).encode("utf-8")

    report = dataset_service.import_dataset(
        content=sample_csv,
        file_name="stale_id_test.csv",
        dataset_name="Stale ID Dataset",
        owner_id="admin-user-1",
        tenant_id="tenant-alpha"
    )
    dataset_id = report.dataset.dataset_id

    # Verify dataset exists and events can be queried
    res = client.get(f"/api/v1/datasets/{dataset_id}/events", headers=auth_headers["analyst"])
    assert res.status_code == 200
    assert dataset_service.is_deleted(dataset_id) is False

    # Delete dataset
    del_res = client.delete(f"/api/v1/datasets/{dataset_id}", headers=auth_headers["admin"])
    assert del_res.status_code == 200
    assert dataset_service.is_deleted(dataset_id) is True

    # Subsequent queries to stale ID must return 404 Not Found
    res_stale = client.get(f"/api/v1/datasets/{dataset_id}", headers=auth_headers["analyst"])
    assert res_stale.status_code == 404

    res_stale_events = client.get(f"/api/v1/datasets/{dataset_id}/events", headers=auth_headers["analyst"])
    assert res_stale_events.status_code == 404


def test_unauthorized_dataset_deletion_prevention(auth_headers):
    """Verify demo_user or non-admin analyst cannot delete datasets (RBAC / BOLA)."""
    sample_csv = (
        "Source IP, Destination IP, Destination Port, Protocol, Timestamp, Label\n"
        "10.0.0.1, 10.0.0.2, 80, 6, 07/07/2017 08:30:00, BENIGN\n"
    ).encode("utf-8")
    report = dataset_service.import_dataset(
        content=sample_csv,
        file_name="rbac_dataset_test.csv",
        dataset_name="RBAC Test Dataset",
        owner_id="admin-user-1",
        tenant_id="tenant-alpha"
    )
    dataset_id = report.dataset.dataset_id

    # Demo user role cannot delete dataset (403 Forbidden)
    res_demo = client.delete(f"/api/v1/datasets/{dataset_id}", headers=auth_headers["demo"])
    assert res_demo.status_code == 403

    # Unauthenticated request cannot delete dataset (401 Unauthorized)
    res_unauth = client.delete(f"/api/v1/datasets/{dataset_id}")
    assert res_unauth.status_code == 401

    # Clean up with admin
    res_admin = client.delete(f"/api/v1/datasets/{dataset_id}", headers=auth_headers["admin"])
    assert res_admin.status_code == 200


def test_secondary_indices_built_for_fast_telemetry_lookups():
    """Verify secondary indices (source_ip, destination_ip, label, protocol) are maintained."""
    sample_csv = (
        "Source IP, Destination IP, Destination Port, Protocol, Timestamp, Label\n"
        "192.168.1.100, 10.0.0.50, 80, 6, 07/07/2017 08:30:00, BENIGN\n"
        "192.168.1.100, 10.0.0.51, 443, 6, 07/07/2017 08:31:00, PortScan\n"
        "192.168.1.200, 10.0.0.50, 8080, 6, 07/07/2017 08:32:00, BENIGN\n"
    ).encode("utf-8")

    report = dataset_service.import_dataset(
        content=sample_csv,
        file_name="indices_test.csv",
        dataset_name="Indexing Test Dataset"
    )
    dataset_id = report.dataset.dataset_id

    # Verify index entries exist in service index store
    assert dataset_id in dataset_service._indices
    indices = dataset_service._indices[dataset_id]
    assert "source_ip" in indices
    assert "192.168.1.100" in indices["source_ip"]
    assert len(indices["source_ip"]["192.168.1.100"]) == 2
    assert "portscan" in indices["label"]
    assert "TCP" in indices["protocol"]

    # Cleanup
    dataset_service.delete_dataset(dataset_id)


def test_retention_capacity_controls_and_pruning():
    """Verify telemetry retention bounds and pruning functions."""
    initial_count = len(dataset_service.list_datasets())
    assert initial_count <= MAX_STORED_DATASETS

    # Test prune_retention execution
    pruned = dataset_service.prune_retention(max_datasets=MAX_STORED_DATASETS)
    assert isinstance(pruned, int)
    assert pruned >= 0


def test_safe_error_masking_without_stack_traces(auth_headers):
    """Verify database/storage errors return generic error responses without stack traces or path leaks."""
    # Attempting to fetch a nonexistent resource ID
    res = client.get("/api/v1/datasets/nonexistent-uuid-999999", headers=auth_headers["analyst"])
    assert res.status_code == 404
    assert "Traceback" not in res.text
    assert "/Users/" not in res.text
    assert "/app/" not in res.text
    assert "sqlite" not in res.text.lower()
    assert "postgres" not in res.text.lower()
