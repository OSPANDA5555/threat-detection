import pytest
import io
from fastapi.testclient import TestClient
from app.main import app
from app.schemas.dataset import NormalizedEvent, DatasetMetadata
from app.ingestion.validator import validate_ip, validate_port, parse_and_validate_timestamp, parse_protocol, get_attack_category
from app.ingestion.normalizers.cic_ids2017 import CicIds2017Normalizer
from app.ingestion.normalizers.json_normalizer import JsonEventNormalizer
from app.ingestion.normalizers.pcap_adapter import PcapIngestionAdapter
from app.ingestion.service import dataset_service

client = TestClient(app)

def test_validator_ip():
    # Valid IPs
    ip, err = validate_ip("192.168.1.100")
    assert ip == "192.168.1.100" and err is None

    ip, err = validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert ip is not None and err is None

    # Invalid IPs
    ip, err = validate_ip("999.999.999.999")
    assert ip is None and "Invalid IP address" in err

    ip, err = validate_ip("not_an_ip")
    assert ip is None and "Invalid IP address" in err

    ip, err = validate_ip(None)
    assert ip is None and "Missing IP" in err

def test_validator_port():
    # Valid ports
    port, err = validate_port(80)
    assert port == 80 and err is None

    port, err = validate_port("443")
    assert port == 443 and err is None

    port, err = validate_port(None)
    assert port is None and err is None

    # Invalid ports
    port, err = validate_port(99999)
    assert port is None and "out of valid range" in err

    port, err = validate_port(-1)
    assert port is None and "out of valid range" in err

    port, err = validate_port("abc")
    assert port is None and "Invalid port" in err

def test_validator_timestamp():
    # ISO-8601
    ts, err = parse_and_validate_timestamp("2026-08-10T19:30:00Z")
    assert ts == "2026-08-10T19:30:00+00:00" and err is None

    # CIC-IDS2017 style
    ts, err = parse_and_validate_timestamp("07/07/2017 08:30:00")
    assert ts is not None and "2017-07-07" in ts and err is None

    # Invalid timestamp
    ts, err = parse_and_validate_timestamp("invalid_date_format_xyz")
    assert ts is None and "Unrecognized timestamp" in err

def test_cic_ids2017_csv_parsing_and_normalization():
    csv_content = (
        "Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration, Total Length of Fwd Packets, Total Length of Bwd Packets, Label\n"
        "192.168.10.5, 49152, 192.168.10.50, 22, 6, 07/07/2017 08:30:00, 45000, 1280, 4200, SSH-Patator\n"
        "192.168.10.8, 51200, 192.168.10.50, 80, 6, 07/07/2017 08:45:00, 120000, 45000, 89000, DoS Hulk\n"
        "192.168.10.14, 52100, 192.168.10.50, 80, 6, 07/07/2017 09:10:00, 85000, 3200, 1400, BENIGN\n"
        "192.168.10.19, 60100, 192.168.10.20, 5432, 6, 07/07/2017 09:25:00, 62000, 1500, 3400, PortScan\n"
    ).encode("utf-8")

    normalizer = CicIds2017Normalizer()
    metadata, events = normalizer.parse_and_normalize(csv_content, "test_cic.csv", "CIC Test Dataset")

    assert metadata.total_events == 4
    assert metadata.benign_events == 1
    assert metadata.malicious_events == 3
    assert metadata.available_labels.get("SSH-Patator") == 1
    assert metadata.available_labels.get("DoS Hulk") == 1
    assert metadata.available_labels.get("PortScan") == 1
    assert metadata.available_labels.get("BENIGN") == 1
    assert metadata.malformed_records_count == 0

    # Verify Normalized Event Fields & Schema Integrity
    e0 = events[0]
    assert e0.source_ip == "192.168.10.5"
    assert e0.source_port == 49152
    assert e0.destination_ip == "192.168.10.50"
    assert e0.destination_port == 22
    assert e0.protocol == "TCP"
    assert e0.duration == 0.045  # 45000 microsec -> 0.045 sec
    assert e0.bytes_in == 1280
    assert e0.bytes_out == 4200
    assert e0.label == "SSH-Patator"
    assert e0.username is None  # Does not invent value
    assert e0.hostname is None  # Does not invent value
    assert e0.process is None   # Does not invent value
    assert "Label" in e0.raw_data  # Raw data stored alongside
    assert e0.source == "cic-ids2017"

def test_malformed_records_resilience():
    """Ensure malformed rows are recorded as errors without rejecting valid rows."""
    malformed_csv = (
        "Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration, Total Length of Fwd Packets, Total Length of Bwd Packets, Label\n"
        "192.168.10.5, 49152, 192.168.10.50, 22, 6, 07/07/2017 08:30:00, 45000, 1280, 4200, SSH-Patator\n"
        "999.999.999.999, 49154, 192.168.10.50, 22, 6, 07/07/2017 08:30:15, 38000, 960, 2400, Bad-IP\n"
        "192.168.10.8, 99999, 192.168.10.50, 80, 6, 07/07/2017 08:45:00, 120000, 45000, 89000, Bad-Port\n"
        "192.168.10.14, 52100, 192.168.10.50, 80, 6, , 85000, 3200, 1400, Missing-TS\n"
        "192.168.10.25, 48200, 192.168.10.50, 443, 6, 07/07/2017 09:30:00, 210000, 18500, 45000, BENIGN\n"
    ).encode("utf-8")

    normalizer = CicIds2017Normalizer()
    metadata, events = normalizer.parse_and_normalize(malformed_csv, "malformed.csv", "Malformed Test")

    # 2 valid rows should succeed despite 3 malformed rows
    assert metadata.total_events == 2
    assert metadata.benign_events == 1
    assert metadata.malicious_events == 1
    assert metadata.malformed_records_count == 3
    assert len(metadata.errors) == 3

    error_fields = [err.field for err in metadata.errors]
    assert "source_ip" in error_fields
    assert "source_port" in error_fields
    assert "timestamp" in error_fields

def test_json_events_normalizer():
    json_data = b"""[
      {
        "timestamp": "2026-08-10T19:30:00Z",
        "source_ip": "192.168.100.99",
        "source_port": 44120,
        "destination_ip": "10.0.1.10",
        "destination_port": 22,
        "protocol": "TCP",
        "event_type": "auth",
        "action": "FAILURE",
        "username": "root",
        "hostname": "web-server-01",
        "process": "sshd",
        "bytes_in": 1420,
        "bytes_out": 2100,
        "duration": 0.08,
        "label": "SSH-Patator"
      },
      {
        "timestamp": "2026-08-10T19:34:12Z",
        "source_ip": "10.0.1.10",
        "source_port": 50110,
        "destination_ip": "10.0.1.20",
        "destination_port": 5432,
        "protocol": "TCP",
        "event_type": "network_flow",
        "action": "ALLOWED",
        "username": "postgres",
        "hostname": "db-server-01",
        "label": "BENIGN"
      }
    ]"""

    normalizer = JsonEventNormalizer()
    metadata, events = normalizer.parse_and_normalize(json_data, "test.json", "JSON Test")

    assert metadata.total_events == 2
    assert metadata.benign_events == 1
    assert metadata.malicious_events == 1
    assert events[0].username == "root"
    assert events[0].hostname == "web-server-01"
    assert events[0].process == "sshd"
    assert events[1].label == "BENIGN"

def test_pcap_adapter_ingestion():
    import struct, socket
    pcap_header = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    
    # Packet 1
    eth = b"\x00\x0c\x29\x12\x34\x56" + b"\x00\x0c\x29\x65\x43\x21" + struct.pack("!H", 0x0800)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, socket.inet_aton("10.0.0.5"), socket.inet_aton("10.0.0.50"))
    tcp_hdr = struct.pack("!HHIIBBHHH", 49152, 22, 1000, 0, 0x50, 0x02, 8192, 0, 0)
    pkt1 = eth + ip_hdr + tcp_hdr
    pkt_hdr1 = struct.pack("<IIII", 1499416200, 100, len(pkt1), len(pkt1))
    
    pcap_bytes = pcap_header + pkt_hdr1 + pkt1

    adapter = PcapIngestionAdapter()
    metadata, events = adapter.parse_and_normalize(pcap_bytes, "test.pcap", "PCAP Test")

    assert metadata.total_events == 1
    assert metadata.source_format == "PCAP"
    assert events[0].source_ip == "10.0.0.5"
    assert events[0].destination_ip == "10.0.0.50"
    assert events[0].destination_port == 22
    assert events[0].protocol == "TCP"

def test_dataset_rest_api_endpoints():
    # 1. Load sample dataset
    res_load = client.post("/api/v1/datasets/sample/load")
    assert res_load.status_code == 200
    report = res_load.json()
    assert report["status"] == "SUCCESS"
    dataset_id = report["dataset"]["dataset_id"]
    assert report["dataset"]["total_events"] > 0

    # 2. List datasets
    res_list = client.get("/api/v1/datasets")
    assert res_list.status_code == 200
    datasets = res_list.json()
    assert len(datasets) > 0
    assert any(ds["dataset_id"] == dataset_id for ds in datasets)

    # 3. Get specific dataset metadata
    res_get = client.get(f"/api/v1/datasets/{dataset_id}")
    assert res_get.status_code == 200
    assert res_get.json()["dataset_id"] == dataset_id

    # 4. Query dataset events with filter
    res_events = client.get(f"/api/v1/datasets/{dataset_id}/events?limit=5")
    assert res_events.status_code == 200
    events_data = res_events.json()
    assert len(events_data["events"]) <= 5
    assert "total_matching" in events_data

    # 5. Raw text import endpoint
    raw_payload = {
        "content": "Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Label\n192.168.1.10, 1234, 192.168.1.50, 80, 6, 2026-08-10T12:00:00Z, BENIGN\n",
        "file_name": "api_test.csv",
        "dataset_name": "API Test Raw"
    }
    res_raw = client.post("/api/v1/datasets/import/raw", json=raw_payload)
    assert res_raw.status_code == 200
    raw_ds_id = res_raw.json()["dataset"]["dataset_id"]

    # 6. Delete dataset
    res_del = client.delete(f"/api/v1/datasets/{raw_ds_id}")
    assert res_del.status_code == 200
