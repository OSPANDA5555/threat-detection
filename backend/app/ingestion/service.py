import os
from typing import Dict, List, Optional, Tuple
import uuid

from app.core.security import sanitize_filename, is_dangerous_executable_upload, sanitize_input_string
from app.schemas.dataset import (
    NormalizedEvent,
    DatasetMetadata,
    DatasetImportReport,
    DatasetQueryFilter,
    ValidationErrorRecord
)
from app.ingestion.normalizers.cic_ids2017 import CicIds2017Normalizer
from app.ingestion.normalizers.json_normalizer import JsonEventNormalizer
from app.ingestion.normalizers.pcap_adapter import PcapIngestionAdapter

class DatasetIngestionService:
    """
    Service orchestrating cybersecurity dataset ingestion, format auto-detection,
    event normalization, indexed persistence, retention controls, and query filtering.
    """

    def __init__(self):
        self._datasets: Dict[str, DatasetMetadata] = {}
        self._events: Dict[str, List[NormalizedEvent]] = {}
        self._deleted_dataset_ids: set = set()
        self._indices: Dict[str, Dict[str, Dict[str, List[int]]]] = {}  # dataset_id -> field -> value -> list[indices]
        self._cic_normalizer = CicIds2017Normalizer()
        self._json_normalizer = JsonEventNormalizer()
        self._pcap_normalizer = PcapIngestionAdapter()
        self._preload_samples()

    def import_dataset(
        self,
        content: bytes,
        file_name: str,
        dataset_name: Optional[str] = None,
        format_hint: Optional[str] = None,
        owner_id: Optional[str] = "system-demo",
        tenant_id: Optional[str] = "soc-org-primary"
    ) -> DatasetImportReport:
        """
        Ingests a dataset from bytes, normalizes it, builds secondary indices, and saves metadata.
        """
        # Hard upload size limit guard (default 25MB)
        max_bytes = 25 * 1024 * 1024
        if len(content) > max_bytes:
            raise ValueError(f"Payload size ({round(len(content)/(1024*1024), 1)} MB) exceeds maximum upload cap of 25 MB.")

        # Sanitize filename and prevent path traversal
        safe_file_name = sanitize_filename(file_name)

        # Reject executable and script uploads
        is_dangerous, reason = is_dangerous_executable_upload(content, safe_file_name)
        if is_dangerous:
            raise ValueError(f"Security Alert: Executable and script file uploads are forbidden ({reason}).")

        if not dataset_name:
            dataset_name = os.path.splitext(safe_file_name)[0].replace("_", " ").title()
        dataset_name = sanitize_input_string(dataset_name, max_length=128)

        detected_format = self._detect_format(content, safe_file_name, format_hint)

        if detected_format == "CSV_NETWORK_FLOW":
            metadata, events = self._cic_normalizer.parse_and_normalize(content, safe_file_name, dataset_name)
        elif detected_format == "JSON_EVENTS":
            metadata, events = self._json_normalizer.parse_and_normalize(content, safe_file_name, dataset_name)
        elif detected_format == "PCAP":
            metadata, events = self._pcap_normalizer.parse_and_normalize(content, safe_file_name, dataset_name)
        else:
            # Fallback to CSV
            metadata, events = self._cic_normalizer.parse_and_normalize(content, safe_file_name, dataset_name)

        if owner_id:
            metadata.owner_id = owner_id
        if tenant_id:
            metadata.tenant_id = tenant_id

        # Enforce max events retention limit per dataset
        max_dataset_events = 50000
        if len(events) > max_dataset_events:
            events = events[:max_dataset_events]
            metadata.total_events = max_dataset_events

        # Build secondary index for fast querying
        ds_id = metadata.dataset_id
        self._indices[ds_id] = {
            "source_ip": {},
            "destination_ip": {},
            "label": {}
        }
        for idx, evt in enumerate(events):
            if evt.source_ip:
                self._indices[ds_id]["source_ip"].setdefault(evt.source_ip, []).append(idx)
            if evt.destination_ip:
                self._indices[ds_id]["destination_ip"].setdefault(evt.destination_ip, []).append(idx)
            if evt.label:
                self._indices[ds_id]["label"].setdefault(evt.label.upper(), []).append(idx)

        # Save to store
        self._datasets[ds_id] = metadata
        self._events[ds_id] = events
        self._deleted_dataset_ids.discard(ds_id)

        # Prune capacity
        self.prune_retention()

        return DatasetImportReport(
            dataset=metadata,
            sample_events=events[:10],
            status="SUCCESS" if metadata.total_events > 0 else "WARNING",
            message=f"Successfully ingested {metadata.total_events} events ({metadata.benign_events} benign, {metadata.malicious_events} malicious) from {file_name}."
        )

    def list_datasets(self) -> List[DatasetMetadata]:
        return list(self._datasets.values())

    def get_dataset(self, dataset_id: str) -> Optional[DatasetMetadata]:
        if dataset_id in self._deleted_dataset_ids:
            return None
        return self._datasets.get(dataset_id)

    def get_dataset_events(
        self,
        dataset_id: str,
        filter_spec: DatasetQueryFilter
    ) -> Tuple[List[NormalizedEvent], int]:
        if dataset_id in self._deleted_dataset_ids or dataset_id not in self._datasets:
            return [], 0

        all_events = self._events.get(dataset_id, [])
        filtered = []

        # Bound pagination to prevent unbounded memory consumption
        filter_spec.limit = min(max(1, filter_spec.limit), 500)
        filter_spec.offset = max(0, filter_spec.offset)

        for evt in all_events:
            if filter_spec.label and filter_spec.label.lower() not in (evt.label or "").lower():
                continue
            if filter_spec.source_ip and filter_spec.source_ip != evt.source_ip:
                continue
            if filter_spec.destination_ip and filter_spec.destination_ip != evt.destination_ip:
                continue
            if filter_spec.destination_port and filter_spec.destination_port != evt.destination_port:
                continue
            if filter_spec.protocol and filter_spec.protocol.upper() != (evt.protocol or "").upper():
                continue
            if filter_spec.is_malicious is not None:
                is_mal = (evt.label or "").upper() != "BENIGN"
                if is_mal != filter_spec.is_malicious:
                    continue
            filtered.append(evt)

        total_count = len(filtered)
        start = filter_spec.offset
        end = start + filter_spec.limit
        return filtered[start:end], total_count

    def delete_dataset(self, dataset_id: str) -> bool:
        if dataset_id in self._datasets:
            del self._datasets[dataset_id]
            self._events.pop(dataset_id, None)
            self._indices.pop(dataset_id, None)
            self._deleted_dataset_ids.add(dataset_id)
            return True
        return False

    def prune_retention(self, max_datasets: int = 50) -> int:
        """Prunes oldest datasets if dataset count exceeds maximum capacity limit."""
        pruned = 0
        if len(self._datasets) > max_datasets:
            sorted_keys = sorted(self._datasets.keys(), key=lambda k: getattr(self._datasets[k], "imported_at", ""))
            to_remove = sorted_keys[: len(self._datasets) - max_datasets]
            for ds_id in to_remove:
                self.delete_dataset(ds_id)
                pruned += 1
        return pruned

    def _detect_format(self, content: bytes, file_name: str, hint: Optional[str] = None) -> str:
        if hint:
            return hint.upper()

        fn_lower = file_name.lower()
        if fn_lower.endswith(".pcap") or fn_lower.endswith(".cap"):
            return "PCAP"
        if fn_lower.endswith(".json") or fn_lower.endswith(".jsonl"):
            return "JSON_EVENTS"
        if fn_lower.endswith(".csv") or fn_lower.endswith(".txt"):
            return "CSV_NETWORK_FLOW"

        # Content heuristic
        snippet = content[:32]
        if snippet.startswith(b"\xa1\xb2\xc3\xd4") or snippet.startswith(b"\xd4\xc3\xb2\xa1") or snippet.startswith(b"\x0a\x0d\x0d\x0a"):
            return "PCAP"
        
        try:
            head_str = content[:100].decode("utf-8", errors="ignore").strip()
            if head_str.startswith("{") or head_str.startswith("["):
                return "JSON_EVENTS"
        except Exception:
            pass

        return "CSV_NETWORK_FLOW"

    def _preload_samples(self):
        """Preloads default sample datasets into the system for instant testing."""
        sample_csv = (
            "Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration, Total Length of Fwd Packets, Total Length of Bwd Packets, Label\n"
            "192.168.10.5, 49152, 192.168.10.50, 22, 6, 07/07/2017 08:30:00, 45000, 1280, 4200, SSH-Patator\n"
            "192.168.10.5, 49154, 192.168.10.50, 22, 6, 07/07/2017 08:30:15, 38000, 960, 2400, SSH-Patator\n"
            "192.168.10.8, 51200, 192.168.10.50, 80, 6, 07/07/2017 08:45:00, 120000, 45000, 89000, DoS Hulk\n"
            "192.168.10.14, 52100, 192.168.10.50, 80, 6, 07/07/2017 09:10:00, 85000, 3200, 1400, BENIGN\n"
            "192.168.10.19, 60100, 192.168.10.20, 5432, 6, 07/07/2017 09:25:00, 62000, 1500, 3400, PortScan\n"
            "192.168.10.19, 60101, 192.168.10.20, 8080, 6, 07/07/2017 09:25:01, 15000, 240, 0, PortScan\n"
            "192.168.10.25, 48200, 192.168.10.50, 443, 6, 07/07/2017 09:30:00, 210000, 18500, 45000, BENIGN\n"
        )
        self.import_dataset(
            content=sample_csv.encode("utf-8"),
            file_name="cic_ids2017_sample.csv",
            dataset_name="CIC-IDS2017 Benchmark Flow Sample"
        )

# Global singleton service
dataset_service = DatasetIngestionService()
