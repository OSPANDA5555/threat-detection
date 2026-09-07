import json
from typing import List, Tuple, Dict, Any, Optional
from datetime import datetime, timezone

from app.schemas.dataset import NormalizedEvent, ValidationErrorRecord, DatasetMetadata
from app.ingestion.normalizers.base import BaseDatasetNormalizer
from app.ingestion.validator import (
    validate_ip,
    validate_port,
    parse_and_validate_timestamp,
    parse_protocol,
    get_attack_category
)

class JsonEventNormalizer(BaseDatasetNormalizer):
    """
    Parser & Normalizer for JSON arrays and JSONL (newline-delimited JSON) event datasets.
    """

    def parse_and_normalize(
        self,
        content: bytes,
        file_name: str,
        dataset_name: str
    ) -> Tuple[DatasetMetadata, List[NormalizedEvent]]:
        text = content.decode("utf-8", errors="replace").strip()
        raw_items: List[Tuple[int, Dict[str, Any]]] = []
        errors: List[ValidationErrorRecord] = []

        if not text:
            meta = DatasetMetadata(
                dataset_name=dataset_name,
                file_name=file_name,
                source_format="JSON_EVENTS",
                errors=[ValidationErrorRecord(row_index=0, field="file", error_message="Empty JSON file")]
            )
            return meta, []

        # Check if text is a single JSON Array
        if text.startswith("[") and text.endswith("]"):
            try:
                parsed_array = json.loads(text)
                if isinstance(parsed_array, list):
                    for idx, item in enumerate(parsed_array):
                        if isinstance(item, dict):
                            raw_items.append((idx + 1, item))
                        else:
                            errors.append(ValidationErrorRecord(
                                row_index=idx + 1,
                                field="root",
                                error_message="Array item is not a JSON object",
                                raw_snippet=str(item)[:100]
                            ))
            except json.JSONDecodeError as jde:
                errors.append(ValidationErrorRecord(
                    row_index=0,
                    field="json",
                    error_message=f"JSON Decode Error: {str(jde)}"
                ))
        else:
            # Parse line by line (JSONL)
            for idx, line in enumerate(text.splitlines()):
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    obj = json.loads(line_str)
                    if isinstance(obj, dict):
                        raw_items.append((idx + 1, obj))
                    else:
                        errors.append(ValidationErrorRecord(
                            row_index=idx + 1,
                            field="jsonl",
                            error_message="Line is not a valid JSON object",
                            raw_snippet=line_str[:100]
                        ))
                except json.JSONDecodeError as jde:
                    errors.append(ValidationErrorRecord(
                        row_index=idx + 1,
                        field="jsonl",
                        error_message=f"Invalid JSON line: {str(jde)}",
                        raw_snippet=line_str[:100]
                    ))

        events: List[NormalizedEvent] = []
        labels_count: Dict[str, int] = {}
        attack_cats_count: Dict[str, int] = {}
        benign_count = 0
        malicious_count = 0

        for row_idx, raw_dict in raw_items:
            event, item_errors = self._normalize_json_object(raw_dict, row_idx)
            if item_errors:
                errors.extend(item_errors)
                if not event:
                    continue

            events.append(event)
            lbl = event.label or "BENIGN"
            labels_count[lbl] = labels_count.get(lbl, 0) + 1

            cat = get_attack_category(lbl)
            attack_cats_count[cat] = attack_cats_count.get(cat, 0) + 1

            if lbl.upper() == "BENIGN":
                benign_count += 1
            else:
                malicious_count += 1

        metadata = DatasetMetadata(
            dataset_name=dataset_name,
            file_name=file_name,
            total_events=len(events),
            benign_events=benign_count,
            malicious_events=malicious_count,
            source_format="JSON_EVENTS",
            available_labels=labels_count,
            attack_categories=attack_cats_count,
            malformed_records_count=len(errors),
            errors=errors[:100]
        )

        return metadata, events

    def _normalize_json_object(
        self,
        raw_dict: Dict[str, Any],
        row_idx: int
    ) -> Tuple[Optional[NormalizedEvent], List[ValidationErrorRecord]]:
        row_errors: List[ValidationErrorRecord] = []

        # 1. Timestamp
        raw_ts = raw_dict.get("timestamp") or raw_dict.get("@timestamp") or raw_dict.get("time") or raw_dict.get("Timestamp")
        iso_ts = None
        if raw_ts is not None:
            iso_ts, ts_err = parse_and_validate_timestamp(raw_ts)
            if ts_err:
                row_errors.append(ValidationErrorRecord(
                    row_index=row_idx,
                    field="timestamp",
                    error_message=ts_err,
                    raw_value=str(raw_ts)
                ))
                return None, row_errors
        else:
            # Default to current time if missing in json log
            iso_ts = datetime.now(timezone.utc).isoformat()

        # 2. Source IP
        raw_src_ip = raw_dict.get("source_ip") or raw_dict.get("src_ip") or raw_dict.get("sourceIp") or raw_dict.get("saddr") or raw_dict.get("Source IP")
        src_ip = None
        if raw_src_ip:
            src_ip, ip_err = validate_ip(raw_src_ip)
            if ip_err:
                row_errors.append(ValidationErrorRecord(
                    row_index=row_idx,
                    field="source_ip",
                    error_message=ip_err,
                    raw_value=str(raw_src_ip)
                ))
                return None, row_errors

        # 3. Destination IP
        raw_dst_ip = raw_dict.get("destination_ip") or raw_dict.get("dst_ip") or raw_dict.get("destinationIp") or raw_dict.get("daddr") or raw_dict.get("Destination IP")
        dst_ip = None
        if raw_dst_ip:
            dst_ip, ip_err = validate_ip(raw_dst_ip)
            if ip_err:
                row_errors.append(ValidationErrorRecord(
                    row_index=row_idx,
                    field="destination_ip",
                    error_message=ip_err,
                    raw_value=str(raw_dst_ip)
                ))
                return None, row_errors

        # 4. Source Port
        raw_src_port = raw_dict.get("source_port") or raw_dict.get("src_port") or raw_dict.get("sourcePort") or raw_dict.get("sport")
        src_port, port_err = validate_port(raw_src_port)
        if port_err:
            row_errors.append(ValidationErrorRecord(
                row_index=row_idx,
                field="source_port",
                error_message=port_err,
                raw_value=str(raw_src_port)
            ))
            return None, row_errors

        # 5. Destination Port
        raw_dst_port = raw_dict.get("destination_port") or raw_dict.get("dst_port") or raw_dict.get("destinationPort") or raw_dict.get("dport")
        dst_port, port_err = validate_port(raw_dst_port)
        if port_err:
            row_errors.append(ValidationErrorRecord(
                row_index=row_idx,
                field="destination_port",
                error_message=port_err,
                raw_value=str(raw_dst_port)
            ))
            return None, row_errors

        # 6. Protocol
        raw_proto = raw_dict.get("protocol") or raw_dict.get("proto")
        protocol = parse_protocol(raw_proto)

        # 7. Event type & Action
        event_type = raw_dict.get("event_type") or raw_dict.get("eventType") or "network_flow"
        action = raw_dict.get("action") or raw_dict.get("status") or ("ALLOWED" if event_type == "network_flow" else None)

        # 8. User / Host / Process
        username = raw_dict.get("username") or raw_dict.get("user")
        hostname = raw_dict.get("hostname") or raw_dict.get("host")
        process = raw_dict.get("process") or raw_dict.get("process_name")

        # 9. Bytes and Duration
        bytes_in = raw_dict.get("bytes_in") or raw_dict.get("fwd_bytes")
        bytes_out = raw_dict.get("bytes_out") or raw_dict.get("bwd_bytes")
        duration = raw_dict.get("duration")

        # 10. Label
        label = str(raw_dict.get("label") or raw_dict.get("attack_type") or raw_dict.get("class") or "BENIGN")

        event = NormalizedEvent(
            timestamp=iso_ts,
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=protocol,
            event_type=event_type,
            action=action,
            username=username,
            hostname=hostname,
            process=process,
            bytes_in=int(bytes_in) if bytes_in is not None and str(bytes_in).isdigit() else None,
            bytes_out=int(bytes_out) if bytes_out is not None and str(bytes_out).isdigit() else None,
            duration=float(duration) if duration is not None else None,
            label=label,
            raw_data=raw_dict,
            source="json_events"
        )

        return event, row_errors
