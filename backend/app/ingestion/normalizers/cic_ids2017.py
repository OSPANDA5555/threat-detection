import csv
import io
import math
from typing import List, Tuple, Dict, Any, Optional
from datetime import datetime, timezone
import uuid

from app.schemas.dataset import NormalizedEvent, ValidationErrorRecord, DatasetMetadata
from app.ingestion.normalizers.base import BaseDatasetNormalizer
from app.ingestion.validator import (
    validate_ip,
    validate_port,
    parse_and_validate_timestamp,
    parse_protocol,
    get_attack_category
)

class CicIds2017Normalizer(BaseDatasetNormalizer):
    """
    Parser & Normalizer for CIC-IDS2017 and general NetFlow / IPFIX CSV datasets.
    Handles varied column naming, whitespace headers, and microsecond flow durations.
    """

    def parse_and_normalize(
        self,
        content: bytes,
        file_name: str,
        dataset_name: str
    ) -> Tuple[DatasetMetadata, List[NormalizedEvent]]:
        # Decode content with UTF-8 fallback
        text_stream = None
        for enc in ["utf-8-sig", "utf-8", "latin-1", "cp1252"]:
            try:
                text_stream = io.StringIO(content.decode(enc))
                break
            except UnicodeDecodeError:
                continue
        
        if text_stream is None:
            text_stream = io.StringIO(content.decode("utf-8", errors="replace"))

        reader = csv.reader(text_stream)
        
        # Read header row
        try:
            raw_headers = next(reader)
        except StopIteration:
            meta = DatasetMetadata(
                dataset_name=dataset_name,
                file_name=file_name,
                source_format="CSV_NETWORK_FLOW",
                errors=[ValidationErrorRecord(row_index=0, field="file", error_message="Empty CSV file")]
            )
            return meta, []

        # Build normalized column index map
        header_map = self._build_header_map(raw_headers)
        
        events: List[NormalizedEvent] = []
        errors: List[ValidationErrorRecord] = []
        labels_count: Dict[str, int] = {}
        attack_cats_count: Dict[str, int] = {}
        benign_count = 0
        malicious_count = 0

        row_idx = 1
        for row in reader:
            row_idx += 1
            if not row or all(not cell.strip() for cell in row):
                continue  # Skip blank lines

            # Check column length
            if len(row) != len(raw_headers):
                errors.append(ValidationErrorRecord(
                    row_index=row_idx,
                    field="row",
                    error_message=f"Malformed row: expected {len(raw_headers)} columns, got {len(row)}",
                    raw_snippet=",".join(row[:6])
                ))
                continue

            # Build raw dictionary for this row
            raw_dict = {raw_headers[i].strip(): row[i].strip() for i in range(len(raw_headers))}

            # Extract fields
            event, row_errors = self._normalize_row(raw_dict, row_idx, header_map)
            
            if row_errors:
                errors.extend(row_errors)
                # If critical fields (IPs or timestamp) failed, skip appending to normalized events
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
            source_format="CSV_NETWORK_FLOW",
            available_labels=labels_count,
            attack_categories=attack_cats_count,
            malformed_records_count=len(errors),
            errors=errors[:100]  # Store first 100 errors for UI display
        )

        return metadata, events

    def _build_header_map(self, raw_headers: List[str]) -> Dict[str, str]:
        """
        Maps normalized semantic field names to the exact CSV header string in this file.
        """
        cleaned = {h.strip().lower(): h.strip() for h in raw_headers}
        mapping = {}

        # 1. Source IP
        for candidate in ["source ip", "src ip", "source_ip", "src_ip", "saddr", "sourceip"]:
            if candidate in cleaned:
                mapping["source_ip"] = cleaned[candidate]
                break

        # 2. Source Port
        for candidate in ["source port", "src port", "source_port", "src_port", "sport", "sourceport"]:
            if candidate in cleaned:
                mapping["source_port"] = cleaned[candidate]
                break

        # 3. Destination IP
        for candidate in ["destination ip", "dst ip", "destination_ip", "dest ip", "dst_ip", "dest_ip", "daddr", "destinationip"]:
            if candidate in cleaned:
                mapping["destination_ip"] = cleaned[candidate]
                break

        # 4. Destination Port
        for candidate in ["destination port", "dst port", "destination_port", "dest port", "dst_port", "dest_port", "dport", "destinationport"]:
            if candidate in cleaned:
                mapping["destination_port"] = cleaned[candidate]
                break

        # 5. Protocol
        for candidate in ["protocol", "proto"]:
            if candidate in cleaned:
                mapping["protocol"] = cleaned[candidate]
                break

        # 6. Timestamp
        for candidate in ["timestamp", "time", "date", "flow start time", "start_time"]:
            if candidate in cleaned:
                mapping["timestamp"] = cleaned[candidate]
                break

        # 7. Flow Duration
        for candidate in ["flow duration", "duration", "flow_duration"]:
            if candidate in cleaned:
                mapping["duration"] = cleaned[candidate]
                break

        # 8. Bytes In / Forward Length
        for candidate in ["total length of fwd packets", "totlen fwd pkts", "bytes in", "bytes_in", "fwd bytes", "tot_fwd_bytes", "fwd_length"]:
            if candidate in cleaned:
                mapping["bytes_in"] = cleaned[candidate]
                break

        # 9. Bytes Out / Backward Length
        for candidate in ["total length of bwd packets", "totlen bwd pkts", "bytes out", "bytes_out", "bwd bytes", "tot_bwd_bytes", "bwd_length"]:
            if candidate in cleaned:
                mapping["bytes_out"] = cleaned[candidate]
                break

        # 10. Label
        for candidate in ["label", "attack", "class", "category", "attack_type"]:
            if candidate in cleaned:
                mapping["label"] = cleaned[candidate]
                break

        return mapping

    def _normalize_row(
        self,
        raw_dict: Dict[str, str],
        row_idx: int,
        header_map: Dict[str, str]
    ) -> Tuple[Optional[NormalizedEvent], List[ValidationErrorRecord]]:
        row_errors: List[ValidationErrorRecord] = []

        # 1. Timestamp validation
        raw_ts = raw_dict.get(header_map.get("timestamp", "")) if "timestamp" in header_map else None
        iso_ts, ts_err = parse_and_validate_timestamp(raw_ts)
        if ts_err:
            row_errors.append(ValidationErrorRecord(
                row_index=row_idx,
                field="timestamp",
                error_message=ts_err,
                raw_value=str(raw_ts),
                raw_snippet=str(list(raw_dict.items())[:3])
            ))
            return None, row_errors

        # 2. Source IP validation
        raw_src_ip = raw_dict.get(header_map.get("source_ip", "")) if "source_ip" in header_map else None
        src_ip = None
        if raw_src_ip:
            src_ip, ip_err = validate_ip(raw_src_ip)
            if ip_err:
                row_errors.append(ValidationErrorRecord(
                    row_index=row_idx,
                    field="source_ip",
                    error_message=ip_err,
                    raw_value=str(raw_src_ip),
                    raw_snippet=str(list(raw_dict.items())[:3])
                ))
                return None, row_errors

        # 3. Destination IP validation
        raw_dst_ip = raw_dict.get(header_map.get("destination_ip", "")) if "destination_ip" in header_map else None
        dst_ip = None
        if raw_dst_ip:
            dst_ip, ip_err = validate_ip(raw_dst_ip)
            if ip_err:
                row_errors.append(ValidationErrorRecord(
                    row_index=row_idx,
                    field="destination_ip",
                    error_message=ip_err,
                    raw_value=str(raw_dst_ip),
                    raw_snippet=str(list(raw_dict.items())[:3])
                ))
                return None, row_errors

        # 4. Source Port validation
        raw_src_port = raw_dict.get(header_map.get("source_port", "")) if "source_port" in header_map else None
        src_port, port_err = validate_port(raw_src_port)
        if port_err:
            row_errors.append(ValidationErrorRecord(
                row_index=row_idx,
                field="source_port",
                error_message=port_err,
                raw_value=str(raw_src_port)
            ))
            return None, row_errors

        # 5. Destination Port validation
        raw_dst_port = raw_dict.get(header_map.get("destination_port", "")) if "destination_port" in header_map else None
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
        raw_proto = raw_dict.get(header_map.get("protocol", "")) if "protocol" in header_map else None
        protocol = parse_protocol(raw_proto)

        # 7. Duration (CIC-IDS2017 durations are in microseconds)
        raw_dur = raw_dict.get(header_map.get("duration", "")) if "duration" in header_map else None
        duration = None
        if raw_dur:
            try:
                dur_float = float(raw_dur)
                if not math.isnan(dur_float) and dur_float >= 0:
                    # If value > 1000, likely microseconds -> convert to seconds
                    duration = round(dur_float / 1000000.0 if dur_float > 1000 else dur_float, 6)
            except ValueError:
                pass

        # 8. Bytes In & Bytes Out
        raw_bin = raw_dict.get(header_map.get("bytes_in", "")) if "bytes_in" in header_map else None
        bytes_in = None
        if raw_bin:
            try:
                bin_num = int(float(raw_bin))
                if bin_num >= 0:
                    bytes_in = bin_num
            except (ValueError, TypeError):
                pass

        raw_bout = raw_dict.get(header_map.get("bytes_out", "")) if "bytes_out" in header_map else None
        bytes_out = None
        if raw_bout:
            try:
                bout_num = int(float(raw_bout))
                if bout_num >= 0:
                    bytes_out = bout_num
            except (ValueError, TypeError):
                pass

        # 9. Label
        raw_label = raw_dict.get(header_map.get("label", "")) if "label" in header_map else "BENIGN"
        label = raw_label.strip() if raw_label else "BENIGN"

        event = NormalizedEvent(
            timestamp=iso_ts,
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=protocol,
            event_type="network_flow",
            action="ALLOWED",
            username=None,   # Non-invented value
            hostname=None,   # Non-invented value
            process=None,    # Non-invented value
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            duration=duration,
            label=label,
            raw_data=raw_dict,
            source="cic-ids2017"
        )

        return event, row_errors
