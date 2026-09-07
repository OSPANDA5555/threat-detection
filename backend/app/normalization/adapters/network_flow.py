import json
from typing import Tuple, Dict, Any, Optional
from datetime import datetime, timezone

from app.normalization.models import SecurityEvent, SourceType
from app.normalization.adapters.base import BaseEventAdapter
from app.ingestion.validator import validate_ip, validate_port, parse_and_validate_timestamp, parse_protocol, get_attack_category

class NetworkFlowAdapter(BaseEventAdapter):
    """
    Adapter for NetFlow, IPFIX, CIC-IDS2017, and packet flow telemetry.
    Converts network flow records into canonical SecurityEvent instances.
    """

    @property
    def source_type(self) -> SourceType:
        return SourceType.NETWORK_FLOW

    def normalize_record(
        self,
        raw_record: Any,
        index: int = 0
    ) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        if isinstance(raw_record, str):
            try:
                data = json.loads(raw_record)
            except json.JSONDecodeError:
                return None, f"Invalid JSON string in NetworkFlowAdapter: {raw_record[:60]}"
        elif isinstance(raw_record, dict):
            data = raw_record
        elif hasattr(raw_record, "model_dump"):
            data = raw_record.model_dump()
        else:
            return None, f"Unsupported record type in NetworkFlowAdapter: {type(raw_record)}"

        # 1. Timestamp
        raw_ts = data.get("timestamp") or data.get("Timestamp") or data.get("time") or data.get("start_time")
        iso_ts = None
        if raw_ts is not None:
            iso_ts, ts_err = parse_and_validate_timestamp(raw_ts)
            if ts_err:
                return None, f"NetworkFlowAdapter: {ts_err}"
        else:
            iso_ts = datetime.now(timezone.utc).isoformat()

        # 2. Source IP & Port
        raw_src_ip = data.get("source_ip") or data.get("Source IP") or data.get("src_ip") or data.get("sourceIp") or data.get("saddr")
        src_ip, ip_err = validate_ip(raw_src_ip)
        if ip_err:
            return None, f"NetworkFlowAdapter source_ip: {ip_err}"

        raw_src_port = data.get("source_port") or data.get("Source Port") or data.get("src_port") or data.get("sport")
        src_port, port_err = validate_port(raw_src_port)
        if port_err:
            return None, f"NetworkFlowAdapter source_port: {port_err}"

        # 3. Destination IP & Port
        raw_dst_ip = data.get("destination_ip") or data.get("Destination IP") or data.get("dst_ip") or data.get("destinationIp") or data.get("daddr")
        dst_ip, dst_err = validate_ip(raw_dst_ip)
        if dst_err:
            return None, f"NetworkFlowAdapter destination_ip: {dst_err}"

        raw_dst_port = data.get("destination_port") or data.get("Destination Port") or data.get("dst_port") or data.get("dport")
        dst_port, dst_port_err = validate_port(raw_dst_port)
        if dst_port_err:
            return None, f"NetworkFlowAdapter destination_port: {dst_port_err}"

        # 4. Protocol
        raw_proto = data.get("protocol") or data.get("Protocol") or data.get("proto")
        protocol = parse_protocol(raw_proto)

        # 5. Bytes and Duration
        bytes_in = data.get("bytes_in") or data.get("Total Length of Fwd Packets") or data.get("fwd_bytes")
        bytes_out = data.get("bytes_out") or data.get("Total Length of Bwd Packets") or data.get("bwd_bytes")
        duration = data.get("duration") or data.get("Flow Duration")

        parsed_bytes_in = int(float(bytes_in)) if bytes_in is not None and str(bytes_in).replace(".", "").isdigit() else None
        parsed_bytes_out = int(float(bytes_out)) if bytes_out is not None and str(bytes_out).replace(".", "").isdigit() else None
        
        parsed_dur = None
        if duration is not None:
            try:
                df = float(duration)
                parsed_dur = round(df / 1e6 if df > 1000 else df, 4)
            except ValueError:
                pass

        # 6. Label & Action
        raw_label = str(data.get("label") or data.get("Label") or data.get("attack") or "BENIGN").strip()
        action = data.get("action") or ("ALLOWED" if raw_label == "BENIGN" else "SUSPICIOUS")
        status = data.get("status") or ("SUCCESS" if action == "ALLOWED" else "ALERT")

        # Stable ID
        event_id = SecurityEvent.generate_stable_id("network_flow", iso_ts, f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}")

        event = SecurityEvent(
            id=event_id,
            timestamp=iso_ts,
            source_type=SourceType.NETWORK_FLOW,
            source=data.get("source") or "network_flow",
            hostname=data.get("hostname") or data.get("host"),
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=protocol,
            username=data.get("username") or data.get("user"),  # null if not present
            process_name=data.get("process_name") or data.get("process"),
            process_id=data.get("process_id"),
            command=data.get("command"),
            event_type=data.get("event_type") or "network_flow",
            action=action,
            status=status,
            bytes_in=parsed_bytes_in,
            bytes_out=parsed_bytes_out,
            severity="HIGH" if raw_label != "BENIGN" else "INFO",
            label=raw_label,
            raw_data=data,
            metadata={"duration_sec": parsed_dur, "attack_category": get_attack_category(raw_label)}
        )

        return event, None
