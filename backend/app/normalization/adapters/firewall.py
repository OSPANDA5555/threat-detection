import re
import json
from typing import Tuple, Dict, Any, Optional
from datetime import datetime, timezone

from app.normalization.models import SecurityEvent, SourceType
from app.normalization.adapters.base import BaseEventAdapter
from app.ingestion.validator import validate_ip, validate_port, parse_and_validate_timestamp, parse_protocol

class FirewallAdapter(BaseEventAdapter):
    """
    Adapter for Firewall and Perimeter Defense telemetry (iptables, UFW, pfSense, Suricata EVE drops).
    Extracts network interfaces, packet lengths, TCP flags, firewall actions (DROP, REJECT, ACCEPT), and rule IDs.
    """

    @property
    def source_type(self) -> SourceType:
        return SourceType.FIREWALL

    def normalize_record(
        self,
        raw_record: Any,
        index: int = 0
    ) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        if isinstance(raw_record, dict):
            return self._normalize_dict(raw_record, index)
        elif hasattr(raw_record, "model_dump"):
            return self._normalize_dict(raw_record.model_dump(), index)
        elif isinstance(raw_record, str):
            trimmed = raw_record.strip()
            if trimmed.startswith("{") and trimmed.endswith("}"):
                try:
                    return self._normalize_dict(json.loads(trimmed), index)
                except json.JSONDecodeError:
                    pass
            return self._normalize_ufw_line(trimmed, index)
        else:
            return None, f"Unsupported record format in FirewallAdapter: {type(raw_record)}"

    def _normalize_dict(self, data: Dict[str, Any], index: int) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        raw_ts = data.get("timestamp") or data.get("time") or datetime.now(timezone.utc).isoformat()
        iso_ts, ts_err = parse_and_validate_timestamp(raw_ts)
        if ts_err:
            return None, f"FirewallAdapter timestamp: {ts_err}"

        src_ip = None
        if data.get("src_ip") or data.get("source_ip") or data.get("SRC"):
            src_ip, ip_err = validate_ip(data.get("src_ip") or data.get("source_ip") or data.get("SRC"))
            if ip_err:
                return None, f"FirewallAdapter src_ip: {ip_err}"

        dst_ip = None
        if data.get("dst_ip") or data.get("destination_ip") or data.get("DST"):
            dst_ip, dst_err = validate_ip(data.get("dst_ip") or data.get("destination_ip") or data.get("DST"))
            if dst_err:
                return None, f"FirewallAdapter dst_ip: {dst_err}"

        src_port, _ = validate_port(data.get("src_port") or data.get("source_port") or data.get("SPT"))
        dst_port, _ = validate_port(data.get("dst_port") or data.get("destination_port") or data.get("DPT"))
        protocol = parse_protocol(data.get("proto") or data.get("protocol") or data.get("PROTO") or "TCP")

        raw_action = str(data.get("action") or ("DROP" if "block" in str(data).lower() else "ALLOW")).upper()
        action = "BLOCK" if any(a in raw_action for a in ["DROP", "BLOCK", "REJECT", "DENY"]) else "ALLOW"
        status = "DENIED" if action == "BLOCK" else "ALLOWED"

        label = "PortScan" if dst_port in [22, 23, 3389, 4444, 8080] and action == "BLOCK" else "BENIGN"

        event_id = SecurityEvent.generate_stable_id("firewall", iso_ts, f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{action}:{index}")

        event = SecurityEvent(
            id=event_id,
            timestamp=iso_ts,
            source_type=SourceType.FIREWALL,
            source=data.get("source") or "iptables.log",
            hostname=data.get("host") or data.get("hostname") or "firewall-gw-01",
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=protocol,
            event_type="FIREWALL_DROP" if action == "BLOCK" else "FIREWALL_ACCEPT",
            action=action,
            status=status,
            bytes_in=data.get("bytes") or data.get("LEN"),
            severity="HIGH" if action == "BLOCK" and src_ip and not src_ip.startswith("10.") else "INFO",
            label=label,
            raw_data=data,
            metadata={"in_interface": data.get("IN"), "out_interface": data.get("OUT"), "flags": data.get("flags")}
        )
        return event, None

    def _normalize_ufw_line(self, line: str, index: int) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        # Example UFW/iptables line:
        # [UFW BLOCK] IN=eth0 OUT= MAC=00:0c:... SRC=192.168.100.99 DST=10.0.1.10 LEN=60 PROTO=TCP SPT=49152 DPT=22 SYN
        now_iso = datetime.now(timezone.utc).isoformat()
        
        kv_pairs = dict(re.findall(r'(\b[A-Z]+)=(\S+)', line))
        
        raw_src = kv_pairs.get("SRC")
        raw_dst = kv_pairs.get("DST")

        src_ip, ip_err = validate_ip(raw_src)
        if ip_err:
            return None, f"FirewallAdapter: {ip_err}"

        dst_ip, _ = validate_ip(raw_dst)
        src_port, _ = validate_port(kv_pairs.get("SPT"))
        dst_port, _ = validate_port(kv_pairs.get("DPT"))
        protocol = parse_protocol(kv_pairs.get("PROTO") or "TCP")
        pkt_len = int(kv_pairs.get("LEN")) if kv_pairs.get("LEN") and kv_pairs.get("LEN").isdigit() else None

        is_block = "BLOCK" in line.upper() or "DROP" in line.upper()
        action = "BLOCK" if is_block else "ALLOW"
        status = "DENIED" if is_block else "ALLOWED"

        label = "PortScan" if dst_port in [22, 23, 3389, 4444] and is_block else "BENIGN"

        return SecurityEvent(
            id=SecurityEvent.generate_stable_id("firewall", now_iso, line),
            timestamp=now_iso,
            source_type=SourceType.FIREWALL,
            source="ufw.log",
            hostname="firewall-gw-01",
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=protocol,
            event_type="FIREWALL_DROP" if is_block else "FIREWALL_ACCEPT",
            action=action,
            status=status,
            bytes_in=pkt_len,
            severity="HIGH" if is_block else "INFO",
            label=label,
            raw_data={"raw": line, "parsed_kv": kv_pairs},
            metadata={"in_interface": kv_pairs.get("IN"), "out_interface": kv_pairs.get("OUT")}
        ), None
