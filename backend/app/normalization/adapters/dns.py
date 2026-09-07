import re
import json
from typing import Tuple, Dict, Any, Optional
from datetime import datetime, timezone

from app.normalization.models import SecurityEvent, SourceType
from app.normalization.adapters.base import BaseEventAdapter
from app.ingestion.validator import validate_ip, validate_port, parse_and_validate_timestamp

class DNSAdapter(BaseEventAdapter):
    """
    Adapter for DNS query and resolution telemetry (CoreDNS, BIND query logs, Zeek dns.log, JSON DNS streams).
    Extracts query domain, record types (A, TXT, AAAA), query status, resolver IPs, and C2 tunneling flags.
    """

    @property
    def source_type(self) -> SourceType:
        return SourceType.DNS

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
            return self._normalize_bind_line(trimmed, index)
        else:
            return None, f"Unsupported record format in DNSAdapter: {type(raw_record)}"

    def _normalize_dict(self, data: Dict[str, Any], index: int) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        raw_ts = data.get("timestamp") or data.get("time") or datetime.now(timezone.utc).isoformat()
        iso_ts, ts_err = parse_and_validate_timestamp(raw_ts)
        if ts_err:
            return None, f"DNSAdapter timestamp: {ts_err}"

        client_ip = data.get("client_ip") or data.get("source_ip") or data.get("src_ip") or data.get("sourceIp")
        src_ip = None
        if client_ip:
            src_ip, ip_err = validate_ip(client_ip)
            if ip_err:
                return None, f"DNSAdapter client_ip: {ip_err}"

        server_ip = data.get("server_ip") or data.get("destination_ip") or data.get("dst_ip") or "10.0.1.2"
        dst_ip, dst_err = validate_ip(server_ip)
        if dst_err:
            dst_ip = "10.0.1.2"

        domain = str(data.get("domain") or data.get("query") or data.get("qname") or "unknown.internal")
        record_type = str(data.get("record_type") or data.get("qtype") or "A").upper()
        rcode = str(data.get("rcode") or data.get("status") or "NOERROR").upper()

        is_c2_tunnel = (
            "c2" in domain.lower() or 
            "tunnel" in domain.lower() or 
            (record_type == "TXT" and len(domain) > 30) or
            len(domain.split(".")[0]) > 25
        )

        event_id = SecurityEvent.generate_stable_id("dns", iso_ts, f"{src_ip}:{domain}:{record_type}:{index}")

        event = SecurityEvent(
            id=event_id,
            timestamp=iso_ts,
            source_type=SourceType.DNS,
            source=data.get("source") or "coredns.log",
            hostname=data.get("host") or data.get("hostname") or "dns-resolver-01",
            source_ip=src_ip,
            source_port=data.get("client_port") or 58210,
            destination_ip=dst_ip,
            destination_port=53,
            protocol="UDP",
            command=f"QUERY {record_type} {domain}",
            event_type="DNS_QUERY",
            action="RESOLVED" if rcode == "NOERROR" else "FAILED",
            status="SUCCESS" if rcode == "NOERROR" else "FAILURE",
            severity="HIGH" if is_c2_tunnel else "INFO",
            label="DNS Tunneling" if is_c2_tunnel else "BENIGN",
            raw_data=data,
            metadata={"domain": domain, "record_type": record_type, "rcode": rcode, "is_covert_c2": is_c2_tunnel}
        )
        return event, None

    def _normalize_bind_line(self, line: str, index: int) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        # Example BIND format:
        # 10-Aug-2026 19:30:15.123 queries: info: client @0x7f88 10.0.1.20#58210 (malicious-c2.internal): query: malicious-c2.internal IN TXT + (10.0.1.2)
        now_iso = datetime.now(timezone.utc).isoformat()
        
        ip_match = re.search(r'client\s+(?:@\S+\s+)?(\d+\.\d+\.\d+\.\d+)#?(\d+)?', line)
        domain_match = re.search(r'query:\s+(\S+)\s+\S+\s+([A-Z0-9]+)', line)

        src_ip = "10.0.1.20"
        src_port = 58210
        if ip_match:
            raw_ip = ip_match.group(1)
            parsed_ip, ip_err = validate_ip(raw_ip)
            if ip_err:
                return None, f"DNSAdapter: {ip_err}"
            src_ip = parsed_ip
            if ip_match.group(2):
                src_port, _ = validate_port(ip_match.group(2))

        domain = "query.internal"
        record_type = "A"
        if domain_match:
            domain = domain_match.group(1)
            record_type = domain_match.group(2)

        is_c2 = "c2" in domain.lower() or record_type == "TXT" or "malicious" in domain.lower()

        return SecurityEvent(
            id=SecurityEvent.generate_stable_id("dns.log", now_iso, line),
            timestamp=now_iso,
            source_type=SourceType.DNS,
            source="bind_query.log",
            hostname="dns-resolver-01",
            source_ip=src_ip,
            source_port=src_port,
            destination_ip="10.0.1.2",
            destination_port=53,
            protocol="UDP",
            command=f"QUERY {record_type} {domain}",
            event_type="DNS_QUERY",
            action="RESOLVED",
            status="SUCCESS",
            severity="HIGH" if is_c2 else "INFO",
            label="DNS Tunneling" if is_c2 else "BENIGN",
            raw_data={"raw": line},
            metadata={"domain": domain, "record_type": record_type}
        ), None
