import re
import json
from typing import Dict, Any, List, Optional, Tuple, Type

from app.normalization.models import SecurityEvent, SourceType, NormalizationResult
from app.normalization.adapters.base import BaseEventAdapter
from app.normalization.adapters.network_flow import NetworkFlowAdapter
from app.normalization.adapters.linux_auth import LinuxAuthAdapter
from app.normalization.adapters.linux_audit import LinuxAuditAdapter
from app.normalization.adapters.web_log import WebLogAdapter
from app.normalization.adapters.dns import DNSAdapter
from app.normalization.adapters.firewall import FirewallAdapter
from app.normalization.adapters.sysmon import WindowsSysmonAdapter

class EventNormalizationPipeline:
    """
    Central dispatch and routing pipeline for normalizing diverse raw cybersecurity
    telemetry streams into uniform, canonical SecurityEvent representations.
    """

    def __init__(self):
        self._adapters: Dict[SourceType, BaseEventAdapter] = {
            SourceType.NETWORK_FLOW: NetworkFlowAdapter(),
            SourceType.LINUX_AUTH: LinuxAuthAdapter(),
            SourceType.LINUX_AUDIT: LinuxAuditAdapter(),
            SourceType.WEB_LOG: WebLogAdapter(),
            SourceType.DNS: DNSAdapter(),
            SourceType.FIREWALL: FirewallAdapter(),
            SourceType.WINDOWS_SYSMON: WindowsSysmonAdapter()
        }

    def register_adapter(self, source_type: SourceType, adapter: BaseEventAdapter) -> None:
        """Register or override an adapter for a specific telemetry source type."""
        self._adapters[source_type] = adapter

    def get_adapter(self, source_type: SourceType) -> Optional[BaseEventAdapter]:
        """Retrieve the adapter registered for a specific source type."""
        return self._adapters.get(source_type)

    def detect_source_type(self, raw_record: Any) -> SourceType:
        """
        Heuristically inspects the structure and contents of a log record
        to automatically detect the most appropriate source type taxonomy category.
        """
        if isinstance(raw_record, dict):
            # Check dictionary keys
            if any(k in raw_record for k in ["EventID", "EventData", "UtcTime", "ParentImage"]):
                return SourceType.WINDOWS_SYSMON
            if any(k in raw_record for k in ["Flow Duration", "Total Length of Fwd Packets", "fwd_bytes", "saddr", "daddr"]):
                return SourceType.NETWORK_FLOW
            if any(k in raw_record for k in ["qname", "qtype", "record_type", "rcode", "query"]):
                return SourceType.DNS
            if any(k in raw_record for k in ["method", "http_method", "status_code", "uri", "user_agent"]):
                return SourceType.WEB_LOG
            if any(k in raw_record for k in ["IN", "OUT", "SPT", "DPT", "SRC", "DST"]):
                return SourceType.FIREWALL
            if any(k in raw_record for k in ["syscall", "exe", "comm", "a0", "a1"]):
                return SourceType.LINUX_AUDIT
            if any(k in raw_record for k in ["pam_service", "auth_method", "pam"]):
                return SourceType.LINUX_AUTH
            if raw_record.get("event_type") == "AUTHENTICATION" or "ssh" in str(raw_record.get("source", "")).lower():
                return SourceType.LINUX_AUTH
            if raw_record.get("event_type") == "NETWORK":
                return SourceType.NETWORK_FLOW
            if raw_record.get("event_type") == "PROCESS":
                return SourceType.LINUX_AUDIT
            if raw_record.get("event_type") == "DNS":
                return SourceType.DNS

        content_str = str(raw_record)
        
        # Windows / Sysmon
        if "Microsoft-Windows-Sysmon" in content_str or "EventID" in content_str:
            return SourceType.WINDOWS_SYSMON
        
        # Linux Auditd
        if "type=SYSCALL" in content_str or "type=EXECVE" in content_str or "type=PATH" in content_str or "msg=audit(" in content_str:
            return SourceType.LINUX_AUDIT
            
        # Linux Auth
        if "sshd[" in content_str or "sudo:" in content_str or "pam_unix" in content_str or "Failed password" in content_str or "Accepted password" in content_str:
            return SourceType.LINUX_AUTH
            
        # Firewall
        if "[UFW BLOCK]" in content_str or "IPTABLES" in content_str or ("SRC=" in content_str and "DST=" in content_str and "SPT=" in content_str):
            return SourceType.FIREWALL
            
        # DNS
        if "queries: info:" in content_str or "query:" in content_str and "IN A" in content_str:
            return SourceType.DNS
            
        # Web Log (CLF/Combined)
        if re.search(r'\]\s+"(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+', content_str):
            return SourceType.WEB_LOG

        # Fallback to network flow or generic
        return SourceType.NETWORK_FLOW

    def normalize_event(
        self,
        raw_record: Any,
        source_type: Optional[SourceType] = None,
        index: int = 0
    ) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        """
        Normalizes a single log record, using the explicit or auto-detected adapter.
        """
        resolved_type = source_type or self.detect_source_type(raw_record)
        adapter = self._adapters.get(resolved_type)
        if not adapter:
            # Fallback to generic network flow adapter
            adapter = self._adapters[SourceType.NETWORK_FLOW]

        return adapter.normalize_record(raw_record, index=index)

    def normalize_stream(
        self,
        raw_records: List[Any],
        source_type: Optional[SourceType] = None
    ) -> NormalizationResult:
        """
        Normalizes a batch of telemetry records with graceful isolation of malformed lines.
        """
        events: List[SecurityEvent] = []
        errors: List[Dict[str, Any]] = []

        target_source_type = source_type or (self.detect_source_type(raw_records[0]) if raw_records else SourceType.GENERIC)

        for idx, record in enumerate(raw_records):
            if not record:
                continue
            event, err = self.normalize_event(record, source_type=source_type, index=idx + 1)
            if err:
                errors.append({
                    "record_index": idx + 1,
                    "error": err,
                    "raw_sample": str(record)[:150]
                })
                if not event:
                    continue
            if event:
                events.append(event)

        return NormalizationResult(
            total_records=len(raw_records),
            successful_events=len(events),
            malformed_records=len(errors),
            source_type=target_source_type,
            events=events,
            errors=errors
        )

    @classmethod
    def from_legacy_event(cls, legacy_event: Any) -> SecurityEvent:
        """
        Transforms legacy internal events (e.g. TelemetryEvent or NormalizedEvent)
        into the canonical SecurityEvent model.
        """
        data = legacy_event.model_dump() if hasattr(legacy_event, "model_dump") else (legacy_event if isinstance(legacy_event, dict) else {})
        meta = data.get("metadata", {})

        src_type_str = str(data.get("event_type", "GENERIC")).lower()
        type_mapping = {
            "authentication": SourceType.LINUX_AUTH,
            "network": SourceType.NETWORK_FLOW,
            "process": SourceType.LINUX_AUDIT,
            "dns": SourceType.DNS,
            "file": SourceType.WINDOWS_SYSMON,
            "firewall": SourceType.FIREWALL
        }
        mapped_source_type = type_mapping.get(src_type_str, SourceType.GENERIC)

        return SecurityEvent(
            id=data.get("id") or data.get("event_id") or SecurityEvent.generate_stable_id("legacy", data.get("timestamp"), str(data)),
            timestamp=data.get("timestamp"),
            source_type=mapped_source_type,
            source=data.get("source") or data.get("source_type"),
            hostname=data.get("host") or data.get("hostname"),
            source_ip=data.get("source_ip") or data.get("sourceIp") or meta.get("source_ip"),
            source_port=data.get("source_port") or meta.get("source_port"),
            destination_ip=data.get("destination_ip") or data.get("destinationIp") or meta.get("destination_ip"),
            destination_port=data.get("destination_port") or meta.get("dest_port"),
            protocol=data.get("protocol") or meta.get("protocol"),
            username=data.get("user") or data.get("username") or meta.get("user"),
            process_name=data.get("process_name") or meta.get("process_name") or meta.get("process"),
            process_id=data.get("process_id") or meta.get("pid"),
            command=data.get("command") or data.get("command_line") or meta.get("command_line"),
            event_type=str(data.get("event_type", "security_event")),
            action=data.get("action"),
            status=data.get("status"),
            bytes_in=data.get("bytes_in") or meta.get("bytes_in"),
            bytes_out=data.get("bytes_out") or meta.get("bytes_out"),
            severity=data.get("severity") or ("HIGH" if data.get("status") in ("FAILURE", "DENIED") else "INFO"),
            label=data.get("label") or "BENIGN",
            raw_data=data.get("raw_data") or data,
            metadata=meta
        )

# Global pipeline instance
normalization_pipeline = EventNormalizationPipeline()
