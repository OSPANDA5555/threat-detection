import re
import json
from typing import Tuple, Dict, Any, Optional
from datetime import datetime, timezone

from app.normalization.models import SecurityEvent, SourceType
from app.normalization.adapters.base import BaseEventAdapter
from app.ingestion.validator import validate_ip, validate_port, parse_and_validate_timestamp, parse_protocol

class WindowsSysmonAdapter(BaseEventAdapter):
    """
    Adapter for Microsoft Windows Event Log & Sysmon telemetry (Event ID 1: Process Creation,
    Event ID 3: Network Connection, Event ID 11: File Create, Event ID 22: DNS Query).
    Supports structured JSON, XML exports, and dictionary records.
    """

    @property
    def source_type(self) -> SourceType:
        return SourceType.WINDOWS_SYSMON

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
                    return None, f"WindowsSysmonAdapter: Invalid JSON string"
            return self._normalize_kv_line(trimmed, index)
        else:
            return None, f"Unsupported record format in WindowsSysmonAdapter: {type(raw_record)}"

    def _normalize_dict(self, data: Dict[str, Any], index: int) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        # Handle nested EventData if present (standard Sysmon structure)
        event_data = data.get("EventData") or data.get("event_data") or data

        # Timestamp
        raw_ts = (
            event_data.get("UtcTime") or
            data.get("TimeCreated") or
            data.get("@timestamp") or
            data.get("timestamp") or
            datetime.now(timezone.utc).isoformat()
        )
        iso_ts, ts_err = parse_and_validate_timestamp(raw_ts)
        if ts_err:
            return None, f"WindowsSysmonAdapter timestamp: {ts_err}"

        # Event ID
        event_id_val = data.get("EventID") or data.get("event_id") or event_data.get("EventID") or 1
        try:
            event_id_num = int(event_id_val)
        except (ValueError, TypeError):
            event_id_num = 1

        hostname = (
            data.get("Computer") or
            data.get("ComputerName") or
            data.get("host") or
            data.get("hostname") or
            "win-host-01"
        )
        user = event_data.get("User") or data.get("user") or data.get("username")
        image = event_data.get("Image") or data.get("process_name") or data.get("image")
        cmdline = event_data.get("CommandLine") or data.get("command") or data.get("cmdline")
        pid_val = event_data.get("ProcessId") or data.get("process_id") or data.get("pid")
        process_id = int(pid_val) if pid_val is not None and str(pid_val).isdigit() else None

        proc_name = None
        if image:
            proc_name = image.split("\\")[-1] if "\\" in image else image.split("/")[-1]

        # Extract network details for Event ID 3 or general network fields
        src_ip = None
        raw_src_ip = event_data.get("SourceIp") or data.get("source_ip") or data.get("src_ip")
        if raw_src_ip:
            src_ip, _ = validate_ip(raw_src_ip)

        dst_ip = None
        raw_dst_ip = event_data.get("DestinationIp") or data.get("destination_ip") or data.get("dst_ip")
        if raw_dst_ip:
            dst_ip, _ = validate_ip(raw_dst_ip)

        src_port, _ = validate_port(event_data.get("SourcePort") or data.get("source_port") or data.get("src_port"))
        dst_port, _ = validate_port(event_data.get("DestinationPort") or data.get("destination_port") or data.get("dst_port"))
        protocol = parse_protocol(event_data.get("Protocol") or data.get("protocol") or ("TCP" if dst_port else None))

        # Event ID mapping
        event_type_name = "SYSMON_GENERIC"
        action = "LOG_ENTRY"
        status = "SUCCESS"
        label = "BENIGN"
        metadata: Dict[str, Any] = {"event_id": event_id_num}

        if event_id_num == 1:
            event_type_name = "PROCESS_CREATE"
            action = "CREATE_PROCESS"
            parent_image = event_data.get("ParentImage") or data.get("parent_process")
            parent_cmdline = event_data.get("ParentCommandLine")
            metadata.update({
                "parent_image": parent_image,
                "parent_command_line": parent_cmdline,
                "hashes": event_data.get("Hashes"),
                "current_directory": event_data.get("CurrentDirectory")
            })
            if cmdline and any(susp in cmdline.lower() for susp in ["powershell -enc", "mimikatz", "vssadmin delete", "certutil -decode", "whoami /priv"]):
                label = "Privilege Escalation / Credential Access"

        elif event_id_num == 3:
            event_type_name = "NETWORK_CONNECT"
            action = "NETWORK_CONNECTION"
            metadata.update({
                "destination_hostname": event_data.get("DestinationHostname"),
                "initiated": event_data.get("Initiated")
            })
            if dst_port in (4444, 1337, 8888, 9001):
                label = "C2 Communication"

        elif event_id_num == 11:
            event_type_name = "FILE_CREATE"
            action = "CREATE_FILE"
            target_file = event_data.get("TargetFilename") or data.get("target_filename")
            metadata.update({"target_filename": target_file})
            command_val = f"CREATE {target_file}" if target_file else None
            cmdline = cmdline or command_val

        elif event_id_num == 22:
            event_type_name = "DNS_QUERY"
            action = "DNS_RESOLVE"
            query_name = event_data.get("QueryName") or data.get("query_name")
            query_status = event_data.get("QueryStatus") or data.get("query_status")
            query_results = event_data.get("QueryResults")
            metadata.update({
                "query_name": query_name,
                "query_status": query_status,
                "query_results": query_results
            })
            cmdline = cmdline or f"QUERY {query_name}"
            if query_name and any(d in query_name.lower() for d in ["c2", "evil", "tunnel", "beacon"]):
                label = "DNS Tunneling / Malicious Domain"

        stable_id = SecurityEvent.generate_stable_id("windows_sysmon", iso_ts, f"{hostname}:{event_id_num}:{proc_name}:{cmdline}:{index}")

        event = SecurityEvent(
            id=stable_id,
            timestamp=iso_ts,
            source_type=SourceType.WINDOWS_SYSMON,
            source=data.get("source") or "Microsoft-Windows-Sysmon/Operational",
            hostname=hostname,
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=protocol,
            username=user,
            process_name=proc_name,
            process_id=process_id,
            command=cmdline,
            event_type=event_type_name,
            action=action,
            status=status,
            severity="HIGH" if label != "BENIGN" else "INFO",
            label=label,
            raw_data=data,
            metadata=metadata
        )
        return event, None

    def _normalize_kv_line(self, line: str, index: int) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        parsed_kv = {}
        for match in re.findall(r'(\w+)=(?:"([^"]*)"|(\S+))', line):
            k = match[0]
            v = match[1] if match[1] else match[2]
            parsed_kv[k] = v

        if not parsed_kv:
            return None, f"WindowsSysmonAdapter: Unable to parse key-value pairs from line: {line[:50]}"

        return self._normalize_dict(parsed_kv, index)
