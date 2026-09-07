import re
import json
from typing import Tuple, Dict, Any, Optional
from datetime import datetime, timezone

from app.normalization.models import SecurityEvent, SourceType
from app.normalization.adapters.base import BaseEventAdapter
from app.ingestion.validator import parse_and_validate_timestamp

class LinuxAuditAdapter(BaseEventAdapter):
    """
    Adapter for Linux Audit daemon telemetry (/var/log/audit/audit.log, SYSCALL, EXECVE, PROCTITLE, PATH).
    Extracts process execution trees, system call numbers, PIDs, UIDs, and file accesses.
    """

    @property
    def source_type(self) -> SourceType:
        return SourceType.LINUX_AUDIT

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
            return self._normalize_audit_line(trimmed, index)
        else:
            return None, f"Unsupported record format in LinuxAuditAdapter: {type(raw_record)}"

    def _normalize_dict(self, data: Dict[str, Any], index: int) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        raw_ts = data.get("timestamp") or data.get("time") or datetime.now(timezone.utc).isoformat()
        iso_ts, ts_err = parse_and_validate_timestamp(raw_ts)
        if ts_err:
            return None, f"LinuxAuditAdapter timestamp: {ts_err}"

        host = data.get("host") or data.get("hostname")
        proc = data.get("process") or data.get("process_name") or data.get("exe")
        cmd = data.get("command") or data.get("command_line")
        pid = data.get("pid") or data.get("process_id")
        user = data.get("user") or data.get("username")
        action = data.get("action") or "EXECUTE"
        status = data.get("status") or "SUCCESS"

        event_id = SecurityEvent.generate_stable_id("audit.log", iso_ts, f"{host}:{proc}:{pid}:{cmd}:{index}")

        event = SecurityEvent(
            id=event_id,
            timestamp=iso_ts,
            source_type=SourceType.LINUX_AUDIT,
            source=data.get("source") or "audit.log",
            hostname=host,
            username=user,
            process_name=proc,
            process_id=int(pid) if pid is not None and str(pid).isdigit() else None,
            command=cmd,
            event_type=data.get("event_type") or "PROCESS_EXECUTION",
            action=action,
            status=status,
            severity="HIGH" if any(k in str(cmd or "").lower() for k in ["shadow", "chmod", "curl", "bash -i"]) else "INFO",
            label="Privilege Escalation" if "sudo" in str(proc or "").lower() or "shadow" in str(cmd or "").lower() else "BENIGN",
            raw_data=data,
            metadata=data.get("metadata", {})
        )
        return event, None

    def _normalize_audit_line(self, line: str, index: int) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        if not line:
            return None, "Empty auditd line"

        # Parse key=value tokens in auditd record
        # Example: type=SYSCALL msg=audit(1691696052.123:456): arch=c000003e syscall=59 success=yes exit=0 pid=2410 comm="sudo" exe="/usr/bin/sudo"
        audit_type_match = re.search(r'type=([A-Z_]+)', line)
        audit_type = audit_type_match.group(1) if audit_type_match else "AUDIT_RECORD"

        # Timestamp from audit epoch: msg=audit(1691696052.123:456)
        msg_match = re.search(r'msg=audit\((\d+\.?\d*):', line)
        iso_ts = datetime.now(timezone.utc).isoformat()
        if msg_match:
            try:
                epoch_sec = float(msg_match.group(1))
                iso_ts = datetime.fromtimestamp(epoch_sec, tz=timezone.utc).isoformat()
            except ValueError:
                pass

        # Parse key-values
        parsed_kv = {}
        for match in re.findall(r'(\w+)=(?:"([^"]*)"|(\S+))', line):
            k = match[0]
            v = match[1] if match[1] else match[2]
            parsed_kv[k] = v

        pid_val = parsed_kv.get("pid")
        process_id = int(pid_val) if pid_val and pid_val.isdigit() else None
        process_name = parsed_kv.get("comm") or parsed_kv.get("exe")
        if process_name and "/" in process_name:
            process_name = process_name.split("/")[-1]

        command_str = parsed_kv.get("exe")
        if "a0" in parsed_kv:
            # Construct command line from args a0, a1, a2...
            arg_keys = sorted([k for k in parsed_kv.keys() if re.match(r'^a\d+$', k)], key=lambda x: int(x[1:]))
            if arg_keys:
                command_str = " ".join(parsed_kv[k] for k in arg_keys)

        success_val = parsed_kv.get("success", "yes").lower()
        status = "SUCCESS" if success_val in ("yes", "1", "true") else "FAILURE"
        action = "EXECUTE" if audit_type in ("SYSCALL", "EXECVE") else "FILE_ACCESS" if audit_type == "PATH" else audit_type

        return SecurityEvent(
            id=SecurityEvent.generate_stable_id("audit.log", iso_ts, line),
            timestamp=iso_ts,
            source_type=SourceType.LINUX_AUDIT,
            source="audit.log",
            hostname=parsed_kv.get("node") or "linux-host",
            username=parsed_kv.get("uid") or parsed_kv.get("euid"),
            process_name=process_name,
            process_id=process_id,
            command=command_str,
            event_type=f"AUDIT_{audit_type}",
            action=action,
            status=status,
            severity="HIGH" if command_str and any(s in command_str for s in ["shadow", "sudo", "chmod +s", "/etc/passwd"]) else "INFO",
            label="Privilege Escalation" if command_str and "shadow" in command_str else "BENIGN",
            raw_data={"raw": line, "fields": parsed_kv},
            metadata={"syscall": parsed_kv.get("syscall"), "key": parsed_kv.get("key"), "cwd": parsed_kv.get("cwd")}
        ), None
