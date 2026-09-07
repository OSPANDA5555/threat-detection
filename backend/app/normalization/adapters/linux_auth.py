import re
import json
from typing import Tuple, Dict, Any, Optional
from datetime import datetime, timezone

from app.normalization.models import SecurityEvent, SourceType
from app.normalization.adapters.base import BaseEventAdapter
from app.ingestion.validator import validate_ip, validate_port, parse_and_validate_timestamp

class LinuxAuthAdapter(BaseEventAdapter):
    """
    Adapter for Linux authentication telemetry (/var/log/auth.log, /var/log/secure, PAM, OpenSSH, sudo).
    Converts auth syslog strings and structured logs into canonical SecurityEvent instances.
    """

    @property
    def source_type(self) -> SourceType:
        return SourceType.LINUX_AUTH

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
            # Check if JSON string
            trimmed = raw_record.strip()
            if trimmed.startswith("{") and trimmed.endswith("}"):
                try:
                    return self._normalize_dict(json.loads(trimmed), index)
                except json.JSONDecodeError:
                    pass
            return self._normalize_syslog_line(trimmed, index)
        else:
            return None, f"Unsupported record format in LinuxAuthAdapter: {type(raw_record)}"

    def _normalize_dict(self, data: Dict[str, Any], index: int) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        raw_ts = data.get("timestamp") or data.get("time") or datetime.now(timezone.utc).isoformat()
        iso_ts, ts_err = parse_and_validate_timestamp(raw_ts)
        if ts_err:
            return None, f"LinuxAuthAdapter timestamp: {ts_err}"

        src_ip = None
        if data.get("sourceIp") or data.get("source_ip"):
            src_ip, ip_err = validate_ip(data.get("sourceIp") or data.get("source_ip"))
            if ip_err:
                return None, f"LinuxAuthAdapter IP: {ip_err}"

        action = str(data.get("action") or "AUTH").upper()
        status = str(data.get("status") or ("FAILURE" if "FAIL" in action else "SUCCESS")).upper()
        user = data.get("user") or data.get("username")
        host = data.get("host") or data.get("hostname")
        event_type = data.get("eventType") or data.get("event_type") or "SSH_AUTHENTICATION"

        event_id = SecurityEvent.generate_stable_id("linux_auth", iso_ts, f"{host}:{user}:{src_ip}:{action}:{index}")

        event = SecurityEvent(
            id=event_id,
            timestamp=iso_ts,
            source_type=SourceType.LINUX_AUTH,
            source=data.get("source") or "auth.log",
            hostname=host,
            source_ip=src_ip,
            source_port=data.get("port") or data.get("source_port"),
            destination_ip=data.get("destinationIp") or data.get("destination_ip"),
            destination_port=22 if "ssh" in str(event_type).lower() else None,
            protocol="TCP",
            username=user,
            process_name="sshd" if "ssh" in str(event_type).lower() else data.get("process_name") or "pam",
            process_id=data.get("pid"),
            command=data.get("command"),
            event_type=str(event_type),
            action=action,
            status=status,
            bytes_in=None,
            bytes_out=None,
            severity="HIGH" if status == "FAILURE" else "INFO",
            label="SSH-Patator" if status == "FAILURE" and src_ip else "BENIGN",
            raw_data=data,
            metadata=data.get("metadata", {})
        )
        return event, None

    def _normalize_syslog_line(self, line: str, index: int) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        if not line:
            return None, "Empty syslog line"

        # Regex patterns for SSH and Sudo auth logs
        # Pattern 1: Failed password for <user> from <ip> port <port> ssh2
        match_fail = re.search(r'sshd\[(\d+)\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)', line, re.IGNORECASE)
        # Pattern 2: Accepted password for <user> from <ip> port <port> ssh2
        match_succ = re.search(r'sshd\[(\d+)\]:\s+Accepted password for (\S+) from (\S+) port (\d+)', line, re.IGNORECASE)
        # Pattern 3: sudo command execution
        match_sudo = re.search(r'sudo:\s+(\S+)\s+:.*?COMMAND=(.+)', line, re.IGNORECASE)

        now_iso = datetime.now(timezone.utc).isoformat()
        hostname = "linux-host"

        # Attempt to parse syslog prefix: "Aug 10 19:30:15 web-server-01 sshd[1482]: ..."
        prefix_match = re.match(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$', line)
        log_content = line
        if prefix_match:
            raw_date_str = prefix_match.group(1)
            hostname = prefix_match.group(2)
            log_content = prefix_match.group(3)
            parsed_ts, _ = parse_and_validate_timestamp(raw_date_str)
            if parsed_ts:
                now_iso = parsed_ts

        if match_fail:
            pid = int(match_fail.group(1))
            username = match_fail.group(2)
            raw_ip = match_fail.group(3)
            raw_port = match_fail.group(4)

            src_ip, ip_err = validate_ip(raw_ip)
            if ip_err:
                return None, f"LinuxAuthAdapter: {ip_err}"
            src_port, _ = validate_port(raw_port)

            return SecurityEvent(
                id=SecurityEvent.generate_stable_id("auth.log", now_iso, line),
                timestamp=now_iso,
                source_type=SourceType.LINUX_AUTH,
                source="auth.log",
                hostname=hostname,
                source_ip=src_ip,
                source_port=src_port,
                destination_port=22,
                protocol="TCP",
                username=username,
                process_name="sshd",
                process_id=pid,
                event_type="SSH_FAILED_PASSWORD",
                action="FAILED_LOGIN",
                status="FAILURE",
                severity="HIGH",
                label="SSH-Patator",
                raw_data={"raw": line},
                metadata={"auth_mechanism": "password", "pam_service": "sshd"}
            ), None

        elif match_succ:
            pid = int(match_succ.group(1))
            username = match_succ.group(2)
            raw_ip = match_succ.group(3)
            raw_port = match_succ.group(4)

            src_ip, ip_err = validate_ip(raw_ip)
            if ip_err:
                return None, f"LinuxAuthAdapter: {ip_err}"
            src_port, _ = validate_port(raw_port)

            return SecurityEvent(
                id=SecurityEvent.generate_stable_id("auth.log", now_iso, line),
                timestamp=now_iso,
                source_type=SourceType.LINUX_AUTH,
                source="auth.log",
                hostname=hostname,
                source_ip=src_ip,
                source_port=src_port,
                destination_port=22,
                protocol="TCP",
                username=username,
                process_name="sshd",
                process_id=pid,
                event_type="SSH_ACCEPTED_PASSWORD",
                action="SUCCESSFUL_LOGIN",
                status="SUCCESS",
                severity="INFO",
                label="BENIGN",
                raw_data={"raw": line},
                metadata={"auth_mechanism": "password", "pam_service": "sshd"}
            ), None

        elif match_sudo:
            username = match_sudo.group(1)
            command_str = match_sudo.group(2).strip()

            return SecurityEvent(
                id=SecurityEvent.generate_stable_id("auth.log", now_iso, line),
                timestamp=now_iso,
                source_type=SourceType.LINUX_AUTH,
                source="auth.log",
                hostname=hostname,
                username=username,
                process_name="sudo",
                command=command_str,
                event_type="SUDO_EXECUTION",
                action="PRIVILEGE_ELEVATION",
                status="SUCCESS",
                severity="HIGH" if any(p in command_str for p in ["bash", "sh", "su", "/etc/shadow"]) else "INFO",
                label="Privilege Escalation" if "bash" in command_str else "BENIGN",
                raw_data={"raw": line},
                metadata={"target_user": "root"}
            ), None

        # Generic auth log fallback
        return SecurityEvent(
            id=SecurityEvent.generate_stable_id("auth.log", now_iso, line),
            timestamp=now_iso,
            source_type=SourceType.LINUX_AUTH,
            source="auth.log",
            hostname=hostname,
            event_type="LINUX_AUTH_GENERIC",
            action="LOG_ENTRY",
            status="INFO",
            raw_data={"raw": line}
        ), None
