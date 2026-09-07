import re
import json
from typing import Tuple, Dict, Any, Optional
from datetime import datetime, timezone

from app.normalization.models import SecurityEvent, SourceType
from app.normalization.adapters.base import BaseEventAdapter
from app.ingestion.validator import validate_ip, validate_port, parse_and_validate_timestamp

class WebLogAdapter(BaseEventAdapter):
    """
    Adapter for Web and Application server telemetry (Nginx, Apache Common/Combined Log Formats, JSON access logs).
    Extracts HTTP method, requested URI/path, status codes, user agents, response bytes, and web attack signatures.
    """

    @property
    def source_type(self) -> SourceType:
        return SourceType.WEB_LOG

    # Standard Apache/Nginx Combined Log regex
    COMBINED_LOG_REGEX = re.compile(
        r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+([^"]*?)\s*(\S+)?"\s+(\d{3})\s+(\d+|-)\s*(?:"([^"]*)"\s*"([^"]*)")?'
    )

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
            return self._normalize_clf_line(trimmed, index)
        else:
            return None, f"Unsupported record format in WebLogAdapter: {type(raw_record)}"

    def _normalize_dict(self, data: Dict[str, Any], index: int) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        raw_ts = data.get("timestamp") or data.get("time") or datetime.now(timezone.utc).isoformat()
        iso_ts, ts_err = parse_and_validate_timestamp(raw_ts)
        if ts_err:
            return None, f"WebLogAdapter timestamp: {ts_err}"

        src_ip = None
        if data.get("client_ip") or data.get("source_ip") or data.get("src_ip"):
            src_ip, ip_err = validate_ip(data.get("client_ip") or data.get("source_ip") or data.get("src_ip"))
            if ip_err:
                return None, f"WebLogAdapter IP: {ip_err}"

        method = data.get("method") or data.get("http_method") or "GET"
        uri = data.get("uri") or data.get("path") or data.get("url") or "/"
        http_status = int(data.get("status_code") or data.get("status") or 200)
        bytes_out = data.get("bytes_sent") or data.get("bytes_out")
        user = data.get("user") or data.get("username")
        if user == "-": user = None

        command_str = f"{method} {uri}"
        action = "ALLOWED" if http_status < 400 else "DENIED"
        status = "SUCCESS" if http_status < 400 else "FAILURE"

        label = "BENIGN"
        if any(p in uri.lower() for p in ["' or '", "union select", "<script>", "../", "/etc/passwd", "sqlmap"]):
            label = "Web Attack - SQL Injection" if "union" in uri.lower() or "' or '" in uri.lower() else "Web Attack - XSS"

        event_id = SecurityEvent.generate_stable_id("web_log", iso_ts, f"{src_ip}:{command_str}:{http_status}:{index}")

        event = SecurityEvent(
            id=event_id,
            timestamp=iso_ts,
            source_type=SourceType.WEB_LOG,
            source=data.get("source") or "nginx_access.log",
            hostname=data.get("host") or data.get("hostname") or "web-server-01",
            source_ip=src_ip,
            source_port=data.get("client_port") or data.get("source_port"),
            destination_ip=data.get("destination_ip") or data.get("server_ip"),
            destination_port=443 if "https" in str(uri).lower() else 80,
            protocol="HTTP/1.1",
            username=user,
            command=command_str,
            event_type="WEB_ACCESS",
            action=action,
            status=status,
            bytes_out=int(bytes_out) if bytes_out and str(bytes_out).isdigit() else None,
            severity="HIGH" if label != "BENIGN" else "INFO",
            label=label,
            raw_data=data,
            metadata={"http_status": http_status, "user_agent": data.get("user_agent"), "method": method, "path": uri}
        )
        return event, None

    def _normalize_clf_line(self, line: str, index: int) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        match = self.COMBINED_LOG_REGEX.match(line)
        if not match:
            # Fallback simple split
            parts = line.split()
            if len(parts) >= 6:
                raw_ip = parts[0]
                src_ip, ip_err = validate_ip(raw_ip)
                if ip_err:
                    return None, f"WebLogAdapter: {ip_err}"
                now_iso = datetime.now(timezone.utc).isoformat()
                return SecurityEvent(
                    id=SecurityEvent.generate_stable_id("web_log", now_iso, line),
                    timestamp=now_iso,
                    source_type=SourceType.WEB_LOG,
                    source="web_access.log",
                    hostname="web-server-01",
                    source_ip=src_ip,
                    destination_port=80,
                    protocol="HTTP/1.1",
                    command=line[:80],
                    event_type="WEB_ACCESS",
                    action="LOG_ENTRY",
                    status="SUCCESS",
                    raw_data={"raw": line}
                ), None
            return None, f"Malformed Common Log Format line in WebLogAdapter: {line[:60]}"

        raw_ip = match.group(1)
        raw_user = match.group(2)
        raw_date = match.group(3)
        method = match.group(4)
        uri = match.group(5)
        proto = match.group(6) or "HTTP/1.1"
        raw_status = match.group(7)
        raw_bytes = match.group(8)
        referer = match.group(9)
        user_agent = match.group(10)

        src_ip, ip_err = validate_ip(raw_ip)
        if ip_err:
            return None, f"WebLogAdapter IP: {ip_err}"

        # Standard Apache timestamp format: 10/Aug/2026:19:35:00 +0000
        iso_ts = datetime.now(timezone.utc).isoformat()
        try:
            dt = datetime.strptime(raw_date.split()[0], "%d/%b/%Y:%H:%M:%S")
            iso_ts = dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            parsed, _ = parse_and_validate_timestamp(raw_date)
            if parsed: iso_ts = parsed

        http_code = int(raw_status)
        bytes_val = int(raw_bytes) if raw_bytes and raw_bytes != "-" and raw_bytes.isdigit() else None
        username = None if raw_user == "-" else raw_user
        import urllib.parse
        decoded_uri = urllib.parse.unquote_plus(uri)
        check_str = f"{uri} {decoded_uri} {user_agent or ''}".lower()

        label = "BENIGN"
        if any(p in check_str for p in ["' or '", "union select", "<script>", "../", "/etc/passwd", "sqlmap", "%27 or %27", "%27%20or%20", "1=1"]):
            label = "Web Attack - SQL Injection" if any(p in check_str for p in ["union", "' or '", "1=1", "sqlmap", "%27 or %27", "%27%20or%20"]) else "Web Attack - XSS"

        command_str = f"{method} {uri}"

        return SecurityEvent(
            id=SecurityEvent.generate_stable_id("web_log", iso_ts, line),
            timestamp=iso_ts,
            source_type=SourceType.WEB_LOG,
            source="nginx_access.log",
            hostname="web-server-01",
            source_ip=src_ip,
            destination_port=443 if "443" in line or proto == "HTTPS" else 80,
            protocol=proto,
            username=username,
            command=command_str,
            event_type="WEB_ACCESS",
            action="ALLOWED" if http_code < 400 else "DENIED",
            status="SUCCESS" if http_code < 400 else "FAILURE",
            bytes_out=bytes_val,
            severity="HIGH" if label != "BENIGN" or (user_agent and "sqlmap" in user_agent.lower()) else "INFO",
            label=label,
            raw_data={"raw": line},
            metadata={"http_status": http_code, "user_agent": user_agent, "referer": referer, "path": uri, "method": method}
        ), None
