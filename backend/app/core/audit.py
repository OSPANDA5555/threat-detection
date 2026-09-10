import os
import logging
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Dict, Any, Optional

# Configure structured audit logger
audit_logger = logging.getLogger("audit_gateway")
audit_logger.setLevel(logging.INFO)

# Console handler for audit log stream
if not audit_logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - AUDIT - %(message)s')
    ch.setFormatter(formatter)
    audit_logger.addHandler(ch)

class AuditLogger:
    @staticmethod
    def log_tool_invocation(
        tool_name: str,
        arguments: Dict[str, Any],
        status: str,
        record_count: int = 0,
        execution_time_ms: float = 0.0,
        error_message: str = None,
        audit_id: str = None
    ) -> Dict[str, Any]:
        """
        Record a structured audit entry for every tool execution request.
        """
        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "TOOL_GATEWAY_EXECUTION",
            "tool_name": tool_name,
            "arguments": arguments,
            "status": status,  # "SUCCESS", "REJECTED", "TIMEOUT", "ERROR"
            "record_count": record_count,
            "execution_time_ms": round(execution_time_ms, 2),
            "error": error_message
        }
        if audit_id is not None:
            audit_entry["audit_id"] = audit_id
        audit_logger.info(json.dumps(audit_entry))

        # Stream to dedicated log_storage container if configured
        log_storage_url = os.getenv("LOG_STORAGE_URL")
        if log_storage_url:
            try:
                payload = json.dumps({
                    "event_type": "TOOL_GATEWAY_EXECUTION",
                    "host": arguments.get("host", "system"),
                    "user": arguments.get("user", "ai-hunter"),
                    "status": status,
                    "details": audit_entry
                }).encode("utf-8")

                req = urllib.request.Request(
                    log_storage_url,
                    data=payload,
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req, timeout=1.0)
            except Exception:
                pass  # Non-blocking log streaming fallback

        return audit_entry

    @staticmethod
    def log_agent_registration(
        agent_id: str,
        hostname: str,
        ip_address: Optional[str] = None,
        platform: str = "Linux",
        status: str = "SUCCESS",
        tenant_id: str = "soc-org-primary"
    ) -> Dict[str, Any]:
        """Record an audit entry for agent registration."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "AGENT_REGISTRATION",
            "agent_id": agent_id,
            "hostname": hostname,
            "ip_address": ip_address,
            "platform": platform,
            "tenant_id": tenant_id,
            "status": status
        }
        audit_logger.info(json.dumps(entry))
        return entry

    @staticmethod
    def log_agent_authentication(
        agent_id: str,
        auth_type: str,
        status: str,
        ip_address: Optional[str] = None,
        error_message: Optional[str] = None
    ) -> Dict[str, Any]:
        """Record an audit entry for agent authentication attempts."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "AGENT_AUTHENTICATION",
            "agent_id": agent_id,
            "auth_type": auth_type,
            "status": status,
            "ip_address": ip_address,
            "error": error_message
        }
        audit_logger.info(json.dumps(entry))
        return entry

    @staticmethod
    def log_rejected_events(
        agent_id: str,
        reason: str,
        sequence_number: Optional[int] = None,
        count: int = 0,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """Record an audit entry when incoming telemetry is rejected."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "TELEMETRY_REJECTED",
            "agent_id": agent_id,
            "reason": reason,
            "sequence_number": sequence_number,
            "event_count": count,
            "ip_address": ip_address
        }
        audit_logger.warning(json.dumps(entry))
        return entry

    @staticmethod
    def log_abnormal_event_rate(
        agent_id: str,
        current_eps: float,
        threshold_eps: float,
        count: int = 0,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """Record an audit entry when an agent exceeds safe EPS limits."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "ABNORMAL_EVENT_RATE",
            "agent_id": agent_id,
            "current_eps": round(current_eps, 2),
            "threshold_eps": threshold_eps,
            "event_count": count,
            "ip_address": ip_address
        }
        audit_logger.warning(json.dumps(entry))
        return entry

    @staticmethod
    def log_websocket_disconnect(
        client_id: str,
        reason: str,
        active_connections: int,
        tenant_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Record an audit entry when a WebSocket client disconnects."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "WEBSOCKET_DISCONNECT",
            "client_id": client_id,
            "reason": reason,
            "active_connections": active_connections,
            "tenant_id": tenant_id
        }
        audit_logger.info(json.dumps(entry))
        return entry

