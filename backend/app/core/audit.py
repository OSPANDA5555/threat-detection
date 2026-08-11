import logging
import json
from datetime import datetime, timezone
from typing import Dict, Any

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
        error_message: str = None
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
        audit_logger.info(json.dumps(audit_entry))
        return audit_entry
