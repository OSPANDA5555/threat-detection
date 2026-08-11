import time
import uuid
import asyncio
from typing import Dict, Any, List, Optional
from app.config import settings
from app.core.audit import AuditLogger
from app.core.security import sanitize_input_string
from app.schemas.tool import ToolDefinition, ToolExecutionRequest, ToolExecutionResult
from .definitions import INITIAL_TOOL_REGISTRY

class ToolGateway:
    """
    Controlled Gateway for AI Tool Invocations.
    Guarantees strict schema validation, read-only enforcement, hard limits,
    execution timeouts, and immutable audit logging.
    """
    def __init__(self, registry: Optional[Dict[str, ToolDefinition]] = None):
        self._registry: Dict[str, ToolDefinition] = registry or INITIAL_TOOL_REGISTRY

    def get_registered_tools(self) -> List[ToolDefinition]:
        """Return list of all approved read-only tool definitions."""
        return list(self._registry.values())

    def get_tool_definition(self, tool_name: str) -> Optional[ToolDefinition]:
        """Retrieve definition for a specific tool."""
        return self._registry.get(tool_name)

    async def execute_tool(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        """
        Main execution gateway. Processes, validates, and safely routes tool requests.
        """
        start_time = time.time()
        audit_id = f"aud-{uuid.uuid4().hex[:10]}"
        tool_name = request.tool_name
        args = request.arguments or {}

        # 1. Registration Check
        tool_def = self._registry.get(tool_name)
        if not tool_def:
            err_msg = f"Security Violation: Tool '{tool_name}' is NOT registered in the approved Tool Gateway whitelist."
            AuditLogger.log_tool_invocation(
                tool_name=tool_name,
                arguments=args,
                status="REJECTED",
                error_message=err_msg
            )
            return ToolExecutionResult(
                tool_name=tool_name,
                status="REJECTED",
                error_message=err_msg,
                audit_id=audit_id
            )

        # 2. Read-Only Verification
        if not tool_def.read_only or not settings.ENFORCE_READ_ONLY:
            err_msg = f"Security Violation: Tool '{tool_name}' violates read-only safety constraints."
            AuditLogger.log_tool_invocation(
                tool_name=tool_name,
                arguments=args,
                status="REJECTED",
                error_message=err_msg
            )
            return ToolExecutionResult(
                tool_name=tool_name,
                status="REJECTED",
                error_message=err_msg,
                audit_id=audit_id
            )

        # 3. Argument Validation & Sanitization
        validated_args, validation_err = self._validate_and_sanitize_args(tool_def, args)
        if validation_err:
            AuditLogger.log_tool_invocation(
                tool_name=tool_name,
                arguments=args,
                status="REJECTED",
                error_message=validation_err
            )
            return ToolExecutionResult(
                tool_name=tool_name,
                status="REJECTED",
                error_message=validation_err,
                audit_id=audit_id
            )

        # 4. Enforce Hard Result Limits (Default cap: 500)
        requested_limit = validated_args.get("limit", 50)
        try:
            requested_limit = int(requested_limit)
        except (ValueError, TypeError):
            requested_limit = 50
        effective_limit = min(max(1, requested_limit), settings.MAX_TOOL_RESULT_COUNT, tool_def.max_results_cap)
        validated_args["limit"] = effective_limit

        # 5. Execute with Timeout Bounds
        try:
            # Simulated telemetry query output for Phase 1 prototype
            records = await asyncio.wait_for(
                self._dispatch_tool_query(tool_name, validated_args),
                timeout=settings.TOOL_TIMEOUT_SECONDS
            )
            elapsed_ms = (time.time() - start_time) * 1000.0

            AuditLogger.log_tool_invocation(
                tool_name=tool_name,
                arguments=validated_args,
                status="SUCCESS",
                record_count=len(records),
                execution_time_ms=elapsed_ms
            )

            return ToolExecutionResult(
                tool_name=tool_name,
                status="SUCCESS",
                record_count=len(records),
                records=records,
                execution_time_ms=elapsed_ms,
                audit_id=audit_id
            )

        except asyncio.TimeoutError:
            elapsed_ms = (time.time() - start_time) * 1000.0
            err_msg = f"Execution Timeout: Tool '{tool_name}' exceeded maximum allowed timeout of {settings.TOOL_TIMEOUT_SECONDS}s."
            AuditLogger.log_tool_invocation(
                tool_name=tool_name,
                arguments=validated_args,
                status="TIMEOUT",
                execution_time_ms=elapsed_ms,
                error_message=err_msg
            )
            return ToolExecutionResult(
                tool_name=tool_name,
                status="TIMEOUT",
                error_message=err_msg,
                execution_time_ms=elapsed_ms,
                audit_id=audit_id
            )
        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000.0
            err_msg = f"Tool Execution Error: {str(e)}"
            AuditLogger.log_tool_invocation(
                tool_name=tool_name,
                arguments=validated_args,
                status="ERROR",
                execution_time_ms=elapsed_ms,
                error_message=err_msg
            )
            return ToolExecutionResult(
                tool_name=tool_name,
                status="ERROR",
                error_message=err_msg,
                execution_time_ms=elapsed_ms,
                audit_id=audit_id
            )

    def _validate_and_sanitize_args(self, tool_def: ToolDefinition, args: Dict[str, Any]) -> tuple[Dict[str, Any], Optional[str]]:
        """Validate input arguments against registered tool parameter specs."""
        sanitized = {}
        allowed_param_names = {p.name for p in tool_def.parameters}

        # Reject unexpected parameter keys
        for key in args.keys():
            if key not in allowed_param_names:
                return {}, f"Invalid Parameter: Argument '{key}' is not allowed for tool '{tool_def.name}'."

        # Check required parameters & set defaults
        for param_spec in tool_def.parameters:
            val = args.get(param_spec.name)
            if val is None:
                if param_spec.required:
                    return {}, f"Missing Required Parameter: '{param_spec.name}' is required for tool '{tool_def.name}'."
                if param_spec.default is not None:
                    sanitized[param_spec.name] = param_spec.default
            else:
                # Sanitize string inputs
                if isinstance(val, str):
                    cleaned_val = sanitize_input_string(val)
                    # Check for shell payload attempt markers
                    if any(shell_char in cleaned_val for shell_char in [";", "&&", "||", "`", "$( ", "<script>"]):
                        return {}, f"Security Alert: Malicious input pattern detected in argument '{param_spec.name}'."
                    sanitized[param_spec.name] = cleaned_val
                else:
                    sanitized[param_spec.name] = val

        return sanitized, None

    async def _dispatch_tool_query(self, tool_name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Internal query dispatcher for telemetry searching.
        Routes queries through the synthetic Telemetry Engine.
        """
        from app.telemetry.generator import telemetry_engine
        from app.telemetry.models import EventFilter, EventType
        await asyncio.sleep(0.02)  # Simulate small database query latency

        # Map tool name to EventType enum filter
        event_type_map = {
            "search_authentication_events": EventType.AUTHENTICATION,
            "search_network_events": EventType.NETWORK,
            "search_dns_events": EventType.DNS,
            "search_process_events": EventType.PROCESS,
            "search_file_events": EventType.FILE,
        }

        limit = args.get("limit", 50)
        host = args.get("host")
        user = args.get("user")
        src_ip = args.get("source_ip") or args.get("src_ip") or args.get("ip") or args.get("client_ip")
        dest_ip = args.get("dest_ip") or args.get("destination_ip")
        action = args.get("action")
        status = args.get("status")

        # Specific event type tool queries
        if tool_name in event_type_map:
            flt = EventFilter(
                host=host,
                user=user,
                source_ip=src_ip,
                destination_ip=dest_ip,
                event_type=event_type_map[tool_name],
                action=action,
                status=status,
                limit=limit
            )
            events = telemetry_engine.query_events(flt)
            return [evt.model_dump() for evt in events]

        # Host timeline query
        elif tool_name == "get_host_timeline":
            flt = EventFilter(host=host, limit=limit)
            events = telemetry_engine.query_events(flt)
            return [evt.model_dump() for evt in events]

        # IP activity query
        elif tool_name == "get_ip_activity":
            target_ip = args.get("ip")
            flt_src = EventFilter(source_ip=target_ip, limit=limit)
            flt_dst = EventFilter(destination_ip=target_ip, limit=limit)
            events = telemetry_engine.query_events(flt_src) + telemetry_engine.query_events(flt_dst)
            return [evt.model_dump() for evt in events[:limit]]

        # Domain activity query
        elif tool_name == "get_domain_activity":
            flt = EventFilter(event_type=EventType.DNS, limit=limit)
            events = telemetry_engine.query_events(flt)
            target_domain = args.get("domain", "").lower()
            filtered = [evt for evt in events if target_domain in evt.metadata.get("domain", "").lower()]
            return [evt.model_dump() for evt in filtered[:limit]]

        # Alerts query
        elif tool_name == "get_alerts":
            flt = EventFilter(host=host, limit=limit)
            events = telemetry_engine.query_events(flt)
            return [evt.model_dump() for evt in events if evt.status == "FAILURE" or evt.status == "DENIED"]

        # Open port & SSH scanner query
        elif tool_name == "scan_open_ports":
            target_host = args.get("host", "web-server-01")
            port_profiles = {
                "web-server-01": [
                    {"port": 22, "service": "SSH", "status": "OPEN", "protocol": "TCP", "version": "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5", "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "risk_level": "INFO"},
                    {"port": 80, "service": "HTTP", "status": "OPEN", "protocol": "TCP", "version": "nginx/1.18.0", "banner": "HTTP/1.1 200 OK", "risk_level": "LOW"},
                    {"port": 443, "service": "HTTPS", "status": "OPEN", "protocol": "TCP", "version": "nginx/1.18.0 (TLS v1.3)", "banner": "HTTP/1.1 200 OK", "risk_level": "LOW"}
                ],
                "db-server-01": [
                    {"port": 22, "service": "SSH", "status": "OPEN", "protocol": "TCP", "version": "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5", "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "risk_level": "INFO"},
                    {"port": 5432, "service": "PostgreSQL", "status": "OPEN", "protocol": "TCP", "version": "PostgreSQL 14.5", "banner": "PostgreSQL 14.5 Database Engine", "risk_level": "MEDIUM"}
                ],
                "jump-host-01": [
                    {"port": 22, "service": "SSH", "status": "OPEN", "protocol": "TCP", "version": "OpenSSH 8.2p1 Restricted Bastion", "banner": "SSH-2.0-OpenSSH_8.2p1 Bastion", "risk_level": "INFO"}
                ],
                "workstation-01": [
                    {"port": 22, "service": "SSH", "status": "CLOSED", "protocol": "TCP", "version": "N/A", "banner": "Connection Refused", "risk_level": "SAFE"},
                    {"port": 8080, "service": "HTTP-ALT", "status": "OPEN", "protocol": "TCP", "version": "Internal Python Dev Server", "banner": "BaseHTTP/0.6 Python/3.9", "risk_level": "MEDIUM"}
                ],
                "workstation-02": [
                    {"port": 22, "service": "SSH", "status": "CLOSED", "protocol": "TCP", "version": "N/A", "banner": "Connection Refused", "risk_level": "SAFE"}
                ]
            }
            results = port_profiles.get(target_host, [
                {"port": 22, "service": "SSH", "status": "OPEN", "protocol": "TCP", "version": "OpenSSH 8.2p1", "banner": "SSH-2.0-OpenSSH_8.2p1", "risk_level": "INFO"}
            ])
            return results[:limit]

        return []

