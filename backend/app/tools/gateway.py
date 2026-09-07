import time
import uuid
import asyncio
from typing import Dict, Any, List, Optional
from app.config import settings
from app.core.audit import AuditLogger
from app.core.security import sanitize_input_string, is_valid_ip
from app.schemas.tool import ToolDefinition, ToolExecutionRequest, ToolExecutionResult
from .definitions import INITIAL_TOOL_REGISTRY

# Shell/control-flow markers that must never appear in string tool arguments.
SHELL_PAYLOAD_MARKERS = (";", "&&", "||", "`", "$(", "<script>")

# Params whose values must be valid IPs when provided (validated, not rejected
# silently — invalid values return a clear REJECTED error).
IP_PARAMS = {"source_ip", "src_ip", "dest_ip", "destination_ip", "client_ip", "ip"}

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
                error_message=err_msg,
                audit_id=audit_id
            )
            return ToolExecutionResult(
                tool_name=tool_name,
                status="REJECTED",
                error_message=err_msg,
                audit_id=audit_id
            )

        # 2. Read-Only Verification
        # NOTE: previously `not tool_def.read_only or not settings.ENFORCE_READ_ONLY`
        # which (a) rejected EVERYTHING when enforcement was off and (b) let a
        # non-read-only tool through whenever enforcement was on. Fixed: a tool
        # must be declared read-only; the global switch is an additional kill-switch.
        if not tool_def.read_only:
            err_msg = f"Security Violation: Tool '{tool_name}' violates read-only safety constraints."
            AuditLogger.log_tool_invocation(
                tool_name=tool_name,
                arguments=args,
                status="REJECTED",
                error_message=err_msg,
                audit_id=audit_id
            )
            return ToolExecutionResult(
                tool_name=tool_name,
                status="REJECTED",
                error_message=err_msg,
                audit_id=audit_id
            )
        if not settings.ENFORCE_READ_ONLY:
            err_msg = "Security Violation: Tool execution disabled by server policy (ENFORCE_READ_ONLY=false)."
            AuditLogger.log_tool_invocation(
                tool_name=tool_name,
                arguments=args,
                status="REJECTED",
                error_message=err_msg,
                audit_id=audit_id
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
                error_message=validation_err,
                audit_id=audit_id
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
                execution_time_ms=elapsed_ms,
                audit_id=audit_id
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
                error_message=err_msg,
                audit_id=audit_id
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
                error_message=err_msg,
                audit_id=audit_id
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
        param_by_name = {p.name: p for p in tool_def.parameters}

        # Reject unexpected parameter keys
        for key in args.keys():
            if key not in param_by_name:
                return {}, f"Invalid Parameter: Argument '{key}' is not allowed for tool '{tool_def.name}'."

        # Check required parameters & set defaults
        for param_spec in tool_def.parameters:
            val = args.get(param_spec.name)
            if val is None:
                if param_spec.required:
                    return {}, f"Missing Required Parameter: '{param_spec.name}' is required for tool '{tool_def.name}'."
                if param_spec.default is not None:
                    sanitized[param_spec.name] = param_spec.default
                continue

            # Type-aware validation & sanitization
            if param_spec.type == "integer":
                if isinstance(val, bool):
                    return {}, f"Invalid Parameter: Argument '{param_spec.name}' must be an integer for tool '{tool_def.name}'."
                try:
                    ival = int(val)
                except (ValueError, TypeError):
                    return {}, f"Invalid Parameter: Argument '{param_spec.name}' must be an integer for tool '{tool_def.name}'."
                if param_spec.name == "limit" and ival < 1:
                    ival = 1
                if param_spec.name == "time_window_hours" and not 1 <= ival <= 72:
                    return {}, f"Invalid Parameter: Argument 'time_window_hours' must be between 1 and 72."
                if param_spec.name == "dest_port" and not 1 <= ival <= 65535:
                    return {}, f"Invalid Parameter: Argument 'dest_port' must be a valid port (1-65535)."
                sanitized[param_spec.name] = ival
            elif isinstance(val, str):
                if len(val) > settings.MAX_STRING_ARG_CHARS:
                    return {}, f"Invalid Parameter: Argument '{param_spec.name}' exceeds maximum length of {settings.MAX_STRING_ARG_CHARS} characters."
                # Check for shell payload attempt markers BEFORE escaping
                # (escaping first would transform e.g. <script> and weaken detection).
                if any(marker in val for marker in SHELL_PAYLOAD_MARKERS):
                    return {}, f"Security Alert: Malicious input pattern detected in argument '{param_spec.name}'."
                cleaned_val = sanitize_input_string(val, max_length=settings.MAX_STRING_ARG_CHARS)
                if param_spec.name in IP_PARAMS and cleaned_val:
                    if not is_valid_ip(cleaned_val):
                        return {}, f"Invalid Parameter: Argument '{param_spec.name}' must be a valid IPv4 address."
                sanitized[param_spec.name] = cleaned_val
            else:
                # Non-string scalars (bool/int already handled) pass through.
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
            records = [evt.model_dump() for evt in events]
            # Apply tool-specific metadata filters the generic EventFilter
            # does not cover (previously these args were silently ignored).
            if tool_name == "search_network_events":
                records = self._apply_network_filters(records, args)
            elif tool_name == "search_process_events":
                records = self._apply_process_filters(records, args)
            elif tool_name == "search_file_events":
                records = self._apply_file_filters(records, args)
            elif tool_name == "search_dns_events":
                records = self._apply_dns_filters(records, args)
            return records[:limit]

        # Host timeline query
        elif tool_name == "get_host_timeline":
            flt = EventFilter(host=host, limit=limit)
            events = telemetry_engine.query_events(flt)
            records = [evt.model_dump() for evt in events]
            window_hours = args.get("time_window_hours")
            if window_hours:
                records = self._apply_time_window(records, window_hours)
            return records[:limit]

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
            records = [evt.model_dump() for evt in events if evt.status == "FAILURE" or evt.status == "DENIED"]
            # Severity filter maps onto event status where telemetry has no
            # dedicated severity field (previously silently ignored).
            severity = (args.get("severity") or "").upper()
            if severity in ("CRITICAL", "HIGH"):
                records = [r for r in records if r.get("status") in ("FAILURE", "DENIED")]
            rule_name = (args.get("rule_name") or "").lower()
            if rule_name:
                records = [r for r in records
                           if rule_name in str(r.get("action", "")).lower()
                           or rule_name in str((r.get("metadata") or {}))[:2000].lower()]
            return records[:limit]

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

        # Multi-workstation and cross-log collector query
        elif tool_name == "collect_workstation_telemetry":
            hosts_arg = args.get("hosts", "all")
            sources_arg = args.get("log_sources", "auth,process,network")
            indicator_arg = args.get("indicator")
            
            hosts_list = [h.strip() for h in hosts_arg.split(",") if h.strip()] if isinstance(hosts_arg, str) else hosts_arg
            sources_list = [s.strip() for s in sources_arg.split(",") if s.strip()] if isinstance(sources_arg, str) else sources_arg
            
            collected_data = telemetry_engine.collect_cross_workstation_telemetry(
                hosts=hosts_list,
                log_sources=sources_list,
                indicator=indicator_arg,
                limit=limit
            )
            return collected_data.get("events", [])

        return []

    # -- Tool-specific metadata post-filters (pure functions, easy to test) --

    @staticmethod
    def _meta(record: Dict[str, Any]) -> Dict[str, Any]:
        return record.get("metadata") or {}

    @staticmethod
    def _contains(haystack: Any, needle: str) -> bool:
        return needle.lower() in str(haystack or "").lower()

    def _apply_network_filters(self, records: List[Dict[str, Any]], args: Dict[str, Any]) -> List[Dict[str, Any]]:
        dest_port = args.get("dest_port")
        if dest_port is not None:
            records = [r for r in records if self._meta(r).get("dest_port") == dest_port]
        protocol = args.get("protocol")
        if protocol:
            records = [r for r in records if str(self._meta(r).get("protocol", "")).upper() == str(protocol).upper()]
        return records

    def _apply_process_filters(self, records: List[Dict[str, Any]], args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if args.get("process_name"):
            records = [r for r in records
                       if self._contains(self._meta(r).get("process_name"), args["process_name"])]
        if args.get("command_line"):
            records = [r for r in records
                       if self._contains(self._meta(r).get("command_line"), args["command_line"])]
        if args.get("parent_process"):
            records = [r for r in records
                       if self._contains(self._meta(r).get("parent_process"), args["parent_process"])]
        return records

    def _apply_file_filters(self, records: List[Dict[str, Any]], args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if args.get("file_path"):
            records = [r for r in records
                       if self._contains(self._meta(r).get("file_path"), args["file_path"])
                       or self._contains(self._meta(r).get("filepath"), args["file_path"])
                       or self._contains(self._meta(r).get("filename"), args["file_path"])]
        if args.get("file_hash"):
            records = [r for r in records
                       if self._contains(self._meta(r).get("file_hash"), args["file_hash"])
                       or self._contains(self._meta(r).get("sha256"), args["file_hash"])
                       or self._contains(self._meta(r).get("md5"), args["file_hash"])]
        return records

    def _apply_dns_filters(self, records: List[Dict[str, Any]], args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if args.get("record_type"):
            records = [r for r in records
                       if str(self._meta(r).get("record_type", "")).upper() == str(args["record_type"]).upper()]
        return records

    @staticmethod
    def _apply_time_window(records: List[Dict[str, Any]], window_hours: int) -> List[Dict[str, Any]]:
        """Keep only records within the last `window_hours` (ISO timestamps)."""
        from datetime import datetime, timezone, timedelta
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=int(window_hours))
        except (ValueError, TypeError):
            return records
        kept = []
        for r in records:
            try:
                ts = datetime.fromisoformat(str(r.get("timestamp", "")).replace("Z", "+00:00"))
            except ValueError:
                kept.append(r)  # Keep unparseable timestamps rather than dropping evidence.
                continue
            if ts >= cutoff:
                kept.append(r)
        return kept
