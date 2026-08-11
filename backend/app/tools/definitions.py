from typing import Dict, List, Any
from app.schemas.tool import ToolDefinition, ToolParameterSpec

INITIAL_TOOL_REGISTRY: Dict[str, ToolDefinition] = {
    "search_authentication_events": ToolDefinition(
        name="search_authentication_events",
        description="Search read-only authentication logs (SSH, Sudo, PAM, Windows Auth Events).",
        read_only=True,
        parameters=[
            ToolParameterSpec(name="host", type="string", description="Filter by hostname", required=False),
            ToolParameterSpec(name="user", type="string", description="Filter by username", required=False),
            ToolParameterSpec(name="source_ip", type="string", description="Filter by source IP address", required=False),
            ToolParameterSpec(name="status", type="string", description="SUCCESS or FAILURE", required=False),
            ToolParameterSpec(name="limit", type="integer", description="Maximum events to retrieve (max 500)", required=False, default=50)
        ]
    ),
    "search_network_events": ToolDefinition(
        name="search_network_events",
        description="Query network connection logs, firewall traffic, and flow telemetry.",
        read_only=True,
        parameters=[
            ToolParameterSpec(name="src_ip", type="string", description="Source IP address", required=False),
            ToolParameterSpec(name="dest_ip", type="string", description="Destination IP address", required=False),
            ToolParameterSpec(name="dest_port", type="integer", description="Destination port number", required=False),
            ToolParameterSpec(name="protocol", type="string", description="TCP, UDP, ICMP", required=False),
            ToolParameterSpec(name="limit", type="integer", description="Maximum events to retrieve", required=False, default=50)
        ]
    ),
    "search_dns_events": ToolDefinition(
        name="search_dns_events",
        description="Search DNS query and resolution logs for suspicious domain lookups.",
        read_only=True,
        parameters=[
            ToolParameterSpec(name="domain", type="string", description="Domain name query (exact or wildcard)", required=False),
            ToolParameterSpec(name="client_ip", type="string", description="Client IP requesting DNS resolution", required=False),
            ToolParameterSpec(name="record_type", type="string", description="A, AAAA, TXT, CNAME, MX", required=False),
            ToolParameterSpec(name="limit", type="integer", description="Maximum events to retrieve", required=False, default=50)
        ]
    ),
    "search_process_events": ToolDefinition(
        name="search_process_events",
        description="Query process execution events, parent-child relationships, and command lines.",
        read_only=True,
        parameters=[
            ToolParameterSpec(name="host", type="string", description="Target hostname", required=False),
            ToolParameterSpec(name="process_name", type="string", description="Executable or process name", required=False),
            ToolParameterSpec(name="command_line", type="string", description="Command line arguments search query", required=False),
            ToolParameterSpec(name="parent_process", type="string", description="Parent executable name", required=False),
            ToolParameterSpec(name="limit", type="integer", description="Maximum events to retrieve", required=False, default=50)
        ]
    ),
    "search_file_events": ToolDefinition(
        name="search_file_events",
        description="Search file system modification, creation, deletion, and file hash events.",
        read_only=True,
        parameters=[
            ToolParameterSpec(name="host", type="string", description="Target hostname", required=False),
            ToolParameterSpec(name="file_path", type="string", description="Directory or file path string", required=False),
            ToolParameterSpec(name="file_hash", type="string", description="SHA256 or MD5 hash value", required=False),
            ToolParameterSpec(name="action", type="string", description="CREATE, MODIFY, DELETE", required=False),
            ToolParameterSpec(name="limit", type="integer", description="Maximum events to retrieve", required=False, default=50)
        ]
    ),
    "get_host_timeline": ToolDefinition(
        name="get_host_timeline",
        description="Retrieve chronological unified event timeline for a specified host.",
        read_only=True,
        parameters=[
            ToolParameterSpec(name="host", type="string", description="Target hostname", required=True),
            ToolParameterSpec(name="time_window_hours", type="integer", description="Hours of timeline to fetch (max 72)", required=False, default=24),
            ToolParameterSpec(name="limit", type="integer", description="Maximum total timeline events", required=False, default=100)
        ]
    ),
    "get_ip_activity": ToolDefinition(
        name="get_ip_activity",
        description="Summarize historical network, DNS, and authentication events associated with an IP.",
        read_only=True,
        parameters=[
            ToolParameterSpec(name="ip", type="string", description="Target IP address", required=True),
            ToolParameterSpec(name="limit", type="integer", description="Maximum summary records", required=False, default=50)
        ]
    ),
    "get_domain_activity": ToolDefinition(
        name="get_domain_activity",
        description="Fetch historical resolution count, associated IPs, and endpoint query volume for a domain.",
        read_only=True,
        parameters=[
            ToolParameterSpec(name="domain", type="string", description="Target domain name", required=True),
            ToolParameterSpec(name="limit", type="integer", description="Maximum records to return", required=False, default=50)
        ]
    ),
    "get_alerts": ToolDefinition(
        name="get_alerts",
        description="Query existing SIEM/EDR alert telemetry related to hosts, IPs, or detection rules.",
        read_only=True,
        parameters=[
            ToolParameterSpec(name="severity", type="string", description="CRITICAL, HIGH, MEDIUM, LOW", required=False),
            ToolParameterSpec(name="host", type="string", description="Target host filter", required=False),
            ToolParameterSpec(name="rule_name", type="string", description="Detection rule name filter", required=False),
            ToolParameterSpec(name="limit", type="integer", description="Maximum alerts to return", required=False, default=50)
        ]
    ),
    "scan_open_ports": ToolDefinition(
        name="scan_open_ports",
        description="Scan read-only network telemetry for open ports, listening services (SSH port 22, HTTP, DB), and active service banners.",
        read_only=True,
        parameters=[
            ToolParameterSpec(name="host", type="string", description="Target host to scan (e.g. web-server-01, db-server-01)", required=True),
            ToolParameterSpec(name="port_range", type="string", description="Port or range (e.g. '22', '1-1024')", required=False, default="1-1024"),
            ToolParameterSpec(name="protocol", type="string", description="TCP or UDP", required=False, default="TCP"),
            ToolParameterSpec(name="limit", type="integer", description="Maximum open port records to return", required=False, default=50)
        ]
    )
}
