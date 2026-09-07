import pytest
from datetime import datetime, timezone

from app.normalization.models import SecurityEvent, SourceType, NormalizationResult
from app.normalization.adapters.network_flow import NetworkFlowAdapter
from app.normalization.adapters.linux_auth import LinuxAuthAdapter
from app.normalization.adapters.linux_audit import LinuxAuditAdapter
from app.normalization.adapters.web_log import WebLogAdapter
from app.normalization.adapters.dns import DNSAdapter
from app.normalization.adapters.firewall import FirewallAdapter
from app.normalization.adapters.sysmon import WindowsSysmonAdapter
from app.normalization.pipeline import EventNormalizationPipeline, normalization_pipeline
from app.hunting.correlation import EvidenceCorrelationEngine


class TestCanonicalSecurityEventModel:
    def test_security_event_defaults_and_non_fabrication(self):
        """Verify non-fabrication: fields absent from telemetry must default to None."""
        event = SecurityEvent(
            source_type=SourceType.GENERIC,
            raw_data={"test": "raw"}
        )
        assert event.id.startswith("sec-evt-")
        assert event.source_ip is None
        assert event.source_port is None
        assert event.destination_ip is None
        assert event.destination_port is None
        assert event.username is None
        assert event.process_name is None
        assert event.process_id is None
        assert event.command is None
        assert event.bytes_in is None
        assert event.bytes_out is None
        assert event.raw_data == {"test": "raw"}

    def test_stable_id_generation(self):
        """Verify that identical source, time, and content yield deterministic IDs."""
        id1 = SecurityEvent.generate_stable_id("auth.log", "2026-08-10T19:30:00Z", "failed login for root")
        id2 = SecurityEvent.generate_stable_id("auth.log", "2026-08-10T19:30:00Z", "failed login for root")
        id3 = SecurityEvent.generate_stable_id("auth.log", "2026-08-10T19:30:01Z", "failed login for root")
        assert id1 == id2
        assert id1 != id3
        assert id1.startswith("sec-evt-")


class TestNetworkFlowAdapter:
    def setup_method(self):
        self.adapter = NetworkFlowAdapter()

    def test_normalize_valid_flow_dict(self):
        raw = {
            "timestamp": "2026-08-10T19:30:15Z",
            "source_ip": "192.168.100.99",
            "source_port": 49152,
            "destination_ip": "10.0.1.10",
            "destination_port": 22,
            "protocol": "TCP",
            "bytes_in": 1240,
            "bytes_out": 4500,
            "duration": "1.25",
            "label": "SSH-Patator"
        }
        event, err = self.adapter.normalize_record(raw)
        assert err is None
        assert event is not None
        assert event.source_type == SourceType.NETWORK_FLOW
        assert event.source_ip == "192.168.100.99"
        assert event.source_port == 49152
        assert event.destination_ip == "10.0.1.10"
        assert event.destination_port == 22
        assert event.protocol == "TCP"
        assert event.bytes_in == 1240
        assert event.bytes_out == 4500
        assert event.severity == "HIGH"
        assert event.label == "SSH-Patator"
        # Non-fabricated fields should be None
        assert event.username is None
        assert event.command is None

    def test_normalize_invalid_ip_returns_error(self):
        raw = {
            "timestamp": "2026-08-10T19:30:15Z",
            "source_ip": "999.999.999.999",
            "destination_ip": "10.0.1.10",
            "destination_port": 80
        }
        event, err = self.adapter.normalize_record(raw)
        assert event is None
        assert "Invalid IP" in err


class TestLinuxAuthAdapter:
    def setup_method(self):
        self.adapter = LinuxAuthAdapter()

    def test_normalize_ssh_failed_password_line(self):
        line = "Aug 10 19:30:15 web-server-01 sshd[1482]: Failed password for root from 192.168.100.99 port 49152 ssh2"
        event, err = self.adapter.normalize_record(line)
        assert err is None
        assert event is not None
        assert event.source_type == SourceType.LINUX_AUTH
        assert event.hostname == "web-server-01"
        assert event.process_name == "sshd"
        assert event.process_id == 1482
        assert event.username == "root"
        assert event.source_ip == "192.168.100.99"
        assert event.source_port == 49152
        assert event.destination_port == 22
        assert event.action == "FAILED_LOGIN"
        assert event.status == "FAILURE"
        assert event.severity == "HIGH"

    def test_normalize_sudo_execution_line(self):
        line = "Aug 10 19:35:00 web-server-01 sudo: attacker : TTY=pts/1 ; PWD=/home/attacker ; USER=root ; COMMAND=/bin/bash -i"
        event, err = self.adapter.normalize_record(line)
        assert err is None
        assert event is not None
        assert event.source_type == SourceType.LINUX_AUTH
        assert event.username == "attacker"
        assert event.process_name == "sudo"
        assert "/bin/bash -i" in event.command
        assert event.action == "PRIVILEGE_ELEVATION"
        assert event.severity == "HIGH"


class TestLinuxAuditAdapter:
    def setup_method(self):
        self.adapter = LinuxAuditAdapter()

    def test_normalize_raw_auditd_syscall_line(self):
        line = 'type=SYSCALL msg=audit(1691696052.123:456): arch=c000003e syscall=59 success=yes exit=0 pid=2410 comm="sudo" exe="/usr/bin/sudo" a0="sudo" a1="cat" a2="/etc/shadow"'
        event, err = self.adapter.normalize_record(line)
        assert err is None
        assert event is not None
        assert event.source_type == SourceType.LINUX_AUDIT
        assert event.process_name == "sudo"
        assert event.process_id == 2410
        assert "sudo cat /etc/shadow" in event.command
        assert event.status == "SUCCESS"
        assert event.severity == "HIGH"
        assert event.label == "Privilege Escalation"


class TestWebLogAdapter:
    def setup_method(self):
        self.adapter = WebLogAdapter()

    def test_normalize_combined_log_format_sqli(self):
        line = '192.168.100.99 - - [10/Aug/2026:19:35:00 +0000] "GET /api/users?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 4502 "https://example.com" "sqlmap/1.6.0"'
        event, err = self.adapter.normalize_record(line)
        assert err is None
        assert event is not None
        assert event.source_type == SourceType.WEB_LOG
        assert event.source_ip == "192.168.100.99"
        assert event.bytes_out == 4502
        assert event.action == "ALLOWED"
        assert event.severity == "HIGH"
        assert "SQL Injection" in event.label
        assert event.metadata.get("http_status") == 200
        assert event.metadata.get("user_agent") == "sqlmap/1.6.0"


class TestDNSAdapter:
    def setup_method(self):
        self.adapter = DNSAdapter()

    def test_normalize_bind_query_line_c2_tunnel(self):
        line = "10-Aug-2026 19:30:15.123 queries: info: client @0x7f88 10.0.1.20#58210 (malicious-c2-beacon.corp): query: malicious-c2-beacon.corp IN TXT + (10.0.1.2)"
        event, err = self.adapter.normalize_record(line)
        assert err is None
        assert event is not None
        assert event.source_type == SourceType.DNS
        assert event.source_ip == "10.0.1.20"
        assert event.destination_ip == "10.0.1.2"
        assert event.destination_port == 53
        assert event.protocol == "UDP"
        assert event.command == "QUERY TXT malicious-c2-beacon.corp"
        assert event.severity == "HIGH"
        assert event.label == "DNS Tunneling"


class TestFirewallAdapter:
    def setup_method(self):
        self.adapter = FirewallAdapter()

    def test_normalize_ufw_block_line(self):
        line = "[UFW BLOCK] IN=eth0 OUT= MAC=00:0c:29:4f:8e:12:00 SRC=192.168.100.99 DST=10.0.1.10 LEN=60 PROTO=TCP SPT=49152 DPT=22 SYN"
        event, err = self.adapter.normalize_record(line)
        assert err is None
        assert event is not None
        assert event.source_type == SourceType.FIREWALL
        assert event.source_ip == "192.168.100.99"
        assert event.source_port == 49152
        assert event.destination_ip == "10.0.1.10"
        assert event.destination_port == 22
        assert event.protocol == "TCP"
        assert event.action == "BLOCK"
        assert event.status == "DENIED"
        assert event.bytes_in == 60
        assert event.severity == "HIGH"


class TestWindowsSysmonAdapter:
    def setup_method(self):
        self.adapter = WindowsSysmonAdapter()

    def test_normalize_sysmon_process_create(self):
        raw = {
            "EventID": 1,
            "Computer": "WORKSTATION-01",
            "UtcTime": "2026-08-10T19:40:00Z",
            "EventData": {
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
                "User": "CORP\\alice",
                "ProcessId": "3412",
                "ParentImage": "C:\\Program Files\\App\\updater.exe"
            }
        }
        event, err = self.adapter.normalize_record(raw)
        assert err is None
        assert event is not None
        assert event.source_type == SourceType.WINDOWS_SYSMON
        assert event.hostname == "WORKSTATION-01"
        assert event.username == "CORP\\alice"
        assert event.process_name == "cmd.exe"
        assert event.process_id == 3412
        assert event.event_type == "PROCESS_CREATE"
        assert event.action == "CREATE_PROCESS"
        assert event.severity == "HIGH"
        assert "Privilege Escalation" in event.label

    def test_normalize_sysmon_network_connect(self):
        raw = {
            "EventID": 3,
            "Computer": "WORKSTATION-01",
            "EventData": {
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "SourceIp": "10.0.1.50",
                "SourcePort": "51234",
                "DestinationIp": "198.51.100.22",
                "DestinationPort": "4444",
                "Protocol": "tcp"
            }
        }
        event, err = self.adapter.normalize_record(raw)
        assert err is None
        assert event is not None
        assert event.source_type == SourceType.WINDOWS_SYSMON
        assert event.source_ip == "10.0.1.50"
        assert event.source_port == 51234
        assert event.destination_ip == "198.51.100.22"
        assert event.destination_port == 4444
        assert event.protocol == "TCP"
        assert event.event_type == "NETWORK_CONNECT"
        assert event.label == "C2 Communication"


class TestEventNormalizationPipeline:
    def setup_method(self):
        self.pipeline = EventNormalizationPipeline()

    def test_auto_detection_and_batch_processing(self):
        raw_stream = [
            "Aug 10 19:30:15 web-server-01 sshd[1482]: Failed password for root from 192.168.100.99 port 49152 ssh2",
            "[UFW BLOCK] IN=eth0 OUT= SRC=192.168.100.99 DST=10.0.1.10 LEN=60 PROTO=TCP SPT=49152 DPT=22 SYN",
            'type=SYSCALL msg=audit(1691696052.123:456): arch=c000003e syscall=59 success=yes exit=0 pid=2410 comm="sudo" exe="/usr/bin/sudo"',
            "MALFORMED GARBAGE LOG LINE THAT CANNOT BE PARSED",
            {
                "EventID": 1,
                "Computer": "WORKSTATION-01",
                "EventData": {"Image": "C:\\Windows\\cmd.exe", "CommandLine": "cmd.exe"}
            }
        ]
        result: NormalizationResult = self.pipeline.normalize_stream(raw_stream)
        assert result.total_records == 5
        assert result.successful_events >= 4
        # Verified graceful error isolation without batch termination
        assert len(result.events) >= 4

    def test_correlation_engine_ingests_security_events(self):
        """Verify the investigation engine EvidenceCorrelationEngine natively ingests SecurityEvent instances."""
        auth_event, _ = LinuxAuthAdapter().normalize_record(
            "Aug 10 19:30:15 web-server-01 sshd[1482]: Failed password for root from 192.168.100.99 port 49152 ssh2"
        )
        assert auth_event is not None

        evidence_list = EvidenceCorrelationEngine.normalize_and_correlate(
            tool_name="search_authentication_events",
            records=[auth_event]
        )
        assert len(evidence_list) == 1
        evd = evidence_list[0]
        assert evd.host == "web-server-01"
        assert evd.user == "root"
        assert evd.sourceIp == "192.168.100.99"
        assert evd.eventType == "FAILED_LOGIN"
        assert "Detected FAILED_LOGIN" in evd.relevance
