import io
import json
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.auth.models import UserRole
from app.auth.security import create_access_token
from app.core.security import (
    sanitize_input_string,
    sanitize_filename,
    is_dangerous_executable_upload,
    is_valid_ip,
    is_valid_hostname,
    is_valid_username,
    is_valid_url,
    detect_sql_injection,
    detect_command_injection,
    detect_path_traversal,
    detect_template_injection,
    detect_xss,
    reset_rate_limit
)
from app.ingestion.service import dataset_service

client = TestClient(app)

def get_auth_token(role: UserRole = UserRole.ANALYST, user_id: str = "analyst", tenant_id: str = "soc-org-primary") -> str:
    return create_access_token(
        user_id=user_id,
        username=user_id,
        role=role,
        tenant_id=tenant_id,
        expires_in_minutes=60
    )

def get_auth_headers(role: UserRole = UserRole.ANALYST, user_id: str = "analyst", tenant_id: str = "soc-org-primary") -> dict:
    token = get_auth_token(role=role, user_id=user_id, tenant_id=tenant_id)
    return {"Authorization": f"Bearer {token}"}


class TestInputSanitizationAndValidationFunctions:
    """Audit and test core sanitizers and validation helpers."""

    def test_sanitize_input_string_removes_control_chars_and_escapes_html(self):
        malicious = "Hello\x00World\x08<script>alert('XSS')</script>\"&'"
        sanitized = sanitize_input_string(malicious)
        assert "\x00" not in sanitized
        assert "\x08" not in sanitized
        assert "<script>" not in sanitized
        assert "&lt;script&gt;" in sanitized
        assert "&quot;" in sanitized or "&#x27;" in sanitized or "&amp;" in sanitized

    def test_sanitize_filename_strips_path_traversal_and_null_bytes(self):
        malicious_names = [
            "../../../../etc/passwd",
            "..\\..\\windows\\system32\\cmd.exe",
            "report\x00.csv",
            ".hidden_config.json",
            "../../../var/log/auth.log"
        ]
        for name in malicious_names:
            clean = sanitize_filename(name)
            assert "/" not in clean
            assert "\\" not in clean
            assert ".." not in clean
            assert "\x00" not in clean
            assert not clean.startswith(".")

    def test_hostname_validation(self):
        valid_hosts = ["web-server-01", "db.internal.corp", "soc-node-1", "workstation-102.sub.domain.local"]
        invalid_hosts = [
            "-bad-host", "bad_host_", "host;rm -rf /", "host$(whoami)",
            "host<script>", "a" * 300, "192.168.1.1:8080"
        ]
        for h in valid_hosts:
            assert is_valid_hostname(h) is True
        for h in invalid_hosts:
            assert is_valid_hostname(h) is False

    def test_username_validation(self):
        valid_users = ["analyst", "admin_01", "john.doe", "user-sec", "analyst@corp.internal"]
        invalid_users = [
            "user;drop table", "user$(id)", "admin'--", "<script>user",
            "user\x00admin", "a" * 100
        ]
        for u in valid_users:
            assert is_valid_username(u) is True
        for u in invalid_users:
            assert is_valid_username(u) is False

    def test_url_validation(self):
        valid_urls = [
            "https://soc.enterprise.local/api/events",
            "http://10.0.1.10:8000/telemetry",
            "https://internal-siem.corp/query"
        ]
        invalid_urls = [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,<script>alert(1)</script>",
            "ftp://anonymous@ftp.server.com",
            "http://",
            "not-a-url"
        ]
        for url in valid_urls:
            assert is_valid_url(url) is True
        for url in invalid_urls:
            assert is_valid_url(url) is False


class TestAttackPatternDetection:
    """Test pattern detection for SQLi, Command Injection, Path Traversal, SSTI, XSS."""

    def test_sql_injection_detection(self):
        sqli_samples = [
            "admin' OR 1=1 --",
            "1; DROP TABLE users;",
            "' UNION SELECT username, password FROM auth_users --",
            "1' AND 1=1 /* test */",
            "exec xp_cmdshell('dir')"
        ]
        for sample in sqli_samples:
            assert detect_sql_injection(sample) is True

        safe_samples = ["search SSH login failure", "web-server-01", "host-audit-log"]
        for sample in safe_samples:
            assert detect_sql_injection(sample) is False

    def test_command_injection_detection(self):
        cmd_samples = [
            "test; cat /etc/passwd",
            "test | whoami",
            "test && rm -rf /",
            "test $(id)",
            "test `whoami`"
        ]
        for sample in cmd_samples:
            assert detect_command_injection(sample) is True

        safe_samples = ["auth.log line 25", "web-server-01", "port 22"]
        for sample in safe_samples:
            assert detect_command_injection(sample) is False

    def test_path_traversal_detection(self):
        traversal_samples = [
            "../../../../etc/passwd",
            "..\\..\\windows\\win.ini",
            "%2e%2e/etc/shadow",
            "/etc/passwd",
            "C:\\Windows\\System32"
        ]
        for sample in traversal_samples:
            assert detect_path_traversal(sample) is True

        safe_samples = ["dataset_sample.csv", "auth_2026.json", "flow_capture.pcap"]
        for sample in safe_samples:
            assert detect_path_traversal(sample) is False

    def test_template_injection_detection(self):
        ssti_samples = [
            "Hello {{7*7}}",
            "Welcome ${7*7}",
            "{% import os %}{{ os.system('id') }}",
            "<% eval('7*7') %>"
        ]
        for sample in ssti_samples:
            assert detect_template_injection(sample) is True

        safe_samples = ["Simple text query", "User login failure", "HTTP 404 response"]
        for sample in safe_samples:
            assert detect_template_injection(sample) is False

    def test_xss_detection(self):
        xss_samples = [
            "<script>alert('XSS')</script>",
            "javascript:alert(document.cookie)",
            "<img src=x onerror=alert(1)>",
            "<iframe src='http://evil.com'></iframe>",
            "<svg onload=alert(1)>"
        ]
        for sample in xss_samples:
            assert detect_xss(sample) is True

        safe_samples = ["Normal description", "SSH connection from 192.168.1.1", "Status: OK"]
        for sample in safe_samples:
            assert detect_xss(sample) is False


class TestFileUploadHardeningAndExecutableRejection:
    """Test uploaded file validation, executable rejection, and magic byte checking."""

    def test_dangerous_file_extensions_rejected(self):
        headers = get_auth_headers()
        dangerous_files = [
            ("malware.exe", b"fake binary content"),
            ("exploit.sh", b"#!/bin/bash\nrm -rf /"),
            ("webshell.php", b"<?php system($_GET['cmd']); ?>"),
            ("script.py", b"import os; os.system('id')"),
            ("payload.bat", b"@echo off\ndel /f /q C:\\*"),
            ("agent.dll", b"MZ fake dll content"),
            ("package.jar", b"fake jar content")
        ]
        for filename, content in dangerous_files:
            resp = client.post(
                "/api/v1/datasets/import/file",
                headers=headers,
                files={"file": (filename, io.BytesIO(content), "application/octet-stream")}
            )
            assert resp.status_code == 400
            assert "forbidden" in resp.json()["detail"].lower() or "executable" in resp.json()["detail"].lower()

    def test_magic_bytes_executable_inspection_blocks_disguised_uploads(self):
        headers = get_auth_headers()
        # ELF binary disguised as .csv
        elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 20
        resp_elf = client.post(
            "/api/v1/datasets/import/file",
            headers=headers,
            files={"file": ("disguised_data.csv", io.BytesIO(elf_header), "text/csv")}
        )
        assert resp_elf.status_code == 400
        assert "binary executable detected" in resp_elf.json()["detail"].lower()

        # Windows PE binary disguised as .json
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 20
        resp_pe = client.post(
            "/api/v1/datasets/import/file",
            headers=headers,
            files={"file": ("disguised_events.json", io.BytesIO(pe_header), "application/json")}
        )
        assert resp_pe.status_code == 400
        assert "binary executable detected" in resp_pe.json()["detail"].lower()

        # Shell script shebang disguised as .txt
        script_header = b"#!/bin/sh\ncat /etc/shadow\n"
        resp_sh = client.post(
            "/api/v1/datasets/import/file",
            headers=headers,
            files={"file": ("network_logs.txt", io.BytesIO(script_header), "text/plain")}
        )
        assert resp_sh.status_code == 400
        assert "script shebang" in resp_sh.json()["detail"].lower()

    def test_valid_csv_and_json_uploads_succeed(self):
        headers = get_auth_headers()
        # Valid CSV network flow
        valid_csv = (
            b"Timestamp,Source IP,Destination IP,Source Port,Destination Port,Protocol,Label\n"
            b"2017-07-07 08:30:00,192.168.1.50,10.0.0.1,49152,80,TCP,BENIGN\n"
        )
        resp_csv = client.post(
            "/api/v1/datasets/import/file",
            headers=headers,
            files={"file": ("valid_network_flow.csv", io.BytesIO(valid_csv), "text/csv")}
        )
        assert resp_csv.status_code == 200
        assert resp_csv.json()["status"] == "SUCCESS"

        # Valid JSON array events
        valid_json = json.dumps([
            {
                "timestamp": "2026-08-10T19:30:00Z",
                "source_ip": "192.168.100.5",
                "destination_ip": "10.0.1.10",
                "destination_port": 22,
                "protocol": "TCP",
                "event_type": "SSH_AUTHENTICATION",
                "label": "BENIGN"
            }
        ]).encode("utf-8")
        resp_json = client.post(
            "/api/v1/datasets/import/file",
            headers=headers,
            files={"file": ("valid_events.json", io.BytesIO(valid_json), "application/json")}
        )
        assert resp_json.status_code == 200
        assert resp_json.json()["status"] == "SUCCESS"


class TestToolGatewayShellInjectionRejection:
    """Test Tool Gateway rejects shell payload markers and malformed inputs."""

    def test_tool_gateway_rejects_shell_command_markers(self):
        headers = get_auth_headers()
        malicious_args = [
            {"host": "web-server-01; cat /etc/passwd"},
            {"host": "web-server-01 && rm -rf /"},
            {"host": "web-server-01 | whoami"},
            {"host": "web-server-01 `id`"},
            {"host": "web-server-01 $(whoami)"},
            {"host": "web-server-01 <script>alert(1)</script>"}
        ]
        for arg in malicious_args:
            resp = client.post(
                "/api/v1/tools/execute",
                headers=headers,
                json={
                    "tool_name": "search_authentication_events",
                    "arguments": arg
                }
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "REJECTED"
            assert "Security Alert" in data["error_message"] or "Security Violation" in data["error_message"]
