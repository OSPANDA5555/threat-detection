#!/usr/bin/env python3
"""
Lightweight Linux Security Telemetry Collector / Agent.
Zero-Dependency Standard Library Agent for Authorized Monitored Hosts.

Features:
- Collects SSH auth, sudo privilege escalation, auditd process executions, and active network connections.
- Normalizes logs into canonical SecurityEvent records.
- Persistent byte-offset checkpointing (~/.threat_hunter_agent.offset) to prevent duplicate event delivery.
- Automatic credential & private key sanitization before network transmission.
- Monotonic sequence tracking, batching, and auto-reconnecting HTTPS shipper.
- Zero Remote Execution: purely outbound read-only telemetry.
"""

import os
import sys
import re
import json
import time
import socket
import struct
import platform
import hashlib
import logging
import argparse
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional, Tuple

AGENT_VERSION = "1.0.0"
DEFAULT_CHECKPOINT_FILE = os.path.expanduser("~/.threat_hunter_agent.offset")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Agent] %(message)s"
)
logger = logging.getLogger("linux_collector")


# ==============================================================================
# Credential & Sensitive Data Sanitizer
# ==============================================================================
class CredentialSanitizer:
    """
    Scrubs passwords, private keys, authentication tokens, and secrets
    from raw log strings and command lines before transmission.
    """
    PATTERNS = [
        (re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----", re.I), "[REDACTED_PRIVATE_KEY]"),
        (re.compile(r"(?:(?:--)?(?:password|passwd|secret|api_key|access_key))\s*[:=]\s*['\"]?([^\s'\";]+)['\"]?", re.I), r"[REDACTED_CREDENTIAL]"),
        (re.compile(r"(?:-p\s+)([^\s]+)", re.I), "-p [REDACTED_PASSWORD]"),
        (re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]+", re.I), "Bearer [REDACTED_TOKEN]"),
        (re.compile(r"\$6\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+"), "[REDACTED_SHA512_CRYPT]"),
        (re.compile(r"\$y\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+"), "[REDACTED_YESCRYPT]")
    ]

    @classmethod
    def sanitize(cls, text: Optional[str]) -> str:
        if not text:
            return ""
        clean = str(text)
        for pattern, replacement in cls.PATTERNS:
            clean = pattern.sub(replacement, clean)
        return clean


# ==============================================================================
# Log Parsers (Auth, Sudo, Auditd, Network)
# ==============================================================================
class LinuxTelemetryParsers:
    """
    Parses standard Linux log lines into normalized SecurityEvent dicts.
    """

    @staticmethod
    def parse_auth_line(line: str, hostname: str) -> Optional[Dict[str, Any]]:
        clean_line = CredentialSanitizer.sanitize(line.strip())
        if not clean_line:
            return None

        # 1. SSH Failed Password
        # e.g.: "Oct 15 14:02:11 host sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2"
        # or: "Oct 15 14:02:11 host sshd[1234]: Failed password for root from 192.168.1.50 port 54321 ssh2"
        m = re.search(r"sshd\[(?P<pid>\d+)\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)", clean_line)
        if m:
            return {
                "source_type": "linux_auth",
                "source": "auth.log",
                "hostname": hostname,
                "source_ip": m.group("ip"),
                "source_port": int(m.group("port")),
                "destination_port": 22,
                "protocol": "TCP",
                "username": m.group("user"),
                "process_name": "sshd",
                "process_id": int(m.group("pid")),
                "event_type": "ssh_authentication",
                "action": "failed_password",
                "status": "FAILURE",
                "severity": "HIGH",
                "raw_data": {"line": clean_line}
            }

        # 2. SSH Accepted Password / PublicKey
        m = re.search(r"sshd\[(?P<pid>\d+)\]:\s+Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)", clean_line)
        if m:
            return {
                "source_type": "linux_auth",
                "source": "auth.log",
                "hostname": hostname,
                "source_ip": m.group("ip"),
                "source_port": int(m.group("port")),
                "destination_port": 22,
                "protocol": "TCP",
                "username": m.group("user"),
                "process_name": "sshd",
                "process_id": int(m.group("pid")),
                "event_type": "ssh_authentication",
                "action": "accepted_password",
                "status": "SUCCESS",
                "severity": "INFO",
                "raw_data": {"line": clean_line}
            }

        # 3. Sudo Execution
        # e.g.: "sudo:   user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash"
        m = re.search(r"sudo:\s+(?P<user>\S+)\s*:\s+TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>[^;]+);\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<cmd>.*)", clean_line)
        if m:
            cmd = m.group("cmd").strip()
            is_privesc = any(p in cmd.lower() for p in ["bash", "sh", "zsh", "su", "chmod +s", "vim", "find"])
            return {
                "source_type": "linux_auth",
                "source": "auth.log",
                "hostname": hostname,
                "username": m.group("user"),
                "process_name": "sudo",
                "command": cmd,
                "event_type": "process_create",
                "action": "sudo_execution",
                "status": "SUCCESS",
                "severity": "HIGH" if is_privesc else "INFO",
                "metadata": {"target_user": m.group("target_user"), "pwd": m.group("pwd")},
                "raw_data": {"line": clean_line}
            }

        # 4. SU command
        m = re.search(r"su(?:\[\d+\])?:\s+(?:\(to (?P<target>\S+)\)\s+)?(?P<user>\S+)\s+on\s+(?P<tty>\S+)", clean_line)
        if m:
            return {
                "source_type": "linux_auth",
                "source": "auth.log",
                "hostname": hostname,
                "username": m.group("user"),
                "process_name": "su",
                "event_type": "privilege_escalation",
                "action": "su_switch_user",
                "status": "SUCCESS",
                "severity": "MEDIUM",
                "metadata": {"target_user": m.group("target") or "root"},
                "raw_data": {"line": clean_line}
            }

        return None

    @staticmethod
    def parse_audit_line(line: str, hostname: str) -> Optional[Dict[str, Any]]:
        clean_line = CredentialSanitizer.sanitize(line.strip())
        if not clean_line or "type=EXECVE" not in clean_line:
            return None

        # Parse auditd EXECVE line
        # e.g.: "type=EXECVE msg=audit(1691695800.123:456): argc=3 a0=\"cat\" a1=\"/etc/shadow\""
        args = re.findall(r'a\d+="(.*?)"', clean_line)
        cmd = " ".join(args) if args else ""
        if cmd:
            is_sensitive = any(p in cmd.lower() for p in ["/etc/shadow", "mimikatz", "sudo", "tar -czf /tmp", "whoami"])
            return {
                "source_type": "linux_audit",
                "source": "audit.log",
                "hostname": hostname,
                "process_name": args[0] if args else "execve",
                "command": cmd,
                "event_type": "process_create",
                "action": "execve",
                "status": "SUCCESS",
                "severity": "HIGH" if is_sensitive else "INFO",
                "raw_data": {"line": clean_line}
            }
        return None

    @staticmethod
    def inspect_proc_net_tcp(hostname: str) -> List[Dict[str, Any]]:
        """
        Inspect /proc/net/tcp to collect active established TCP sockets.
        """
        events = []
        path = "/proc/net/tcp"
        if not os.path.exists(path):
            return events

        try:
            with open(path, "r") as f:
                lines = f.readlines()[1:]  # skip header

            for line in lines:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                state = parts[3]
                if state != "01":  # 01 = TCP_ESTABLISHED
                    continue

                local_ip, local_port = LinuxTelemetryParsers._decode_proc_ip_port(parts[1])
                remote_ip, remote_port = LinuxTelemetryParsers._decode_proc_ip_port(parts[2])

                # Filter loopback
                if remote_ip in ["127.0.0.1", "0.0.0.0"] or local_ip == remote_ip:
                    continue

                events.append({
                    "source_type": "network_flow",
                    "source": "/proc/net/tcp",
                    "hostname": hostname,
                    "source_ip": local_ip,
                    "source_port": local_port,
                    "destination_ip": remote_ip,
                    "destination_port": remote_port,
                    "protocol": "TCP",
                    "event_type": "network_flow",
                    "action": "tcp_established",
                    "status": "ESTABLISHED",
                    "severity": "INFO",
                    "raw_data": {"local": f"{local_ip}:{local_port}", "remote": f"{remote_ip}:{remote_port}"}
                })
        except Exception as e:
            logger.debug(f"Error reading /proc/net/tcp: {e}")

        return events

    @staticmethod
    def _decode_proc_ip_port(hex_ip_port: str) -> Tuple[str, int]:
        try:
            ip_hex, port_hex = hex_ip_port.split(":")
            ip_int = int(ip_hex, 16)
            ip_str = socket.inet_ntoa(struct.pack("<L", ip_int))
            port_int = int(port_hex, 16)
            return ip_str, port_int
        except Exception:
            return "0.0.0.0", 0


# ==============================================================================
# Persistent Checkpoint Tracker
# ==============================================================================
class CheckpointTracker:
    """
    Maintains file byte offsets across restarts to avoid duplicate event shipment.
    """
    def __init__(self, checkpoint_file: str = DEFAULT_CHECKPOINT_FILE):
        self.checkpoint_file = checkpoint_file
        self.offsets: Dict[str, int] = {}
        self.load()

    def load(self):
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, "r") as f:
                    self.offsets = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load checkpoint file: {e}")
                self.offsets = {}

    def save(self):
        try:
            temp_file = f"{self.checkpoint_file}.tmp"
            with open(temp_file, "w") as f:
                json.dump(self.offsets, f)
            os.replace(temp_file, self.checkpoint_file)
        except Exception as e:
            logger.warning(f"Failed to save checkpoint file: {e}")

    def get_offset(self, file_path: str) -> int:
        return self.offsets.get(file_path, 0)

    def update_offset(self, file_path: str, offset: int):
        self.offsets[file_path] = offset
        self.save()


# ==============================================================================
# Linux Agent Shipper & Event Engine
# ==============================================================================
class LinuxCollectorAgent:
    """
    Main collector agent that tails log files, inspects network sockets,
    batches SecurityEvents, and transmits them to the backend API over HTTPS.
    """

    def __init__(
        self,
        backend_url: str = "http://localhost:8000/api/events",
        agent_id: Optional[str] = None,
        auth_token: Optional[str] = None,
        batch_size: int = 25,
        flush_interval_seconds: float = 2.0,
        checkpoint_file: str = DEFAULT_CHECKPOINT_FILE
    ):
        self.backend_url = backend_url.rstrip("/")
        if not self.backend_url.endswith("/events") and not self.backend_url.endswith("/events/ingest"):
            self.backend_url = f"{self.backend_url}/api/events"

        self.hostname = socket.gethostname()
        self.agent_id = agent_id or f"agent-{self.hostname.lower()}-{hashlib.md5(self.hostname.encode()).hexdigest()[:6]}"
        self.auth_token = auth_token
        self.batch_size = batch_size
        self.flush_interval = flush_interval_seconds
        self.checkpoint = CheckpointTracker(checkpoint_file)
        self.sequence_number = 0
        self.buffer: List[Dict[str, Any]] = []
        self.last_flush_time = time.time()
        self.platform_info = f"{platform.system()} {platform.release()} ({platform.machine()})"

    def run_once(self) -> int:
        """Single polling & log ingestion iteration."""
        new_events: List[Dict[str, Any]] = []

        # 1. Identify and tail auth log
        auth_log_candidates = ["/var/log/auth.log", "/var/log/secure"]
        for p in auth_log_candidates:
            if os.path.exists(p) and os.access(p, os.R_OK):
                evs = self._tail_log_file(p, LinuxTelemetryParsers.parse_auth_line)
                new_events.extend(evs)
                break

        # 2. Identify and tail audit log
        audit_log = "/var/log/audit/audit.log"
        if os.path.exists(audit_log) and os.access(audit_log, os.R_OK):
            evs = self._tail_log_file(audit_log, LinuxTelemetryParsers.parse_audit_line)
            new_events.extend(evs)

        # 3. Inspect socket connections
        net_events = LinuxTelemetryParsers.inspect_proc_net_tcp(self.hostname)
        new_events.extend(net_events)

        # Add to batch buffer
        for ev in new_events:
            self._enrich_and_buffer(ev)

        # Flush if batch size or interval reached
        now = time.time()
        if len(self.buffer) >= self.batch_size or (self.buffer and (now - self.last_flush_time) >= self.flush_interval):
            self.flush()

        return len(new_events)

    def _tail_log_file(self, file_path: str, parser_func) -> List[Dict[str, Any]]:
        events = []
        try:
            file_size = os.path.getsize(file_path)
            last_offset = self.checkpoint.get_offset(file_path)

            # Log rotation check: if file size is smaller than offset, reset offset to 0
            if file_size < last_offset:
                last_offset = 0

            with open(file_path, "r", errors="ignore") as f:
                f.seek(last_offset)
                for line in f:
                    ev = parser_func(line, self.hostname)
                    if ev:
                        events.append(ev)
                
                # Record new offset
                new_offset = f.tell()
                self.checkpoint.update_offset(file_path, new_offset)
        except Exception as e:
            logger.debug(f"Error tailing {file_path}: {e}")

        return events

    def _enrich_and_buffer(self, event: Dict[str, Any]):
        now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if not event.get("timestamp"):
            event["timestamp"] = now_str
        if not event.get("hostname"):
            event["hostname"] = self.hostname
        if not event.get("id"):
            raw_str = f"{self.agent_id}:{event['timestamp']}:{json.dumps(event)}"
            event["id"] = f"ev-{hashlib.sha256(raw_str.encode()).hexdigest()[:16]}"

        self.buffer.append(event)

    def flush(self) -> bool:
        """Transmits buffered events to backend over HTTPS."""
        if not self.buffer:
            return True

        self.sequence_number += 1
        payload = {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "agent_version": AGENT_VERSION,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sequence_number": self.sequence_number,
            "events": self.buffer
        }

        try:
            data_bytes = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.backend_url,
                data=data_bytes,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"ThreatHunterAgent/{AGENT_VERSION} ({self.platform_info})"
                }
            )
            if self.auth_token:
                req.add_header("Authorization", f"Bearer {self.auth_token}")

            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status in [200, 201, 202]:
                    logger.info(f"Shipped batch seq={self.sequence_number} ({len(self.buffer)} events) to {self.backend_url}")
                    self.buffer.clear()
                    self.last_flush_time = time.time()
                    return True
                else:
                    logger.warning(f"Backend returned HTTP {resp.status}")
                    return False
        except urllib.error.URLError as e:
            logger.warning(f"Connection failure to backend ({self.backend_url}): {e.reason}")
            return False
        except Exception as e:
            logger.warning(f"Unexpected error during shipment: {e}")
            return False

    def start_daemon(self, poll_interval: float = 1.0):
        """Continuously tails logs and ships telemetry."""
        logger.info(f"Starting Linux Collector Agent {AGENT_VERSION} for host '{self.hostname}'")
        logger.info(f"Agent ID: {self.agent_id}")
        logger.info(f"Ingestion Backend: {self.backend_url}")
        logger.info(f"Checkpoint File: {self.checkpoint.checkpoint_file}")

        try:
            while True:
                self.run_once()
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            logger.info("Stopping Linux Collector Agent...")
            self.flush()


# ==============================================================================
# CLI Entrypoint
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="Threat-Hunting Linux Telemetry Collector Agent")
    parser.add_argument("--backend-url", default="http://localhost:8000/api/events", help="Backend ingestion endpoint")
    parser.add_argument("--agent-id", default=None, help="Unique agent identifier")
    parser.add_argument("--auth-token", default=None, help="Agent authentication bearer token")
    parser.add_argument("--checkpoint-file", default=DEFAULT_CHECKPOINT_FILE, help="Path to offset checkpoint file")
    parser.add_argument("--interval", type=float, default=1.5, help="Polling interval in seconds")
    parser.add_argument("--once", action="store_true", help="Run a single collection iteration and exit")
    args = parser.parse_args()

    agent = LinuxCollectorAgent(
        backend_url=args.backend_url,
        agent_id=args.agent_id,
        auth_token=args.auth_token,
        checkpoint_file=args.checkpoint_file
    )

    if args.once:
        count = agent.run_once()
        agent.flush()
        logger.info(f"Single run completed: {count} events processed.")
    else:
        agent.start_daemon(poll_interval=args.interval)


if __name__ == "__main__":
    main()
