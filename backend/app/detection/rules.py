import re
import uuid
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict, deque
from datetime import datetime

from app.detection.models import DetectionAlert

def parse_iso_timestamp(ts_str: Optional[str]) -> float:
    if not ts_str:
        return 0.0
    try:
        # Handle ISO strings like 2026-08-10T19:30:00Z or with milliseconds
        clean_ts = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_ts).timestamp()
    except Exception:
        try:
            return float(ts_str)
        except Exception:
            return 0.0

class BehavioralRuleEngine:
    """
    Multi-event stateful behavioral pattern detection engine.
    Maintains sliding temporal windows across telemetry entities (IPs, users, hosts)
    and evaluates complex attack progression without referencing dataset ground-truth labels.
    """

    def __init__(self):
        # Sliding windows
        # key: source_ip or (source_ip, username) -> list of events [(timestamp_epoch, event_dict)]
        self._auth_failures: Dict[str, deque] = defaultdict(deque)
        self._port_scan_history: Dict[str, deque] = defaultdict(deque)
        self._dns_query_history: Dict[str, deque] = defaultdict(deque)
        self._process_history: Dict[str, deque] = defaultdict(deque)
        self._fired_signature_dedup: Set[str] = set()

    def reset(self):
        self._auth_failures.clear()
        self._port_scan_history.clear()
        self._dns_query_history.clear()
        self._process_history.clear()
        self._fired_signature_dedup.clear()

    def evaluate_event(self, event: Dict[str, Any]) -> List[DetectionAlert]:
        """
        Evaluate an incoming SecurityEvent dict against all behavioral pattern rules.
        """
        alerts: List[DetectionAlert] = []
        eid = event.get("id") or event.get("event_id") or "unknown"
        ts = str(event.get("timestamp") or "2026-08-10T19:30:00Z")
        epoch = parse_iso_timestamp(ts)
        src_ip = event.get("source_ip")
        dst_ip = event.get("destination_ip")
        dst_port = event.get("destination_port")
        host = event.get("hostname")
        user = event.get("username")
        cmd = str(event.get("command") or "").lower()
        proc = str(event.get("process_name") or "").lower()
        evt_type = str(event.get("event_type") or "").lower()
        action = str(event.get("action") or "").lower()
        status = str(event.get("status") or "").upper()
        bytes_out = int(event.get("bytes_out") or 0)
        raw_data = event.get("raw_data") or {}
        raw_text = str(raw_data).lower()

        # -----------------------------------------------------------------
        # 1. AUTHENTICATION FAILURE SURGE (T1110 - Brute Force)
        # -----------------------------------------------------------------
        is_auth_fail = (
            "auth" in evt_type or "ssh" in evt_type or "login" in evt_type or
            action in ["failed_login", "failed_password", "auth_failed", "login_failed", "drop"]
        ) and (status in ["FAILED", "FAILURE", "BLOCKED", "DENY", "DROP"])

        if is_auth_fail and src_ip:
            key = f"{src_ip}:{user or 'unknown'}"
            self._auth_failures[key].append((epoch, eid, event))
            # Clean events older than 120s
            cutoff = epoch - 120.0
            while self._auth_failures[key] and self._auth_failures[key][0][0] < cutoff:
                self._auth_failures[key].popleft()

            recent = list(self._auth_failures[key])
            if len(recent) >= 3:
                sig = f"bruteforce:{key}:{recent[-1][1]}"
                if sig not in self._fired_signature_dedup:
                    self._fired_signature_dedup.add(sig)
                    evidence_ids = [e[1] for e in recent]
                    alerts.append(DetectionAlert(
                        id=f"alert-{uuid.uuid4().hex[:8]}",
                        detection="Authentication Brute Force Surge",
                        severity="HIGH",
                        confidence=0.92,
                        tactic="Credential Access",
                        technique="T1110 - Brute Force",
                        technique_id="T1110",
                        timestamp=ts,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        hostname=host,
                        username=user,
                        evidenceEventIds=evidence_ids,
                        reasoning=f"Observed {len(recent)} consecutive authentication failures for user '{user or 'unknown'}' from IP {src_ip} within 120 seconds."
                    ))

        # -----------------------------------------------------------------
        # 2. SUCCESSFUL LOGIN AFTER BRUTE FORCE (T1078 - Valid Accounts)
        # -----------------------------------------------------------------
        is_auth_success = (
            "auth" in evt_type or "ssh" in evt_type or "login" in evt_type or
            action in ["login_success", "session_opened", "accepted_password", "authenticated"]
        ) and (status in ["SUCCESS", "ACCEPTED", "ALLOWED"])

        if is_auth_success and src_ip:
            key = f"{src_ip}:{user or 'unknown'}"
            recent_fails = [e for e in self._auth_failures.get(key, []) if e[0] >= (epoch - 300.0)]
            if len(recent_fails) >= 3:
                sig = f"compromise_after_bf:{key}:{eid}"
                if sig not in self._fired_signature_dedup:
                    self._fired_signature_dedup.add(sig)
                    evidence_ids = [e[1] for e in recent_fails] + [eid]
                    alerts.append(DetectionAlert(
                        id=f"alert-{uuid.uuid4().hex[:8]}",
                        detection="Compromised Account: Successful Login Following Brute Force",
                        severity="CRITICAL",
                        confidence=0.96,
                        tactic="Initial Access",
                        technique="T1078 - Valid Accounts",
                        technique_id="T1078",
                        timestamp=ts,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        hostname=host,
                        username=user,
                        evidenceEventIds=evidence_ids,
                        reasoning=f"Successful authentication for user '{user}' from IP {src_ip} immediately after {len(recent_fails)} failed attempts."
                    ))

        # -----------------------------------------------------------------
        # 3. PRIVILEGE ESCALATION / SUSPICIOUS SUDO (T1548.003 - Sudo Caching)
        # -----------------------------------------------------------------
        privesc_patterns = [
            "sudo bash", "sudo sh", "sudo zsh", "sudo su", "sudo -i", "chmod +s",
            "sudo /bin/bash", "sudo /bin/sh", "sudo cp /bin/bash", "sudo find",
            "sudo vim", "sudo nmap", "sudo python", "sudo perl", "nopasswd: all"
        ]
        if any(p in cmd for p in privesc_patterns) or (action == "sudo_execution" and ("bash" in cmd or "sh" in cmd or "root" in raw_text)):
            alerts.append(DetectionAlert(
                id=f"alert-{uuid.uuid4().hex[:8]}",
                detection="Suspicious Privilege Escalation Command",
                severity="HIGH",
                confidence=0.93,
                tactic="Privilege Escalation",
                technique="T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                technique_id="T1548.003",
                timestamp=ts,
                source_ip=src_ip,
                destination_ip=dst_ip,
                hostname=host,
                username=user or "root",
                evidenceEventIds=[eid],
                reasoning=f"Privilege escalation mechanism executed by user '{user or 'unknown'}' on host '{host or 'unknown'}': command '{cmd}'."
            ))

        # -----------------------------------------------------------------
        # 4. CREDENTIAL ACCESS & DUMPING (T1003 - OS Credential Dumping)
        # -----------------------------------------------------------------
        cred_dump_patterns = [
            "/etc/shadow", "mimikatz", "sekurlsa", "whoami /priv", "vssadmin delete shadows",
            "reg save hklm\\sam", "reg save hklm\\system", "lsass.dmp", "pwdump", "procdump -ma lsass"
        ]
        if any(p in cmd for p in cred_dump_patterns) or any(p in raw_text for p in ["/etc/shadow", "mimikatz", "sekurlsa", "lsass.dmp"]):
            alerts.append(DetectionAlert(
                id=f"alert-{uuid.uuid4().hex[:8]}",
                detection="OS Credential Dumping & Discovery",
                severity="HIGH",
                confidence=0.95,
                tactic="Credential Access",
                technique="T1003 - OS Credential Dumping",
                technique_id="T1003",
                timestamp=ts,
                source_ip=src_ip,
                destination_ip=dst_ip,
                hostname=host,
                username=user,
                evidenceEventIds=[eid],
                reasoning=f"Direct credential store discovery/access attempted on host '{host or 'unknown'}' via command or target path: '{cmd or raw_text[:80]}'."
            ))

        # -----------------------------------------------------------------
        # 5. SUSPICIOUS ARCHIVE CREATION / STAGING (T1560 - Archive Collected Data)
        # -----------------------------------------------------------------
        archive_patterns = ["tar -czf", "tar -cf", "zip -r", "7z a", "pg_dump", "mysqldump", "rar a"]
        staging_paths = ["/tmp/", "/dev/shm/", "/var/tmp/", "c:\\temp\\", "c:\\windows\\temp\\"]
        if any(p in cmd for p in archive_patterns) and (any(sp in cmd for sp in staging_paths) or "backup" in cmd or "exfil" in cmd):
            alerts.append(DetectionAlert(
                id=f"alert-{uuid.uuid4().hex[:8]}",
                detection="Suspicious Archive Creation in Temporary Staging Directory",
                severity="MEDIUM",
                confidence=0.88,
                tactic="Collection",
                technique="T1560 - Archive Collected Data",
                technique_id="T1560",
                timestamp=ts,
                source_ip=src_ip,
                destination_ip=dst_ip,
                hostname=host,
                username=user,
                evidenceEventIds=[eid],
                reasoning=f"Data staging activity identified: archiving command '{cmd}' targeting sensitive staging directory."
            ))

        # -----------------------------------------------------------------
        # 6. UNUSUAL OUTBOUND EXFILTRATION (T1048 - Exfiltration Over Alternative Protocol)
        # -----------------------------------------------------------------
        is_large_outbound = bytes_out >= 500000 or (
            ("curl -x post" in cmd or "nc -e" in cmd or "scp " in cmd or "rsync " in cmd) and
            dst_ip and not dst_ip.startswith("10.") and not dst_ip.startswith("192.168.")
        )
        if is_large_outbound:
            alerts.append(DetectionAlert(
                id=f"alert-{uuid.uuid4().hex[:8]}",
                detection="High-Volume Outbound Data Exfiltration",
                severity="HIGH",
                confidence=0.91,
                tactic="Exfiltration",
                technique="T1048 - Exfiltration Over Alternative Protocol",
                technique_id="T1048",
                timestamp=ts,
                source_ip=src_ip,
                destination_ip=dst_ip,
                hostname=host,
                username=user,
                evidenceEventIds=[eid],
                reasoning=f"High-volume outbound data transfer ({bytes_out:,} bytes) to external IP '{dst_ip or 'unknown'}' from source '{src_ip or host or 'unknown'}'."
            ))

        # -----------------------------------------------------------------
        # 7. PORT SCANNING / NETWORK RECONNAISSANCE (T1046 - Network Service Discovery)
        # -----------------------------------------------------------------
        if src_ip and dst_port:
            scan_key = src_ip
            self._port_scan_history[scan_key].append((epoch, dst_port, eid))
            cutoff = epoch - 60.0
            while self._port_scan_history[scan_key] and self._port_scan_history[scan_key][0][0] < cutoff:
                self._port_scan_history[scan_key].popleft()

            ports_seen = set(e[1] for e in self._port_scan_history[scan_key])
            if len(ports_seen) >= 3:
                sig = f"portscan:{scan_key}:{len(ports_seen)}"
                if sig not in self._fired_signature_dedup:
                    self._fired_signature_dedup.add(sig)
                    evidence_ids = [e[2] for e in self._port_scan_history[scan_key]]
                    alerts.append(DetectionAlert(
                        id=f"alert-{uuid.uuid4().hex[:8]}",
                        detection="Network Port Scanning & Service Discovery",
                        severity="MEDIUM",
                        confidence=0.87,
                        tactic="Discovery",
                        technique="T1046 - Network Service Discovery",
                        technique_id="T1046",
                        timestamp=ts,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        hostname=host,
                        username=user,
                        evidenceEventIds=evidence_ids,
                        reasoning=f"Sequential port probing detected across {len(ports_seen)} distinct ports ({sorted(list(ports_seen))[:5]}) originating from source IP {src_ip} within 60s."
                    ))

        # -----------------------------------------------------------------
        # 8. SUSPICIOUS PROCESS CHAINS / WEB EXPLOITATION (T1059.004 - Unix Shell)
        # -----------------------------------------------------------------
        web_parents = ["nginx", "httpd", "apache2", "tomcat", "w3wp", "caddy"]
        is_web_spawn = (
            any(wp in proc for wp in web_parents) and any(sh in cmd for sh in ["/bin/sh", "/bin/bash", "cmd.exe", "powershell", "whoami"])
        ) or (
            "powershell" in proc and ("-enc" in cmd or "-encodedcommand" in cmd or "bypass" in cmd)
        )
        if is_web_spawn or ("union select" in raw_text and status in ["SUCCESS", "200"]):
            alerts.append(DetectionAlert(
                id=f"alert-{uuid.uuid4().hex[:8]}",
                detection="Suspicious Web Server Shell Spawn / Execution Chain",
                severity="HIGH",
                confidence=0.94,
                tactic="Execution",
                technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
                technique_id="T1059.004",
                timestamp=ts,
                source_ip=src_ip,
                destination_ip=dst_ip,
                hostname=host,
                username=user,
                evidenceEventIds=[eid],
                reasoning=f"Anomalous process execution chain detected: process '{proc}' executed command '{cmd}' on host '{host or 'unknown'}'."
            ))

        # -----------------------------------------------------------------
        # 9. COVERT DNS TUNNELING (T1071.004 - DNS)
        # -----------------------------------------------------------------
        domain = str(raw_data.get("domain") or raw_data.get("query_domain") or "")
        subdomain_len = len(domain.split(".")[0]) if "." in domain else len(domain)
        is_dns_tunnel = "dns" in evt_type and (
            subdomain_len > 40 or
            ("c2" in domain and "tunnel" in domain) or
            ("data" in domain and ".tunnel." in domain)
        )
        if is_dns_tunnel:
            alerts.append(DetectionAlert(
                id=f"alert-{uuid.uuid4().hex[:8]}",
                detection="Covert DNS Tunneling & C2 Channel",
                severity="HIGH",
                confidence=0.92,
                tactic="Command and Control",
                technique="T1071.004 - Application Layer Protocol: DNS",
                technique_id="T1071.004",
                timestamp=ts,
                source_ip=src_ip,
                destination_ip=dst_ip,
                hostname=host,
                username=user,
                evidenceEventIds=[eid],
                reasoning=f"Potential DNS tunneling payload: excessive subdomain length ({subdomain_len} chars) or suspicious C2 domain format '{domain}'."
            ))

        return alerts
