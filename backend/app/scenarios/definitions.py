from typing import Dict, List, Any
from pydantic import BaseModel, Field

class PrebuiltScenario(BaseModel):
    scenario_id: str
    name: str
    description: str
    category: str = "SIMULATED ATTACK REPLAY"
    telemetry_source: str = "SIMULATED_SCENARIO"
    expected_techniques: List[str]
    expected_tactics: List[str]
    events_count: int
    events: List[Dict[str, Any]] = Field(default_factory=list)

def get_prebuilt_scenarios() -> Dict[str, PrebuiltScenario]:
    base_time = "2026-08-10T19:00:00Z"

    scenarios = {}

    # 1. SSH Brute Force
    sc1_events = [
        {
            "id": "sim-bf-01",
            "timestamp": "2026-08-10T19:00:01Z",
            "source_type": "linux_auth",
            "source": "simulated:ssh-bruteforce",
            "hostname": "srv-web-01",
            "source_ip": "198.51.100.99",
            "source_port": 51234,
            "destination_ip": "10.0.1.10",
            "destination_port": 22,
            "protocol": "TCP",
            "username": "deploy",
            "process_name": "sshd",
            "event_type": "ssh_authentication",
            "action": "failed_password",
            "status": "FAILURE",
            "severity": "HIGH",
            "label": "SIMULATED ATTACK REPLAY",
            "metadata": {"telemetry_source": "SIMULATED_SCENARIO", "simulated": True}
        },
        {
            "id": "sim-bf-02",
            "timestamp": "2026-08-10T19:00:05Z",
            "source_type": "linux_auth",
            "source": "simulated:ssh-bruteforce",
            "hostname": "srv-web-01",
            "source_ip": "198.51.100.99",
            "source_port": 51236,
            "destination_ip": "10.0.1.10",
            "destination_port": 22,
            "protocol": "TCP",
            "username": "deploy",
            "process_name": "sshd",
            "event_type": "ssh_authentication",
            "action": "failed_password",
            "status": "FAILURE",
            "severity": "HIGH",
            "label": "SIMULATED ATTACK REPLAY",
            "metadata": {"telemetry_source": "SIMULATED_SCENARIO", "simulated": True}
        },
        {
            "id": "sim-bf-03",
            "timestamp": "2026-08-10T19:00:10Z",
            "source_type": "linux_auth",
            "source": "simulated:ssh-bruteforce",
            "hostname": "srv-web-01",
            "source_ip": "198.51.100.99",
            "source_port": 51238,
            "destination_ip": "10.0.1.10",
            "destination_port": 22,
            "protocol": "TCP",
            "username": "deploy",
            "process_name": "sshd",
            "event_type": "ssh_authentication",
            "action": "failed_password",
            "status": "FAILURE",
            "severity": "HIGH",
            "label": "SIMULATED ATTACK REPLAY",
            "metadata": {"telemetry_source": "SIMULATED_SCENARIO", "simulated": True}
        },
        {
            "id": "sim-bf-04",
            "timestamp": "2026-08-10T19:00:15Z",
            "source_type": "linux_auth",
            "source": "simulated:ssh-bruteforce",
            "hostname": "srv-web-01",
            "source_ip": "198.51.100.99",
            "source_port": 51240,
            "destination_ip": "10.0.1.10",
            "destination_port": 22,
            "protocol": "TCP",
            "username": "deploy",
            "process_name": "sshd",
            "event_type": "ssh_authentication",
            "action": "failed_password",
            "status": "FAILURE",
            "severity": "HIGH",
            "label": "SIMULATED ATTACK REPLAY",
            "metadata": {"telemetry_source": "SIMULATED_SCENARIO", "simulated": True}
        }
    ]
    scenarios["ssh-bruteforce"] = PrebuiltScenario(
        scenario_id="ssh-bruteforce",
        name="SSH Brute Force Surge",
        description="Rapid password spray against sshd on srv-web-01 originating from external IP 198.51.100.99.",
        expected_techniques=["T1110", "T1110.001"],
        expected_tactics=["Credential Access"],
        events_count=len(sc1_events),
        events=sc1_events
    )

    # 2. Successful Account Compromise
    sc2_events = list(sc1_events[:3]) + [
        {
            "id": "sim-comp-01",
            "timestamp": "2026-08-10T19:00:20Z",
            "source_type": "linux_auth",
            "source": "simulated:account-compromise",
            "hostname": "srv-web-01",
            "source_ip": "198.51.100.99",
            "source_port": 51242,
            "destination_ip": "10.0.1.10",
            "destination_port": 22,
            "protocol": "TCP",
            "username": "deploy",
            "process_name": "sshd",
            "event_type": "ssh_authentication",
            "action": "accepted_password",
            "status": "SUCCESS",
            "severity": "CRITICAL",
            "label": "SIMULATED ATTACK REPLAY",
            "metadata": {"telemetry_source": "SIMULATED_SCENARIO", "simulated": True}
        }
    ]
    scenarios["account-compromise"] = PrebuiltScenario(
        scenario_id="account-compromise",
        name="Successful Account Compromise",
        description="Brute force authentication surge followed by successful password login for user deploy from the same attacker IP.",
        expected_techniques=["T1110", "T1078"],
        expected_tactics=["Credential Access", "Initial Access"],
        events_count=len(sc2_events),
        events=sc2_events
    )

    # 3. Privilege Escalation
    sc3_events = [
        {
            "id": "sim-priv-01",
            "timestamp": "2026-08-10T19:01:00Z",
            "source_type": "linux_auth",
            "source": "simulated:privilege-escalation",
            "hostname": "srv-web-01",
            "username": "deploy",
            "process_name": "sudo",
            "command": "sudo -l",
            "event_type": "process_create",
            "action": "sudo_execution",
            "status": "SUCCESS",
            "severity": "INFO",
            "label": "SIMULATED ATTACK REPLAY",
            "metadata": {"telemetry_source": "SIMULATED_SCENARIO", "simulated": True}
        },
        {
            "id": "sim-priv-02",
            "timestamp": "2026-08-10T19:01:15Z",
            "source_type": "linux_auth",
            "source": "simulated:privilege-escalation",
            "hostname": "srv-web-01",
            "username": "deploy",
            "process_name": "sudo",
            "command": "sudo bash",
            "event_type": "process_create",
            "action": "sudo_execution",
            "status": "SUCCESS",
            "severity": "HIGH",
            "label": "SIMULATED ATTACK REPLAY",
            "metadata": {"telemetry_source": "SIMULATED_SCENARIO", "simulated": True}
        }
    ]
    scenarios["privilege-escalation"] = PrebuiltScenario(
        scenario_id="privilege-escalation",
        name="Sudo Privilege Escalation",
        description="Compromised user deploy escalates privileges to root UID 0 via sudo bash execution.",
        expected_techniques=["T1548.003"],
        expected_tactics=["Privilege Escalation"],
        events_count=len(sc3_events),
        events=sc3_events
    )

    # 4. Credential Discovery
    sc4_events = [
        {
            "id": "sim-cred-01",
            "timestamp": "2026-08-10T19:02:00Z",
            "source_type": "linux_audit",
            "source": "simulated:credential-discovery",
            "hostname": "srv-web-01",
            "username": "root",
            "process_name": "cat",
            "command": "cat /etc/shadow",
            "event_type": "file_access",
            "action": "read",
            "status": "SUCCESS",
            "severity": "HIGH",
            "label": "SIMULATED ATTACK REPLAY",
            "metadata": {"telemetry_source": "SIMULATED_SCENARIO", "simulated": True}
        },
        {
            "id": "sim-cred-02",
            "timestamp": "2026-08-10T19:02:20Z",
            "source_type": "linux_audit",
            "source": "simulated:credential-discovery",
            "hostname": "srv-web-01",
            "username": "root",
            "process_name": "cat",
            "command": "cat /root/.ssh/id_rsa",
            "event_type": "file_access",
            "action": "read",
            "status": "SUCCESS",
            "severity": "HIGH",
            "label": "SIMULATED ATTACK REPLAY",
            "metadata": {"telemetry_source": "SIMULATED_SCENARIO", "simulated": True}
        }
    ]
    scenarios["credential-discovery"] = PrebuiltScenario(
        scenario_id="credential-discovery",
        name="OS Credential Discovery & Dumping",
        description="Root shell accesses local password hashes in /etc/shadow and searches for private SSH keys.",
        expected_techniques=["T1003", "T1087"],
        expected_tactics=["Credential Access", "Discovery"],
        events_count=len(sc4_events),
        events=sc4_events
    )

    # 5. Suspicious Data Collection
    sc5_events = [
        {
            "id": "sim-coll-01",
            "timestamp": "2026-08-10T19:03:00Z",
            "source_type": "linux_audit",
            "source": "simulated:data-collection",
            "hostname": "srv-web-01",
            "username": "root",
            "process_name": "tar",
            "command": "tar -czf /tmp/staging_data.tar.gz /var/www/data",
            "event_type": "process_create",
            "action": "archive_creation",
            "status": "SUCCESS",
            "severity": "MEDIUM",
            "label": "SIMULATED ATTACK REPLAY",
            "metadata": {"telemetry_source": "SIMULATED_SCENARIO", "simulated": True}
        }
    ]
    scenarios["data-collection"] = PrebuiltScenario(
        scenario_id="data-collection",
        name="Suspicious Data Collection",
        description="Attacker archives internal application data and stages the compressed file in /tmp/staging_data.tar.gz.",
        expected_techniques=["T1560"],
        expected_tactics=["Collection"],
        events_count=len(sc5_events),
        events=sc5_events
    )

    # 6. Data Exfiltration
    sc6_events = [
        {
            "id": "sim-exfil-01",
            "timestamp": "2026-08-10T19:04:00Z",
            "source_type": "network_flow",
            "source": "simulated:data-exfiltration",
            "hostname": "srv-web-01",
            "source_ip": "10.0.1.10",
            "source_port": 49120,
            "destination_ip": "203.0.113.88",
            "destination_port": 8443,
            "protocol": "TCP",
            "bytes_out": 2500000,
            "bytes_in": 1200,
            "event_type": "network_flow",
            "action": "outbound_transfer",
            "status": "SUCCESS",
            "severity": "HIGH",
            "label": "SIMULATED ATTACK REPLAY",
            "metadata": {"telemetry_source": "SIMULATED_SCENARIO", "simulated": True}
        }
    ]
    scenarios["data-exfiltration"] = PrebuiltScenario(
        scenario_id="data-exfiltration",
        name="High-Volume Data Exfiltration",
        description="High-volume outbound data transfer of 2.5 MB from srv-web-01 to external C2 IP 203.0.113.88 over port 8443.",
        expected_techniques=["T1048"],
        expected_tactics=["Exfiltration"],
        events_count=len(sc6_events),
        events=sc6_events
    )

    # 7. Multi-Stage Attack (Full Kill-Chain)
    sc7_events = (
        list(sc1_events[:3]) + 
        [sc2_events[-1]] + 
        [sc3_events[1]] + 
        [sc4_events[0]] + 
        [sc5_events[0]] + 
        [sc6_events[0]]
    )
    scenarios["multi-stage-attack"] = PrebuiltScenario(
        scenario_id="multi-stage-attack",
        name="Multi-Stage Attack (Full Kill-Chain)",
        description="End-to-end simulated kill chain: SSH Brute Force → Account Compromise → Sudo Escalation → Credential Dumping → Archive Staging → C2 Exfiltration.",
        expected_techniques=["T1110", "T1078", "T1548.003", "T1003", "T1560", "T1048"],
        expected_tactics=["Credential Access", "Initial Access", "Privilege Escalation", "Collection", "Exfiltration"],
        events_count=len(sc7_events),
        events=sc7_events
    )

    return scenarios
