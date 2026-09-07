# Autonomous Threat-Hunting Copilot & AI SOC Investigator

> An AI-Assisted, Zero-Trust Threat-Hunting Workstation, Real-Time SOC Investigation Engine & Linux Telemetry Platform.

---

## 🛡️ Executive Summary

The **Autonomous Threat-Hunting Copilot** is a security-first investigation workstation designed to assist SOC analysts in identifying, investigating, and responding to cyber threats across enterprise telemetry.

It supports three operational telemetry ingestion modes:
1. **LIVE MONITORING**: Collects real Linux authentication (`/var/log/auth.log`, `secure`), auditd (`execve`), process, and network connection telemetry via a lightweight, secure Linux collector agent.
2. **DATASET REPLAY**: Ingests and replays benchmark security datasets (such as **CIC-IDS2017**, JSON event streams, and raw PCAP packet captures) with configurable speed multipliers without altering original timestamps.
3. **SIMULATION**: Replays 7 prebuilt realistic multi-stage attack scenarios (SSH brute force, credential dumping, privilege escalation, data exfiltration, port scanning) with full MITRE ATT&CK technique mapping.

---

## 🏛️ End-to-End Pipeline Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                TELEMETRY SOURCES                                      │
├──────────────────────────┬─────────────────────────────┬──────────────────────────────┤
│    1. LIVE MONITORING    │      2. DATASET REPLAY      │        3. SIMULATION         │
│  • Linux Auth & Sudo     │  • CIC-IDS2017 NetFlow CSV  │  • 7 Prebuilt Attack Scenarios│
│  • auditd / Syscall Exec │  • Raw PCAP Packet Captures │  • Ordered SecurityEvents     │
│  • Network Connections   │  • JSON / JSONL Event Logs  │  • Labeled MITRE ATT&CK TTPs │
└────────────┬─────────────┴──────────────┬──────────────┴──────────────┬───────────────┘
             │                            │                             │
             │ HTTPS POST /api/events     │ Replay Engine (0.25x-100x)  │ Simulated Replay Engine
             ▼                            ▼                             ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        CANONICAL SECURITY EVENT NORMALIZATION                         │
│  [NetworkFlowAdapter • LinuxAuthAdapter • LinuxAuditAdapter • WebLog • DNS • Firewall] │
└─────────────────────────────────────────┬──────────────────────────────────────────────┘
                                          │ Real-Time Sequence Streaming (WebSocket / SSE)
                                          ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                    REAL-TIME DETECTION & BEHAVIORAL RULE ENGINE                        │
│  • SSH Brute Force Surge              • Account Compromise After Brute Force          │
│  • Privilege Escalation (Sudo/Setuid) • Credential Discovery (Shadow/Mimikatz)         │
│  • Suspicious Data Collection/Tar/Zip • Data Exfiltration Outbound Surges              │
│  • Fast/Distributed Port Scanning     • Suspicious Process Chains                     │
└─────────────────────────────────────────┬──────────────────────────────────────────────┘
                                          │ Entity Correlations (IP, Hostname, Username)
                                          ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                       MULTI-ENTITY CORRELATION & ATTACK GRAPH                          │
│  • Dynamic Node & Edge Builder: (Attacker IP ──> Host ──> User ──> Process ──> C2)   │
│  • Kill-Chain Stage Tracker: Recon ──> Access ──> PrivEsc ──> Discovery ──> Exfil    │
└─────────────────────────────────────────┬──────────────────────────────────────────────┘
                                          │ Active Incident Package
                                          ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                   MITRE ATT&CK MAPPING & BEHAVIORAL PROVENANCE                         │
│  • T1110 (Brute Force)      • T1078 (Valid Accounts)     • T1068 (Privilege Escalation)│
│  • T1003 (Credential Dump)  • T1560 (Archive Collected)  • T1041 (Exfiltration Over C2)│
│  • T1046 (Network Scanning) • T1059 (Command/Script Execution)                         │
└─────────────────────────────────────────┬──────────────────────────────────────────────┘
                                          │ Zero-Trust Tool Gateway
                                          ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                       CONTROLLED AUTONOMOUS AI INVESTIGATOR                            │
│  • Schema-Validated Read-Only Tool Execution (Max 10 calls, max 1000 records cap)      │
│  • Strict Evidence Grounding & Anti-Hallucination Verification                         │
│  • Automated Structured Incident Report Generation                                     │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🧭 Global Operational Modes

The analyst interface features a **Global Telemetry Mode Selector** in the navigation bar:

| Mode | Visual Indicator | Ingestion Source | Primary Use Case |
| :--- | :--- | :--- | :--- |
| **Live Monitoring** | `[ 🟢 Live Monitoring ]` | Linux collector agent streaming to `POST /api/events` | Real-time enterprise server and workstation monitoring. |
| **Dataset Replay** | `[ 🔵 Dataset Replay ]` | Imported CIC-IDS2017 CSVs, PCAPs, and JSON logs | Historical triage, benchmark evaluation, and PCAP inspection. |
| **Simulation** | `[ 🟣 Simulation ]` | 7 Prebuilt Attack Scenarios (`SIMULATED ATTACK REPLAY`) | Training, testing detection rules, and verifying incident response playbooks. |

---

## 🩺 Subsystem Health & Diagnostics

The platform includes a real-time subsystem diagnostic monitor (`GET /api/health/comprehensive`) displaying live health for all 6 operational subsystems:

1. **Backend Core**: FastAPI runtime, process uptime, and resource allocations.
2. **Database & Stores**: In-memory telemetry repository, event indexers, and schema integrity.
3. **Event Stream Hub**: Live WebSocket clients, sequence counters, bounded circular buffer (10,000 events), and rate limiting.
4. **Detection Engine**: Active behavioral rules, correlation graph state, active incidents count, and statistically significant evaluation metrics.
5. **AI Investigator**: Registered read-only tools, safety gating flags, and AI model provider status.
6. **Connected Linux Agents**: Registered agent count, online heartbeat status, and telemetry transmission rates.

---

## 📦 Real Cybersecurity Dataset Ingestion & Replay

### Supported Ingestion Formats:
1. **CIC-IDS2017 & NetFlow/IPFIX (CSV)**:
   - Ingests Canadian Institute for Cybersecurity flow CSVs with whitespace-padded headers (` Source IP`, ` Flow Duration`, ` Label`, etc.).
   - Converts microsecond flow durations to seconds and maps numeric protocols (`6` -> `TCP`, `17` -> `UDP`, `1` -> `ICMP`).
2. **JSON Event Telemetry (JSON / JSONL)**:
   - Ingests structured SIEM streams and EDR authentication records.
3. **PCAP Packet Captures (Libpcap)**:
   - Pure-Python binary packet parser extracting layer-3/4 packet flows and byte counters.

### Event Replay Engine (`/api/replay/*`):
- **Preserved Timestamps**: Original historical timestamps are never altered.
- **Configurable Speed**: Supports `0.25x` (slow-motion), `1.0x` (real-time), `10x`, and `100x` speed multipliers.
- **Lifecycle Controls**: `POST /api/replay/start`, `pause`, `resume`, `stop`, and `GET /api/replay/status`.

---

## 🐧 Linux Collector Agent Deployment

The platform includes a lightweight, secure Linux collector agent located at `agent/linux_collector.py`.

### Capabilities:
- **Telemetry Sources**: Parses `/var/log/auth.log`, `/var/log/secure`, `/var/log/audit/audit.log` (`execve`), process execution, and `/proc/net/tcp` connections.
- **Zero Credential Transmission**: Redacts passwords, API keys, and private keys (`BEGIN PRIVATE KEY`) before normalization.
- **Offset & Checkpoint Persistence**: Tracks file inode and byte offset in `.collector_checkpoint.json` to prevent duplicate transmissions across restarts.
- **Automatic Reconnection & Batching**: Batches up to 50 events or 1.0s flush intervals with exponential backoff on connection drops.

### Quick Start Agent Installation:
```bash
# 1. Run Linux Collector Agent pointing to SOC backend:
python3 agent/linux_collector.py \
  --backend http://localhost:8000 \
  --agent-id linux-srv-alpha \
  --api-key SOC_AGENT_SECRET_KEY \
  --batch-size 50 \
  --flush-interval 1.0
```

---

## 🎯 Prebuilt Attack Scenarios

The Simulation engine provides 7 realistic, ordered attack scenarios:
1. **SSH Brute Force (`ssh_brute_force`)**: Rapid failed SSH attempts from external reconnaissance IP (`198.51.100.44`).
2. **Successful Account Compromise (`account_compromise`)**: Brute force surge followed by successful authentication from `198.51.100.77`.
3. **Privilege Escalation (`privilege_escalation`)**: Compromised standard user spawns root shell via `sudo su` and `setuid` binary exploitation.
4. **Credential Discovery (`credential_discovery`)**: Accessing `/etc/shadow`, dumping memory strings, and credential harvesting.
5. **Suspicious Data Collection (`suspicious_collection`)**: Staging sensitive files into `/tmp/.stash.tar.gz`.
6. **Data Exfiltration (`data_exfiltration`)**: Outbound high-volume transfer (150 MB) to remote C2 server over port 443.
7. **Full Multi-Stage Attack (`multi_stage_attack`)**: Complete end-to-end kill chain combining Reconnaissance $\to$ Initial Access $\to$ Privilege Escalation $\to$ Credential Access $\to$ Collection $\to$ Exfiltration.

---

## 🔒 Threat Model & Zero-Trust Security Controls

| Security Boundary | Design Rule & Enforcement Mechanism |
| :--- | :--- |
| **No Shell Access** | The AI engine has zero shell, terminal, or code execution access. |
| **Read-Only Telemetry** | Tool Gateway exposes strictly read-only search tools. No write/delete operations exist. |
| **Strict Parameter Validation** | Inputs pass Pydantic schema validation. Malicious injection triggers immediate rejection. |
| **Untrusted Data Labeling** | Telemetry logs are wrapped in `<UNTRUSTED_TELEMETRY_DATA>` XML boundaries before reasoning. |
| **Hard Autonomy Caps** | Max 5 iterations per hunt, max 10 tool calls, max 1000 records per call, 300s timeout. |
| **Evidence Grounding** | Claims citing non-existent evidence IDs are rejected as *"Insufficient evidence."* |
| **Bounded Memory Buffer** | Circular buffer with max 10,000 events prevents memory leaks under heavy load. |

---

## 🚀 Quick Start & Local Setup

### Option 1: Local Python & Node Development

#### Backend Setup:
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### Frontend Setup:
```bash
cd frontend
npm install
npm run dev
```

The application will be accessible at:
- **Frontend UI**: `http://localhost:5173`
- **Backend API & Swagger Docs**: `http://localhost:8000/docs`
- **Comprehensive Health Monitor**: `http://localhost:8000/api/health/comprehensive`

---

## 🔬 Automated Pytest Verification Suite

To run the complete automated test suite (100 unit, integration, and stress tests):

```bash
backend/venv/bin/pytest backend/tests -v
```

### Test Suite Coverage:
- `test_production_integration_and_stress.py`: 10k event throughput, $O(1)$ memory boundedness, 10 concurrent agent shippers, and cross-source multi-telemetry attack correlation.
- `test_linux_agent_and_ingestion.py`: Redaction of credentials, auth/audit/process log parsing, checkpoint offset tracking, and live agent telemetry detection.
- `test_simulated_attack_scenarios.py`: 7 scenario definitions, replay lifecycle, and automated incident creation.
- `test_realtime_detection_and_incidents.py`: Real-time behavioral detection rules, zero label leakage, and dynamic attack graph correlation.
- `test_realtime_event_streaming.py`: WebSocket broadcast, reconnect handling, duplicate prevention, and sequence integrity.
- `test_event_normalization_pipeline.py`: Adapters for NetFlow, Linux Auth, Auditd, Web logs, DNS, Firewall, and Sysmon.
- `test_event_replay_engine.py`: Chronological ordering, speed multipliers, and pause/resume/stop state machine.
- `test_hunting_engine.py`: Grounding validator, hallucination rejection, and autonomous tool safety.
- `test_production_security.py`: Rate limiting, security headers, and input sanitization.

---

## 📄 License & Contact

Developed as part of the **Autonomous Threat-Hunting Copilot & AI SOC Investigator Project**. Built for enterprise SOC operations and autonomous security research.
