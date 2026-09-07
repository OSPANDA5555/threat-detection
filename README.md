# Autonomous Threat-Hunting Copilot

> An AI-Assisted, Zero-Trust Threat-Hunting Workstation & Controlled Autonomous Investigation Engine for SOC Analysts.

---

## 🛡️ Executive Summary

The **Autonomous Threat-Hunting Copilot** is a security-first investigation workstation designed to assist SOC analysts in identifying, investigating, and responding to cyber threats across enterprise telemetry.

Unlike generic LLM chatbots or unconstrained AI agents, this platform enforces a **Zero-Trust Tool Gateway**. The AI is **never allowed direct shell access, Python execution, or arbitrary SQL queries**. All investigations route through read-only, schema-validated security tools subject to hard autonomy caps, human oversight approval gates, and reproducible audit streams.

---

## 🏛️ System Architecture

```
               ┌─────────────────────────────────────────────────┐
               │    React SOC Analyst Workstation (Frontend)     │
               └────────────────────────┬────────────────────────┘
                                        │ REST API & Server-Sent Audit Logs
               ┌────────────────────────▼────────────────────────┐
               │          FastAPI Core Engine (Backend)          │
               │   • Autonomous Hunting State Engine             │
               │   • Prompt Injection Detector & Sanitizer       │
               │   • Evaluation Lab & Ground Truth Harness       │
               │   • Dataset Ingestion & Normalization Engine    │
               │   • Indicator Graph Builder (IP→USER→HOST...)   │
               └────────────────────────┬────────────────────────┘
                                        │ Strict Parameter Validation
               ┌────────────────────────▼────────────────────────┐
               │             Zero-Trust Tool Gateway             │
               │  [Read-Only Enforced • Max 1000 Events Cap]     │
               └─────┬──────────────┬──────────────┬─────────────┘
                     │              │              │
        ┌────────────▼───┐  ┌───────▼──────┐  ┌────▼───────────┐
        │ Authentication │  │ SSH & Process│  │ DNS & Network  │
        │ Events Stream  │  │ Events Logs  │  │ Connections    │
        └────────────────┘  └──────────────┘  └────────────────┘
```

---

## 📦 Real Cybersecurity Dataset Ingestion & Normalization

The platform includes a dedicated **Dataset Ingestion Module** designed to import, validate, normalize, and explore real cybersecurity telemetry, network flows, and packet captures.

### Supported Ingestion Formats:
1. **CIC-IDS2017 & NetFlow/IPFIX (CSV)**:
   - Ingests standard Canadian Institute for Cybersecurity (CIC-IDS2017) flow CSVs and general network flow logs.
   - Automatically handles whitespace-padded headers (` Source IP`, ` Flow Duration`, ` Label`, etc.).
   - Converts microsecond flow durations to seconds and maps numeric protocols (`6` -> `TCP`, `17` -> `UDP`, `1` -> `ICMP`).
2. **JSON Event Telemetry (JSON / JSONL)**:
   - Ingests structured event logs, SIEM streams, and EDR authentication records.
3. **PCAP Packet Captures (Libpcap)**:
   - Safely parses raw PCAP binary files using pure-Python unpacking to extract layer-3/4 packet flows and byte counters.

---

### 📋 Normalized Internal Event Schema

Every imported record is normalized into the following standardized schema:

| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | `string (ISO-8601)` | Standardized UTC event timestamp. |
| `source_ip` | `string \| null` | Validated source IPv4 or IPv6 address. |
| `source_port` | `integer \| null` | Source port (0–65535). |
| `destination_ip` | `string \| null` | Validated destination IPv4 or IPv6 address. |
| `destination_port` | `integer \| null` | Destination port (0–65535). |
| `protocol` | `string \| null` | Standardized transport protocol (`TCP`, `UDP`, `ICMP`). |
| `event_type` | `string` | High-level event category (`network_flow`, `auth`, `process`). |
| `action` | `string \| null` | Action taken (`ALLOWED`, `DENIED`, `SUCCESS`, `FAILURE`). |
| `username` | `string \| null` | Associated user identity (`null` when not in dataset). |
| `hostname` | `string \| null` | Target endpoint hostname (`null` when not in dataset). |
| `process` | `string \| null` | Process executable name (`null` when not in dataset). |
| `bytes_in` | `integer \| null` | Forward packet length / incoming bytes. |
| `bytes_out` | `integer \| null` | Backward packet length / outgoing bytes. |
| `duration` | `float \| null` | Flow duration in seconds. |
| `label` | `string` | Preserved attack label (`BENIGN`, `SSH-Patator`, `PortScan`, `DoS Hulk`, `DDoS`). |
| `raw_data` | `object` | Complete original un-normalized raw event record. |
| `source` | `string` | Source origin identifier (`cic-ids2017`, `json_events`, `pcap`). |

> [!IMPORTANT]
> **Strict Non-Invention Rule**: The normalizer **never invents values** for missing fields. If a dataset does not provide hostnames or processes, they are strictly set to `null`. The original raw record is always preserved in `raw_data`.

---

### 🛡️ Validation & Error Resilience

The ingestion engine validates:
- **IP Format**: Rejects invalid addresses (e.g. `999.999.999.999`).
- **Port Ranges**: Rejects out-of-range ports (`< 0` or `> 65535`).
- **Timestamp Integrity**: Validates and standardizes multi-format date strings.
- **Malformed Rows**: Rows with mismatched column counts are flagged and reported.

> **Resilience Guarantee**: Individual malformed records are safely isolated in the dataset error log and **do not reject the entire dataset**. Valid rows are preserved and normalized.

---

### 📖 How to Import CIC-IDS2017 Datasets

#### Method 1: Via SOC Web Interface (UI)
1. Open the workstation at `http://localhost:5173` (or `http://localhost`).
2. Click the **"Dataset Import"** tab in the top navigation bar.
3. Choose **File Upload** or **Raw Text**:
   - **Upload File**: Drag & drop any CIC-IDS2017 CSV file (e.g. `sample_data/cic_ids2017_sample.csv`).
   - **Sample Demo**: Click **"LOAD BENCHMARK SAMPLE (CIC-IDS2017)"** for instant 1-click loading.
4. Click **"IMPORT & NORMALIZE DATASET"**.
5. Inspect:
   - Real-time import progress and statistics.
   - Attack categories & label distribution breakdown.
   - Malformed records table (if any invalid rows occurred).
   - Normalized event stream with raw payload inspector drawer.

#### Method 2: Via REST API (`curl`)

```bash
# 1. Import a CIC-IDS2017 CSV file:
curl -X POST "http://localhost:8000/api/v1/datasets/import/file" \
  -F "file=@sample_data/cic_ids2017_sample.csv" \
  -F "dataset_name=CIC-IDS2017 Friday Infiltration" \
  -F "format_hint=CSV_NETWORK_FLOW"

# 2. Load the bundled benchmark sample:
curl -X POST "http://localhost:8000/api/v1/datasets/sample/load"

# 3. List all imported datasets:
curl "http://localhost:8000/api/v1/datasets"

# 4. Query normalized events for a dataset with filtering:
curl "http://localhost:8000/api/v1/datasets/{dataset_id}/events?label=SSH-Patator&limit=25"
```

---

## 🔒 Threat Model & Zero-Trust Security Controls

| Security Boundary | Design Rule & Enforcement Mechanism |
| :--- | :--- |
| **No Shell Access** | The AI engine has zero shell, terminal, or code execution access. |
| **Read-Only Telemetry** | Tool Gateway exposes 11 read-only search tools. No write/delete operations exist. |
| **Strict Parameter Validation** | Inputs pass Pydantic schema validation. Malicious parameters trigger immediate rejection. |
| **Untrusted Data Labeling** | Telemetry logs are wrapped in `<UNTRUSTED_TELEMETRY_DATA>` XML boundaries before reasoning. |
| **Hard Autonomy Caps** | Max 5 iterations per hunt, max 10 tool calls, max 1000 records per call, 300s timeout. |
| **Evidence Grounding** | Claims citing non-existent evidence IDs are rejected as *"Insufficient evidence."* |
| **Dual Execution Modes** | `ASSISTED` (requires analyst approval per step) vs `AUTONOMOUS` (bounded loop). |

---

## 🚀 Quick Start & Local Setup

### Option 1: Docker Compose (Recommended)

1. Clone or navigate to the repository:
   ```bash
   cd threat-hunting-copilot
   ```

2. Launch all containerized services:
   ```bash
   docker-compose up --build -d
   ```

3. Access the SOC Analyst Interface:
   - **Frontend UI**: `http://localhost`
   - **FastAPI OpenAPI Docs**: `http://localhost:8000/docs`
   - **Health Endpoint**: `http://localhost:8000/api/v1/health`

### Option 2: Local Python & Node Development

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

---

## 🔬 Automated Pytest Verification Suite

To run the complete automated test suite (48 unit tests):

```bash
backend/venv/bin/pytest backend/tests -v
```

**Test Coverage Highlights**:
- `test_dataset_ingestion.py`: CSV normalization, JSON events, PCAP parsing, malformed error resilience, label preservation
- `test_autonomous_control.py`: Autonomy caps & approval gates
- `test_enrichment_graph.py`: Entity indicator graph builder
- `test_evaluation_lab.py`: Quantitative ground truth benchmark runner
- `test_adversarial_security.py`: Prompt injection detection & zero tool violations
- `test_production_security.py`: Rate limiting, secure HTTP headers, and CORS policies

---

## 📄 License & Contact

Developed as part of the **Autonomous Threat-Hunting Copilot Project**. Built for enterprise SOC operations and autonomous security research.
