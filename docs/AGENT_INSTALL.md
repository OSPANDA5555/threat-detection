# Linux Telemetry Collector Agent — Installation & Operational Guide

This guide provides instructions for safely deploying the lightweight Linux security telemetry collector agent on authorized test VMs and production workloads.

---

## 1. Security & Zero-Trust Architecture

- **Read-Only Telemetry**: The agent only reads telemetry from standard Linux system logs (`/var/log/auth.log`, `/var/log/secure`, `/var/log/audit/audit.log`, `/proc/net/tcp`).
- **Zero Inbound Ports / Zero Remote Execution**: The agent never opens inbound TCP ports and does not execute remote commands from the SOC backend.
- **Client-Side Credential Redaction**: Passwords, private keys (`BEGIN RSA PRIVATE KEY`), SSH secrets, and PAM hashes are scrubbed automatically before leaving the machine.
- **Persistent Offset Checkpoint**: Byte-level offsets are persisted to `~/.threat_hunter_agent.offset` to prevent resending duplicate logs across agent restarts.
- **Zero Third-Party Dependencies**: Runs on standard Python 3.6+ standard library with no external pip packages required.

---

## 2. Prerequisites

1. **Python 3.6+** installed on the monitored Linux machine:
   ```bash
   python3 --version
   ```
2. **Log Read Permissions**:
   The agent requires read access to authentication logs. On Debian/Ubuntu:
   ```bash
   sudo usermod -aG adm <agent_user>
   ```
   Or on RHEL/CentOS/Rocky:
   ```bash
   sudo usermod -aG wheel <agent_user>
   ```

---

## 3. Quick Test (Single-Run Verification)

To test event ingestion from your Linux VM to the Threat Copilot backend:

```bash
python3 agent/linux_collector.py \
  --backend-url http://<YOUR_SOC_SERVER_IP>:8000/api/events \
  --agent-id agent-test-vm-01 \
  --once
```

Expected output:
```text
2026-09-07 11:00:00 [INFO] [Agent] Shipped batch seq=1 (12 events) to http://<YOUR_SOC_SERVER_IP>:8000/api/events
2026-09-07 11:00:00 [INFO] [Agent] Single run completed: 12 events processed.
```

---

## 4. Production Systemd Service Setup

To run the agent as a background daemon managed by `systemd`:

1. **Copy Agent Script**:
   ```bash
   sudo mkdir -p /opt/threat-hunter-agent /var/lib/threat-hunter-agent
   sudo cp agent/linux_collector.py /opt/threat-hunter-agent/
   sudo chmod 750 /opt/threat-hunter-agent/linux_collector.py
   ```

2. **Create Service User**:
   ```bash
   sudo useradd -r -s /bin/false -d /var/lib/threat-hunter-agent threat-agent
   sudo usermod -aG adm threat-agent
   sudo chown -R threat-agent:threat-agent /var/lib/threat-hunter-agent
   ```

3. **Install Systemd Unit**:
   Create `/etc/systemd/system/threat-hunter-agent.service`:

   ```ini
   [Unit]
   Description=Threat Hunter Lightweight Linux Telemetry Collector
   After=network.target syslog.target

   [Service]
   Type=simple
   User=threat-agent
   Group=threat-agent
   WorkingDirectory=/var/lib/threat-hunter-agent
   ExecStart=/usr/bin/python3 /opt/threat-hunter-agent/linux_collector.py \
       --backend-url https://soc.internal.corp/api/events \
       --checkpoint-file /var/lib/threat-hunter-agent/offsets.json \
       --interval 1.5
   Restart=always
   RestartSec=5s
   ProtectSystem=full
   ProtectHome=true
   NoNewPrivileges=true

   [Install]
   WantedBy=multi-user.target
   ```

4. **Enable and Start Service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now threat-hunter-agent.service
   sudo systemctl status threat-hunter-agent.service
   ```

---

## 5. Verification Checklist

1. Open the **Threat Copilot Web UI** at `http://<SOC_HOST>:3000`.
2. Navigate to the **LIVE AGENTS** tab.
3. Verify that your host appears with:
   - Status: **`ONLINE`**
   - Platform: `Linux ...`
   - Real-time **Events/sec** throughput.
4. Simulate an SSH event on the monitored VM:
   ```bash
   ssh invaliduser@localhost
   ```
5. Check the **Live Incident Center** and **SOC Dashboard** to confirm the authentication failure is ingested and correlated into an active incident.
