import React, { useState, useEffect } from 'react';
import { 
  Server, 
  Activity, 
  Shield, 
  Radio, 
  RefreshCw, 
  Terminal, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  HardDrive, 
  Cpu, 
  Download, 
  Copy, 
  Check, 
  ExternalLink,
  Zap,
  Play
} from 'lucide-react';

export default function LiveAgentsDashboard() {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [isDeployModalOpen, setIsDeployModalOpen] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [simFeedback, setSimFeedback] = useState(null);

  const fetchAgents = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/agents');
      if (res.ok) {
        const data = await res.json();
        setAgents(data);
      }
    } catch (e) {
      console.warn("Failed to fetch registered agents:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAgents();
    const interval = setInterval(fetchAgents, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleCopyInstallCmd = () => {
    const cmd = "curl -fsSL https://raw.githubusercontent.com/OSPANDA5555/threat-detection/main/agent/linux_collector.py | python3 - --backend-url http://localhost:8000/api/events";
    navigator.clipboard.writeText(cmd);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const handleSimulateAgentTelemetry = async () => {
    try {
      setSimulating(true);
      setSimFeedback(null);
      const testPayload = {
        agent_id: "agent-demo-linux-01",
        hostname: "ubuntu-server-prod",
        agent_version: "1.0.0",
        timestamp: new Date().toISOString(),
        sequence_number: Math.floor(Math.random() * 1000) + 1,
        events: [
          {
            source_type: "linux_auth",
            source: "auth.log",
            hostname: "ubuntu-server-prod",
            source_ip: "192.168.1.105",
            source_port: 48210,
            destination_port: 22,
            username: "root",
            process_name: "sshd",
            event_type: "ssh_authentication",
            action: "failed_password",
            status: "FAILURE",
            severity: "HIGH",
            timestamp: new Date().toISOString()
          },
          {
            source_type: "linux_auth",
            source: "auth.log",
            hostname: "ubuntu-server-prod",
            username: "admin",
            process_name: "sudo",
            command: "sudo bash",
            event_type: "process_create",
            action: "sudo_execution",
            status: "SUCCESS",
            severity: "HIGH",
            timestamp: new Date().toISOString()
          }
        ]
      };

      const res = await fetch('/api/events', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(testPayload)
      });

      if (res.ok) {
        setSimFeedback("Telemetry batch received! Live agent registered and events dispatched.");
        await fetchAgents();
      }
    } catch (e) {
      setSimFeedback("Error simulating agent telemetry.");
    } finally {
      setSimulating(false);
    }
  };

  const onlineCount = agents.filter(a => a.status === 'ONLINE').length;
  const offlineCount = agents.filter(a => a.status === 'OFFLINE').length;
  const totalEvents = agents.reduce((sum, a) => sum + (a.total_events_sent || 0), 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Banner */}
      <div className="glass-card" style={{
        padding: '24px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: '16px',
        flexWrap: 'wrap'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
            <span className="badge badge-info">Linux Telemetry Collector</span>
            <span className="badge badge-success">Zero Remote Execution</span>
            <span className="badge badge-warning">Standard Syslog & Auditd</span>
          </div>
          <h2 className="page-title" style={{ fontSize: '1.4rem' }}>
            Live Monitored Linux Agents
          </h2>
          <p className="page-subtitle" style={{ maxWidth: '780px', fontSize: '0.85rem' }}>
            Lightweight Python standard-library agents streaming real-time authentication, sudo executions, audit logs, and network telemetry into the Threat Hunting Copilot.
          </p>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={handleSimulateAgentTelemetry}
            disabled={simulating}
            className="btn btn-secondary"
            style={{ padding: '8px 14px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <Play size={14} color="#38bdf8" />
            {simulating ? "Sending..." : "Simulate Agent Batch"}
          </button>
          <button
            onClick={() => setIsDeployModalOpen(true)}
            className="btn btn-primary"
            style={{ padding: '8px 16px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <Download size={14} />
            Deploy Agent
          </button>
          <button
            onClick={fetchAgents}
            className="btn btn-secondary"
            style={{ padding: '8px 12px', fontSize: '0.8rem' }}
          >
            <RefreshCw size={14} className={loading ? "spin-icon" : ""} />
          </button>
        </div>
      </div>

      {simFeedback && (
        <div style={{
          padding: '10px 16px',
          background: 'rgba(16, 185, 129, 0.15)',
          border: '1px solid rgba(16, 185, 129, 0.4)',
          color: '#34d399',
          borderRadius: 'var(--radius-sm)',
          fontSize: '0.8rem',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <CheckCircle2 size={16} />
          {simFeedback}
        </div>
      )}

      {/* Metrics Strip */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '16px'
      }}>
        <div className="soc-card" style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)' }}>CONNECTED AGENTS</span>
            <Server size={16} color="var(--accent-blue)" />
          </div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#f8fafc' }}>
            {agents.length}
          </div>
          <div style={{ fontSize: '0.70rem', color: 'var(--text-dim)' }}>
            <span style={{ color: '#34d399', fontWeight: 700 }}>{onlineCount} Online</span> • <span style={{ color: '#f87171' }}>{offlineCount} Offline</span>
          </div>
        </div>

        <div className="soc-card" style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)' }}>INGESTED TELEMETRY</span>
            <Activity size={16} color="var(--status-green)" />
          </div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#34d399' }}>
            {totalEvents.toLocaleString()}
          </div>
          <div style={{ fontSize: '0.70rem', color: 'var(--text-dim)' }}>
            Real-time security events received
          </div>
        </div>

        <div className="soc-card" style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)' }}>INGESTION ENDPOINT</span>
            <Zap size={16} color="#fbbf24" />
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            POST /api/events
          </div>
          <div style={{ fontSize: '0.70rem', color: 'var(--text-dim)' }}>
            HTTPS Batched with Sequence Tracking
          </div>
        </div>

        <div className="soc-card" style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)' }}>COLLECTOR AGENT</span>
            <Shield size={16} color="#a78bfa" />
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc' }}>
            v1.0.0 (Standard Lib)
          </div>
          <div style={{ fontSize: '0.70rem', color: 'var(--text-dim)' }}>
            Zero third-party pip dependencies
          </div>
        </div>
      </div>

      {/* Agents Table */}
      <div className="soc-card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div style={{ fontSize: '0.85rem', fontWeight: 800, color: 'var(--text-main)', letterSpacing: '0.04em' }}>
            REGISTERED LINUX HOSTS ({agents.length})
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Auto-refreshed every 3s</span>
        </div>

        {agents.length === 0 ? (
          <div style={{ padding: '40px 20px', textAlign: 'center' }}>
            <Server size={36} color="var(--text-dim)" style={{ margin: '0 auto 12px auto' }} />
            <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-muted)' }}>
              No Linux agents connected yet
            </div>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-dim)', maxWidth: '450px', margin: '8px auto 16px auto' }}>
              Install the lightweight collector on your Linux machine or click "Simulate Agent Batch" above to test real telemetry ingestion.
            </p>
            <button
              onClick={() => setIsDeployModalOpen(true)}
              className="btn btn-primary"
              style={{ fontSize: '0.8rem', padding: '8px 18px' }}
            >
              View Installation Guide
            </button>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.80rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  <th style={{ padding: '10px 12px' }}>STATUS</th>
                  <th style={{ padding: '10px 12px' }}>AGENT ID</th>
                  <th style={{ padding: '10px 12px' }}>HOSTNAME</th>
                  <th style={{ padding: '10px 12px' }}>PLATFORM / OS</th>
                  <th style={{ padding: '10px 12px' }}>IP ADDRESS</th>
                  <th style={{ padding: '10px 12px' }}>LAST SEEN</th>
                  <th style={{ padding: '10px 12px' }}>THROUGHPUT</th>
                  <th style={{ padding: '10px 12px' }}>TOTAL EVENTS</th>
                  <th style={{ padding: '10px 12px' }}>VERSION</th>
                </tr>
              </thead>
              <tbody>
                {agents.map(ag => {
                  const isOnline = ag.status === 'ONLINE';
                  return (
                    <tr key={ag.agent_id} style={{ borderBottom: '1px solid var(--border-subtle)', background: 'transparent' }}>
                      <td style={{ padding: '12px' }}>
                        <span style={{
                          background: isOnline ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                          border: `1px solid ${isOnline ? 'rgba(16, 185, 129, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`,
                          color: isOnline ? '#34d399' : '#f87171',
                          fontSize: '0.70rem',
                          fontWeight: 700,
                          padding: '3px 8px',
                          borderRadius: '4px',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '5px'
                        }}>
                          <span className="pulse-dot" style={{ background: isOnline ? '#34d399' : '#f87171', width: '6px', height: '6px' }} />
                          {ag.status}
                        </span>
                      </td>
                      <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#f8fafc' }}>
                        {ag.agent_id}
                      </td>
                      <td style={{ padding: '12px', color: '#93c5fd', fontWeight: 600 }}>
                        {ag.hostname}
                      </td>
                      <td style={{ padding: '12px', color: 'var(--text-muted)' }}>
                        {ag.platform}
                      </td>
                      <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                        {ag.ip_address || '127.0.0.1'}
                      </td>
                      <td style={{ padding: '12px', color: 'var(--text-muted)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                        {ag.last_seen}
                      </td>
                      <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', color: '#38bdf8' }}>
                        {ag.events_per_sec} EPS
                      </td>
                      <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#34d399' }}>
                        {ag.total_events_sent.toLocaleString()}
                      </td>
                      <td style={{ padding: '12px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                        v{ag.agent_version}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Deployment Modal */}
      {isDeployModalOpen && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          backdropFilter: 'blur(8px)',
          padding: '20px'
        }}>
          <div className="soc-card" style={{
            maxWidth: '680px',
            width: '100%',
            padding: '28px',
            background: 'var(--bg-panel)',
            border: '1px solid var(--border-color)',
            maxHeight: '90vh',
            overflowY: 'auto'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Terminal size={20} color="var(--accent-blue)" />
                <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#f8fafc' }}>
                  Deploy Linux Collector Agent
                </h3>
              </div>
              <button
                onClick={() => setIsDeployModalOpen(false)}
                className="btn btn-secondary"
                style={{ padding: '4px 10px', fontSize: '0.75rem' }}
              >
                ✕ Close
              </button>
            </div>

            <p style={{ fontSize: '0.80rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
              Run this standard-library agent on authorized Debian, Ubuntu, RHEL, or CentOS VMs. The agent tails logs, strips credentials, and streams telemetry via HTTPS to this backend.
            </p>

            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '6px' }}>
                1. Single-Line Test Execution
              </div>
              <div style={{
                background: '#040406',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                padding: '12px 14px',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.75rem',
                color: '#38bdf8',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                gap: '10px'
              }}>
                <span style={{ wordBreak: 'break-all' }}>
                  python3 agent/linux_collector.py --backend-url http://localhost:8000/api/events --once
                </span>
                <button
                  onClick={handleCopyInstallCmd}
                  style={{
                    background: 'var(--bg-subtle)',
                    border: '1px solid var(--border-color)',
                    color: '#f8fafc',
                    padding: '4px 8px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    fontSize: '0.70rem'
                  }}
                >
                  {copiedCode ? <Check size={12} color="#34d399" /> : <Copy size={12} />}
                  {copiedCode ? "Copied" : "Copy"}
                </button>
              </div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '6px' }}>
                2. Continuous Background Daemon
              </div>
              <pre style={{
                background: '#040406',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                padding: '12px',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.72rem',
                color: '#e2e8f0',
                overflowX: 'auto',
                margin: 0
              }}>
{`python3 agent/linux_collector.py \\
  --backend-url http://localhost:8000/api/events \\
  --agent-id agent-$(hostname) \\
  --interval 1.5`}
              </pre>
            </div>

            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
              Full systemd service setup guide is available in <code style={{ color: '#93c5fd' }}>docs/AGENT_INSTALL.md</code>.
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
