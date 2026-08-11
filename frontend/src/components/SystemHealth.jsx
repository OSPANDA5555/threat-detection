import React, { useState } from 'react';
import { Server, Lock, Shield, CheckCircle2, Terminal, Play, Cpu, AlertTriangle } from 'lucide-react';

export default function SystemHealth({ healthData }) {
  const [selectedTool, setSelectedTool] = useState('search_authentication_events');
  const [testArgs, setTestArgs] = useState('{"host": "srv-prod-linux01", "limit": 5}');
  const [execResult, setExecResult] = useState(null);
  const [isExecuting, setIsExecuting] = useState(false);

  const registeredTools = [
    { name: "search_authentication_events", desc: "Search authentication logs (SSH, Sudo, PAM)", read_only: true, max_cap: 500 },
    { name: "search_network_events", desc: "Query network connection logs & firewall traffic", read_only: true, max_cap: 500 },
    { name: "search_dns_events", desc: "Search DNS query & resolution logs", read_only: true, max_cap: 500 },
    { name: "search_process_events", desc: "Query process execution & command lines", read_only: true, max_cap: 500 },
    { name: "search_file_events", desc: "Search file system modification & hash events", read_only: true, max_cap: 500 },
    { name: "get_host_timeline", desc: "Retrieve unified event timeline for a host", read_only: true, max_cap: 500 },
    { name: "get_ip_activity", desc: "Summarize network/auth activity for an IP", read_only: true, max_cap: 500 },
    { name: "get_domain_activity", desc: "Fetch resolution count & query volume for a domain", read_only: true, max_cap: 500 },
    { name: "get_alerts", desc: "Query existing SIEM/EDR alert telemetry", read_only: true, max_cap: 500 }
  ];

  const handleTestExecution = async () => {
    setIsExecuting(true);
    try {
      const parsed = JSON.parse(testArgs);
      const res = await fetch('/api/v1/tools/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool_name: selectedTool, arguments: parsed })
      });
      const data = await res.json();
      setExecResult(data);
    } catch (err) {
      setExecResult({ status: 'ERROR', error_message: 'Invalid JSON arguments string' });
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Top Health Metrics */}
      <div className="glass-card" style={{ padding: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
            <Server size={22} color="var(--accent-emerald)" />
            <h2 style={{ fontSize: '1.2rem', fontWeight: 800 }}>TOOL GATEWAY & API HEALTH INSPECTOR</h2>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Inspect whitelisted read-only tools, test schema enforcement, and review system configuration.
          </p>
        </div>
        <span className="badge badge-success" style={{ padding: '8px 16px', fontSize: '0.85rem' }}>
          SYSTEM STATUS: HEALTHY
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        
        {/* Left Column: Registered Tool Catalog */}
        <div className="glass-card" style={{ padding: '20px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Lock size={18} color="var(--primary-cyan)" />
            APPROVED READ-ONLY TOOLS CATALOG ({registeredTools.length})
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '520px', overflowY: 'auto' }}>
            {registeredTools.map((tool, idx) => (
              <div key={idx} style={{
                background: 'rgba(2, 6, 23, 0.6)',
                border: selectedTool === tool.name ? '1px solid var(--primary-cyan)' : '1px solid var(--border-color)',
                borderRadius: '8px',
                padding: '12px 16px',
                cursor: 'pointer'
              }} onClick={() => {
                setSelectedTool(tool.name);
                setExecResult(null);
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--primary-cyan)', fontSize: '0.9rem' }}>
                    {tool.name}
                  </span>
                  <span className="badge badge-success">READ-ONLY</span>
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{tool.desc}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: Live Tool Gateway Tester */}
        <div className="glass-card" style={{ padding: '20px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Terminal size={18} color="var(--accent-purple)" />
            INTERACTIVE TOOL GATEWAY TESTER
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div>
              <label style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-muted)', display: 'block', marginBottom: '6px' }}>
                SELECTED WHITELISTED TOOL:
              </label>
              <select
                value={selectedTool}
                onChange={(e) => setSelectedTool(e.target.value)}
                style={{
                  width: '100%',
                  background: 'rgba(2, 6, 23, 0.8)',
                  border: '1px solid var(--border-color)',
                  color: 'var(--text-main)',
                  padding: '10px',
                  borderRadius: '6px',
                  fontSize: '0.9rem',
                  fontFamily: 'var(--font-mono)'
                }}
              >
                {registeredTools.map(t => (
                  <option key={t.name} value={t.name}>{t.name}</option>
                ))}
              </select>
            </div>

            <div>
              <label style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-muted)', display: 'block', marginBottom: '6px' }}>
                ARGUMENTS (JSON SCHEMA ENFORCED):
              </label>
              <textarea
                rows={4}
                value={testArgs}
                onChange={(e) => setTestArgs(e.target.value)}
                style={{
                  width: '100%',
                  background: 'rgba(2, 6, 23, 0.85)',
                  border: '1px solid var(--border-color)',
                  color: '#a5f3fc',
                  padding: '12px',
                  borderRadius: '6px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.85rem'
                }}
              />
            </div>

            <button
              onClick={handleTestExecution}
              disabled={isExecuting}
              style={{
                padding: '10px 20px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, var(--accent-purple), var(--primary-blue))',
                color: '#fff',
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px'
              }}
            >
              <Play size={16} />
              {isExecuting ? 'GATEWAY VALIDATING...' : 'EXECUTE TOOL VIA GATEWAY'}
            </button>

            {execResult && (
              <div style={{ marginTop: '10px' }}>
                <div style={{ fontSize: '0.8rem', fontWeight: 700, marginBottom: '4px', color: execResult.status === 'SUCCESS' ? 'var(--accent-emerald)' : 'var(--accent-crimson)' }}>
                  EXECUTION RESULT: {execResult.status}
                </div>
                <div className="code-block" style={{ maxHeight: '200px', overflowY: 'auto' }}>
                  {JSON.stringify(execResult, null, 2)}
                </div>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
