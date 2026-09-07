import React from 'react';
import { Shield, Activity, Lock, Terminal, Database, Server, CheckCircle2, AlertTriangle, ArrowRight } from 'lucide-react';

export default function SOCDashboard({ onStartHunt, healthData }) {
  const isHealthy = healthData?.status === 'HEALTHY';
  const registeredTools = healthData?.tool_gateway?.registered_tools_count || 11;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner */}
      <div className="glass-card" style={{
        padding: '28px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: '16px',
        flexWrap: 'wrap'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
            <span className="badge badge-info">SOC operations console</span>
            <span className="badge badge-success">Zero-trust AI gateway</span>
          </div>
          <h2 className="page-title" style={{ fontSize: '1.5rem' }}>
            Autonomous threat-hunting engine
          </h2>
          <p className="page-subtitle" style={{ maxWidth: '750px' }}>
            Turn natural-language investigation queries into structured, hypothesis-driven threat hunts with enforced safety constraints and evidence traceability.
          </p>
        </div>
        <button
          onClick={onStartHunt}
          className="btn btn-primary"
          style={{ padding: '12px 22px', fontSize: '0.9rem' }}
        >
          <Terminal size={18} />
          Open hunt workspace
          <ArrowRight size={18} />
        </button>
      </div>

      {/* Metrics Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '18px' }}>
        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: '12px' }}>
            <span className="section-label">Tool gateway registry</span>
            <Lock size={18} color="var(--accent-blue)" />
          </div>
          <div className="metric-value" style={{ fontSize: '2rem', fontWeight: 700, color: '#f8fafc', marginBottom: '4px' }}>
            {registeredTools} <span style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-muted)' }}>read-only tools</span>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--status-green)' }}>
            Whitelisted and schema-enforced
          </p>
        </div>

        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: '12px' }}>
            <span className="section-label">Safety enforcement</span>
            <Shield size={18} color="var(--accent-blue)" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: '#f8fafc', marginBottom: '4px' }}>
            Zero <span style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-muted)' }}>shell exec</span>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Arbitrary command execution blocked
          </p>
        </div>

        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: '12px' }}>
            <span className="section-label">Max query result cap</span>
            <Database size={18} color="var(--accent-blue)" />
          </div>
          <div className="metric-value" style={{ fontSize: '2rem', fontWeight: 700, color: '#f8fafc', marginBottom: '4px' }}>
            500 <span style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-muted)' }}>records</span>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Enforced query protection
          </p>
        </div>

        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: '12px' }}>
            <span className="section-label">Backend health</span>
            <Server size={18} color={isHealthy ? 'var(--status-green)' : 'var(--status-red)'} />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: isHealthy ? 'var(--status-green)' : 'var(--status-red)', marginBottom: '4px' }}>
            {isHealthy ? 'Online' : 'Offline'}
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            FastAPI + Pydantic v2 engine
          </p>
        </div>
      </div>

      {/* Architecture Highlights */}
      <div className="glass-card" style={{ padding: '24px' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Activity size={18} color="var(--accent-blue)" />
          How an investigation runs
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
          <div style={{ background: 'rgba(2, 6, 23, 0.6)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontWeight: 700, color: '#f8fafc', marginBottom: '6px' }}>1. Question to hypothesis</div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Analyst enters natural language query. AI formulates a testable threat hunting hypothesis.
            </p>
          </div>
          <div style={{ background: 'rgba(2, 6, 23, 0.6)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontWeight: 700, color: '#f8fafc', marginBottom: '6px' }}>2. Controlled tool gateway</div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              AI requests execution of registered read-only tools. Tool Gateway enforces schema validation, rate caps, timeouts, and audit logging.
            </p>
          </div>
          <div style={{ background: 'rgba(2, 6, 23, 0.6)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontWeight: 700, color: '#f8fafc', marginBottom: '6px' }}>3. Evidence-backed findings</div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Collected telemetry is normalized into Evidence records. Findings must explicitly link to verified evidence IDs.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
