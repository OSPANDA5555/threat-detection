import React from 'react';
import { Shield, Activity, Lock, Terminal, Database, Server, CheckCircle2, AlertTriangle, ArrowRight } from 'lucide-react';

export default function SOCDashboard({ onStartHunt, healthData }) {
  const isHealthy = healthData?.status === 'HEALTHY';
  const registeredTools = healthData?.tool_gateway?.registered_tools_count || 9;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner */}
      <div className="glass-card" style={{
        padding: '28px',
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(7, 10, 18, 0.95))',
        border: '1px solid var(--border-glow)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
            <span className="badge badge-info">SOC OPERATIONS CONSOLE</span>
            <span className="badge badge-success">ZERO-TRUST AI GATEWAY</span>
          </div>
          <h2 style={{ fontSize: '1.75rem', fontWeight: 800, marginBottom: '8px' }}>
            Autonomous Threat-Hunting Engine
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.95rem', maxWidth: '750px', lineHeight: 1.6 }}>
            Empowers SOC analysts to transform natural language investigation queries into structured, hypothesis-driven threat hunts with guaranteed safety constraints and evidence traceability.
          </p>
        </div>
        <button
          onClick={onStartHunt}
          style={{
            padding: '14px 24px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, var(--primary-cyan), var(--primary-blue))',
            color: '#070a12',
            fontWeight: 800,
            fontSize: '0.95rem',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            boxShadow: '0 0 20px rgba(0, 242, 254, 0.3)'
          }}
        >
          <Terminal size={18} />
          LAUNCH HUNT WORKSPACE
          <ArrowRight size={18} />
        </button>
      </div>

      {/* Metrics Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '18px' }}>
        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>TOOL GATEWAY REGISTRY</span>
            <Lock size={18} color="var(--primary-cyan)" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--primary-cyan)', marginBottom: '4px' }}>
            {registeredTools} Read-Only Tools
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--accent-emerald)' }}>
            ✓ 100% Whitelisted & Schema Enforced
          </p>
        </div>

        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>SAFETY ENFORCEMENT</span>
            <Shield size={18} color="var(--accent-purple)" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--accent-purple)', marginBottom: '4px' }}>
            ZERO Shell Exec
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Arbitrary command execution blocked
          </p>
        </div>

        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>MAX QUERY RESULT CAP</span>
            <Database size={18} color="var(--accent-amber)" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--accent-amber)', marginBottom: '4px' }}>
            500 Records
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Enforced DoS query protection
          </p>
        </div>

        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>BACKEND HEALTH</span>
            <Server size={18} color={isHealthy ? 'var(--accent-emerald)' : 'var(--accent-crimson)'} />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: isHealthy ? 'var(--accent-emerald)' : 'var(--accent-crimson)', marginBottom: '4px' }}>
            {isHealthy ? '100% ONLINE' : 'OFFLINE'}
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            FastAPI + Pydantic v2 Engine
          </p>
        </div>
      </div>

      {/* Architecture Highlights */}
      <div className="glass-card" style={{ padding: '24px' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Activity size={18} color="var(--primary-cyan)" />
          Phase 1 Architecture Controls & Pipeline Guarantee
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
          <div style={{ background: 'rgba(2, 6, 23, 0.6)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontWeight: 700, color: 'var(--primary-cyan)', marginBottom: '6px' }}>1. Question to Hypothesis</div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Analyst enters natural language query. AI formulates a testable threat hunting hypothesis.
            </p>
          </div>
          <div style={{ background: 'rgba(2, 6, 23, 0.6)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontWeight: 700, color: 'var(--accent-purple)', marginBottom: '6px' }}>2. Controlled Tool Gateway</div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              AI requests execution of registered read-only tools. Tool Gateway enforces schema validation, rate caps, timeouts, and audit logging.
            </p>
          </div>
          <div style={{ background: 'rgba(2, 6, 23, 0.6)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontWeight: 700, color: 'var(--accent-emerald)', marginBottom: '6px' }}>3. Evidence-Backed Findings</div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Collected telemetry is normalized into Evidence records. Findings must explicitly link to verified evidence IDs.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
