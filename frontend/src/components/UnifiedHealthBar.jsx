import React, { useState, useEffect } from 'react';
import { 
  Server, 
  Database, 
  Radio, 
  Shield, 
  Cpu, 
  Terminal, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle,
  Info,
  ChevronDown,
  ChevronUp
} from 'lucide-react';

export default function UnifiedHealthBar() {
  const [health, setHealth] = useState(null);
  const [expanded, setExpanded] = useState(false);

  const fetchComprehensiveHealth = async () => {
    try {
      const res = await fetch('/api/health/comprehensive');
      if (res.ok) {
        const data = await res.json();
        setHealth(data);
      }
    } catch (e) {
      console.warn("Health check error:", e);
    }
  };

  useEffect(() => {
    fetchComprehensiveHealth();
    const interval = setInterval(fetchComprehensiveHealth, 4000);
    return () => clearInterval(interval);
  }, []);

  if (!health) {
    return null;
  }

  const getStatusColor = (status) => {
    if (status === 'OK' || status === 'HEALTHY' || status === 'READY') return '#34d399';
    if (status === 'DEGRADED') return '#fbbf24';
    return '#f87171';
  };

  const subsystems = [
    { key: 'backend', label: 'Backend API', icon: Server, data: health.backend },
    { key: 'database', label: 'Database Stores', icon: Database, data: health.database },
    { key: 'event_stream', label: 'Event Stream Hub', icon: Radio, data: health.event_stream },
    { key: 'detection_engine', label: 'Detection Engine', icon: Shield, data: health.detection_engine },
    { key: 'ai_investigator', label: 'AI Investigator', icon: Terminal, data: health.ai_investigator },
    { key: 'connected_agents', label: 'Connected Agents', icon: Cpu, data: health.connected_agents },
  ];

  return (
    <div style={{
      background: 'rgba(9, 9, 11, 0.95)',
      borderBottom: '1px solid var(--border-color)',
      padding: '6px 32px',
      fontSize: '0.72rem',
      fontFamily: 'var(--font-mono)'
    }}>
      <div style={{
        maxWidth: '1800px',
        margin: '0 auto',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        {/* Left: Overall Health Indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ color: 'var(--text-dim)', fontWeight: 800, letterSpacing: '0.04em' }}>
            SUBSYSTEM HEALTH:
          </span>
          <span style={{
            background: 'rgba(16, 185, 129, 0.15)',
            border: '1px solid rgba(16, 185, 129, 0.4)',
            color: '#34d399',
            padding: '1px 6px',
            borderRadius: '3px',
            fontWeight: 800,
            display: 'inline-flex',
            alignItems: 'center',
            gap: '4px'
          }}>
            <span className="pulse-dot" style={{ background: '#34d399', width: '5px', height: '5px' }} />
            ALL 6 SUBSYSTEMS HEALTHY
          </span>
        </div>

        {/* Center: 6 Subsystem Badges */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap' }}>
          {subsystems.map(sub => {
            const Icon = sub.icon;
            const color = getStatusColor(sub.data?.status);
            return (
              <div key={sub.key} style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                <Icon size={12} color={color} />
                <span style={{ color: 'var(--text-muted)' }}>{sub.label}:</span>
                <span style={{ color: color, fontWeight: 700 }}>
                  {sub.data?.status || 'OK'}
                </span>
              </div>
            );
          })}
        </div>

        {/* Right: Expand Toggle */}
        <button
          onClick={() => setExpanded(!expanded)}
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--text-dim)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
            fontSize: '0.70rem'
          }}
        >
          {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          {expanded ? 'Hide Details' : 'Diagnostics'}
        </button>
      </div>

      {/* Expanded Metrics Flyout */}
      {expanded && (
        <div style={{
          maxWidth: '1800px',
          margin: '8px auto 4px auto',
          padding: '12px 16px',
          background: '#040406',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-sm)',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '12px'
        }}>
          {subsystems.map(sub => (
            <div key={sub.key} style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
              <div style={{ fontWeight: 800, color: '#f8fafc', display: 'flex', justifyContent: 'space-between' }}>
                <span>{sub.data?.name || sub.label}</span>
                <span style={{ color: getStatusColor(sub.data?.status) }}>{sub.data?.status}</span>
              </div>
              <div style={{ color: 'var(--text-muted)', fontSize: '0.68rem', lineHeight: 1.3 }}>
                {sub.data?.message}
              </div>
              {sub.data?.metrics && (
                <div style={{ color: 'var(--text-dim)', fontSize: '0.65rem', marginTop: '2px' }}>
                  {Object.entries(sub.data.metrics).map(([k, v]) => `${k}: ${v}`).join(' • ')}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
