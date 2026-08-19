import React, { useState, useEffect } from 'react';
import { Shield, Activity, Terminal, Database, FileText, Server, Lock, Download, Layers, UserCheck, Zap, Clock, Cpu } from 'lucide-react';

export default function Navigation({ activeTab, setActiveTab, activeHunt, healthData, onOpenReport, executionMode, setExecutionMode }) {
  const [utcTime, setUtcTime] = useState('');

  useEffect(() => {
    const timer = setInterval(() => {
      const now = new Date();
      setUtcTime(now.toISOString().split('T')[1].slice(0, 8) + ' UTC');
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const isHealthy = healthData?.status === 'HEALTHY';
  const huntId = activeHunt?.id ? `HUNT #${activeHunt.id.split('-').pop().toUpperCase()}` : 'HUNT #00042';
  const huntTitle = activeHunt?.question ? activeHunt.question.toUpperCase() : 'SSH COMPROMISE INVESTIGATION';
  const confidence = activeHunt?.confidence ? `${Math.round(activeHunt.confidence * 100)}%` : '78%';
  const status = activeHunt?.status || 'COMPLETED';

  const navItems = [
    { id: 'workspace', label: 'Hunt Workstation', icon: Terminal },
    { id: 'graph', label: 'Investigation Graph', icon: Layers },
    { id: 'security', label: 'Adversarial Security', icon: Lock },
    { id: 'explorer', label: 'Telemetry Explorer', icon: Database },
    { id: 'evidence', label: 'Evidence Store', icon: FileText },
    { id: 'findings', label: 'Findings & Reports', icon: Shield },
    { id: 'evaluation', label: 'Ground Truth Eval', icon: Activity },
    { id: 'health', label: 'Tool Gateway', icon: Server },
  ];

  return (
    <header style={{
      background: 'var(--bg-panel)',
      borderBottom: '1px solid var(--border-color)',
      position: 'sticky',
      top: 0,
      zIndex: 100,
      backdropFilter: 'blur(12px)'
    }}>
      {/* Top SOC Status & Telemetry Header */}
      <div style={{
        borderBottom: '1px solid var(--border-subtle)',
        padding: '10px 28px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: '#040406'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Shield size={20} color="var(--accent-blue)" />
            <span style={{ fontSize: '0.82rem', fontFamily: 'var(--font-mono)', fontWeight: 800, color: 'var(--accent-blue)', letterSpacing: '0.06em' }}>
              {huntId}
            </span>
          </div>
          <div style={{ height: '16px', width: '1px', background: 'var(--border-color)' }} />
          <h1 style={{ fontSize: '0.92rem', fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.01em' }}>
            {huntTitle}
          </h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className={`badge ${status === 'EXECUTING' || status === 'AWAITING_APPROVAL' ? 'badge-warning' : 'badge-success'}`}>
              STATUS: {status}
            </span>
            <span className="badge badge-info">
              CONFIDENCE: {confidence}
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          {/* UTC Clock & System Metric */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <Clock size={13} color="var(--accent-blue)" />
              <span style={{ color: 'var(--text-muted)' }}>{utcTime || '00:00:00 UTC'}</span>
            </div>
            <div style={{ height: '12px', width: '1px', background: 'var(--border-color)' }} />
            <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <Cpu size={13} color="var(--status-green)" />
              <span style={{ color: 'var(--text-muted)' }}>0.4ms GATEWAY</span>
            </div>
          </div>

          {/* Dual Mode Selector Toggle */}
          <div style={{ display: 'flex', background: 'var(--bg-subtle)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', padding: '2px' }}>
            <button
              onClick={() => setExecutionMode('AUTONOMOUS')}
              style={{
                background: executionMode === 'AUTONOMOUS' ? 'var(--accent-blue)' : 'transparent',
                color: executionMode === 'AUTONOMOUS' ? '#ffffff' : 'var(--text-dim)',
                padding: '5px 12px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.72rem',
                fontWeight: 800,
                display: 'flex',
                alignItems: 'center',
                gap: '5px',
                boxShadow: executionMode === 'AUTONOMOUS' ? '0 0 10px rgba(59,130,246,0.3)' : 'none'
              }}
            >
              <Zap size={12} />
              AUTONOMOUS MODE
            </button>
            <button
              onClick={() => setExecutionMode('ASSISTED')}
              style={{
                background: executionMode === 'ASSISTED' ? 'var(--status-amber)' : 'transparent',
                color: executionMode === 'ASSISTED' ? '#ffffff' : 'var(--text-dim)',
                padding: '5px 12px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.72rem',
                fontWeight: 800,
                display: 'flex',
                alignItems: 'center',
                gap: '5px',
                boxShadow: executionMode === 'ASSISTED' ? '0 0 10px rgba(245,158,11,0.3)' : 'none'
              }}
            >
              <UserCheck size={12} />
              ASSISTED MODE
            </button>
          </div>

          <button
            onClick={onOpenReport}
            style={{
              background: 'var(--accent-blue)',
              color: '#ffffff',
              padding: '6px 14px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.8rem',
              fontWeight: 800,
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              boxShadow: '0 0 12px var(--accent-blue-glow)'
            }}
          >
            <Download size={14} />
            EXPORT REPORT
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.75rem', fontWeight: 700, color: isHealthy ? 'var(--status-green)' : 'var(--status-red)' }}>
            <span className="pulse-dot" style={{ background: isHealthy ? 'var(--status-green)' : 'var(--status-red)' }} />
            {isHealthy ? 'GATEWAY ONLINE' : 'DISCONNECTED'}
          </div>
        </div>
      </div>

      {/* Main Navigation Tabs */}
      <div style={{
        maxWidth: '1800px',
        margin: '0 auto',
        padding: '0 28px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <nav style={{ display: 'flex', gap: '4px' }}>
          {navItems.map(item => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '14px 20px',
                  fontSize: '0.84rem',
                  fontWeight: isActive ? 800 : 600,
                  color: isActive ? '#f8fafc' : 'var(--text-dim)',
                  background: 'transparent',
                  borderBottom: isActive ? '3px solid var(--accent-blue)' : '3px solid transparent',
                  transition: 'all 0.15s ease'
                }}
              >
                <Icon size={16} color={isActive ? 'var(--accent-blue)' : 'var(--text-dim)'} />
                {item.label}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
