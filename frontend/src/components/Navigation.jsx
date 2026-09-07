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
  const huntTitle = activeHunt?.question ? activeHunt.question : 'Find evidence of suspicious SSH activity on web-server-01.';
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
      backdropFilter: 'blur(16px)'
    }}>
      {/* Spacious SOC Operational Header */}
      <div style={{
        borderBottom: '1px solid var(--border-subtle)',
        padding: '14px 32px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: '#040406'
      }}>
        {/* Left: Brand Identity & Active Hunt Tag */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              background: 'var(--accent-blue-subtle)',
              border: '1px solid rgba(59, 130, 246, 0.4)',
              padding: '6px 10px',
              borderRadius: 'var(--radius-sm)',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}>
              <Shield size={18} color="var(--accent-blue)" />
              <span style={{ fontSize: '0.82rem', fontFamily: 'var(--font-mono)', fontWeight: 800, color: '#f8fafc', letterSpacing: '0.04em' }}>
                THREAT COPILOT
              </span>
            </div>
            <span className="badge badge-info" style={{ fontFamily: 'var(--font-mono)' }}>
              {huntId}
            </span>
          </div>

          <div style={{ height: '18px', width: '1px', background: 'var(--border-color)' }} />

          {/* Active Query Title */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '0.88rem', fontWeight: 700, color: '#e2e8f0', maxWidth: '380px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {huntTitle}
            </span>
            <span className={`badge ${status === 'EXECUTING' || status === 'AWAITING_APPROVAL' ? 'badge-warning' : 'badge-success'}`}>
              {status}
            </span>
          </div>
        </div>

        {/* Right: Mode Selector & Gateway Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '18px' }}>
          
          {/* UTC Clock & System Latency */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <Clock size={13} color="var(--accent-blue)" />
              <span style={{ color: 'var(--text-muted)' }}>{utcTime || '00:00:00 UTC'}</span>
            </div>
            <div style={{ height: '12px', width: '1px', background: 'var(--border-color)' }} />
            <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <Cpu size={13} color="var(--status-green)" />
              <span style={{ color: 'var(--text-muted)' }}>0.4ms</span>
            </div>
          </div>

          {/* Dual Mode Toggle */}
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
                gap: '5px'
              }}
            >
              <Zap size={12} />
              AUTONOMOUS
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
                gap: '5px'
              }}
            >
              <UserCheck size={12} />
              ASSISTED
            </button>
          </div>

          <button
            onClick={onOpenReport}
            style={{
              background: 'var(--accent-blue)',
              color: '#ffffff',
              padding: '6px 14px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.78rem',
              fontWeight: 800,
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <Download size={13} />
            EXPORT REPORT
          </button>

          {/* Gateway Status Badge */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '0.74rem',
            fontWeight: 700,
            color: isHealthy ? 'var(--status-green)' : 'var(--status-red)',
            background: isHealthy ? 'var(--status-green-subtle)' : 'var(--status-red-subtle)',
            border: isHealthy ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(239, 68, 68, 0.3)',
            padding: '4px 10px',
            borderRadius: 'var(--radius-sm)'
          }}>
            <span className="pulse-dot" style={{ background: isHealthy ? 'var(--status-green)' : 'var(--status-red)', width: '6px', height: '6px' }} />
            {isHealthy ? 'GATEWAY ONLINE' : 'OFFLINE'}
          </div>

        </div>
      </div>

      {/* Main Navigation Bar */}
      <div style={{
        maxWidth: '1800px',
        margin: '0 auto',
        padding: '0 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <nav style={{ display: 'flex', gap: '6px' }}>
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
                  padding: '12px 16px',
                  fontSize: '0.82rem',
                  fontWeight: isActive ? 800 : 600,
                  color: isActive ? '#f8fafc' : 'var(--text-dim)',
                  background: isActive ? 'rgba(59, 130, 246, 0.08)' : 'transparent',
                  borderBottom: isActive ? '3px solid var(--accent-blue)' : '3px solid transparent',
                  borderRadius: 'var(--radius-sm) var(--radius-sm) 0 0',
                  transition: 'all 0.15s ease'
                }}
              >
                <Icon size={15} color={isActive ? 'var(--accent-blue)' : 'var(--text-dim)'} />
                {item.label}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
