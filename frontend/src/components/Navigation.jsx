import React from 'react';
import { Shield, Activity, Terminal, Database, FileText, Server, Lock, Download, Layers, UserCheck, Zap } from 'lucide-react';

export default function Navigation({ activeTab, setActiveTab, activeHunt, healthData, onOpenReport, executionMode, setExecutionMode }) {
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
      background: '#09090b',
      borderBottom: '1px solid #27272a',
      position: 'sticky',
      top: 0,
      zIndex: 100
    }}>
      {/* Top Hunt Status Bar */}
      <div style={{
        borderBottom: '1px solid #18181b',
        padding: '10px 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: '#0d0d10'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Shield size={18} color="#2563eb" />
            <span style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#2563eb', letterSpacing: '0.05em' }}>
              {huntId}
            </span>
          </div>
          <div style={{ height: '14px', width: '1px', background: '#27272a' }} />
          <h1 style={{ fontSize: '0.9rem', fontWeight: 800, color: '#fafafa', letterSpacing: '-0.01em' }}>
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

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          
          {/* Dual Mode Selector Toggle */}
          <div style={{ display: 'flex', background: '#18181b', border: '1px solid #27272a', borderRadius: '4px', padding: '2px' }}>
            <button
              onClick={() => setExecutionMode('AUTONOMOUS')}
              style={{
                background: executionMode === 'AUTONOMOUS' ? '#2563eb' : 'transparent',
                color: executionMode === 'AUTONOMOUS' ? '#ffffff' : '#71717a',
                padding: '4px 10px',
                borderRadius: '3px',
                fontSize: '0.72rem',
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                gap: '4px'
              }}
            >
              <Zap size={12} />
              AUTONOMOUS MODE
            </button>
            <button
              onClick={() => setExecutionMode('ASSISTED')}
              style={{
                background: executionMode === 'ASSISTED' ? '#d97706' : 'transparent',
                color: executionMode === 'ASSISTED' ? '#ffffff' : '#71717a',
                padding: '4px 10px',
                borderRadius: '3px',
                fontSize: '0.72rem',
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                gap: '4px'
              }}
            >
              <UserCheck size={12} />
              ASSISTED MODE
            </button>
          </div>

          <button
            onClick={onOpenReport}
            style={{
              background: '#2563eb',
              color: '#ffffff',
              padding: '6px 14px',
              borderRadius: '4px',
              fontSize: '0.8rem',
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <Download size={14} />
            EXPORT REPORT
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: '#a1a1aa' }}>
            <span style={{
              width: '7px',
              height: '7px',
              borderRadius: '50%',
              background: isHealthy ? '#16a34a' : '#dc2626'
            }} />
            {isHealthy ? 'GATEWAY ONLINE' : 'DISCONNECTED'}
          </div>
        </div>
      </div>

      {/* Main Navigation Tabs */}
      <div style={{
        maxWidth: '1800px',
        margin: '0 auto',
        padding: '0 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <nav style={{ display: 'flex', gap: '2px' }}>
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
                  padding: '12px 18px',
                  fontSize: '0.82rem',
                  fontWeight: isActive ? 700 : 500,
                  color: isActive ? '#fafafa' : '#71717a',
                  background: 'transparent',
                  borderBottom: isActive ? '2px solid #2563eb' : '2px solid transparent'
                }}
              >
                <Icon size={15} color={isActive ? '#2563eb' : '#71717a'} />
                {item.label}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
