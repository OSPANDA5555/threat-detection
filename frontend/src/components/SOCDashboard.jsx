import React, { useState } from 'react';
import { 
  Shield, 
  Activity, 
  Lock, 
  Terminal, 
  Database, 
  Server, 
  CheckCircle2, 
  AlertTriangle, 
  ArrowRight,
  Radio,
  Zap,
  Gauge,
  Clock,
  Layers,
  Pause,
  Play,
  Trash2,
  RefreshCw,
  Eye
} from 'lucide-react';
import { useEventStream, ConnectionState } from '../services/useEventStream';

export default function SOCDashboard({ onStartHunt, healthData }) {
  const isHealthy = healthData?.status === 'HEALTHY';
  const registeredTools = healthData?.tool_gateway?.registered_tools_count || 11;
  const [inspectedEvent, setInspectedEvent] = useState(null);

  // Hook into real-time event streaming layer with bounded client-side buffer (max 200)
  const {
    connectionState,
    events,
    currentEvent,
    totalEventsReceived,
    eventsPerSec,
    isPaused,
    clearEvents,
    togglePause,
    reconnectNow
  } = useEventStream({ maxBufferSize: 200, enabled: true });

  const getConnectionBadge = () => {
    switch (connectionState) {
      case ConnectionState.CONNECTED:
        return {
          bg: 'rgba(16, 185, 129, 0.15)',
          border: 'rgba(16, 185, 129, 0.4)',
          text: '#34d399',
          label: 'CONNECTED',
          dot: true
        };
      case ConnectionState.RECONNECTING:
        return {
          bg: 'rgba(245, 158, 11, 0.15)',
          border: 'rgba(245, 158, 11, 0.4)',
          text: '#fbbf24',
          label: 'RECONNECTING...',
          dot: false
        };
      default:
        return {
          bg: 'rgba(239, 68, 68, 0.15)',
          border: 'rgba(239, 68, 68, 0.4)',
          text: '#f87171',
          label: 'DISCONNECTED',
          dot: false
        };
    }
  };

  const connBadge = getConnectionBadge();

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
            <span style={{
              background: connBadge.bg,
              border: `1px solid ${connBadge.border}`,
              color: connBadge.text,
              fontSize: '0.72rem',
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: '4px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px'
            }}>
              {connBadge.dot && (
                <span style={{
                  width: '6px',
                  height: '6px',
                  borderRadius: '50%',
                  background: connBadge.text,
                  display: 'inline-block',
                  boxShadow: `0 0 6px ${connBadge.text}`
                }} />
              )}
              {connBadge.label}
            </span>
          </div>
          <h2 className="page-title" style={{ fontSize: '1.5rem' }}>
            Autonomous threat-hunting engine
          </h2>
          <p className="page-subtitle" style={{ maxWidth: '750px' }}>
            Turn natural-language investigation queries into structured, hypothesis-driven threat hunts with enforced safety constraints and real-time live telemetry correlation.
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

      {/* Real-Time Telemetry Streaming Dashboard Banner */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
        gap: '16px'
      }}>
        {/* Metric 1: Connection Status */}
        <div className="soc-card" style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)' }}>STREAM CONNECTION</span>
            <Radio size={16} color={connBadge.text} />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: connBadge.text }}>
            {connBadge.label}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.70rem', color: 'var(--text-muted)' }}>
              WebSocket `/ws/events`
            </span>
            {connectionState === ConnectionState.DISCONNECTED && (
              <button
                onClick={reconnectNow}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--accent-blue)',
                  fontSize: '0.72rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}
              >
                <RefreshCw size={12} /> Retry
              </button>
            )}
          </div>
        </div>

        {/* Metric 2: Live Events Streamed */}
        <div className="soc-card" style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)' }}>LIVE EVENTS STREAMED</span>
            <Activity size={16} color="#34d399" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#10b981' }}>
            {totalEventsReceived.toLocaleString()}
          </div>
          <span style={{ fontSize: '0.70rem', color: 'var(--text-muted)' }}>
            Buffered in DOM: {events.length} / 200 events
          </span>
        </div>

        {/* Metric 3: Events Per Second */}
        <div className="soc-card" style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)' }}>THROUGHPUT (EPS)</span>
            <Gauge size={16} color="#60a5fa" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#3b82f6' }}>
            {eventsPerSec} <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)' }}>evt/s</span>
          </div>
          <span style={{ fontSize: '0.70rem', color: 'var(--text-muted)' }}>
            Real-time sliding window velocity
          </span>
        </div>

        {/* Metric 4: Latest Sequence */}
        <div className="soc-card" style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)' }}>LATEST SEQUENCE ID</span>
            <Layers size={16} color="#c084fc" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#a855f7', fontFamily: 'monospace' }}>
            #{currentEvent?.sequence || 0}
          </div>
          <span style={{ fontSize: '0.70rem', color: 'var(--text-muted)' }}>
            Duplicate-free monotonic stream
          </span>
        </div>
      </div>

      {/* Current Event Spotlight & Live Event Stream Table */}
      <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: '20px' }}>
        {/* Left: Current Event Card */}
        <div className="soc-card" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="section-label" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Zap size={14} color="#f59e0b" />
              CURRENT EVENT SPOTLIGHT
            </span>
            {currentEvent && (
              <span className={`badge ${currentEvent.label && currentEvent.label.toUpperCase() !== 'BENIGN' ? 'badge-danger' : 'badge-success'}`}>
                {currentEvent.label || 'BENIGN'}
              </span>
            )}
          </div>

          {!currentEvent ? (
            <div style={{ padding: '30px 10px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
              Awaiting real-time stream telemetry... Run the Event Replay Engine or import a dataset to stream live.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '0.8rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '6px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Sequence:</span>
                <span style={{ fontFamily: 'monospace', fontWeight: 700, color: '#f8fafc' }}>#{currentEvent.sequence}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '6px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Event ID:</span>
                <span style={{ fontFamily: 'monospace', color: '#60a5fa' }}>{currentEvent.event_id}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '6px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Timestamp:</span>
                <span style={{ fontFamily: 'monospace', color: '#38bdf8' }}>{currentEvent.timestamp}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '6px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Event Type:</span>
                <span style={{ fontWeight: 600, color: '#f8fafc' }}>{currentEvent.event_type}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '6px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Source:</span>
                <span style={{ fontFamily: 'monospace' }}>{currentEvent.source_ip || '-'}:{currentEvent.source_port || '-'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '6px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Destination:</span>
                <span style={{ fontFamily: 'monospace' }}>{currentEvent.destination_ip || '-'}:{currentEvent.destination_port || '-'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '6px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Action:</span>
                <span>{currentEvent.action || 'ALLOWED'}</span>
              </div>
              <button
                onClick={() => setInspectedEvent(currentEvent)}
                className="btn btn-secondary"
                style={{ marginTop: '8px', padding: '6px 12px', fontSize: '0.78rem', justifyContent: 'center' }}
              >
                <Eye size={14} /> Inspect Full Payload
              </button>
            </div>
          )}
        </div>

        {/* Right: Incremental Real-Time Event Stream */}
        <div className="soc-card" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px', minHeight: '380px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="section-label" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Radio size={14} color="#34d399" />
              INCREMENTAL LIVE EVENT STREAM
            </span>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                onClick={togglePause}
                style={{
                  background: isPaused ? 'rgba(16, 185, 129, 0.2)' : 'var(--bg-subtle)',
                  border: '1px solid var(--border-color)',
                  color: isPaused ? '#34d399' : 'var(--text-dim)',
                  padding: '4px 10px',
                  borderRadius: '4px',
                  fontSize: '0.72rem',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  cursor: 'pointer'
                }}
              >
                {isPaused ? <Play size={12} fill="#34d399" /> : <Pause size={12} />}
                {isPaused ? 'Resume UI Feed' : 'Pause UI Feed'}
              </button>
              <button
                onClick={clearEvents}
                style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-color)',
                  color: 'var(--text-dim)',
                  padding: '4px 10px',
                  borderRadius: '4px',
                  fontSize: '0.72rem',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  cursor: 'pointer'
                }}
              >
                <Trash2 size={12} /> Clear
              </button>
            </div>
          </div>

          <div style={{
            flex: 1,
            overflowY: 'auto',
            maxHeight: '340px',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-sm)',
            background: '#040406'
          }}>
            {events.length === 0 ? (
              <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.80rem' }}>
                No streaming events in client buffer. Connect to the Replay Engine or simulate attacks to broadcast events.
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem', textAlign: 'left' }}>
                <thead>
                  <tr style={{ background: '#0a0a0f', color: 'var(--text-dim)', borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '6px 10px' }}>Seq</th>
                    <th style={{ padding: '6px 10px' }}>Event ID</th>
                    <th style={{ padding: '6px 10px' }}>Timestamp</th>
                    <th style={{ padding: '6px 10px' }}>Type</th>
                    <th style={{ padding: '6px 10px' }}>Source $\rightarrow$ Destination</th>
                    <th style={{ padding: '6px 10px' }}>Label</th>
                    <th style={{ padding: '6px 10px' }}>Action</th>
                    <th style={{ padding: '6px 10px' }}>View</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((evt, idx) => {
                    const isMal = evt.label && evt.label.toUpperCase() !== 'BENIGN';
                    return (
                      <tr
                        key={evt.sequence || idx}
                        style={{
                          borderBottom: '1px solid #14141a',
                          background: idx % 2 === 0 ? 'rgba(255,255,255,0.01)' : 'transparent'
                        }}
                      >
                        <td style={{ padding: '6px 10px', fontFamily: 'monospace', color: '#a855f7', fontWeight: 700 }}>
                          #{evt.sequence}
                        </td>
                        <td style={{ padding: '6px 10px', fontFamily: 'monospace', color: '#60a5fa' }}>
                          {(evt.event_id || '').slice(0, 14)}...
                        </td>
                        <td style={{ padding: '6px 10px', fontFamily: 'monospace', color: '#38bdf8' }}>
                          {evt.timestamp}
                        </td>
                        <td style={{ padding: '6px 10px', color: '#cbd5e1' }}>
                          {evt.event_type}
                        </td>
                        <td style={{ padding: '6px 10px', fontFamily: 'monospace', color: '#e2e8f0' }}>
                          {evt.source_ip || '-'}:{evt.source_port || '-'} $\rightarrow$ {evt.destination_ip || '-'}:{evt.destination_port || '-'}
                        </td>
                        <td style={{ padding: '6px 10px' }}>
                          <span style={{
                            padding: '1px 5px',
                            borderRadius: '3px',
                            fontSize: '0.68rem',
                            fontWeight: 700,
                            background: isMal ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                            color: isMal ? '#f87171' : '#34d399',
                            border: `1px solid ${isMal ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`
                          }}>
                            {evt.label}
                          </span>
                        </td>
                        <td style={{ padding: '6px 10px', color: 'var(--text-dim)' }}>
                          {evt.action || 'ALLOWED'}
                        </td>
                        <td style={{ padding: '6px 10px' }}>
                          <button
                            onClick={() => setInspectedEvent(evt)}
                            style={{
                              background: '#18181b',
                              border: '1px solid var(--border-color)',
                              color: '#60a5fa',
                              padding: '2px 6px',
                              borderRadius: '3px',
                              fontSize: '0.68rem',
                              cursor: 'pointer'
                            }}
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {/* Static Operational Metrics Grid */}
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

      {/* Payload Modal */}
      {inspectedEvent && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0,0,0,0.7)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{
            background: '#121215',
            border: '1px solid var(--border-color)',
            borderRadius: 'var(--radius-md)',
            padding: '24px',
            width: '600px',
            maxHeight: '80vh',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', color: '#f4f4f5' }}>
                Stream Event #{inspectedEvent.sequence} Payload
              </h3>
              <button
                onClick={() => setInspectedEvent(null)}
                style={{ background: 'none', border: 'none', color: '#a1a1aa', cursor: 'pointer', fontSize: '1.2rem' }}
              >
                ✕
              </button>
            </div>
            <pre style={{
              background: '#09090b',
              padding: '12px',
              borderRadius: '6px',
              overflowX: 'auto',
              fontSize: '0.8rem',
              color: '#34d399',
              maxHeight: '400px'
            }}>
              {JSON.stringify(inspectedEvent, null, 2)}
            </pre>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setInspectedEvent(null)}
                style={{
                  background: '#27272a',
                  color: '#f4f4f5',
                  border: 'none',
                  padding: '8px 16px',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
