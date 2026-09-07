import React, { useState, useEffect, useRef } from 'react';
import { 
  Play, 
  Pause, 
  Square, 
  RotateCcw, 
  Clock, 
  Activity, 
  Database, 
  Gauge, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  FastForward, 
  Layers, 
  ArrowRight,
  Terminal,
  Cpu,
  Radio,
  FileText
} from 'lucide-react';

export default function EventReplayPanel({ initialDatasetId }) {
  const [datasets, setDatasets] = useState([]);
  const [selectedDatasetId, setSelectedDatasetId] = useState(initialDatasetId || '');
  const [speedMultiplier, setSpeedMultiplier] = useState(10.0);
  const [customSpeed, setCustomSpeed] = useState('10');
  const [startTimestamp, setStartTimestamp] = useState('');
  const [endTimestamp, setEndTimestamp] = useState('');
  
  const [replayStatus, setReplayStatus] = useState({
    state: 'idle',
    datasetId: null,
    datasetName: null,
    speedMultiplier: 1.0,
    startTimestamp: null,
    endTimestamp: null,
    currentSimulatedTimestamp: null,
    totalEvents: 0,
    eventsEmitted: 0,
    eventsRemaining: 0,
    progressPercent: 0.0,
    lastEmittedEvent: null,
    emittedEvents: [],
    startedAt: null,
    elapsedRealTimeSec: 0.0,
    message: 'Replay engine is idle.'
  });

  const [loading, setLoading] = useState(false);
  const [selectedEventModal, setSelectedEventModal] = useState(null);
  const pollingRef = useRef(null);

  const speedPresets = [0.25, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0];

  useEffect(() => {
    fetchDatasets();
    fetchStatus();

    // Poll status periodically
    pollingRef.current = setInterval(() => {
      fetchStatus();
    }, 1000);

    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, []);

  useEffect(() => {
    if (initialDatasetId) {
      setSelectedDatasetId(initialDatasetId);
    }
  }, [initialDatasetId]);

  const fetchDatasets = async () => {
    try {
      const res = await fetch('/api/v1/datasets');
      if (!res.ok) throw new Error("Failed to fetch datasets");
      const data = await res.json();
      setDatasets(data);
      if (data.length > 0 && !selectedDatasetId) {
        setSelectedDatasetId(data[0].dataset_id);
      }
    } catch (err) {
      console.error("Error fetching datasets for replay:", err);
    }
  };

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/replay/status');
      if (!res.ok) throw new Error("Failed to fetch replay status");
      const data = await res.json();
      setReplayStatus(data);
    } catch (err) {
      console.warn("Replay status poll error:", err);
    }
  };

  const handleStart = async () => {
    if (!selectedDatasetId) return;
    setLoading(true);
    try {
      const payload = {
        datasetId: selectedDatasetId,
        speedMultiplier: parseFloat(speedMultiplier) || 1.0,
        startTimestamp: startTimestamp.trim() || null,
        endTimestamp: endTimestamp.trim() || null
      };
      const res = await fetch('/api/replay/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Error starting replay: ${err.detail || 'Unknown error'}`);
        return;
      }
      const data = await res.json();
      setReplayStatus(data);
    } catch (err) {
      console.error("Start replay failed:", err);
    } finally {
      setLoading(false);
    }
  };

  const handlePause = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/replay/pause', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setReplayStatus(data);
      }
    } catch (err) {
      console.error("Pause replay failed:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleResume = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/replay/resume', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setReplayStatus(data);
      }
    } catch (err) {
      console.error("Resume replay failed:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/replay/stop', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setReplayStatus(data);
      }
    } catch (err) {
      console.error("Stop replay failed:", err);
    } finally {
      setLoading(false);
    }
  };

  const getStateBadge = (state) => {
    switch (state) {
      case 'running':
        return {
          bg: 'rgba(16, 185, 129, 0.15)',
          border: 'rgba(16, 185, 129, 0.4)',
          text: '#34d399',
          label: 'EMITTING LIVE',
          pulsing: true
        };
      case 'paused':
        return {
          bg: 'rgba(245, 158, 11, 0.15)',
          border: 'rgba(245, 158, 11, 0.4)',
          text: '#fbbf24',
          label: 'PAUSED',
          pulsing: false
        };
      case 'completed':
        return {
          bg: 'rgba(6, 182, 212, 0.15)',
          border: 'rgba(6, 182, 212, 0.4)',
          text: '#22d3ee',
          label: 'COMPLETED',
          pulsing: false
        };
      case 'stopped':
        return {
          bg: 'rgba(239, 68, 68, 0.15)',
          border: 'rgba(239, 68, 68, 0.4)',
          text: '#f87171',
          label: 'STOPPED',
          pulsing: false
        };
      default:
        return {
          bg: 'rgba(113, 113, 122, 0.15)',
          border: 'rgba(113, 113, 122, 0.4)',
          text: '#a1a1aa',
          label: 'IDLE',
          pulsing: false
        };
    }
  };

  const badge = getStateBadge(replayStatus.state);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(17, 24, 39, 0.8), rgba(9, 9, 11, 0.95))',
        border: '1px solid var(--border-color)',
        borderRadius: 'var(--radius-lg)',
        padding: '24px 28px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        boxShadow: '0 4px 20px rgba(0,0,0,0.4)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{
            background: 'rgba(59, 130, 246, 0.15)',
            border: '1px solid rgba(59, 130, 246, 0.3)',
            borderRadius: 'var(--radius-md)',
            padding: '14px',
            display: 'flex'
          }}>
            <FastForward size={28} color="#60a5fa" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <h1 style={{ fontSize: '1.4rem', fontWeight: 700, margin: 0, color: '#f4f4f5' }}>
                Security-Event Replay Engine
              </h1>
              <span style={{
                background: badge.bg,
                border: `1px solid ${badge.border}`,
                color: badge.text,
                fontSize: '0.72rem',
                fontWeight: 700,
                padding: '3px 8px',
                borderRadius: '4px',
                letterSpacing: '0.05em',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px'
              }}>
                {badge.pulsing && (
                  <span style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    background: badge.text,
                    display: 'inline-block',
                    boxShadow: `0 0 8px ${badge.text}`
                  }} />
                )}
                {badge.label}
              </span>
            </div>
            <p style={{ margin: '4px 0 0 0', fontSize: '0.85rem', color: '#a1a1aa' }}>
              Streamline imported datasets as live simulated telemetry in chronological order without modifying original event timestamps.
            </p>
          </div>
        </div>

        {/* Global Controls */}
        <div style={{ display: 'flex', gap: '10px' }}>
          {replayStatus.state !== 'running' && (
            <button
              onClick={replayStatus.state === 'paused' ? handleResume : handleStart}
              disabled={loading || !selectedDatasetId}
              style={{
                background: '#10b981',
                color: '#fff',
                border: 'none',
                padding: '10px 18px',
                borderRadius: 'var(--radius-md)',
                fontWeight: 600,
                fontSize: '0.85rem',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                cursor: 'pointer',
                boxShadow: '0 0 15px rgba(16, 185, 129, 0.3)',
                opacity: loading || !selectedDatasetId ? 0.6 : 1
              }}
            >
              <Play size={16} fill="#fff" />
              {replayStatus.state === 'paused' ? 'Resume Replay' : 'Start Replay'}
            </button>
          )}

          {replayStatus.state === 'running' && (
            <button
              onClick={handlePause}
              disabled={loading}
              style={{
                background: '#f59e0b',
                color: '#fff',
                border: 'none',
                padding: '10px 18px',
                borderRadius: 'var(--radius-md)',
                fontWeight: 600,
                fontSize: '0.85rem',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                cursor: 'pointer',
                boxShadow: '0 0 15px rgba(245, 158, 11, 0.3)'
              }}
            >
              <Pause size={16} fill="#fff" />
              Pause Replay
            </button>
          )}

          {(replayStatus.state === 'running' || replayStatus.state === 'paused') && (
            <button
              onClick={handleStop}
              disabled={loading}
              style={{
                background: '#ef4444',
                color: '#fff',
                border: 'none',
                padding: '10px 16px',
                borderRadius: 'var(--radius-md)',
                fontWeight: 600,
                fontSize: '0.85rem',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                cursor: 'pointer',
                boxShadow: '0 0 15px rgba(239, 68, 68, 0.3)'
              }}
            >
              <Square size={15} fill="#fff" />
              Stop
            </button>
          )}
        </div>
      </div>

      {/* Progress & Simulated Clock Dashboard */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '16px'
      }}>
        {/* Metric 1: Current Simulated Timestamp */}
        <div style={{
          background: 'var(--bg-panel)',
          border: '1px solid var(--border-color)',
          borderRadius: 'var(--radius-md)',
          padding: '18px 20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#71717a', letterSpacing: '0.05em' }}>
              SIMULATED TIMESTAMP
            </span>
            <Clock size={16} color="#60a5fa" />
          </div>
          <div style={{
            fontSize: '1.15rem',
            fontWeight: 700,
            fontFamily: 'monospace',
            color: '#38bdf8',
            wordBreak: 'break-all'
          }}>
            {replayStatus.currentSimulatedTimestamp || '0000-00-00T00:00:00Z'}
          </div>
          <span style={{ fontSize: '0.72rem', color: '#71717a' }}>
            Original timestamp preserved without mutation
          </span>
        </div>

        {/* Metric 2: Events Emitted */}
        <div style={{
          background: 'var(--bg-panel)',
          border: '1px solid var(--border-color)',
          borderRadius: 'var(--radius-md)',
          padding: '18px 20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#71717a', letterSpacing: '0.05em' }}>
              EVENTS EMITTED
            </span>
            <Radio size={16} color="#34d399" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#10b981' }}>
            {replayStatus.eventsEmitted.toLocaleString()}
          </div>
          <span style={{ fontSize: '0.72rem', color: '#71717a' }}>
            Progress: {replayStatus.progressPercent}% completed
          </span>
        </div>

        {/* Metric 3: Events Remaining */}
        <div style={{
          background: 'var(--bg-panel)',
          border: '1px solid var(--border-color)',
          borderRadius: 'var(--radius-md)',
          padding: '18px 20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#71717a', letterSpacing: '0.05em' }}>
              EVENTS REMAINING
            </span>
            <Layers size={16} color="#fbbf24" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f59e0b' }}>
            {replayStatus.eventsRemaining.toLocaleString()}
          </div>
          <span style={{ fontSize: '0.72rem', color: '#71717a' }}>
            Total in queue: {replayStatus.totalEvents.toLocaleString()}
          </span>
        </div>

        {/* Metric 4: Replay Speed & Real Duration */}
        <div style={{
          background: 'var(--bg-panel)',
          border: '1px solid var(--border-color)',
          borderRadius: 'var(--radius-md)',
          padding: '18px 20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#71717a', letterSpacing: '0.05em' }}>
              REPLAY SPEED
            </span>
            <Gauge size={16} color="#c084fc" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#a855f7' }}>
            {replayStatus.speedMultiplier}x
          </div>
          <span style={{ fontSize: '0.72rem', color: '#71717a' }}>
            Real elapsed: {replayStatus.elapsedRealTimeSec}s
          </span>
        </div>
      </div>

      {/* Progress Bar */}
      <div style={{
        background: 'var(--bg-panel)',
        border: '1px solid var(--border-color)',
        borderRadius: 'var(--radius-md)',
        padding: '16px 20px',
        display: 'flex',
        flexDirection: 'column',
        gap: '8px'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: '#a1a1aa' }}>
          <span>Replay Sequence Progress</span>
          <span style={{ fontWeight: 600, color: '#f4f4f5' }}>{replayStatus.progressPercent}% ({replayStatus.eventsEmitted} / {replayStatus.totalEvents})</span>
        </div>
        <div style={{
          width: '100%',
          height: '10px',
          background: '#27272a',
          borderRadius: '5px',
          overflow: 'hidden'
        }}>
          <div style={{
            width: `${Math.min(100, replayStatus.progressPercent)}%`,
            height: '100%',
            background: 'linear-gradient(90deg, #3b82f6, #06b6d4, #10b981)',
            borderRadius: '5px',
            transition: 'width 0.3s ease',
            boxShadow: '0 0 10px rgba(59, 130, 246, 0.5)'
          }} />
        </div>
      </div>

      {/* Main Configuration & Live Stream Split */}
      <div style={{ display: 'grid', gridTemplateColumns: '400px 1fr', gap: '20px' }}>
        {/* Left Column: Replay Configuration Form */}
        <div style={{
          background: 'var(--bg-panel)',
          border: '1px solid var(--border-color)',
          borderRadius: 'var(--radius-md)',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '18px'
        }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 600, margin: 0, color: '#f4f4f5', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Terminal size={18} color="#60a5fa" />
            Replay Configuration
          </h2>

          {/* Dataset Selector */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label style={{ fontSize: '0.8rem', color: '#a1a1aa', fontWeight: 500 }}>Target Dataset:</label>
            <select
              value={selectedDatasetId}
              onChange={(e) => setSelectedDatasetId(e.target.value)}
              disabled={replayStatus.state === 'running' || replayStatus.state === 'paused'}
              style={{
                background: '#18181b',
                border: '1px solid var(--border-color)',
                color: '#f4f4f5',
                borderRadius: 'var(--radius-sm)',
                padding: '8px 12px',
                fontSize: '0.85rem',
                outline: 'none'
              }}
            >
              {datasets.map(ds => (
                <option key={ds.dataset_id} value={ds.dataset_id}>
                  {ds.dataset_name} ({ds.total_events} events)
                </option>
              ))}
            </select>
          </div>

          {/* Speed Multiplier */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <label style={{ fontSize: '0.8rem', color: '#a1a1aa', fontWeight: 500 }}>
              Replay Speed Multiplier:
            </label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {speedPresets.map(spd => (
                <button
                  key={spd}
                  onClick={() => {
                    setSpeedMultiplier(spd);
                    setCustomSpeed(spd.toString());
                  }}
                  disabled={replayStatus.state === 'running' || replayStatus.state === 'paused'}
                  style={{
                    background: speedMultiplier === spd ? 'rgba(59, 130, 246, 0.25)' : '#18181b',
                    border: `1px solid ${speedMultiplier === spd ? '#3b82f6' : 'var(--border-color)'}`,
                    color: speedMultiplier === spd ? '#60a5fa' : '#a1a1aa',
                    borderRadius: '4px',
                    padding: '5px 9px',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  {spd}x
                </button>
              ))}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
              <span style={{ fontSize: '0.75rem', color: '#71717a' }}>Custom:</span>
              <input
                type="number"
                min="0.01"
                max="1000"
                step="0.1"
                value={customSpeed}
                onChange={(e) => {
                  setCustomSpeed(e.target.value);
                  const val = parseFloat(e.target.value);
                  if (!isNaN(val) && val > 0) setSpeedMultiplier(val);
                }}
                disabled={replayStatus.state === 'running' || replayStatus.state === 'paused'}
                style={{
                  background: '#18181b',
                  border: '1px solid var(--border-color)',
                  color: '#f4f4f5',
                  borderRadius: '4px',
                  padding: '4px 8px',
                  fontSize: '0.8rem',
                  width: '90px'
                }}
              />
              <span style={{ fontSize: '0.75rem', color: '#71717a' }}>multiplier</span>
            </div>
          </div>

          {/* Time Window Filters */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <label style={{ fontSize: '0.8rem', color: '#a1a1aa', fontWeight: 500 }}>
              Optional Time Window Filter:
            </label>
            <div>
              <span style={{ fontSize: '0.72rem', color: '#71717a' }}>Start ISO Timestamp:</span>
              <input
                type="text"
                placeholder="e.g. 2017-07-07T08:30:00Z"
                value={startTimestamp}
                onChange={(e) => setStartTimestamp(e.target.value)}
                disabled={replayStatus.state === 'running' || replayStatus.state === 'paused'}
                style={{
                  width: '100%',
                  background: '#18181b',
                  border: '1px solid var(--border-color)',
                  color: '#f4f4f5',
                  borderRadius: '4px',
                  padding: '6px 10px',
                  fontSize: '0.8rem',
                  marginTop: '2px'
                }}
              />
            </div>
            <div>
              <span style={{ fontSize: '0.72rem', color: '#71717a' }}>End ISO Timestamp:</span>
              <input
                type="text"
                placeholder="e.g. 2017-07-07T09:30:00Z"
                value={endTimestamp}
                onChange={(e) => setEndTimestamp(e.target.value)}
                disabled={replayStatus.state === 'running' || replayStatus.state === 'paused'}
                style={{
                  width: '100%',
                  background: '#18181b',
                  border: '1px solid var(--border-color)',
                  color: '#f4f4f5',
                  borderRadius: '4px',
                  padding: '6px 10px',
                  fontSize: '0.8rem',
                  marginTop: '2px'
                }}
              />
            </div>
          </div>

          <div style={{
            background: 'rgba(59, 130, 246, 0.05)',
            border: '1px solid rgba(59, 130, 246, 0.2)',
            borderRadius: 'var(--radius-sm)',
            padding: '12px',
            fontSize: '0.75rem',
            color: '#93c5fd',
            lineHeight: 1.4
          }}>
            <strong>Deterministic Replay:</strong> Replaying the same dataset at any multiplier guarantees the exact same sequence of emitted events with original raw timestamps.
          </div>
        </div>

        {/* Right Column: Live Emitted Events Stream */}
        <div style={{
          background: 'var(--bg-panel)',
          border: '1px solid var(--border-color)',
          borderRadius: 'var(--radius-md)',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px',
          minHeight: '480px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2 style={{ fontSize: '1rem', fontWeight: 600, margin: 0, color: '#f4f4f5', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Activity size={18} color="#10b981" />
              Live Emitted Security Events Stream
            </h2>
            <span style={{ fontSize: '0.75rem', color: '#71717a' }}>
              Showing latest {replayStatus.emittedEvents?.length || 0} events
            </span>
          </div>

          {/* Events Table / Feed */}
          <div style={{
            flex: 1,
            overflowY: 'auto',
            maxHeight: '440px',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-sm)',
            background: '#09090b'
          }}>
            {(!replayStatus.emittedEvents || replayStatus.emittedEvents.length === 0) ? (
              <div style={{ padding: '40px', textAlign: 'center', color: '#71717a', fontSize: '0.85rem' }}>
                No events emitted yet. Select a dataset and click "Start Replay" to stream telemetry in real-time.
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
                <thead>
                  <tr style={{ background: '#121215', color: '#a1a1aa', borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '8px 12px' }}>Original Timestamp</th>
                    <th style={{ padding: '8px 12px' }}>Source IP:Port</th>
                    <th style={{ padding: '8px 12px' }}>Dest IP:Port</th>
                    <th style={{ padding: '8px 12px' }}>Protocol</th>
                    <th style={{ padding: '8px 12px' }}>Label</th>
                    <th style={{ padding: '8px 12px' }}>Action</th>
                    <th style={{ padding: '8px 12px' }}>Inspect</th>
                  </tr>
                </thead>
                <tbody>
                  {[...replayStatus.emittedEvents].reverse().map((evt, idx) => {
                    const isMalicious = evt.label && evt.label.toUpperCase() !== 'BENIGN';
                    return (
                      <tr
                        key={idx}
                        style={{
                          borderBottom: '1px solid #1c1c20',
                          background: idx % 2 === 0 ? 'rgba(255,255,255,0.01)' : 'transparent'
                        }}
                      >
                        <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#38bdf8' }}>
                          {evt.timestamp}
                        </td>
                        <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#e4e4e7' }}>
                          {evt.source_ip || '-'}:{evt.source_port || '-'}
                        </td>
                        <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#e4e4e7' }}>
                          {evt.destination_ip || '-'}:{evt.destination_port || '-'}
                        </td>
                        <td style={{ padding: '8px 12px', color: '#a1a1aa' }}>
                          {evt.protocol || 'TCP'}
                        </td>
                        <td style={{ padding: '8px 12px' }}>
                          <span style={{
                            padding: '2px 6px',
                            borderRadius: '4px',
                            fontSize: '0.7rem',
                            fontWeight: 600,
                            background: isMalicious ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                            color: isMalicious ? '#f87171' : '#34d399',
                            border: `1px solid ${isMalicious ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`
                          }}>
                            {evt.label}
                          </span>
                        </td>
                        <td style={{ padding: '8px 12px', color: '#a1a1aa' }}>
                          {evt.action || 'ALLOWED'}
                        </td>
                        <td style={{ padding: '8px 12px' }}>
                          <button
                            onClick={() => setSelectedEventModal(evt)}
                            style={{
                              background: '#27272a',
                              border: 'none',
                              color: '#60a5fa',
                              padding: '3px 8px',
                              borderRadius: '4px',
                              fontSize: '0.72rem',
                              cursor: 'pointer'
                            }}
                          >
                            View
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

      {/* Raw Event Detail Modal */}
      {selectedEventModal && (
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
                Emitted Event Payload
              </h3>
              <button
                onClick={() => setSelectedEventModal(null)}
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
              {JSON.stringify(selectedEventModal, null, 2)}
            </pre>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setSelectedEventModal(null)}
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
