import React, { useState, useEffect } from 'react';
import { 
  Flame, 
  Play, 
  Pause, 
  Square, 
  Layers, 
  Shield, 
  AlertTriangle, 
  CheckCircle2, 
  Zap, 
  Activity, 
  ArrowRight,
  Gauge
} from 'lucide-react';

export default function SimulatedAttackSelector({ onScenarioStarted }) {
  const [scenarios, setScenarios] = useState([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState('multi-stage-attack');
  const [speedMultiplier, setSpeedMultiplier] = useState(2.0);
  const [replayStatus, setReplayStatus] = useState({ status: 'idle', events_emitted: 0, total_events: 0 });
  const [loading, setLoading] = useState(false);

  const fetchScenarios = async () => {
    try {
      const res = await fetch('/api/scenarios');
      if (res.ok) {
        const data = await res.json();
        setScenarios(data);
      }
    } catch (e) {
      console.warn("Failed to fetch prebuilt scenarios:", e);
    }
  };

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/scenarios/status');
      if (res.ok) {
        const data = await res.json();
        setReplayStatus(data);
      }
    } catch (e) {
      console.warn("Failed to fetch scenario status:", e);
    }
  };

  useEffect(() => {
    fetchScenarios();
    fetchStatus();
    const timer = setInterval(fetchStatus, 1500);
    return () => clearInterval(timer);
  }, []);

  const handleStartReplay = async () => {
    try {
      setLoading(true);
      const res = await fetch(`/api/scenarios/replay/${selectedScenarioId}?speed_multiplier=${speedMultiplier}`, {
        method: 'POST'
      });
      if (res.ok) {
        const data = await res.json();
        setReplayStatus(data);
        if (onScenarioStarted) {
          onScenarioStarted(selectedScenarioId);
        }
      }
    } catch (e) {
      console.warn("Error starting scenario replay:", e);
    } finally {
      setLoading(false);
    }
  };

  const handleStopReplay = async () => {
    try {
      const res = await fetch('/api/scenarios/stop', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setReplayStatus(data);
      }
    } catch (e) {
      console.warn("Error stopping scenario replay:", e);
    }
  };

  const selectedScenario = scenarios.find(s => s.scenario_id === selectedScenarioId) || scenarios[0] || null;
  const isRunning = replayStatus.status === 'running';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      
      {/* Telemetry Source Clear Distinction Legend */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '10px 16px',
        background: 'rgba(15, 23, 42, 0.6)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-sm)',
        fontSize: '0.72rem',
        flexWrap: 'wrap',
        gap: '8px'
      }}>
        <span style={{ fontWeight: 800, color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
          TELEMETRY SOURCE MODES:
        </span>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', color: '#34d399', fontWeight: 700 }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#34d399' }} />
            REAL TELEMETRY (Linux Agent)
          </span>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', color: '#60a5fa', fontWeight: 700 }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#60a5fa' }} />
            DATASET REPLAY (PCAP / Flow)
          </span>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', color: '#c084fc', fontWeight: 700 }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#c084fc' }} />
            SIMULATED SCENARIO (Prebuilt Attack)
          </span>
        </div>
      </div>

      {/* Scenario Selector Buttons */}
      <div className="soc-card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <div style={{ fontSize: '0.82rem', fontWeight: 800, color: 'var(--text-main)', letterSpacing: '0.04em' }}>
            PREBUILT ATTACK SCENARIO REPLAY
          </div>
          <span style={{
            background: 'rgba(192, 132, 252, 0.15)',
            border: '1px solid rgba(192, 132, 252, 0.4)',
            color: '#c084fc',
            fontSize: '0.68rem',
            fontWeight: 800,
            padding: '2px 8px',
            borderRadius: '4px'
          }}>
            SIMULATED ATTACK REPLAY
          </span>
        </div>

        {/* Buttons Grid */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '16px' }}>
          {scenarios.map(sc => {
            const isSelected = sc.scenario_id === selectedScenarioId;
            return (
              <button
                key={sc.scenario_id}
                onClick={() => setSelectedScenarioId(sc.scenario_id)}
                style={{
                  background: isSelected ? 'rgba(192, 132, 252, 0.2)' : 'var(--bg-subtle)',
                  border: isSelected ? '2px solid #c084fc' : '1px solid var(--border-color)',
                  color: isSelected ? '#ffffff' : 'var(--text-muted)',
                  padding: '7px 14px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.78rem',
                  fontWeight: isSelected ? 800 : 600,
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
              >
                {sc.name}
              </button>
            );
          })}
        </div>

        {/* Selected Scenario Preview */}
        {selectedScenario && (
          <div style={{
            background: '#040406',
            border: '1px solid rgba(192, 132, 252, 0.3)',
            borderRadius: 'var(--radius-sm)',
            padding: '16px',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px' }}>
              <div>
                <h4 style={{ fontSize: '1rem', fontWeight: 800, color: '#f8fafc', marginBottom: '4px' }}>
                  {selectedScenario.name}
                </h4>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', maxWidth: '650px', lineHeight: 1.4 }}>
                  {selectedScenario.description}
                </p>
              </div>

              {/* Controls */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                  <Gauge size={14} />
                  <span>Speed:</span>
                  <select
                    value={speedMultiplier}
                    onChange={(e) => setSpeedMultiplier(parseFloat(e.target.value))}
                    disabled={isRunning}
                    style={{
                      background: 'var(--bg-subtle)',
                      border: '1px solid var(--border-color)',
                      color: '#f8fafc',
                      padding: '4px 8px',
                      borderRadius: '4px',
                      fontSize: '0.75rem'
                    }}
                  >
                    <option value={0.5}>0.5x</option>
                    <option value={1.0}>1x</option>
                    <option value={2.0}>2x</option>
                    <option value={5.0}>5x</option>
                    <option value={10.0}>10x</option>
                  </select>
                </div>

                {isRunning ? (
                  <button
                    onClick={handleStopReplay}
                    className="btn btn-secondary"
                    style={{ padding: '7px 14px', fontSize: '0.80rem', color: 'var(--status-red)' }}
                  >
                    <Square size={13} />
                    Stop Replay
                  </button>
                ) : (
                  <button
                    onClick={handleStartReplay}
                    disabled={loading}
                    className="btn btn-primary"
                    style={{
                      padding: '7px 16px',
                      fontSize: '0.80rem',
                      background: '#9333ea',
                      borderColor: '#a855f7'
                    }}
                  >
                    <Play size={13} />
                    {loading ? "Launching..." : "Launch Simulated Replay"}
                  </button>
                )}
              </div>
            </div>

            {/* Expected Techniques & Tactics */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem' }}>
                <span style={{ color: 'var(--text-dim)', fontWeight: 700 }}>EXPECTED MITRE TECHNIQUES:</span>
                {selectedScenario.expected_techniques.map((tech, i) => (
                  <span key={i} className="badge badge-info" style={{ fontSize: '0.65rem', fontFamily: 'var(--font-mono)' }}>
                    {tech}
                  </span>
                ))}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem' }}>
                <span style={{ color: 'var(--text-dim)', fontWeight: 700 }}>TACTICS:</span>
                {selectedScenario.expected_tactics.map((tac, i) => (
                  <span key={i} style={{
                    fontSize: '0.65rem',
                    background: 'rgba(192, 132, 252, 0.15)',
                    color: '#d8b4fe',
                    padding: '2px 6px',
                    borderRadius: '3px',
                    fontWeight: 700
                  }}>
                    {tac}
                  </span>
                ))}
              </div>

              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginLeft: 'auto' }}>
                Total Events: <strong>{selectedScenario.events_count}</strong>
              </div>
            </div>

            {/* Replay Progress Bar */}
            {isRunning && (
              <div style={{ marginTop: '6px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.70rem', color: '#c084fc', marginBottom: '4px', fontWeight: 700 }}>
                  <span>REPLAY IN PROGRESS ({replayStatus.speed_multiplier}x speed)</span>
                  <span>{replayStatus.events_emitted} / {replayStatus.total_events} events emitted</span>
                </div>
                <div style={{ width: '100%', height: '4px', background: 'var(--bg-subtle)', borderRadius: '2px', overflow: 'hidden' }}>
                  <div style={{
                    width: `${Math.round((replayStatus.events_emitted / (replayStatus.total_events || 1)) * 100)}%`,
                    height: '100%',
                    background: '#c084fc',
                    transition: 'width 0.2s ease'
                  }} />
                </div>
              </div>
            )}
          </div>
        )}
      </div>

    </div>
  );
}
