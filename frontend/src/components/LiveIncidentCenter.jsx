import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  Activity, 
  Flame, 
  Layers, 
  Clock, 
  Server, 
  User, 
  Terminal, 
  RefreshCw, 
  Trash2, 
  ArrowRight, 
  CheckCircle2, 
  Info,
  Radio,
  ExternalLink,
  ChevronRight,
  TrendingUp
} from 'lucide-react';
import { useEventStream, ConnectionState } from '../services/useEventStream';

const MITRE_TACTIC_ORDER = [
  "RECONNAISSANCE",
  "INITIAL ACCESS",
  "EXECUTION",
  "PERSISTENCE",
  "PRIVILEGE ESCALATION",
  "DEFENSE EVASION",
  "CREDENTIAL ACCESS",
  "DISCOVERY",
  "LATERAL MOVEMENT",
  "COLLECTION",
  "COMMAND AND CONTROL",
  "EXFILTRATION",
  "IMPACT"
];

export default function LiveIncidentCenter({ onInvestigateIncident }) {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [evalMetrics, setEvalMetrics] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);

  const {
    connectionState,
    latestAlert,
    activeIncidentsCount,
    eventsPerSec
  } = useEventStream({ maxBufferSize: 50, enabled: true });

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/incidents/active');
      if (res.ok) {
        const data = await res.json();
        setIncidents(data);
        if (data.length > 0 && !selectedIncidentId) {
          setSelectedIncidentId(data[0].incident_id);
        }
      }
    } catch (e) {
      console.warn("Error fetching active incidents:", e);
    } finally {
      setLoading(false);
    }
  };

  const fetchEvaluation = async () => {
    try {
      const res = await fetch('/api/incidents/evaluation');
      if (res.ok) {
        const data = await res.json();
        setEvalMetrics(data);
      }
    } catch (e) {
      console.warn("Error fetching evaluation metrics:", e);
    }
  };

  const handleReset = async () => {
    try {
      await fetch('/api/incidents/reset', { method: 'POST' });
      setIncidents([]);
      setSelectedIncidentId(null);
      fetchEvaluation();
    } catch (e) {
      console.warn("Error resetting incidents:", e);
    }
  };

  useEffect(() => {
    fetchIncidents();
    fetchEvaluation();
    const timer = setInterval(() => {
      fetchIncidents();
      fetchEvaluation();
    }, 2500);
    return () => clearInterval(timer);
  }, []);

  const selectedIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0] || null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Banner */}
      <div className="glass-card" style={{
        padding: '24px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: '16px',
        flexWrap: 'wrap'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
            <span className="badge badge-info">Real-time detection pipeline</span>
            <span className="badge badge-success">Zero label leakage</span>
            <span style={{
              background: connectionState === ConnectionState.CONNECTED ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
              border: `1px solid ${connectionState === ConnectionState.CONNECTED ? 'rgba(16, 185, 129, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`,
              color: connectionState === ConnectionState.CONNECTED ? '#34d399' : '#f87171',
              fontSize: '0.72rem',
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: '4px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px'
            }}>
              <span className="pulse-dot" style={{ background: connectionState === ConnectionState.CONNECTED ? '#34d399' : '#f87171', width: '6px', height: '6px' }} />
              STREAM {connectionState} ({eventsPerSec} EPS)
            </span>
          </div>
          <h2 className="page-title" style={{ fontSize: '1.4rem' }}>
            Live Security Incidents & Attack Graphs
          </h2>
          <p className="page-subtitle" style={{ maxWidth: '800px', fontSize: '0.85rem' }}>
            Multi-event behavioral pattern correlation engine. Grouping real-time telemetry into MITRE ATT&CK progression stages and dynamic causal attack graphs with strictly zero label leakage.
          </p>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={fetchIncidents}
            className="btn btn-secondary"
            style={{ padding: '8px 14px', fontSize: '0.8rem' }}
          >
            <RefreshCw size={14} className={loading ? "spin-icon" : ""} />
            Refresh
          </button>
          <button
            onClick={handleReset}
            className="btn btn-secondary"
            style={{ padding: '8px 14px', fontSize: '0.8rem', color: 'var(--status-red)' }}
          >
            <Trash2 size={14} />
            Reset incidents
          </button>
        </div>
      </div>

      {/* Real-Time Online Evaluation Metrics Strip */}
      {evalMetrics && (
        <div className="soc-card" style={{
          padding: '16px 20px',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '12px',
          alignItems: 'center',
          background: 'rgba(15, 23, 42, 0.6)'
        }}>
          <div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 700 }}>EVALUATION MODE</div>
            <div style={{ fontSize: '1.05rem', fontWeight: 800, color: evalMetrics.is_statistically_significant ? '#34d399' : '#fbbf24' }}>
              {evalMetrics.is_statistically_significant ? 'Statistically Valid' : 'Warming Up (< 10)'}
            </div>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>
              {evalMetrics.total_labeled_events} ground-truth events
            </div>
          </div>

          <div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 700 }}>PRECISION</div>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#60a5fa' }}>
              {Math.round(evalMetrics.precision * 100)}%
            </div>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>TP / (TP + FP)</div>
          </div>

          <div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 700 }}>RECALL</div>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#38bdf8' }}>
              {Math.round(evalMetrics.recall * 100)}%
            </div>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>TP / (TP + FN)</div>
          </div>

          <div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 700 }}>F1-SCORE</div>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#a78bfa' }}>
              {Math.round(evalMetrics.f1_score * 100)}%
            </div>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>Harmonic mean</div>
          </div>

          <div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 700 }}>CONFUSION MATRIX</div>
            <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-main)' }}>
              TP: <span style={{ color: '#34d399', fontWeight: 700 }}>{evalMetrics.true_positives}</span> | FP: <span style={{ color: '#f87171', fontWeight: 700 }}>{evalMetrics.false_positives}</span>
            </div>
            <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-main)' }}>
              TN: <span style={{ color: '#94a3b8', fontWeight: 700 }}>{evalMetrics.true_negatives}</span> | FN: <span style={{ color: '#f59e0b', fontWeight: 700 }}>{evalMetrics.false_negatives}</span>
            </div>
          </div>
        </div>
      )}

      {/* Main Grid: Incident List (Left) + Detailed Incident View (Right) */}
      <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: '20px', alignItems: 'start' }}>
        
        {/* Left Column: Active Incidents Feed */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 800, color: 'var(--text-main)', letterSpacing: '0.05em' }}>
              ACTIVE INCIDENTS ({incidents.length})
            </span>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Auto-correlating</span>
          </div>

          {incidents.length === 0 ? (
            <div className="soc-card" style={{ padding: '32px 20px', textAlign: 'center' }}>
              <Shield size={32} color="var(--text-dim)" style={{ margin: '0 auto 12px auto' }} />
              <div style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-muted)' }}>
                No active security incidents
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '6px' }}>
                Replay an imported dataset or stream live events to trigger real-time multi-event behavioral correlation.
              </p>
            </div>
          ) : (
            incidents.map(inc => {
              const isSelected = selectedIncident?.incident_id === inc.incident_id;
              const isCritical = inc.severity === 'CRITICAL';
              return (
                <div
                  key={inc.incident_id}
                  onClick={() => setSelectedIncidentId(inc.incident_id)}
                  className="soc-card"
                  style={{
                    padding: '16px',
                    cursor: 'pointer',
                    borderLeft: isSelected ? '4px solid var(--accent-blue)' : (isCritical ? '4px solid #ef4444' : '4px solid #f59e0b'),
                    background: isSelected ? 'rgba(59, 130, 246, 0.08)' : 'var(--bg-panel)',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '6px' }}>
                    <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', fontWeight: 700 }}>
                      {inc.incident_id.toUpperCase()}
                    </span>
                    <span className={`badge ${isCritical ? 'badge-danger' : 'badge-warning'}`} style={{ fontSize: '0.65rem' }}>
                      {inc.severity}
                    </span>
                  </div>

                  <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#f8fafc', marginBottom: '8px', lineHeight: 1.3 }}>
                    {inc.title}
                  </div>

                  {/* Tactics Progress Tag */}
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginBottom: '10px' }}>
                    {inc.mitre_tactics.slice(0, 3).map((t, idx) => (
                      <span key={idx} style={{
                        fontSize: '0.65rem',
                        background: 'rgba(59, 130, 246, 0.15)',
                        border: '1px solid rgba(59, 130, 246, 0.3)',
                        color: '#93c5fd',
                        padding: '1px 6px',
                        borderRadius: '3px',
                        fontWeight: 600
                      }}>
                        {t}
                      </span>
                    ))}
                    {inc.mitre_tactics.length > 3 && (
                      <span style={{ fontSize: '0.65rem', color: 'var(--text-dim)', alignSelf: 'center' }}>
                        +{inc.mitre_tactics.length - 3} more
                      </span>
                    )}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.70rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                    <span>{inc.affected_hosts[0] || 'Unknown Host'}</span>
                    <span>{inc.detections.length} detections</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right Column: Detailed Incident View */}
        {selectedIncident ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            
            {/* Incident Header Card */}
            <div className="soc-card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                    <span style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', fontWeight: 800 }}>
                      {selectedIncident.incident_id.toUpperCase()}
                    </span>
                    <span className={`badge ${selectedIncident.severity === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}`}>
                      {selectedIncident.severity} SEVERITY
                    </span>
                    <span className="badge badge-info">
                      Confidence: {Math.round(selectedIncident.confidence * 100)}%
                    </span>
                  </div>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#f8fafc', marginBottom: '8px' }}>
                    {selectedIncident.title}
                  </h3>
                  <div style={{ display: 'flex', gap: '16px', fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    <span>Started: {selectedIncident.start_time}</span>
                    <span>•</span>
                    <span>Last Seen: {selectedIncident.last_seen}</span>
                  </div>
                </div>

                {onInvestigateIncident && (
                  <button
                    onClick={() => onInvestigateIncident(selectedIncident)}
                    className="btn btn-primary"
                    style={{ padding: '9px 16px', fontSize: '0.82rem' }}
                  >
                    <Terminal size={15} />
                    Launch Copilot Investigation
                    <ArrowRight size={15} />
                  </button>
                )}
              </div>

              {/* Entity Badges */}
              <div style={{
                marginTop: '16px',
                paddingTop: '16px',
                borderTop: '1px solid var(--border-subtle)',
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                gap: '12px'
              }}>
                <div>
                  <div style={{ fontSize: '0.70rem', color: 'var(--text-dim)', fontWeight: 700, marginBottom: '4px' }}>ATTACKER IPS</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {selectedIncident.source_ips.map((ip, i) => (
                      <span key={i} className="badge badge-danger" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                        {ip}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '0.70rem', color: 'var(--text-dim)', fontWeight: 700, marginBottom: '4px' }}>AFFECTED HOSTS</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {selectedIncident.affected_hosts.map((h, i) => (
                      <span key={i} className="badge badge-warning" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                        {h}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '0.70rem', color: 'var(--text-dim)', fontWeight: 700, marginBottom: '4px' }}>TARGETED USERS</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {selectedIncident.users.map((u, i) => (
                      <span key={i} className="badge badge-info" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                        {u}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* MITRE ATT&CK Progression Bar */}
            <div className="soc-card" style={{ padding: '18px 20px' }}>
              <div style={{ fontSize: '0.78rem', fontWeight: 800, color: 'var(--text-main)', marginBottom: '12px', letterSpacing: '0.04em' }}>
                MITRE ATT&CK KILL-CHAIN PROGRESSION
              </div>
              <div style={{ display: 'flex', gap: '6px', overflowX: 'auto', paddingBottom: '6px' }}>
                {MITRE_TACTIC_ORDER.map((tactic, idx) => {
                  const isHit = selectedIncident.mitre_tactics.some(t => t.toUpperCase() === tactic);
                  return (
                    <div
                      key={idx}
                      style={{
                        flex: '1 0 110px',
                        background: isHit ? 'rgba(239, 68, 68, 0.15)' : 'rgba(15, 23, 42, 0.4)',
                        border: isHit ? '1px solid rgba(239, 68, 68, 0.5)' : '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                        padding: '8px 10px',
                        textAlign: 'center',
                        transition: 'all 0.2s ease'
                      }}
                    >
                      <div style={{ fontSize: '0.62rem', fontFamily: 'var(--font-mono)', color: isHit ? '#ef4444' : 'var(--text-dim)', fontWeight: 700 }}>
                        STAGE {idx + 1}
                      </div>
                      <div style={{ fontSize: '0.70rem', fontWeight: 700, color: isHit ? '#fca5a5' : 'var(--text-dim)', marginTop: '2px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {tactic}
                      </div>
                      {isHit && (
                        <div style={{ marginTop: '4px', fontSize: '0.62rem', color: '#ef4444', fontWeight: 800 }}>
                          ● DETECTED
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Interactive Attack Graph View */}
            <div className="soc-card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                <div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 800, color: 'var(--text-main)' }}>
                    DYNAMIC ATTACK TOPOLOGY GRAPH
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                    Causal relationships: Attacker IP → Compromised Account → Host → Exploit Stage → C2 Exfiltration
                  </div>
                </div>
                <span className="badge badge-info" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem' }}>
                  {selectedIncident.attack_graph?.nodes?.length || 0} Nodes • {selectedIncident.attack_graph?.edges?.length || 0} Edges
                </span>
              </div>

              {/* Node Layout Canvas */}
              <div style={{
                background: '#040406',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                padding: '24px',
                minHeight: '220px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '24px',
                flexWrap: 'wrap',
                position: 'relative'
              }}>
                {selectedIncident.attack_graph?.nodes?.map((node, i) => {
                  const isNodeSelected = selectedNode?.id === node.id;
                  let nodeColor = '#3b82f6';
                  if (node.type === 'IP') nodeColor = '#ef4444';
                  if (node.type === 'USER') nodeColor = '#f59e0b';
                  if (node.type === 'HOST') nodeColor = '#10b981';
                  if (node.type === 'STAGE') nodeColor = '#8b5cf6';

                  return (
                    <React.Fragment key={node.id}>
                      <div
                        onClick={() => setSelectedNode(node)}
                        style={{
                          background: 'rgba(15, 23, 42, 0.8)',
                          border: `2px solid ${isNodeSelected ? '#ffffff' : nodeColor}`,
                          borderRadius: 'var(--radius-sm)',
                          padding: '12px 16px',
                          cursor: 'pointer',
                          minWidth: '150px',
                          boxShadow: isNodeSelected ? `0 0 12px ${nodeColor}` : 'none',
                          transition: 'all 0.15s ease'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span style={{ fontSize: '0.65rem', fontWeight: 800, color: nodeColor, fontFamily: 'var(--font-mono)' }}>
                            {node.type}
                          </span>
                          {node.stage && (
                            <span style={{ fontSize: '0.60rem', color: 'var(--text-dim)' }}>
                              {node.stage}
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: '0.80rem', fontWeight: 700, color: '#f8fafc', wordBreak: 'break-all' }}>
                          {node.value}
                        </div>
                      </div>

                      {i < (selectedIncident.attack_graph?.nodes?.length - 1) && (
                        <div style={{ color: 'var(--text-dim)', display: 'flex', alignItems: 'center' }}>
                          <ArrowRight size={18} />
                        </div>
                      )}
                    </React.Fragment>
                  );
                })}
              </div>

              {/* Node Inspector Details */}
              {selectedNode && (
                <div style={{
                  marginTop: '12px',
                  padding: '12px 16px',
                  background: 'rgba(15, 23, 42, 0.5)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.75rem'
                }}>
                  <div style={{ fontWeight: 700, color: '#f8fafc', marginBottom: '4px' }}>
                    Node Inspector: {selectedNode.label}
                  </div>
                  <div style={{ color: 'var(--text-muted)' }}>
                    Linked Evidence Events: {selectedNode.evidence_ids?.join(', ') || 'Direct entity reference'}
                  </div>
                </div>
              )}
            </div>

            {/* Evidence-Grounded Detection Timeline */}
            <div className="soc-card" style={{ padding: '20px' }}>
              <div style={{ fontSize: '0.82rem', fontWeight: 800, color: 'var(--text-main)', marginBottom: '14px' }}>
                GROUNDED DETECTION TIMELINE & REASONING
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {selectedIncident.detections.map((det, idx) => (
                  <div
                    key={det.id || idx}
                    style={{
                      padding: '14px 16px',
                      background: 'rgba(15, 23, 42, 0.4)',
                      borderLeft: det.severity === 'CRITICAL' ? '3px solid #ef4444' : '3px solid #f59e0b',
                      borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '0.82rem', fontWeight: 800, color: '#f8fafc' }}>
                          {det.detection}
                        </span>
                        <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>
                          {det.technique}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.70rem', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                        {det.timestamp}
                      </div>
                    </div>

                    <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>
                      {det.reasoning}
                    </p>

                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center', fontSize: '0.68rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
                      <span>Evidence IDs:</span>
                      {det.evidenceEventIds.map((eid, i) => (
                        <span key={i} style={{ background: 'var(--bg-subtle)', padding: '1px 6px', borderRadius: '3px', color: '#93c5fd' }}>
                          {eid}
                        </span>
                      ))}
                      <span>•</span>
                      <span>Confidence: {Math.round(det.confidence * 100)}%</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

          </div>
        ) : null}

      </div>
    </div>
  );
}
