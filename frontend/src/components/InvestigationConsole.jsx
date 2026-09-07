import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  Activity, 
  Layers, 
  Clock, 
  Server, 
  Terminal, 
  RefreshCw, 
  ArrowRight, 
  CheckCircle2, 
  Radio, 
  FileText, 
  Download, 
  Search,
  ExternalLink,
  ChevronRight,
  Zap,
  Globe,
  Lock,
  Flame
} from 'lucide-react';
import { useEventStream, ConnectionState } from '../services/useEventStream';

const MITRE_STAGES = [
  { id: "INITIAL ACCESS", label: "Initial Access", color: "#f59e0b" },
  { id: "EXECUTION", label: "Execution", color: "#ef4444" },
  { id: "PRIVILEGE ESCALATION", label: "Privilege Escalation", color: "#dc2626" },
  { id: "CREDENTIAL ACCESS", label: "Credential Access", color: "#e11d48" },
  { id: "COLLECTION", label: "Collection", color: "#9333ea" },
  { id: "COMMAND AND CONTROL", label: "C2 Communication", color: "#6366f1" },
  { id: "EXFILTRATION", label: "Exfiltration", color: "#ec4899" }
];

export default function InvestigationConsole({ 
  telemetryMode = 'LIVE_MONITORING', 
  onStartHunt, 
  onOpenReport 
}) {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);

  const {
    connectionState,
    eventsPerSec,
    latestAlert,
    totalEventsReceived
  } = useEventStream({ maxBufferSize: 100, enabled: true });

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
      console.warn("Failed to fetch active incidents:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 2500);
    return () => clearInterval(interval);
  }, []);

  const getModeBadge = () => {
    switch (telemetryMode) {
      case 'SIMULATION':
        return { label: 'SIMULATION MODE', bg: 'rgba(192, 132, 252, 0.15)', border: 'rgba(192, 132, 252, 0.4)', text: '#c084fc' };
      case 'DATASET_REPLAY':
        return { label: 'DATASET REPLAY MODE', bg: 'rgba(59, 130, 246, 0.15)', border: 'rgba(59, 130, 246, 0.4)', text: '#60a5fa' };
      default:
        return { label: 'LIVE MONITORING MODE', bg: 'rgba(16, 185, 129, 0.15)', border: 'rgba(16, 185, 129, 0.4)', text: '#34d399' };
    }
  };

  const modeBadge = getModeBadge();

  // Aggregate metrics across all active incidents
  const allAffectedHosts = Array.from(new Set(incidents.flatMap(i => i.affected_hosts || [])));
  const allSourceIps = Array.from(new Set(incidents.flatMap(i => i.source_ips || [])));
  const criticalCount = incidents.filter(i => i.severity === 'CRITICAL').length;
  const highCount = incidents.filter(i => i.severity === 'HIGH').length;

  const filteredIncidents = incidents.filter(i => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      i.title?.toLowerCase().includes(q) ||
      i.incident_id?.toLowerCase().includes(q) ||
      i.affected_hosts?.some(h => h.toLowerCase().includes(q)) ||
      i.source_ips?.some(ip => ip.includes(q))
    );
  });

  const selectedIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0] || null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Top Banner & Mode Tag */}
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
            <span style={{
              background: modeBadge.bg,
              border: `1px solid ${modeBadge.border}`,
              color: modeBadge.text,
              fontSize: '0.72rem',
              fontWeight: 800,
              padding: '2px 8px',
              borderRadius: '4px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px'
            }}>
              <span className="pulse-dot" style={{ background: modeBadge.text, width: '6px', height: '6px' }} />
              {modeBadge.label}
            </span>
            <span className="badge badge-info">Zero Label Leakage Pipeline</span>
            <span className="badge badge-success">Live Graph Engine</span>
          </div>
          <h2 className="page-title" style={{ fontSize: '1.4rem' }}>
            Unified SOC Threat Investigation Console
          </h2>
          <p className="page-subtitle" style={{ maxWidth: '800px', fontSize: '0.85rem' }}>
            End-to-end security correlation pipeline: Real telemetry & replay events → behavioral detection rules → dynamic entity attack graphs → MITRE ATT&CK kill-chain mapping → autonomous investigation.
          </p>
        </div>

        {/* Global Quick Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {onOpenReport && (
            <button
              onClick={onOpenReport}
              className="btn btn-secondary"
              style={{ padding: '8px 14px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <FileText size={14} />
              Executive Report
            </button>
          )}
          {onStartHunt && (
            <button
              onClick={onStartHunt}
              className="btn btn-primary"
              style={{ padding: '8px 16px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Terminal size={14} />
              Open Hunt Workstation
            </button>
          )}
          <button
            onClick={fetchIncidents}
            className="btn btn-secondary"
            style={{ padding: '8px 12px', fontSize: '0.8rem' }}
          >
            <RefreshCw size={14} className={loading ? "spin-icon" : ""} />
          </button>
        </div>
      </div>

      {/* Real-Time Operational Metrics Strip */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '14px'
      }}>
        {/* Metric 1: Active Incidents */}
        <div className="soc-card" style={{ padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.70rem', fontWeight: 700, color: 'var(--text-muted)' }}>ACTIVE INCIDENTS</span>
            <Flame size={15} color="#ef4444" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#f8fafc' }}>
            {incidents.length}
          </div>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>
            <span style={{ color: '#ef4444', fontWeight: 700 }}>{criticalCount} Critical</span> • <span style={{ color: '#f59e0b' }}>{highCount} High</span>
          </div>
        </div>

        {/* Metric 2: Live Stream Rate */}
        <div className="soc-card" style={{ padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.70rem', fontWeight: 700, color: 'var(--text-muted)' }}>STREAM THROUGHPUT</span>
            <Activity size={15} color="#38bdf8" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#38bdf8' }}>
            {eventsPerSec} EPS
          </div>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>
            {totalEventsReceived.toLocaleString()} events received
          </div>
        </div>

        {/* Metric 3: Compromised / Affected Hosts */}
        <div className="soc-card" style={{ padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.70rem', fontWeight: 700, color: 'var(--text-muted)' }}>AFFECTED HOSTS</span>
            <Server size={15} color="#10b981" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#10b981' }}>
            {allAffectedHosts.length || 0}
          </div>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {allAffectedHosts.slice(0, 2).join(', ') || 'No impacted endpoints'}
          </div>
        </div>

        {/* Metric 4: Attacker / Source IPs */}
        <div className="soc-card" style={{ padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.70rem', fontWeight: 700, color: 'var(--text-muted)' }}>ATTACKER SOURCE IPS</span>
            <Globe size={15} color="#f87171" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#f87171' }}>
            {allSourceIps.length || 0}
          </div>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {allSourceIps.slice(0, 2).join(', ') || 'No active adversaries'}
          </div>
        </div>
      </div>

      {/* Main Grid: Incidents Master (Left) + Detail & Attack Graph (Right) */}
      <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: '20px', alignItems: 'start' }}>
        
        {/* Left Column: Active Incidents List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 800, color: 'var(--text-main)', letterSpacing: '0.04em' }}>
              INCIDENT QUEUE ({filteredIncidents.length})
            </span>
            <span style={{ fontSize: '0.70rem', color: 'var(--text-dim)' }}>Auto-correlating</span>
          </div>

          {/* Search Box */}
          <div style={{ position: 'relative' }}>
            <Search size={14} color="var(--text-dim)" style={{ position: 'absolute', left: '10px', top: '9px' }} />
            <input
              type="text"
              placeholder="Filter by host, IP, title..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: '100%',
                background: 'var(--bg-panel)',
                border: '1px solid var(--border-color)',
                borderRadius: 'var(--radius-sm)',
                padding: '6px 10px 6px 30px',
                fontSize: '0.75rem',
                color: '#f8fafc'
              }}
            />
          </div>

          {/* Incident Cards */}
          {filteredIncidents.length === 0 ? (
            <div className="soc-card" style={{ padding: '32px 20px', textAlign: 'center' }}>
              <Shield size={32} color="var(--text-dim)" style={{ margin: '0 auto 10px auto' }} />
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-muted)' }}>
                No matching incidents
              </div>
              <p style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '4px' }}>
                Launch a simulated scenario or connect a Linux agent to generate live security incidents.
              </p>
            </div>
          ) : (
            filteredIncidents.map(inc => {
              const isSelected = selectedIncident?.incident_id === inc.incident_id;
              const isCritical = inc.severity === 'CRITICAL';
              return (
                <div
                  key={inc.incident_id}
                  onClick={() => setSelectedIncidentId(inc.incident_id)}
                  className="soc-card"
                  style={{
                    padding: '14px',
                    cursor: 'pointer',
                    borderLeft: isSelected ? '4px solid var(--accent-blue)' : (isCritical ? '4px solid #ef4444' : '4px solid #f59e0b'),
                    background: isSelected ? 'rgba(59, 130, 246, 0.08)' : 'var(--bg-panel)',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <span style={{ fontSize: '0.70rem', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', fontWeight: 700 }}>
                      {inc.incident_id.toUpperCase()}
                    </span>
                    <span className={`badge ${isCritical ? 'badge-danger' : 'badge-warning'}`} style={{ fontSize: '0.62rem' }}>
                      {inc.severity}
                    </span>
                  </div>

                  <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#f8fafc', marginBottom: '6px', lineHeight: 1.3 }}>
                    {inc.title}
                  </div>

                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px', marginBottom: '8px' }}>
                    {inc.mitre_tactics?.slice(0, 3).map((t, idx) => (
                      <span key={idx} style={{
                        fontSize: '0.62rem',
                        background: 'rgba(59, 130, 246, 0.15)',
                        border: '1px solid rgba(59, 130, 246, 0.3)',
                        color: '#93c5fd',
                        padding: '1px 5px',
                        borderRadius: '3px',
                        fontWeight: 600
                      }}>
                        {t}
                      </span>
                    ))}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.68rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                    <span>{inc.affected_hosts[0] || 'Infrastructure'}</span>
                    <span>{inc.detections?.length || 0} detections</span>
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
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                    <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', fontWeight: 800 }}>
                      {selectedIncident.incident_id.toUpperCase()}
                    </span>
                    <span className={`badge ${selectedIncident.severity === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}`}>
                      {selectedIncident.severity}
                    </span>
                    <span className="badge badge-info">
                      Confidence: {Math.round(selectedIncident.confidence * 100)}%
                    </span>
                  </div>
                  <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#f8fafc', marginBottom: '6px' }}>
                    {selectedIncident.title}
                  </h3>
                  <div style={{ display: 'flex', gap: '14px', fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    <span>Started: {selectedIncident.start_time}</span>
                    <span>•</span>
                    <span>Last Seen: {selectedIncident.last_seen}</span>
                  </div>
                </div>

                {onStartHunt && (
                  <button
                    onClick={onStartHunt}
                    className="btn btn-primary"
                    style={{ padding: '8px 14px', fontSize: '0.80rem' }}
                  >
                    <Terminal size={14} />
                    Investigate in Workstation
                    <ArrowRight size={14} />
                  </button>
                )}
              </div>

              {/* Entity Badges Grid */}
              <div style={{
                marginTop: '14px',
                paddingTop: '14px',
                borderTop: '1px solid var(--border-subtle)',
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
                gap: '10px'
              }}>
                <div>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', fontWeight: 700, marginBottom: '4px' }}>ATTACKER IPS</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {selectedIncident.source_ips.map((ip, i) => (
                      <span key={i} className="badge badge-danger" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.70rem' }}>
                        {ip}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', fontWeight: 700, marginBottom: '4px' }}>AFFECTED HOSTS</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {selectedIncident.affected_hosts.map((h, i) => (
                      <span key={i} className="badge badge-warning" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.70rem' }}>
                        {h}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', fontWeight: 700, marginBottom: '4px' }}>TARGETED USERS</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {selectedIncident.users.map((u, i) => (
                      <span key={i} className="badge badge-info" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.70rem' }}>
                        {u}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* MITRE ATT&CK Kill-Chain Progression Bar */}
            <div className="soc-card" style={{ padding: '16px 20px' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 800, color: 'var(--text-main)', marginBottom: '10px', letterSpacing: '0.04em' }}>
                MITRE ATT&CK PROGRESSION
              </div>
              <div style={{ display: 'flex', gap: '6px', overflowX: 'auto', paddingBottom: '4px' }}>
                {MITRE_STAGES.map((stg, idx) => {
                  const isHit = selectedIncident.mitre_tactics?.some(t => t.toUpperCase() === stg.id);
                  return (
                    <div
                      key={idx}
                      style={{
                        flex: '1 0 100px',
                        background: isHit ? 'rgba(239, 68, 68, 0.15)' : 'rgba(15, 23, 42, 0.4)',
                        border: isHit ? '1px solid rgba(239, 68, 68, 0.5)' : '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                        padding: '6px 8px',
                        textAlign: 'center'
                      }}
                    >
                      <div style={{ fontSize: '0.60rem', fontFamily: 'var(--font-mono)', color: isHit ? '#ef4444' : 'var(--text-dim)', fontWeight: 700 }}>
                        STAGE {idx + 1}
                      </div>
                      <div style={{ fontSize: '0.68rem', fontWeight: 700, color: isHit ? '#fca5a5' : 'var(--text-dim)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {stg.label}
                      </div>
                      {isHit && (
                        <div style={{ marginTop: '2px', fontSize: '0.58rem', color: '#ef4444', fontWeight: 800 }}>
                          ● DETECTED
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Interactive Attack Graph */}
            <div className="soc-card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <div>
                  <div style={{ fontSize: '0.80rem', fontWeight: 800, color: 'var(--text-main)' }}>
                    CAUSAL ATTACK GRAPH
                  </div>
                  <div style={{ fontSize: '0.70rem', color: 'var(--text-dim)' }}>
                    Directional progression: Attacker IP → Account → Host → Exploit Stage → C2 Exfiltration
                  </div>
                </div>
                <span className="badge badge-info" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem' }}>
                  {selectedIncident.attack_graph?.nodes?.length || 0} Nodes • {selectedIncident.attack_graph?.edges?.length || 0} Edges
                </span>
              </div>

              {/* Graph Nodes */}
              <div style={{
                background: '#040406',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                padding: '20px',
                minHeight: '180px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '18px',
                flexWrap: 'wrap'
              }}>
                {selectedIncident.attack_graph?.nodes?.map((node, i) => {
                  let color = '#3b82f6';
                  if (node.type === 'IP') color = '#ef4444';
                  if (node.type === 'USER') color = '#f59e0b';
                  if (node.type === 'HOST') color = '#10b981';
                  if (node.type === 'STAGE') color = '#8b5cf6';

                  return (
                    <React.Fragment key={node.id}>
                      <div
                        onClick={() => setSelectedNode(node)}
                        style={{
                          background: 'rgba(15, 23, 42, 0.8)',
                          border: `2px solid ${color}`,
                          borderRadius: 'var(--radius-sm)',
                          padding: '10px 14px',
                          cursor: 'pointer',
                          minWidth: '130px'
                        }}
                      >
                        <div style={{ fontSize: '0.62rem', fontWeight: 800, color: color, fontFamily: 'var(--font-mono)' }}>
                          {node.type}
                        </div>
                        <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#f8fafc', wordBreak: 'break-all' }}>
                          {node.value}
                        </div>
                      </div>

                      {i < (selectedIncident.attack_graph?.nodes?.length - 1) && (
                        <div style={{ color: 'var(--text-dim)' }}>
                          <ArrowRight size={16} />
                        </div>
                      )}
                    </React.Fragment>
                  );
                })}
              </div>

              {/* Node Inspector */}
              {selectedNode && (
                <div style={{
                  marginTop: '10px',
                  padding: '10px 14px',
                  background: 'rgba(15, 23, 42, 0.5)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.72rem'
                }}>
                  <div style={{ fontWeight: 700, color: '#f8fafc' }}>
                    Inspected Node: {selectedNode.label}
                  </div>
                  <div style={{ color: 'var(--text-muted)' }}>
                    Linked Evidence: {selectedNode.evidence_ids?.join(', ') || 'Direct entity reference'}
                  </div>
                </div>
              )}
            </div>

            {/* Evidence-Grounded Detection Timeline */}
            <div className="soc-card" style={{ padding: '20px' }}>
              <div style={{ fontSize: '0.80rem', fontWeight: 800, color: 'var(--text-main)', marginBottom: '12px' }}>
                GROUNDED DETECTION TIMELINE ({selectedIncident.detections?.length || 0})
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {selectedIncident.detections?.map((det, idx) => (
                  <div
                    key={det.id || idx}
                    style={{
                      padding: '12px 14px',
                      background: 'rgba(15, 23, 42, 0.4)',
                      borderLeft: det.severity === 'CRITICAL' ? '3px solid #ef4444' : '3px solid #f59e0b',
                      borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '4px'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span style={{ fontSize: '0.80rem', fontWeight: 800, color: '#f8fafc' }}>
                          {det.detection}
                        </span>
                        <span className="badge badge-info" style={{ fontSize: '0.62rem' }}>
                          {det.technique}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.68rem', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                        {det.timestamp}
                      </div>
                    </div>

                    <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.3 }}>
                      {det.reasoning}
                    </p>

                    <div style={{ display: 'flex', gap: '6px', alignItems: 'center', fontSize: '0.65rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                      <span>Evidence:</span>
                      {det.evidenceEventIds?.map((eid, i) => (
                        <span key={i} style={{ background: 'var(--bg-subtle)', padding: '1px 5px', borderRadius: '3px', color: '#93c5fd' }}>
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
