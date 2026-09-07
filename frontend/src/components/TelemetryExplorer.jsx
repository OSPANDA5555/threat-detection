import React, { useState, useEffect } from 'react';
import { 
  Database, 
  Filter, 
  Search, 
  Server, 
  User, 
  Globe, 
  Lock, 
  Shield, 
  RefreshCw, 
  Terminal, 
  Eye, 
  Layers, 
  Cpu, 
  FileText, 
  AlertTriangle, 
  CheckCircle2, 
  Share2, 
  Sparkles,
  ArrowRight
} from 'lucide-react';

const WORKSTATION_OPTIONS = [
  { id: 'all', name: 'ALL ENDPOINTS & WORKSTATIONS', role: 'Enterprise Fleet', ip: '10.0.1.0/24' },
  { id: 'workstation-01', name: 'workstation-01', role: 'Executive / HR (Win 11)', ip: '10.0.1.50' },
  { id: 'workstation-02', name: 'workstation-02', role: 'DevOps Endpoint (Ubuntu)', ip: '10.0.1.51' },
  { id: 'web-server-01', name: 'web-server-01', role: 'DMZ Web Server (Ubuntu)', ip: '10.0.1.10' },
  { id: 'db-server-01', name: 'db-server-01', role: 'Core Database (RHEL 9)', ip: '10.0.1.20' },
  { id: 'jump-host-01', name: 'jump-host-01', role: 'Admin Bastion (Debian)', ip: '10.0.1.5' }
];

const LOG_SOURCE_OPTIONS = [
  { id: 'auth', label: 'Authentication', sub: 'SSH, PAM, Windows Auth' },
  { id: 'process', label: 'Process Execution', sub: 'Auditd, Sysmon, CLI' },
  { id: 'network', label: 'Network Flows', sub: 'NetFlow, Firewall, Egress' },
  { id: 'dns', label: 'DNS Queries', sub: 'CoreDNS, TXT Beacons' },
  { id: 'file', label: 'File Integrity', sub: 'FIM, /etc/shadow, Dumps' }
];

export default function TelemetryExplorer({ onNavigateToHunt }) {
  const [scenarios, setScenarios] = useState([]);
  const [selectedScenario, setSelectedScenario] = useState("ssh-bruteforce");
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);

  // Multi-Workstation & Multi-Log Selection
  const [selectedHosts, setSelectedHosts] = useState(['all']);
  const [selectedLogSources, setSelectedLogSources] = useState(['auth', 'process', 'network', 'dns', 'file']);
  const [indicatorSearch, setIndicatorSearch] = useState('');
  const [collectionStats, setCollectionStats] = useState(null);

  // Filters
  const [userFilter, setUserFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [limit, setLimit] = useState(100);

  useEffect(() => {
    fetch('/api/v1/telemetry/scenarios')
      .then(res => res.json())
      .then(data => setScenarios(data))
      .catch(err => console.error("Scenarios fetch error:", err));

    handleCollectData();
  }, [selectedScenario]);

  const handleCollectData = () => {
    setLoading(true);
    const payload = {
      hosts: selectedHosts.includes('all') ? ['all'] : selectedHosts,
      log_sources: selectedLogSources,
      indicator: indicatorSearch || undefined,
      limit: limit
    };

    fetch('/api/v1/telemetry/collect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
      .then(res => {
        if (!res.ok) throw new Error("Collection API failure");
        return res.json();
      })
      .then(data => {
        setEvents(data.events || []);
        setCollectionStats(data);
      })
      .catch(err => {
        // Fallback local query
        let url = `/api/v1/telemetry/events?limit=${limit}`;
        if (!selectedHosts.includes('all') && selectedHosts.length === 1) {
          url += `&host=${encodeURIComponent(selectedHosts[0])}`;
        }
        fetch(url)
          .then(res => res.json())
          .then(data => {
            setEvents(data);
            setCollectionStats({
              total_events_collected: data.length,
              workstations_ingested: selectedHosts,
              log_sources_aggregated: selectedLogSources,
              anomalies_detected_count: data.filter(e => e.status === 'FAILURE').length,
              anomalies: []
            });
          });
      })
      .finally(() => setLoading(false));
  };

  const toggleHostSelection = (hostId) => {
    if (hostId === 'all') {
      setSelectedHosts(['all']);
      return;
    }
    let updated = selectedHosts.filter(h => h !== 'all');
    if (updated.includes(hostId)) {
      updated = updated.filter(h => h !== hostId);
      if (updated.length === 0) updated = ['all'];
    } else {
      updated.push(hostId);
    }
    setSelectedHosts(updated);
  };

  const toggleLogSource = (sourceId) => {
    if (selectedLogSources.includes(sourceId)) {
      if (selectedLogSources.length <= 1) return;
      setSelectedLogSources(selectedLogSources.filter(s => s !== sourceId));
    } else {
      setSelectedLogSources([...selectedLogSources, sourceId]);
    }
  };

  const handleScenarioChange = (scId) => {
    setSelectedScenario(scId);
    fetch(`/api/v1/telemetry/scenarios/select/${scId}`, { method: 'POST' })
      .then(() => handleCollectData());
  };

  const filteredEvents = events.filter(evt => {
    if (userFilter && (!evt.user || !evt.user.toLowerCase().includes(userFilter.toLowerCase()))) return false;
    if (statusFilter && evt.status !== statusFilter) return false;
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* MULTI-WORKSTATION & LOG COLLECTOR BANNER */}
      <div className="soc-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <Database size={24} color="var(--accent-blue)" />
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h2 className="page-title">
                Telemetry collector
              </h2>
              <span className="badge badge-info">Multi-host correlation</span>
            </div>
            <p className="page-subtitle">
              Ingest, aggregate, and normalize telemetry from distributed endpoints (Auth, Process, NetFlow, DNS, File integrity).
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '0.76rem', fontWeight: 800, color: 'var(--text-dim)' }}>LAB SCENARIO:</span>
          <select
            value={selectedScenario}
            onChange={(e) => handleScenarioChange(e.target.value)}
            style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-color)',
              color: 'var(--text-main)',
              padding: '6px 12px',
              borderRadius: 'var(--radius-sm)',
              fontWeight: 700,
              fontSize: '0.80rem'
            }}
          >
            {scenarios.map(sc => (
              <option key={sc.id} value={sc.id}>[{sc.difficulty}] {sc.name}</option>
            ))}
          </select>
        </div>
      </div>

      {/* COLLECTOR CONTROLS: HOSTS & LOG SOURCES */}
      <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        
        {/* Row 1: Target Workstations & Endpoints */}
        <div>
          <div className="section-label" style={{ marginBottom: '8px' }}>
            1. Target endpoints
          </div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {WORKSTATION_OPTIONS.map(ws => {
              const isSelected = selectedHosts.includes(ws.id);
              return (
                <button
                  key={ws.id}
                  onClick={() => toggleHostSelection(ws.id)}
                  style={{
                    background: isSelected ? 'var(--accent-blue-subtle)' : 'var(--bg-subtle)',
                    border: isSelected ? '1px solid var(--accent-blue)' : '1px solid var(--border-color)',
                    color: isSelected ? '#60a5fa' : 'var(--text-dim)',
                    padding: '6px 12px',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '0.76rem',
                    fontWeight: 700,
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'flex-start',
                    textAlign: 'left'
                  }}
                >
                  <span style={{ fontWeight: 800, color: isSelected ? '#f8fafc' : 'inherit' }}>{ws.name}</span>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>{ws.role}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Row 2: Log Source Streams */}
        <div>
          <div className="section-label" style={{ marginBottom: '8px' }}>
            2. Log sources
          </div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {LOG_SOURCE_OPTIONS.map(src => {
              const isSelected = selectedLogSources.includes(src.id);
              return (
                <button
                  key={src.id}
                  onClick={() => toggleLogSource(src.id)}
                  style={{
                    background: isSelected ? 'rgba(16, 185, 129, 0.12)' : 'var(--bg-subtle)',
                    border: isSelected ? '1px solid #10b981' : '1px solid var(--border-color)',
                    color: isSelected ? '#34d399' : 'var(--text-dim)',
                    padding: '6px 12px',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '0.76rem',
                    fontWeight: 700,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  <CheckCircle2 size={13} color={isSelected ? '#34d399' : 'var(--text-muted)'} />
                  <span>{src.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Row 3: Action Toolbar & Indicator Query */}
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center', borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'var(--bg-subtle)', padding: '6px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', flex: 1, minWidth: '220px' }}>
            <Search size={14} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Filter by indicator (IP, user, hash, process)..."
              value={indicatorSearch}
              onChange={(e) => setIndicatorSearch(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleCollectData(); }}
              style={{ background: 'transparent', border: 'none', color: '#f8fafc', fontSize: '0.80rem', width: '100%' }}
            />
          </div>

          <button
            onClick={handleCollectData}
            disabled={loading}
            className="btn btn-primary"
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            {loading ? 'Collecting…' : 'Collect & correlate'}
          </button>
        </div>

      </div>

      {/* AGGREGATED COLLECTION METRICS STRIP */}
      {collectionStats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
          <div className="soc-card" style={{ padding: '12px 16px' }}>
            <span style={{ fontSize: '0.68rem', fontWeight: 800, color: 'var(--text-dim)', letterSpacing: '0.04em' }}>TOTAL EVENTS COLLECTED</span>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#f8fafc', marginTop: '2px' }}>
              {collectionStats.total_events_collected}
            </div>
          </div>

          <div className="soc-card" style={{ padding: '12px 16px' }}>
            <span style={{ fontSize: '0.68rem', fontWeight: 800, color: 'var(--text-dim)', letterSpacing: '0.04em' }}>WORKSTATIONS INGESTED</span>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#60a5fa', marginTop: '2px' }}>
              {collectionStats.workstations_ingested?.length || 0} Hosts
            </div>
          </div>

          <div className="soc-card" style={{ padding: '12px 16px' }}>
            <span style={{ fontSize: '0.68rem', fontWeight: 800, color: 'var(--text-dim)', letterSpacing: '0.04em' }}>LOG SOURCES AGGREGATED</span>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#34d399', marginTop: '2px' }}>
              {collectionStats.log_sources_aggregated?.length || 0} Types
            </div>
          </div>

          <div className="soc-card" style={{ padding: '12px 16px' }}>
            <span style={{ fontSize: '0.68rem', fontWeight: 800, color: 'var(--text-dim)', letterSpacing: '0.04em' }}>ANOMALIES FLAGGED</span>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--status-red)', marginTop: '2px' }}>
              {collectionStats.anomalies_detected_count || 0}
            </div>
          </div>
        </div>
      )}

      {/* UNIFIED CROSS-WORKSTATION EVENTS TABLE & INSPECTOR */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedEvent ? '1fr 380px' : '1fr', gap: '20px' }}>
        
        {/* Events Table */}
        <div className="soc-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Layers size={16} color="var(--accent-blue)" />
              <h3 style={{ fontSize: '0.9rem', fontWeight: 700, color: '#f8fafc' }}>
                Telemetry stream <span className="metric-value" style={{ color: 'var(--text-muted)', fontWeight: 600 }}>({filteredEvents.length})</span>
              </h3>
            </div>

            <div style={{ display: 'flex', gap: '8px' }}>
              <input
                type="text"
                placeholder="User filter..."
                value={userFilter}
                onChange={(e) => setUserFilter(e.target.value)}
                style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-color)', color: '#f8fafc', padding: '4px 8px', borderRadius: '4px', fontSize: '0.72rem' }}
              />
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-color)', color: '#f8fafc', padding: '4px 8px', borderRadius: '4px', fontSize: '0.72rem' }}
              >
                <option value="">All Statuses</option>
                <option value="SUCCESS">SUCCESS</option>
                <option value="FAILURE">FAILURE</option>
                <option value="DENIED">DENIED</option>
              </select>
            </div>
          </div>

          <div style={{ overflowX: 'auto', maxHeight: '520px', overflowY: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.78rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-dim)' }}>
                  <th style={{ padding: '8px 10px' }}>TIMESTAMP</th>
                  <th style={{ padding: '8px 10px' }}>WORKSTATION / HOST</th>
                  <th style={{ padding: '8px 10px' }}>LOG SOURCE</th>
                  <th style={{ padding: '8px 10px' }}>USER</th>
                  <th style={{ padding: '8px 10px' }}>ENDPOINT / IP</th>
                  <th style={{ padding: '8px 10px' }}>ACTION</th>
                  <th style={{ padding: '8px 10px' }}>STATUS</th>
                  <th style={{ padding: '8px 10px' }}>INSPECT</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.length === 0 && (
                  <tr>
                    <td colSpan={8}>
                      <div className="empty-state">
                        No events collected yet.<br />
                        Select endpoints above and run “Collect & correlate”.
                      </div>
                    </td>
                  </tr>
                )}
                {filteredEvents.map((evt, idx) => (
                  <tr
                    key={idx}
                    onClick={() => setSelectedEvent(evt)}
                    style={{
                      borderBottom: '1px solid var(--border-subtle)',
                      background: selectedEvent?.eventId === evt.eventId ? 'var(--accent-blue-subtle)' : 'transparent',
                      cursor: 'pointer'
                    }}
                  >
                    <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                      {evt.timestamp?.split('T')[1] || evt.timestamp}
                    </td>
                    <td style={{ padding: '8px 10px', fontWeight: 700, color: '#60a5fa' }}>
                      {evt.host}
                    </td>
                    <td style={{ padding: '8px 10px' }}>
                      <span className="badge" style={{ background: 'rgba(59, 130, 246, 0.15)', color: '#93c5fd' }}>
                        {evt.eventType}
                      </span>
                    </td>
                    <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)' }}>
                      {evt.user || '-'}
                    </td>
                    <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: evt.sourceIp === '192.168.100.99' ? '#fca5a5' : 'var(--text-dim)' }}>
                      {evt.sourceIp || evt.destinationIp || '-'}
                    </td>
                    <td style={{ padding: '8px 10px', fontWeight: 600 }}>
                      {evt.action}
                    </td>
                    <td style={{ padding: '8px 10px' }}>
                      <span className={`badge ${evt.status === 'SUCCESS' || evt.status === 'ALLOWED' ? 'badge-success' : 'badge-danger'}`}>
                        {evt.status}
                      </span>
                    </td>
                    <td style={{ padding: '8px 10px' }}>
                      <Eye size={14} color="var(--accent-blue)" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Raw Log Event Inspector */}
        {selectedEvent && (
          <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px' }}>
              <div>
                <span className="badge badge-info">{selectedEvent.eventType} EVENT</span>
                <h3 style={{ fontSize: '0.90rem', fontWeight: 800, color: '#f8fafc', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
                  {selectedEvent.eventId}
                </h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                style={{ background: 'transparent', color: 'var(--text-dim)', fontSize: '0.80rem', fontWeight: 700 }}
              >
                ✕ CLOSE
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '0.75rem' }}>
              <div className="soc-card-subtle">
                <span style={{ color: 'var(--text-dim)', fontSize: '0.68rem', fontWeight: 700 }}>WORKSTATION</span>
                <div style={{ fontWeight: 800, color: '#60a5fa', marginTop: '2px' }}>{selectedEvent.host}</div>
              </div>
              <div className="soc-card-subtle">
                <span style={{ color: 'var(--text-dim)', fontSize: '0.68rem', fontWeight: 700 }}>USER ACCOUNT</span>
                <div style={{ fontWeight: 800, color: '#f8fafc', marginTop: '2px' }}>{selectedEvent.user || 'SYSTEM'}</div>
              </div>
            </div>

            <div className="code-block" style={{ fontSize: '0.76rem', maxHeight: '360px', overflowY: 'auto' }}>
              {JSON.stringify(selectedEvent, null, 2)}
            </div>
          </div>
        )}

      </div>

    </div>
  );
}
