import React, { useState, useEffect } from 'react';
import { Database, Filter, Search, Server, User, Globe, Lock, Shield, RefreshCw, Terminal, Eye } from 'lucide-react';

export default function TelemetryExplorer() {
  const [scenarios, setScenarios] = useState([]);
  const [selectedScenario, setSelectedScenario] = useState("ssh-bruteforce");
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);

  // Filter states
  const [hostFilter, setHostFilter] = useState("");
  const [userFilter, setUserFilter] = useState("");
  const [ipFilter, setIpFilter] = useState("");
  const [eventTypeFilter, setEventTypeFilter] = useState("");
  const [limit, setLimit] = useState(50);

  useEffect(() => {
    // Fetch available scenarios
    fetch('/api/v1/telemetry/scenarios')
      .then(res => res.json())
      .then(data => setScenarios(data))
      .catch(err => console.error("Scenarios fetch error:", err));

    fetchEvents();
  }, [selectedScenario]);

  const fetchEvents = () => {
    setLoading(true);
    let url = `/api/v1/telemetry/events?limit=${limit}`;
    if (hostFilter) url += `&host=${encodeURIComponent(hostFilter)}`;
    if (userFilter) url += `&user=${encodeURIComponent(userFilter)}`;
    if (ipFilter) url += `&source_ip=${encodeURIComponent(ipFilter)}`;
    if (eventTypeFilter) url += `&event_type=${encodeURIComponent(eventTypeFilter)}`;

    fetch(url)
      .then(res => res.json())
      .then(data => setEvents(data))
      .catch(err => console.error("Events fetch error:", err))
      .finally(() => setLoading(false));
  };

  const handleScenarioChange = (scId) => {
    setSelectedScenario(scId);
    fetch(`/api/v1/telemetry/scenarios/select/${scId}`, { method: 'POST' })
      .then(() => fetchEvents());
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* SYNTHETIC LAB TELEMETRY BANNER */}
      <div className="glass-card" style={{
        padding: '20px 24px',
        background: 'linear-gradient(135deg, rgba(139, 92, 246, 0.15), rgba(7, 10, 18, 0.95))',
        border: '1px solid var(--accent-purple)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '40px',
            height: '40px',
            borderRadius: '8px',
            background: 'rgba(139, 92, 246, 0.2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Database size={22} color="var(--accent-purple)" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h2 style={{ fontSize: '1.1rem', fontWeight: 800 }}>SYNTHETIC LAB TELEMETRY EXPLORER</h2>
              <span className="badge badge-purple">BENCHMARK LAB DATA</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Inspect generated enterprise events, filter telemetry by host/IP, and test laboratory attack scenarios.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <label style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-muted)' }}>LAB SCENARIO:</label>
          <select
            value={selectedScenario}
            onChange={(e) => handleScenarioChange(e.target.value)}
            style={{
              background: 'rgba(2, 6, 23, 0.85)',
              border: '1px solid var(--primary-cyan)',
              color: 'var(--text-main)',
              padding: '8px 14px',
              borderRadius: '6px',
              fontWeight: 700,
              fontSize: '0.85rem'
            }}
          >
            {scenarios.map(sc => (
              <option key={sc.id} value={sc.id}>[{sc.difficulty}] {sc.name}</option>
            ))}
          </select>
        </div>
      </div>

      {/* FILTER BAR */}
      <div className="glass-card" style={{ padding: '16px 20px', display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'rgba(2, 6, 23, 0.8)', padding: '6px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', flex: 1, minWidth: '150px' }}>
          <Server size={14} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="Host (e.g. web-server-01)"
            value={hostFilter}
            onChange={(e) => setHostFilter(e.target.value)}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-main)', fontSize: '0.85rem', width: '100%' }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'rgba(2, 6, 23, 0.8)', padding: '6px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', flex: 1, minWidth: '150px' }}>
          <User size={14} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="User (e.g. root, alice)"
            value={userFilter}
            onChange={(e) => setUserFilter(e.target.value)}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-main)', fontSize: '0.85rem', width: '100%' }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'rgba(2, 6, 23, 0.8)', padding: '6px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', flex: 1, minWidth: '150px' }}>
          <Globe size={14} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="Source IP (e.g. 192.168.100.99)"
            value={ipFilter}
            onChange={(e) => setIpFilter(e.target.value)}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-main)', fontSize: '0.85rem', width: '100%' }}
          />
        </div>

        <select
          value={eventTypeFilter}
          onChange={(e) => setEventTypeFilter(e.target.value)}
          style={{ background: 'rgba(2, 6, 23, 0.8)', border: '1px solid var(--border-color)', color: 'var(--text-main)', padding: '8px 12px', borderRadius: '6px', fontSize: '0.85rem' }}
        >
          <option value="">All Event Types</option>
          <option value="auth">Authentication</option>
          <option value="ssh">SSH</option>
          <option value="process">Process Execution</option>
          <option value="network">Network Traffic</option>
          <option value="dns">DNS Resolution</option>
          <option value="file">File System</option>
          <option value="privilege_escalation">Privilege Escalation</option>
          <option value="web_access">Web Access</option>
        </select>

        <button
          onClick={fetchEvents}
          style={{
            background: 'linear-gradient(135deg, var(--primary-cyan), var(--primary-blue))',
            color: '#070a12',
            fontWeight: 700,
            padding: '8px 16px',
            borderRadius: '6px',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}
        >
          <Filter size={14} />
          APPLY FILTERS
        </button>
      </div>

      {/* EVENTS TABLE & RAW PAYLOAD INSPECTOR */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedEvent ? '1fr 1fr' : '1fr', gap: '20px' }}>
        
        {/* Events Table */}
        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 700 }}>TELEMETRY EVENT STREAM ({events.length} EVENTS)</h3>
            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>MAX CAP: 500 RECORDS</span>
          </div>

          <div style={{ overflowX: 'auto', maxHeight: '550px', overflowY: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '8px 10px' }}>TIMESTAMP</th>
                  <th style={{ padding: '8px 10px' }}>HOST</th>
                  <th style={{ padding: '8px 10px' }}>TYPE</th>
                  <th style={{ padding: '8px 10px' }}>USER</th>
                  <th style={{ padding: '8px 10px' }}>SOURCE IP</th>
                  <th style={{ padding: '8px 10px' }}>STATUS</th>
                  <th style={{ padding: '8px 10px' }}>INSPECT</th>
                </tr>
              </thead>
              <tbody>
                {events.map((evt, idx) => (
                  <tr
                    key={idx}
                    style={{
                      borderBottom: '1px solid rgba(51, 65, 85, 0.3)',
                      background: selectedEvent?.eventId === evt.eventId ? 'rgba(0, 242, 254, 0.1)' : 'transparent',
                      cursor: 'pointer'
                    }}
                    onClick={() => setSelectedEvent(evt)}
                  >
                    <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                      {evt.timestamp.split('T')[1]}
                    </td>
                    <td style={{ padding: '8px 10px', fontWeight: 600, color: 'var(--primary-cyan)' }}>
                      {evt.host}
                    </td>
                    <td style={{ padding: '8px 10px' }}>
                      <span className="badge badge-purple">{evt.eventType}</span>
                    </td>
                    <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)' }}>
                      {evt.user || '-'}
                    </td>
                    <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: evt.sourceIp === '192.168.100.99' ? '#fca5a5' : 'var(--text-muted)' }}>
                      {evt.sourceIp || '-'}
                    </td>
                    <td style={{ padding: '8px 10px' }}>
                      <span className={`badge ${evt.status === 'SUCCESS' || evt.status === 'ALLOWED' ? 'badge-success' : 'badge-danger'}`}>
                        {evt.status}
                      </span>
                    </td>
                    <td style={{ padding: '8px 10px' }}>
                      <Eye size={14} color="var(--primary-cyan)" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Event Payload Inspector */}
        {selectedEvent && (
          <div className="glass-card" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--primary-cyan)' }}>
                EVENT INSPECTOR: {selectedEvent.eventId}
              </h3>
              <button onClick={() => setSelectedEvent(null)} style={{ background: 'transparent', color: 'var(--text-muted)', fontSize: '0.8rem' }}>✕ CLOSE</button>
            </div>

            <div className="code-block" style={{ maxHeight: '480px', overflowY: 'auto' }}>
              {JSON.stringify(selectedEvent, null, 2)}
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
