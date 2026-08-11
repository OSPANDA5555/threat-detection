import React from 'react';
import { Activity, Clock, Shield, Terminal, ArrowRight } from 'lucide-react';

export default function TimelineView() {
  const events = [
    {
      time: "2026-08-10T19:30:15Z",
      type: "AUTHENTICATION",
      title: "SSH Authentication Failure Surge Start",
      details: "18 failed password attempts recorded for root from IP 192.168.1.105 targeting srv-prod-linux01",
      severity: "HIGH"
    },
    {
      time: "2026-08-10T19:30:45Z",
      type: "NETWORK",
      title: "Elevated TCP Port 22 Connection Volume",
      details: "High frequency connection attempts from 192.168.1.105 to 10.0.0.12",
      severity: "MEDIUM"
    },
    {
      time: "2026-08-10T19:31:00Z",
      type: "DNS",
      title: "Internal Domain Query Resolution",
      details: "Client host 10.0.0.12 queried c2-control-node.internal",
      severity: "LOW"
    }
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="glass-card" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.2rem', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Activity size={20} color="var(--primary-cyan)" />
            CHRONOLOGICAL INVESTIGATION TIMELINE
          </h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Unified view of telemetry events across authentication, network, DNS, and host execution.
          </p>
        </div>
        <span className="badge badge-info">{events.length} CHRONOLOGICAL EVENTS</span>
      </div>

      <div className="glass-card" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', position: 'relative' }}>
          {events.map((evt, idx) => (
            <div key={idx} style={{ display: 'flex', gap: '16px', alignItems: 'flex-start' }}>
              <div style={{
                width: '120px',
                fontSize: '0.78rem',
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-muted)',
                textAlign: 'right',
                paddingTop: '2px'
              }}>
                {evt.time.split('T')[1]}
              </div>

              <div style={{
                width: '12px',
                height: '12px',
                borderRadius: '50%',
                background: evt.severity === 'HIGH' ? 'var(--accent-crimson)' : 'var(--primary-cyan)',
                boxShadow: evt.severity === 'HIGH' ? '0 0 8px var(--accent-crimson)' : '0 0 8px var(--primary-cyan)',
                marginTop: '4px'
              }} />

              <div style={{
                flex: 1,
                background: 'rgba(2, 6, 23, 0.6)',
                border: '1px solid var(--border-color)',
                borderRadius: '8px',
                padding: '14px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontWeight: 700, fontSize: '0.95rem', color: '#f8fafc' }}>{evt.title}</span>
                  <span className={`badge ${evt.severity === 'HIGH' ? 'badge-danger' : 'badge-info'}`}>{evt.type}</span>
                </div>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{evt.details}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
