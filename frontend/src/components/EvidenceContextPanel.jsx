import React from 'react';
import { Database, FileText, Globe, Server, User, Hash, Clock, AlertCircle } from 'lucide-react';

export default function EvidenceContextPanel({ selectedEvidence, onClose }) {
  if (!selectedEvidence) {
    return (
      <div className="soc-card soc-inspector-right" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '350px', textAlign: 'center', color: 'var(--text-dim)' }}>
        <Database size={32} color="var(--border-active)" style={{ marginBottom: '12px' }} />
        <div style={{ fontSize: '0.88rem', fontWeight: 700, color: 'var(--text-muted)' }}>EVIDENCE INSPECTOR</div>
        <p style={{ fontSize: '0.78rem', marginTop: '6px', maxWidth: '240px' }}>
          Click any <code style={{ color: 'var(--accent-blue)', background: 'var(--bg-subtle)', padding: '2px 4px' }}>[EVID-xxx]</code> reference in findings or execution traces to inspect raw log payload details.
        </p>
      </div>
    );
  }

  return (
    <div className="soc-card soc-inspector-right" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <FileText size={16} color="var(--accent-blue)" />
          <span style={{ fontSize: '0.85rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#fafafa' }}>
            {selectedEvidence.id}
          </span>
        </div>
        <button onClick={onClose} style={{ background: 'transparent', color: 'var(--text-dim)', fontSize: '0.8rem', fontWeight: 700 }}>
          ✕ CLOSE
        </button>
      </div>

      {/* WHY IT MATTERS */}
      <div style={{ background: 'var(--accent-blue-subtle)', border: '1px solid rgba(37, 99, 235, 0.3)', borderRadius: 'var(--radius-sm)', padding: '10px 12px' }}>
        <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#60a5fa', marginBottom: '4px', letterSpacing: '0.04em' }}>
          WHY THIS EVIDENCE MATTERS:
        </div>
        <p style={{ fontSize: '0.82rem', color: '#e4e4e7', lineHeight: 1.4 }}>
          {selectedEvidence.relevance}
        </p>
      </div>

      {/* FIELD METADATA LIST */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '0.78rem' }}>
        <div className="soc-card-subtle">
          <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem' }}>TIMESTAMP</span>
          <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{selectedEvidence.timestamp?.split('T')?.[1] || selectedEvidence.timestamp}</div>
        </div>

        <div className="soc-card-subtle">
          <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem' }}>EVENT TYPE</span>
          <div><span className="badge badge-purple">{selectedEvidence.eventType}</span></div>
        </div>

        <div className="soc-card-subtle">
          <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem' }}>TARGET HOST</span>
          <div style={{ fontWeight: 700, color: '#fafafa' }}>{selectedEvidence.host || 'N/A'}</div>
        </div>

        <div className="soc-card-subtle">
          <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem' }}>USER</span>
          <div style={{ fontFamily: 'var(--font-mono)' }}>{selectedEvidence.user || 'N/A'}</div>
        </div>

        <div className="soc-card-subtle">
          <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem' }}>SOURCE IP</span>
          <div style={{ fontFamily: 'var(--font-mono)', color: '#f87171', fontWeight: 700 }}>{selectedEvidence.sourceIp || 'N/A'}</div>
        </div>

        <div className="soc-card-subtle">
          <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem' }}>DESTINATION IP</span>
          <div style={{ fontFamily: 'var(--font-mono)' }}>{selectedEvidence.destinationIp || 'N/A'}</div>
        </div>
      </div>

      {/* RAW EVENT REFERENCE */}
      <div>
        <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '4px' }}>
          RAW REFERENCE POINTER:
        </div>
        <div className="code-block" style={{ fontSize: '0.75rem' }}>
          {selectedEvidence.rawReference}
        </div>
      </div>

      {/* NORMALIZED PAYLOAD JSON */}
      <div>
        <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '4px' }}>
          NORMALIZED PAYLOAD:
        </div>
        <div className="code-block" style={{ fontSize: '0.72rem', maxHeight: '180px', overflowY: 'auto' }}>
          {JSON.stringify(selectedEvidence.normalizedData, null, 2)}
        </div>
      </div>
    </div>
  );
}
