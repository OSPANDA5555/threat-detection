import React, { useState } from 'react';
import { Database, FileText, Globe, Server, User, Hash, Clock, AlertCircle, Copy, Check, ChevronRight } from 'lucide-react';

export default function EvidenceContextPanel({ selectedEvidence, timelineEvents, onSelectEvidenceId, onClose }) {
  const [copiedId, setCopiedId] = useState(false);

  const handleCopyId = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  if (!selectedEvidence) {
    return (
      <div className="soc-card soc-inspector-right" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px' }}>
          <Clock size={16} color="var(--accent-blue)" />
          <div style={{ fontSize: '0.85rem', fontWeight: 800, color: '#f8fafc' }}>
            INVESTIGATION CHRONOLOGY
          </div>
        </div>

        <p style={{ fontSize: '0.78rem', color: 'var(--text-dim)', lineHeight: 1.4 }}>
          Click any <code style={{ color: 'var(--accent-blue)', background: 'var(--bg-subtle)', padding: '2px 6px', borderRadius: '4px' }}>[EVID-xxx]</code> badge in findings or execution traces to inspect raw log payload details.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {timelineEvents?.map((evt, idx) => (
            <div
              key={idx}
              onClick={() => onSelectEvidenceId && onSelectEvidenceId(evt.eid)}
              className="soc-card-subtle"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--accent-blue)', fontWeight: 800 }}>
                  {evt.time}
                </span>
                <div>
                  <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#f8fafc' }}>
                    {evt.title}
                  </div>
                  <div style={{ fontSize: '0.70rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                    Host: {evt.host} | IP: <span style={{ color: '#f87171' }}>{evt.ip}</span>
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span className={`badge ${evt.status === 'SUCCESS' ? 'badge-success' : evt.status === 'FAILURE' ? 'badge-danger' : 'badge-info'}`} style={{ fontSize: '0.65rem' }}>
                  {evt.status}
                </span>
                <ChevronRight size={14} color="var(--text-dim)" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="soc-card soc-inspector-right" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <FileText size={16} color="var(--accent-blue)" />
          <span style={{ fontSize: '0.85rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#f8fafc' }}>
            {selectedEvidence.id}
          </span>
          <button
            onClick={() => handleCopyId(selectedEvidence.id)}
            style={{ background: 'transparent', color: copiedId ? '#34d399' : 'var(--text-dim)', padding: '2px' }}
          >
            {copiedId ? <Check size={12} /> : <Copy size={12} />}
          </button>
        </div>
        <button onClick={onClose} style={{ background: 'transparent', color: 'var(--text-dim)', fontSize: '0.78rem', fontWeight: 700 }}>
          ✕ CLOSE
        </button>
      </div>

      {/* WHY IT MATTERS */}
      <div style={{ background: 'var(--accent-blue-subtle)', border: '1px solid rgba(59, 130, 246, 0.35)', borderRadius: 'var(--radius-sm)', padding: '12px' }}>
        <div style={{ fontSize: '0.72rem', fontWeight: 800, color: '#60a5fa', marginBottom: '4px', letterSpacing: '0.05em' }}>
          WHY THIS EVIDENCE MATTERS:
        </div>
        <p style={{ fontSize: '0.82rem', color: '#e2e8f0', lineHeight: 1.4 }}>
          {selectedEvidence.relevance}
        </p>
      </div>

      {/* FIELD METADATA LIST */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '0.78rem' }}>
        <div className="soc-card-subtle">
          <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem', fontWeight: 700 }}>TIMESTAMP</span>
          <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, marginTop: '2px' }}>{selectedEvidence.timestamp?.split('T')?.[1]?.slice(0, 8) || selectedEvidence.timestamp}</div>
        </div>

        <div className="soc-card-subtle">
          <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem', fontWeight: 700 }}>EVENT TYPE</span>
          <div style={{ marginTop: '2px' }}><span className="badge badge-purple">{selectedEvidence.eventType}</span></div>
        </div>

        <div className="soc-card-subtle">
          <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem', fontWeight: 700 }}>TARGET HOST</span>
          <div style={{ fontWeight: 800, color: '#f8fafc', marginTop: '2px' }}>{selectedEvidence.host || 'N/A'}</div>
        </div>

        <div className="soc-card-subtle">
          <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem', fontWeight: 700 }}>USER</span>
          <div style={{ fontFamily: 'var(--font-mono)', marginTop: '2px' }}>{selectedEvidence.user || 'N/A'}</div>
        </div>

        <div className="soc-card-subtle">
          <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem', fontWeight: 700 }}>SOURCE IP</span>
          <div style={{ fontFamily: 'var(--font-mono)', color: '#f87171', fontWeight: 800, marginTop: '2px' }}>{selectedEvidence.sourceIp || 'N/A'}</div>
        </div>

        <div className="soc-card-subtle">
          <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem', fontWeight: 700 }}>DESTINATION IP</span>
          <div style={{ fontFamily: 'var(--font-mono)', marginTop: '2px' }}>{selectedEvidence.destinationIp || 'N/A'}</div>
        </div>
      </div>

      {/* RAW EVENT REFERENCE */}
      <div>
        <div style={{ fontSize: '0.72rem', fontWeight: 800, color: 'var(--text-dim)', marginBottom: '4px', letterSpacing: '0.05em' }}>
          RAW REFERENCE POINTER:
        </div>
        <div className="code-block" style={{ fontSize: '0.75rem' }}>
          {selectedEvidence.rawReference}
        </div>
      </div>

      {/* NORMALIZED PAYLOAD JSON */}
      <div>
        <div style={{ fontSize: '0.72rem', fontWeight: 800, color: 'var(--text-dim)', marginBottom: '4px', letterSpacing: '0.05em' }}>
          NORMALIZED PAYLOAD:
        </div>
        <div className="code-block" style={{ fontSize: '0.72rem', maxHeight: '180px', overflowY: 'auto' }}>
          {JSON.stringify(selectedEvidence.normalizedData, null, 2)}
        </div>
      </div>
    </div>
  );
}
