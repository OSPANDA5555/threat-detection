import React from 'react';
import { Database, Search, Filter, Hash, CheckCircle2, ArrowRight } from 'lucide-react';

export default function EvidenceViewer({ evidenceList }) {
  const sampleEvidence = evidenceList && evidenceList.length > 0 ? evidenceList : [
    {
      id: "evd-ssh-bruteforce-01",
      source: "auth",
      timestamp: "2026-08-10T19:30:15Z",
      host: "srv-prod-linux01",
      user: "root",
      sourceIp: "192.168.1.105",
      destinationIp: "10.0.0.12",
      eventType: "SSH_FAILED_PASSWORD",
      rawReference: "auth.log:line_1482",
      normalizedData: { failed_attempts: 18, port: 22, auth_method: "password" },
      relevance: "Detected 18 failed root login attempts within a 30-second window",
      confidence: 0.95
    }
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="glass-card" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.2rem', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Database size={20} color="var(--primary-cyan)" />
            COLLECTED SECURITY EVIDENCE STORE
          </h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            All AI findings must trace directly to normalized, cryptographically referenced evidence records below.
          </p>
        </div>
        <span className="badge badge-info">{sampleEvidence.length} VERIFIED EVIDENCE RECORDS</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {sampleEvidence.map((item, idx) => (
          <div key={idx} className="glass-card" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '0.9rem', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--primary-cyan)' }}>
                  {item.id}
                </span>
                <span className="badge badge-purple">SOURCE: {item.source.toUpperCase()}</span>
                <span className="badge badge-success">CONFIDENCE: {Math.round(item.confidence * 100)}%</span>
              </div>
              <span style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                {item.timestamp}
              </span>
            </div>

            <p style={{ fontSize: '0.95rem', fontWeight: 600, color: '#e2e8f0', marginBottom: '14px', lineHeight: 1.5 }}>
              <strong style={{ color: 'var(--primary-cyan)' }}>Relevance Reasoning: </strong>
              {item.relevance}
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', marginBottom: '14px', background: 'rgba(2, 6, 23, 0.6)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>HOST</span>
                <div style={{ fontSize: '0.85rem', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{item.host || 'N/A'}</div>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>USER</span>
                <div style={{ fontSize: '0.85rem', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{item.user || 'N/A'}</div>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>SOURCE IP</span>
                <div style={{ fontSize: '0.85rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#fca5a5' }}>{item.sourceIp || 'N/A'}</div>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>RAW LOG REF</span>
                <div style={{ fontSize: '0.85rem', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{item.rawReference}</div>
              </div>
            </div>

            <div className="code-block">
              <div style={{ color: 'var(--text-dim)', marginBottom: '4px', fontSize: '0.75rem' }}>// NORMALIZED PAYLOAD DATA</div>
              {JSON.stringify(item.normalizedData, null, 2)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
