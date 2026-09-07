import React from 'react';
import { Shield } from 'lucide-react';

const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

const severityBadge = (severity) => {
  switch (severity) {
    case 'CRITICAL': return 'badge-danger';
    case 'HIGH': return 'badge-danger';
    case 'MEDIUM': return 'badge-warning';
    case 'LOW': return 'badge-info';
    default: return 'badge-info';
  }
};

const severityBorder = (severity) => {
  switch (severity) {
    case 'CRITICAL': return 'var(--status-red)';
    case 'HIGH': return 'var(--status-red)';
    case 'MEDIUM': return 'var(--status-amber)';
    default: return 'var(--accent-blue)';
  }
};

export default function FindingsPanel({ findingsList }) {
  const sampleFindings = findingsList && findingsList.length > 0 ? findingsList : [
    {
      id: "fnd-ssh-bruteforce-01",
      title: "SSH Credential Access Attempt via Password Spray",
      severity: "HIGH",
      confidence: 0.92,
      description: "High volume of SSH authentication failures observed from internal IP 192.168.1.105 targeting host srv-prod-linux01.",
      evidenceIds: ["evd-ssh-bruteforce-01"],
      affectedHosts: ["srv-prod-linux01"],
      sourceIps: ["192.168.1.105"],
      timeline: [
        { timestamp: "2026-08-10T19:30:15Z", event: "SSH authentication failure surge detected" }
      ],
      mitreTechniques: ["T1110.001"],
      recommendation: "Isolate host 192.168.1.105, block SSH traffic, and rotate root credentials."
    }
  ];

  const worstSeverity = sampleFindings
    .map(f => f.severity)
    .sort((a, b) => (SEVERITY_RANK[b] ?? 0) - (SEVERITY_RANK[a] ?? 0))[0] || 'INFO';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="glass-card" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
        <div>
          <h2 className="page-title">
            <Shield size={18} color="var(--accent-blue)" />
            Findings & reports
          </h2>
          <p className="page-subtitle">
            Threat findings validated by correlated evidence and mapped to MITRE ATT&CK.
          </p>
        </div>
        <span className={`badge ${severityBadge(worstSeverity)}`}>{sampleFindings.length} {worstSeverity} severity finding{sampleFindings.length === 1 ? '' : 's'}</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {sampleFindings.map((finding, idx) => (
          <div key={idx} className="glass-card" style={{ padding: '24px', borderLeft: `3px solid ${severityBorder(finding.severity)}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px', marginBottom: '12px', flexWrap: 'wrap' }}>
              <div>
                <span className={`badge ${severityBadge(finding.severity)}`} style={{ marginBottom: '8px' }}>{finding.severity}</span>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc' }}>{finding.title}</h3>
              </div>
              <span className="tag-neutral">AI confidence {typeof finding.confidence === 'number' ? `${Math.round(finding.confidence * 100)}%` : '—'}</span>
            </div>

            <p style={{ fontSize: '0.92rem', color: '#cbd5e1', lineHeight: 1.6, marginBottom: '16px' }}>
              {finding.description}
            </p>

            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '16px' }}>
              <span className="tag-neutral">MITRE {(finding.mitreTechniques || []).join(', ')}</span>
              <span className="tag-neutral">Evidence: {(finding.evidenceIds || []).join(', ')}</span>
              <span className="tag-neutral">Hosts: {(finding.affectedHosts || []).join(', ')}</span>
              <span className="tag-neutral">Attacker IP: {(finding.sourceIps || []).join(', ')}</span>
            </div>

            <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', padding: '14px' }}>
              <div className="section-label" style={{ marginBottom: '4px' }}>Recommended mitigation</div>
              <p style={{ fontSize: '0.88rem', color: '#e2e8f0', marginTop: '4px', lineHeight: 1.55 }}>
                {finding.recommendation}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
