import React from 'react';
import { Shield, AlertTriangle, CheckCircle2, FileText, Share2, ExternalLink } from 'lucide-react';

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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="glass-card" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.2rem', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Shield size={20} color="var(--accent-crimson)" />
            INVESTIGATION FINDINGS & REPORTS
          </h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Professional threat findings validated by correlated security evidence and mapped to MITRE ATT&CK framework.
          </p>
        </div>
        <span className="badge badge-danger">{sampleFindings.length} HIGH SEVERITY FINDING</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {sampleFindings.map((finding, idx) => (
          <div key={idx} className="glass-card" style={{ padding: '24px', borderLeft: '4px solid var(--accent-crimson)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
              <div>
                <span className="badge badge-danger" style={{ marginBottom: '8px' }}>SEVERITY: {finding.severity}</span>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#f8fafc' }}>{finding.title}</h3>
              </div>
              <span className="badge badge-success">AI CONFIDENCE: {Math.round(finding.confidence * 100)}%</span>
            </div>

            <p style={{ fontSize: '0.95rem', color: '#cbd5e1', lineHeight: 1.6, marginBottom: '16px' }}>
              {finding.description}
            </p>

            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '16px' }}>
              <span className="badge badge-purple">MITRE ATT&CK: {finding.mitreTechniques.join(', ')}</span>
              <span className="badge badge-info">EVIDENCE REFS: {finding.evidenceIds.join(', ')}</span>
              <span className="badge badge-warning">HOSTS: {finding.affectedHosts.join(', ')}</span>
              <span className="badge badge-danger">ATTACKER IP: {finding.sourceIps.join(', ')}</span>
            </div>

            <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '8px', padding: '14px' }}>
              <strong style={{ color: 'var(--accent-emerald)', fontSize: '0.9rem' }}>RECOMMENDED MITIGATION STEPS:</strong>
              <p style={{ fontSize: '0.88rem', color: '#e2e8f0', marginTop: '4px' }}>
                {finding.recommendation}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
