import React, { useState } from 'react';
import { Shield, Download, Copy, Check, AlertTriangle, FileText } from 'lucide-react';

export default function ExecutiveReportModal({ activeHunt, onClose }) {
  const [copied, setCopied] = useState(false);

  const huntId = activeHunt?.id || "hunt-00042";
  const question = activeHunt?.question || "Find evidence of suspicious SSH activity.";
  const hypothesis = activeHunt?.hypothesis || "Credential access attempt via SSH password spray.";
  const primaryFinding = activeHunt?.findings?.[0];
  const affectedHosts = primaryFinding?.affectedHosts || ["web-server-01"];
  const attackerIps = primaryFinding?.sourceIps || ["192.168.100.99"];
  const mitre = primaryFinding?.mitreTechniques || ["T1110", "T1110.001"];
  const confidence = activeHunt?.confidence ? `${Math.round(activeHunt.confidence * 100)}%` : "92%";
  const recommendation = primaryFinding?.recommendation || "Isolate source IP at firewall and rotate root credentials.";

  const reportMarkdown = `# SOC THREAT INVESTIGATION REPORT
**HUNT ID:** ${huntId}
**DATE:** ${new Date().toISOString().split('T')[0]}
**STATUS:** COMPLETED
**CONFIDENCE:** ${confidence}

---

> [!WARNING]
> **AI-GENERATED DRAFT — ANALYST REVIEW REQUIRED BEFORE EXPORT**

## 1. Executive Summary
An automated threat-hunting investigation was conducted to address the analyst query: *"${question}"*. 
The investigation confirmed the hypothesis: *"${hypothesis}"*. High-frequency authentication failures were detected originating from IP \`${attackerIps.join(', ')}\` targeting host \`${affectedHosts.join(', ')}\`.

## 2. Affected Assets & Indicators of Compromise (IOCs)
- **Affected Hosts**: ${affectedHosts.join(', ')}
- **Attacker Source IPs**: ${attackerIps.join(', ')}
- **Target User Accounts**: root

## 3. MITRE ATT&CK Mapping
- **Techniques Identified**: ${mitre.join(', ')} (Credential Access: Password Spray / Brute Force)

## 4. Evidence Citations
${activeHunt?.evidence?.slice(0, 5).map(e => `- **[${e.id}]**: ${e.relevance} (Raw Ref: \`${e.rawReference}\`)`).join('\n') || '- **[evd-ssh-01]**: 25 failed SSH password attempts'}

## 5. Recommended Mitigation Actions
1. ${recommendation}
2. Audit SSH authentication logs for secondary attempts across internal subnet.
3. Enforce multi-factor authentication (MFA) and SSH key-only access for administrative accounts.
`;

  const handleCopy = () => {
    navigator.clipboard.writeText(reportMarkdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([reportMarkdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SOC_Report_${huntId}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="soc-card"
        onClick={(e) => e.stopPropagation()}
        style={{
          maxWidth: '850px',
          width: '100%',
          maxHeight: '90vh',
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
          border: '1px solid var(--accent-blue)'
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <FileText size={20} color="var(--accent-blue)" />
            <h2 style={{ fontSize: '1.1rem', fontWeight: 800 }}>EXECUTIVE THREAT INVESTIGATION REPORT</h2>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button onClick={handleCopy} style={{ background: 'var(--bg-subtle)', color: 'var(--text-main)', border: '1px solid var(--border-active)', padding: '6px 12px', borderRadius: '4px', fontSize: '0.8rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
              {copied ? <Check size={14} color="#4ade80" /> : <Copy size={14} />}
              {copied ? 'COPIED!' : 'COPY MARKDOWN'}
            </button>
            <button onClick={handleDownload} style={{ background: '#2563eb', color: '#fff', padding: '6px 14px', borderRadius: '4px', fontSize: '0.8rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '4px' }}>
              <Download size={14} />
              DOWNLOAD REPORT
            </button>
            <button onClick={onClose} style={{ background: 'transparent', color: 'var(--text-dim)', fontSize: '0.9rem', fontWeight: 700, paddingLeft: '8px' }}>✕</button>
          </div>
        </div>

        {/* PROMINENT DRAFT WARNING BANNER */}
        <div style={{ background: 'rgba(217, 119, 6, 0.15)', border: '1px solid #d97706', borderRadius: 'var(--radius-sm)', padding: '12px 16px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <AlertTriangle size={20} color="#fbbf24" />
          <div>
            <strong style={{ color: '#fbbf24', fontSize: '0.85rem', display: 'block' }}>AI-GENERATED DRAFT — ANALYST REVIEW REQUIRED BEFORE EXPORT</strong>
            <span style={{ fontSize: '0.78rem', color: '#a1a1aa' }}>Review all evidence citations and MITRE technique mappings prior to executive escalation.</span>
          </div>
        </div>

        {/* REPORT CONTENT MARKDOWN DISPLAY */}
        <div className="code-block" style={{ fontSize: '0.85rem', lineHeight: 1.6, whiteSpace: 'pre-wrap', maxHeight: '550px' }}>
          {reportMarkdown}
        </div>
      </div>
    </div>
  );
}
