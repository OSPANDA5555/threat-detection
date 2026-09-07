import React, { useState } from 'react';
import { Cpu, CheckCircle2, HelpCircle, ArrowRight, Link as LinkIcon, Copy, Check } from 'lucide-react';

export default function AIExplanationCard({ currentHunt, onSelectEvidenceId }) {
  const [copied, setCopied] = useState(false);

  const hypothesis = currentHunt?.hypothesis || "An attacker conducted security-relevant events matching request query targeting host infrastructure.";
  const primaryFinding = currentHunt?.findings?.[0];
  const evidenceList = currentHunt?.evidence || [];
  const citedEids = primaryFinding?.evidenceIds || evidenceList.slice(0, 3).map(e => e.id);
  const recommendation = primaryFinding?.recommendation || "Isolate IP at firewall perimeter, revoke compromised tokens, and audit credentials.";

  const handleCopyRecommendation = () => {
    navigator.clipboard.writeText(recommendation);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Cpu size={18} color="var(--accent-blue)" />
          <h3 style={{ fontSize: '0.92rem', fontWeight: 800, color: '#f8fafc' }}>
            AI INVESTIGATION REASONING & ANALYSIS
          </h3>
        </div>
        <span className="badge badge-info">EVIDENCE-GROUNDED REASONING</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
        
        {/* 1. WHAT WE THINK */}
        <div className="soc-card-subtle" style={{ borderLeft: '3px solid var(--accent-blue)' }}>
          <div style={{ fontSize: '0.72rem', fontWeight: 800, color: 'var(--accent-blue)', marginBottom: '6px', letterSpacing: '0.05em' }}>
            1. WHAT WE THINK
          </div>
          <p style={{ fontSize: '0.86rem', color: '#f8fafc', fontWeight: 700, lineHeight: 1.4 }}>
            "{hypothesis}"
          </p>
        </div>

        {/* 2. WHY WE THINK IT */}
        <div className="soc-card-subtle" style={{ borderLeft: '3px solid var(--status-purple)' }}>
          <div style={{ fontSize: '0.72rem', fontWeight: 800, color: '#c084fc', marginBottom: '6px', letterSpacing: '0.05em' }}>
            2. WHY WE THINK IT
          </div>
          <p style={{ fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.4 }}>
            {primaryFinding?.description || "Observed high-confidence telemetry logs matching known threat pattern vectors."}
          </p>
        </div>

      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '14px' }}>
        
        {/* 3. WHAT EVIDENCE SUPPORTS IT */}
        <div className="soc-card-subtle" style={{ borderLeft: '3px solid var(--status-green)' }}>
          <div style={{ fontSize: '0.72rem', fontWeight: 800, color: '#34d399', marginBottom: '8px', letterSpacing: '0.05em' }}>
            3. SUPPORTING EVIDENCE
          </div>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {citedEids.map(eid => (
              <button
                key={eid}
                onClick={() => onSelectEvidenceId && onSelectEvidenceId(eid)}
                style={{
                  background: 'var(--accent-blue-subtle)',
                  border: '1px solid rgba(59, 130, 246, 0.4)',
                  color: '#60a5fa',
                  padding: '4px 10px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.75rem',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}
              >
                <LinkIcon size={12} />
                [{eid}]
              </button>
            ))}
          </div>
        </div>

        {/* 4. WHAT WE DON'T KNOW */}
        <div className="soc-card-subtle" style={{ borderLeft: '3px solid var(--status-amber)' }}>
          <div style={{ fontSize: '0.72rem', fontWeight: 800, color: '#fbbf24', marginBottom: '6px', letterSpacing: '0.05em' }}>
            4. UNCERTAINTIES & GAPS
          </div>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-dim)', lineHeight: 1.4 }}>
            Full scope of external C2 network connections beyond recorded telemetry window remains unverified.
          </p>
        </div>

        {/* 5. RECOMMENDED ACTION */}
        <div className="soc-card-subtle" style={{ borderLeft: '3px solid var(--accent-blue)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
            <div style={{ fontSize: '0.72rem', fontWeight: 800, color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
              5. RECOMMENDED ACTION
            </div>
            <button
              onClick={handleCopyRecommendation}
              style={{
                background: 'transparent',
                color: copied ? '#34d399' : 'var(--text-dim)',
                fontSize: '0.72rem',
                display: 'flex',
                alignItems: 'center',
                gap: '3px'
              }}
            >
              {copied ? <Check size={12} /> : <Copy size={12} />}
              {copied ? 'COPIED' : 'COPY'}
            </button>
          </div>
          <p style={{ fontSize: '0.78rem', color: '#e2e8f0', lineHeight: 1.4 }}>
            {recommendation}
          </p>
        </div>

      </div>
    </div>
  );
}
