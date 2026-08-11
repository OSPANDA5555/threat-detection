import React from 'react';
import { Cpu, CheckCircle2, HelpCircle, ArrowRight, Link as LinkIcon } from 'lucide-react';

export default function AIExplanationCard({ activeHunt, onSelectEvidenceId }) {
  const hypothesis = activeHunt?.hypothesis || "An attacker may have attempted credential-based access against web-server-01.";
  const primaryFinding = activeHunt?.findings?.[0];
  const evidenceList = activeHunt?.evidence || [];
  const citedEids = primaryFinding?.evidenceIds || evidenceList.slice(0, 3).map(e => e.id);

  return (
    <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Cpu size={16} color="var(--accent-blue)" />
          <h3 style={{ fontSize: '0.9rem', fontWeight: 800, color: '#fafafa' }}>
            AI INVESTIGATION REASONING & ANALYSIS
          </h3>
        </div>
        <span className="badge badge-info">EVIDENCE-GROUNDED REASONING</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
        
        {/* 1. WHAT WE THINK */}
        <div className="soc-card-subtle" style={{ borderLeft: '3px solid var(--accent-blue)' }}>
          <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--accent-blue)', marginBottom: '4px', letterSpacing: '0.04em' }}>
            1. WHAT WE THINK
          </div>
          <p style={{ fontSize: '0.85rem', color: '#fafafa', fontWeight: 600, lineHeight: 1.4 }}>
            "{hypothesis}"
          </p>
        </div>

        {/* 2. WHY WE THINK IT */}
        <div className="soc-card-subtle" style={{ borderLeft: '3px solid var(--status-purple)' }}>
          <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#c084fc', marginBottom: '4px', letterSpacing: '0.04em' }}>
            2. WHY WE THINK IT
          </div>
          <p style={{ fontSize: '0.82rem', color: '#a1a1aa', lineHeight: 1.4 }}>
            {primaryFinding?.description || "High frequency authentication failure surge observed in telemetry logs matching brute force patterns."}
          </p>
        </div>

      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
        
        {/* 3. WHAT EVIDENCE SUPPORTS IT */}
        <div className="soc-card-subtle">
          <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#4ade80', marginBottom: '6px', letterSpacing: '0.04em' }}>
            3. SUPPORTING EVIDENCE
          </div>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {citedEids.map(eid => (
              <button
                key={eid}
                onClick={() => onSelectEvidenceId(eid)}
                style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-active)',
                  color: 'var(--accent-blue)',
                  padding: '3px 8px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.72rem',
                  fontFamily: 'var(--font-mono)',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '3px'
                }}
              >
                <LinkIcon size={10} />
                {eid}
              </button>
            ))}
          </div>
        </div>

        {/* 4. WHAT WE DON'T KNOW */}
        <div className="soc-card-subtle">
          <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#fbbf24', marginBottom: '4px', letterSpacing: '0.04em' }}>
            4. UNCERTAINTIES & GAPS
          </div>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-dim)', lineHeight: 1.3 }}>
            Full scope of external C2 network connections beyond recorded telemetry window remains unverified.
          </p>
        </div>

        {/* 5. WHAT TO INVESTIGATE NEXT */}
        <div className="soc-card-subtle">
          <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '4px', letterSpacing: '0.04em' }}>
            5. NEXT INVESTIGATION STEP
          </div>
          <p style={{ fontSize: '0.78rem', color: '#e4e4e7', lineHeight: 1.3 }}>
            {activeHunt?.recommendations?.[0] || "Audit secondary SSH access logs and rotate privileged root credentials."}
          </p>
        </div>

      </div>
    </div>
  );
}
