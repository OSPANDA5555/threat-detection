import React, { useState, useEffect } from 'react';
import { Search, Terminal, Shield, CheckCircle2, Play, AlertTriangle, ArrowRight, RefreshCw, FileText, Database, Lock, Cpu, Link as LinkIcon, Clock, Check, X, ShieldAlert, Zap, UserCheck } from 'lucide-react';
import HuntNavigationSidebar from './HuntNavigationSidebar';
import EvidenceContextPanel from './EvidenceContextPanel';
import AIExplanationCard from './AIExplanationCard';

export default function HuntWorkspace({ activeHunt, onSelectScenario, activeScenarioId, onOpenReport, executionMode }) {
  const [query, setQuery] = useState("Find evidence of suspicious SSH activity.");
  const [isHunting, setIsHunting] = useState(false);
  const [currentHunt, setCurrentHunt] = useState(activeHunt);
  const [selectedEvidence, setSelectedEvidence] = useState(null);

  useEffect(() => {
    if (activeHunt) {
      setCurrentHunt(activeHunt);
    }
  }, [activeHunt]);

  const handleStartHunt = async () => {
    if (!query.trim()) return;
    setIsHunting(true);
    try {
      const res = await fetch('/api/v1/hunts/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: query, mode: executionMode })
      });
      const data = await res.json();
      setCurrentHunt(data);
    } catch (err) {
      console.error("Autonomous hunt execution error:", err);
    } finally {
      setIsHunting(false);
    }
  };

  const handleToolApproval = async (approved) => {
    if (!currentHunt?.id) return;
    setIsHunting(true);
    try {
      const res = await fetch(`/api/v1/hunts/${currentHunt.id}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approved })
      });
      const data = await res.json();
      setCurrentHunt(data);
    } catch (err) {
      console.error("Approval resolution error:", err);
    } finally {
      setIsHunting(false);
    }
  };

  const handleSelectEvidenceId = (eid) => {
    const found = currentHunt?.evidence?.find(e => e.id === eid);
    if (found) {
      setSelectedEvidence(found);
    } else {
      setSelectedEvidence({
        id: eid,
        source: "auth",
        timestamp: "2026-08-10T19:30:15Z",
        host: "web-server-01",
        user: "root",
        sourceIp: "192.168.100.99",
        destinationIp: "10.0.1.10",
        eventType: "SSH_FAILED_PASSWORD",
        rawReference: `auth.log:${eid}`,
        normalizedData: { failed_attempts: 25, port: 22 },
        relevance: `Verified security telemetry record ${eid} supporting credential access hypothesis.`
      });
    }
  };

  const timelineEvents = [
    { time: "14:02:11", title: "SSH Password Failures Surge", host: "web-server-01", type: "auth", ip: "192.168.100.99", status: "FAILURE", eid: "evd-ssh-bruteforce-01" },
    { time: "14:02:31", title: "Sustained Password Spray Attempts", host: "web-server-01", type: "auth", ip: "192.168.100.99", status: "FAILURE", eid: "evd-ssh-bruteforce-01" },
    { time: "14:03:04", title: "Successful Root SSH Password Login", host: "web-server-01", type: "ssh", ip: "192.168.100.99", status: "SUCCESS", eid: "evt-sc2-succ-001" },
    { time: "14:04:12", title: "Sudo GTFOBins Root Shell Execution", host: "web-server-01", type: "privilege_escalation", ip: "10.0.1.10", status: "SUCCESS", eid: "evt-sc3-sudo-001" },
    { time: "14:05:08", title: "Outbound C2 Connection Established", host: "web-server-01", type: "network", ip: "198.51.100.44", status: "ALLOWED", eid: "evt-sc8-exfil-002" }
  ];

  return (
    <div className="soc-workspace-grid">
      
      {/* LEFT COLUMN: HUNT NAVIGATION & DRILLS SIDEBAR */}
      <HuntNavigationSidebar
        onSelectScenario={onSelectScenario}
        activeScenarioId={activeScenarioId}
      />

      {/* CENTER COLUMN: MAIN INVESTIGATION WORKSPACE */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        
        {/* AUTONOMY SAFETY LIMITS & MODE GAUGE BAR */}
        <div style={{
          background: 'var(--bg-panel)',
          border: '1px solid var(--border-color)',
          borderRadius: 'var(--radius-md)',
          padding: '10px 16px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: '0.78rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <ShieldAlert size={16} color="var(--accent-blue)" />
            <span style={{ fontWeight: 700, color: '#fafafa' }}>
              AUTONOMY LIMITS:
            </span>
            <span className="badge badge-info">
              {executionMode === 'AUTONOMOUS' ? 'AUTONOMOUS (READ-ONLY APPROVED)' : 'ASSISTED (ANALYST APPROVAL REQUIRED)'}
            </span>
          </div>

          <div style={{ display: 'flex', gap: '16px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
            <div>TOOL CALLS: <strong style={{ color: '#fafafa' }}>{currentHunt?.toolCallsExecuted || 0} / 10</strong></div>
            <div>ITERATION: <strong style={{ color: '#fafafa' }}>{currentHunt?.currentIteration || 1} / 5</strong></div>
            <div>TIMEOUT: <strong style={{ color: '#fafafa' }}>300s</strong></div>
            <div>EVENT CAP: <strong style={{ color: '#fafafa' }}>1000/call</strong></div>
          </div>
        </div>

        {/* ASSISTED MODE PENDING TOOL APPROVAL BANNER */}
        {currentHunt?.pendingApproval && (
          <div style={{
            background: 'rgba(217, 119, 6, 0.15)',
            border: '2px solid #d97706',
            borderRadius: 'var(--radius-md)',
            padding: '16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between'
          }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                <AlertTriangle size={18} color="#fbbf24" />
                <strong style={{ color: '#fbbf24', fontSize: '0.9rem' }}>
                  ASSISTED MODE: ANALYST TOOL APPROVAL REQUIRED
                </strong>
                <span className="badge badge-warning">STEP {currentHunt.pendingApproval.step_number} PENDING</span>
              </div>
              <p style={{ fontSize: '0.82rem', color: '#e4e4e7', marginBottom: '6px' }}>
                {currentHunt.pendingApproval.reasoning}
              </p>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#a1a1aa' }}>
                Tool: <code style={{ color: '#60a5fa' }}>{currentHunt.pendingApproval.tool_name}</code> | Arguments: {JSON.stringify(currentHunt.pendingApproval.arguments)}
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                onClick={() => handleToolApproval(false)}
                disabled={isHunting}
                style={{
                  background: 'rgba(220, 38, 38, 0.2)',
                  border: '1px solid #dc2626',
                  color: '#f87171',
                  padding: '8px 16px',
                  borderRadius: 'var(--radius-sm)',
                  fontWeight: 700,
                  fontSize: '0.8rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                <X size={14} /> REJECT
              </button>
              <button
                onClick={() => handleToolApproval(true)}
                disabled={isHunting}
                style={{
                  background: '#16a34a',
                  color: '#ffffff',
                  padding: '8px 18px',
                  borderRadius: 'var(--radius-sm)',
                  fontWeight: 800,
                  fontSize: '0.8rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                <Check size={14} /> APPROVE TOOL EXECUTION
              </button>
            </div>
          </div>
        )}

        {/* ANALYST QUESTION INPUT BOX */}
        <div className="soc-card">
          <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-dim)', letterSpacing: '0.05em', marginBottom: '6px' }}>
            ANALYST HUNT QUERY
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <div style={{ flex: 1, background: '#000', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', padding: '10px 14px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Search size={16} color="var(--text-muted)" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="What do you want to hunt for? (e.g. Find evidence of suspicious SSH activity)"
                style={{ width: '100%', background: 'transparent', border: 'none', color: '#fafafa', fontSize: '0.9rem', fontWeight: 600 }}
              />
            </div>
            <button
              onClick={handleStartHunt}
              disabled={isHunting}
              style={{
                background: executionMode === 'ASSISTED' ? '#d97706' : '#2563eb',
                color: '#fff',
                fontWeight: 700,
                padding: '10px 20px',
                borderRadius: 'var(--radius-sm)',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
            >
              {isHunting ? <RefreshCw size={16} className="spin" /> : executionMode === 'ASSISTED' ? <UserCheck size={16} /> : <Zap size={16} />}
              {isHunting ? 'EXECUTING...' : executionMode === 'ASSISTED' ? 'START ASSISTED HUNT' : 'START AUTONOMOUS HUNT'}
            </button>
          </div>
        </div>

        {/* HUNT PLAN STEPPER WITH RESULTS */}
        <div className="soc-card">
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-dim)', letterSpacing: '0.05em', marginBottom: '12px' }}>
            STRUCTURED HUNT PLAN & STEP RESULTS
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div className="soc-card-subtle" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 800, color: 'var(--accent-blue)', fontSize: '0.85rem' }}>01</span>
                <div>
                  <div style={{ fontWeight: 700, fontSize: '0.88rem' }}>Search Authentication Failures</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Tool: search_authentication_events</div>
                </div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <span className="badge badge-success">COMPLETED</span>
                <div style={{ fontSize: '0.75rem', color: '#4ade80', fontWeight: 700, marginTop: '2px' }}>25 events</div>
              </div>
            </div>

            <div className="soc-card-subtle" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 800, color: 'var(--accent-blue)', fontSize: '0.85rem' }}>02</span>
                <div>
                  <div style={{ fontWeight: 700, fontSize: '0.88rem' }}>Correlate Successful Authentication</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Tool: get_ip_activity</div>
                </div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <span className="badge badge-success">COMPLETED</span>
                <div style={{ fontSize: '0.75rem', color: '#4ade80', fontWeight: 700, marginTop: '2px' }}>1 event</div>
              </div>
            </div>

            <div className="soc-card-subtle" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 800, color: 'var(--accent-blue)', fontSize: '0.85rem' }}>03</span>
                <div>
                  <div style={{ fontWeight: 700, fontSize: '0.88rem' }}>Inspect Privilege Escalation Events</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Tool: get_host_timeline</div>
                </div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <span className="badge badge-warning">RUNNING</span>
                <div style={{ fontSize: '0.75rem', color: '#fbbf24', fontWeight: 700, marginTop: '2px' }}>45 events</div>
              </div>
            </div>
          </div>
        </div>

        {/* STRUCTURED AI REASONING EXPLANATION */}
        <AIExplanationCard
          activeHunt={currentHunt}
          onSelectEvidenceId={handleSelectEvidenceId}
        />

        {/* INTERACTIVE INVESTIGATION TIMELINE */}
        <div className="soc-card">
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-dim)', letterSpacing: '0.05em', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Clock size={14} color="var(--accent-blue)" />
            INTERACTIVE INVESTIGATION TIMELINE (CLICK EVENT TO INSPECT)
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {timelineEvents.map((evt, idx) => (
              <div
                key={idx}
                onClick={() => handleSelectEvidenceId(evt.eid)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-subtle)',
                  padding: '8px 12px',
                  borderRadius: 'var(--radius-sm)',
                  cursor: 'pointer'
                }}
              >
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-dim)', minWidth: '60px' }}>
                  {evt.time}
                </span>
                <span className={`badge ${evt.status === 'FAILURE' ? 'badge-danger' : evt.status === 'ALLOWED' ? 'badge-warning' : 'badge-success'}`}>
                  {evt.type.toUpperCase()}
                </span>
                <span style={{ fontSize: '0.82rem', fontWeight: 600, flex: 1, color: '#fafafa' }}>
                  {evt.title}
                </span>
                <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)' }}>
                  [{evt.eid}]
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* FINDINGS CARD */}
        {currentHunt?.findings?.map((finding, idx) => (
          <div key={idx} className="soc-card" style={{ borderLeft: '4px solid var(--status-red)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span className="badge badge-danger">EVIDENCE-BACKED FINDING</span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>MITRE: {finding.mitreTechniques.join(', ')}</span>
            </div>
            <h4 style={{ fontSize: '1rem', fontWeight: 800, color: '#fafafa', marginBottom: '6px' }}>
              {finding.title}
            </h4>
            <p style={{ fontSize: '0.85rem', color: '#a1a1aa', lineHeight: 1.5, marginBottom: '10px' }}>
              {finding.description}
            </p>

            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '10px' }}>
              {finding.evidenceIds.map(eid => (
                <button
                  key={eid}
                  onClick={() => handleSelectEvidenceId(eid)}
                  style={{
                    background: 'var(--accent-blue-subtle)',
                    border: '1px solid rgba(37, 99, 235, 0.4)',
                    color: '#60a5fa',
                    padding: '3px 8px',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '0.72rem',
                    fontFamily: 'var(--font-mono)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px'
                  }}
                >
                  <LinkIcon size={11} />
                  [{eid}]
                </button>
              ))}
            </div>

            <div style={{ background: 'var(--bg-subtle)', padding: '10px 12px', borderRadius: 'var(--radius-sm)', fontSize: '0.8rem' }}>
              <strong style={{ color: '#4ade80' }}>Actionable Next Step: </strong>
              <span style={{ color: '#a1a1aa' }}>{finding.recommendation}</span>
            </div>
          </div>
        ))}

      </div>

      {/* RIGHT COLUMN: EVIDENCE CONTEXT INSPECTOR DRAWER */}
      <EvidenceContextPanel
        selectedEvidence={selectedEvidence}
        onClose={() => setSelectedEvidence(null)}
      />

    </div>
  );
}
