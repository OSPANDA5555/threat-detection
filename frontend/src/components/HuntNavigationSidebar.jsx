import React from 'react';
import { Terminal, Shield, Folder, CheckCircle2, Clock, Play } from 'lucide-react';

export default function HuntNavigationSidebar({ onSelectScenario, activeScenarioId }) {
  const drills = [
    { id: "ssh-bruteforce", name: "SSH Password Brute Force", severity: "HIGH", diff: "EASY" },
    { id: "port-ssh-scan", name: "Open SSH & Port Service Scan", severity: "MEDIUM", diff: "EASY" },
    { id: "credential-compromise", name: "Credential Access & Login", severity: "CRITICAL", diff: "MEDIUM" },
    { id: "privilege-escalation", name: "Sudo GTFOBins Escalation", severity: "HIGH", diff: "MEDIUM" },
    { id: "network-recon", name: "Internal Nmap Network Recon", severity: "MEDIUM", diff: "EASY" },
    { id: "suspicious-dns", name: "DNS Tunneling C2 Beacon", severity: "HIGH", diff: "MEDIUM" },
    { id: "post-login-exec", name: "Post-Login Shell Pipe Exec", severity: "CRITICAL", diff: "EASY" },
    { id: "lateral-movement", name: "SSH Pivot Lateral Move", severity: "HIGH", diff: "HARD" },
    { id: "suspicious-exfil", name: "Database Dump Exfiltration", severity: "CRITICAL", diff: "HARD" }
  ];


  return (
    <div className="soc-card soc-sidebar-left" style={{ display: 'flex', flexDirection: 'column', gap: '16px', height: 'fit-content' }}>
      <div>
        <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-dim)', letterSpacing: '0.05em', marginBottom: '8px' }}>
          INVESTIGATION DRILLS ({drills.length})
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {drills.map((drill) => {
            const isSelected = activeScenarioId === drill.id;
            return (
              <div
                key={drill.id}
                onClick={() => onSelectScenario(drill.id)}
                style={{
                  background: isSelected ? '#18181b' : 'transparent',
                  border: isSelected ? '1px solid var(--accent-blue)' : '1px solid transparent',
                  borderRadius: 'var(--radius-sm)',
                  padding: '10px 12px',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <span style={{ fontSize: '0.82rem', fontWeight: 700, color: isSelected ? '#fafafa' : '#a1a1aa' }}>
                    {drill.name}
                  </span>
                  <span className={`badge ${drill.severity === 'CRITICAL' || drill.severity === 'HIGH' ? 'badge-danger' : 'badge-warning'}`} style={{ fontSize: '0.65rem' }}>
                    {drill.severity}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                  <span>Scenario: {drill.id}</span>
                  <span>[{drill.diff}]</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '14px' }}>
        <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-dim)', letterSpacing: '0.05em', marginBottom: '8px' }}>
          ENTERPRISE LAB ASSETS
        </div>
        <div style={{ fontSize: '0.78rem', color: '#a1a1aa', display: 'flex', flexDirection: 'column', gap: '6px', fontFamily: 'var(--font-mono)' }}>
          <div>• web-server-01 (10.0.1.10)</div>
          <div>• db-server-01 (10.0.1.20)</div>
          <div>• jump-host-01 (10.0.1.5)</div>
          <div>• workstation-01 (10.0.1.50)</div>
          <div>• workstation-02 (10.0.1.51)</div>
        </div>
      </div>
    </div>
  );
}
