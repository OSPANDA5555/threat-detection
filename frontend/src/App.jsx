import React, { useState, useEffect } from 'react';
import Navigation from './components/Navigation';
import SOCDashboard from './components/SOCDashboard';
import HuntWorkspace from './components/HuntWorkspace';
import EvidenceViewer from './components/EvidenceViewer';
import FindingsPanel from './components/FindingsPanel';
import SystemHealth from './components/SystemHealth';
import TelemetryExplorer from './components/TelemetryExplorer';
import EvaluationPanel from './components/EvaluationPanel';
import ExecutiveReportModal from './components/ExecutiveReportModal';

import InvestigationGraph from './components/InvestigationGraph';
import SecurityPanel from './components/SecurityPanel';

export const FALLBACK_SAMPLE_HUNT = {
  id: "hunt-demo-ssh-01",
  question: "Find evidence of suspicious SSH activity on web-server-01.",
  status: "COMPLETED",
  confidence: 0.92,
  executionTrace: [
    {
      step_id: "step-01",
      description: "Search authentication failure logs on host web-server-01",
      tool_name: "search_authentication_events",
      tool_args: { host: "web-server-01", status: "FAILURE", limit: 100 },
      status: "COMPLETED",
      result_summary: "Found 40 SSH password failure events originating from IP 192.168.100.99."
    },
    {
      step_id: "step-02",
      description: "Inspect successful authentication events following failure surge",
      tool_name: "search_authentication_events",
      tool_args: { host: "web-server-01", status: "SUCCESS", limit: 50 },
      status: "COMPLETED",
      result_summary: "Identified 1 successful root SSH login from 192.168.100.99 immediately following brute force surge."
    },
    {
      step_id: "step-03",
      description: "Inspect process execution events for privilege escalation",
      tool_name: "search_process_events",
      tool_args: { host: "web-server-01", limit: 50 },
      status: "COMPLETED",
      result_summary: "Detected sudo GTFOBins root shell execution (PID 2841)."
    },
    {
      step_id: "step-04",
      description: "Correlate outbound network connections from web-server-01",
      tool_name: "search_network_events",
      tool_args: { host: "web-server-01", limit: 50 },
      status: "COMPLETED",
      result_summary: "Discovered active C2 TCP connection to 198.51.100.44 over port 443."
    }
  ],
  evidence: [
    {
      id: "evd-ssh-bruteforce-01",
      source: "auth",
      timestamp: "2026-08-10T19:30:15Z",
      host: "web-server-01",
      user: "root",
      sourceIp: "192.168.100.99",
      destinationIp: "10.0.1.10",
      eventType: "SSH_FAILED_PASSWORD",
      rawReference: "search_authentication_events:evt-sc1-001",
      normalizedData: { failed_attempts: 40, port: 22 },
      relevance: "Surge of 40 SSH password failures from single external IP 192.168.100.99 within 3-minute window."
    },
    {
      id: "evt-sc2-succ-001",
      source: "ssh",
      timestamp: "2026-08-10T19:33:04Z",
      host: "web-server-01",
      user: "root",
      sourceIp: "192.168.100.99",
      destinationIp: "10.0.1.10",
      eventType: "SSH_ACCEPTED_PASSWORD",
      rawReference: "search_authentication_events:evt-sc2-succ-001",
      normalizedData: { port: 22, auth_method: "password" },
      relevance: "Successful root SSH authentication from attacker IP 192.168.100.99."
    },
    {
      id: "evt-sc3-sudo-001",
      source: "privilege_escalation",
      timestamp: "2026-08-10T19:34:12Z",
      host: "web-server-01",
      user: "root",
      sourceIp: "10.0.1.10",
      destinationIp: "10.0.1.10",
      eventType: "SUDO_EXECUTION",
      rawReference: "search_process_events:evt-sc3-sudo-001",
      normalizedData: { pid: 2841, process_name: "bash", command_line: "sudo bash -c 'whoami'" },
      relevance: "Sudo GTFOBins privilege escalation execution yielding root UID 0."
    },
    {
      id: "evt-sc8-exfil-002",
      source: "network",
      timestamp: "2026-08-10T19:35:08Z",
      host: "web-server-01",
      user: "root",
      sourceIp: "10.0.1.10",
      destinationIp: "198.51.100.44",
      eventType: "OUTBOUND_C2_CONNECTION",
      rawReference: "search_network_events:evt-sc8-exfil-002",
      normalizedData: { dest_port: 443, bytes_sent: 148200 },
      relevance: "Outbound encrypted data transfer to external C2 IP 198.51.100.44."
    }
  ],
  findings: [
    {
      id: "fnd-ssh-001",
      title: "Compromised SSH Credential & Privilege Escalation on web-server-01",
      severity: "CRITICAL",
      confidence: 0.92,
      description: "Attacker IP 192.168.100.99 conducted password brute force against SSH on web-server-01, achieved successful root authentication, escalated privileges via sudo GTFOBins, and established outbound C2 connection to 198.51.100.44.",
      evidenceIds: ["evd-ssh-bruteforce-01", "evt-sc2-succ-001", "evt-sc3-sudo-001", "evt-sc8-exfil-002"],
      affectedHosts: ["web-server-01"],
      sourceIps: ["192.168.100.99", "198.51.100.44"],
      mitreTechniques: ["T1110.001", "T1548.003", "T1071.001"],
      mitreDetails: [
        {
          tactic: "Credential Access",
          technique_name: "Brute Force: Password Spray",
          technique_id: "T1110.001",
          description: "Attacker attempted 40 consecutive password authentication requests.",
          evidence_ids: ["evd-ssh-bruteforce-01"]
        },
        {
          tactic: "Privilege Escalation",
          technique_name: "Abuse Elevation Control: Sudo",
          technique_id: "T1548.003",
          description: "Executed sudo GTFOBins shell to elevate to UID 0.",
          evidence_ids: ["evt-sc3-sudo-001"]
        }
      ],
      recommendation: "Immediately block IP 192.168.100.99 and 198.51.100.44 at perimeter firewall, revoke compromised root credentials on web-server-01, and isolate host."
    }
  ],
  toolCallsExecuted: 4,
  iterationCount: 4
};

export const FALLBACK_HEALTH_DATA = {
  status: "HEALTHY",
  environment: "production-cloud",
  version: "1.0.0-phase1",
  tool_gateway: {
    status: "ACTIVE",
    enforce_read_only: true,
    registered_tools_count: 9,
    max_tool_result_count: 500,
    timeout_seconds: 5.0
  },
  modules: {
    backend: "OK",
    schemas: "OK",
    tool_gateway: "OK",
    audit_logger: "OK",
    ai_interface: "READY"
  }
};

export default function App() {
  const [activeTab, setActiveTab] = useState('workspace');
  const [healthData, setHealthData] = useState(FALLBACK_HEALTH_DATA);
  const [sampleHunt, setSampleHunt] = useState(FALLBACK_SAMPLE_HUNT);
  const [activeScenarioId, setActiveScenarioId] = useState("ssh-bruteforce");
  const [executionMode, setExecutionMode] = useState("AUTONOMOUS");
  const [isReportOpen, setIsReportOpen] = useState(false);

  useEffect(() => {
    // Fetch system health status with fallback
    fetch('/api/v1/health')
      .then(res => {
        if (!res.ok) throw new Error("Health non-200 response");
        return res.json();
      })
      .then(data => setHealthData(data))
      .catch(err => {
        console.warn("Backend offline or non-API deployment; using active standalone fallback health data.");
        setHealthData(FALLBACK_HEALTH_DATA);
      });

    // Fetch sample hunt data with fallback
    fetch('/api/v1/hunts/sample')
      .then(res => {
        if (!res.ok) throw new Error("Sample hunt non-200 response");
        return res.json();
      })
      .then(data => setSampleHunt(data))
      .catch(err => {
        console.warn("Backend offline; using initial sample hunt fallback data.");
        setSampleHunt(FALLBACK_SAMPLE_HUNT);
      });
  }, []);

  const handleSelectScenario = (scId) => {
    setActiveScenarioId(scId);
    fetch(`/api/v1/telemetry/scenarios/select/${scId}`, { method: 'POST' }).catch(() => {});
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navigation
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        activeHunt={sampleHunt}
        healthData={healthData}
        onOpenReport={() => setIsReportOpen(true)}
        executionMode={executionMode}
        setExecutionMode={setExecutionMode}
      />

      <main style={{
        maxWidth: '1800px',
        width: '100%',
        margin: '0 auto',
        padding: '20px 24px'
      }}>
        {activeTab === 'dashboard' && (
          <SOCDashboard
            onStartHunt={() => setActiveTab('workspace')}
            healthData={healthData}
          />
        )}

        {activeTab === 'workspace' && (
          <HuntWorkspace
            activeHunt={sampleHunt}
            activeScenarioId={activeScenarioId}
            onSelectScenario={handleSelectScenario}
            onOpenReport={() => setIsReportOpen(true)}
            executionMode={executionMode}
          />
        )}

        {activeTab === 'graph' && (
          <InvestigationGraph
            activeHunt={sampleHunt}
            onSelectEvidenceId={(eid) => setActiveTab('evidence')}
          />
        )}


        {activeTab === 'security' && (
          <SecurityPanel />
        )}

        {activeTab === 'explorer' && (
          <TelemetryExplorer />
        )}

        {activeTab === 'evidence' && (
          <EvidenceViewer
            evidenceList={sampleHunt?.evidence}
          />
        )}

        {activeTab === 'findings' && (
          <FindingsPanel
            findingsList={sampleHunt?.findings}
          />
        )}

        {activeTab === 'evaluation' && (
          <EvaluationPanel
            sampleHunt={sampleHunt}
          />
        )}

        {activeTab === 'health' && (
          <SystemHealth
            healthData={healthData}
          />
        )}
      </main>

      {/* EXECUTIVE INVESTIGATION REPORT MODAL */}
      {isReportOpen && (
        <ExecutiveReportModal
          activeHunt={sampleHunt}
          onClose={() => setIsReportOpen(false)}
        />
      )}

      <footer style={{
        marginTop: 'auto',
        borderTop: '1px solid #27272a',
        padding: '12px 24px',
        textAlign: 'center',
        fontSize: '0.75rem',
        color: '#71717a',
        background: '#09090b'
      }}>
        Autonomous Threat-Hunting Copilot • Controlled Autonomy Engine Active • Permanent Hard Safety Limits Enforced
      </footer>
    </div>
  );
}
