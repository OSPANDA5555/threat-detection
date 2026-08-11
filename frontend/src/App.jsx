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

export default function App() {
  const [activeTab, setActiveTab] = useState('workspace');
  const [healthData, setHealthData] = useState(null);
  const [sampleHunt, setSampleHunt] = useState(null);
  const [activeScenarioId, setActiveScenarioId] = useState("ssh-bruteforce");
  const [executionMode, setExecutionMode] = useState("AUTONOMOUS");
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Fetch system health status
    fetch('/api/v1/health')
      .then(res => res.json())
      .then(data => setHealthData(data))
      .catch(err => console.error("Health check error:", err));

    // Fetch sample hunt data
    fetch('/api/v1/hunts/sample')
      .then(res => res.json())
      .then(data => setSampleHunt(data))
      .catch(err => console.error("Sample hunt fetch error:", err))
      .finally(() => setLoading(false));
  }, []);

  const handleSelectScenario = (scId) => {
    setActiveScenarioId(scId);
    fetch(`/api/v1/telemetry/scenarios/select/${scId}`, { method: 'POST' });
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
