import React, { useState, useEffect } from 'react';
import { Layers, Network, Server, User, Globe, FileText, Cpu, Key, ArrowRight, Database, Link as LinkIcon, Box } from 'lucide-react';
import Attack3DVisualizer from './Attack3DVisualizer';

export default function InvestigationGraph({ activeHunt, onSelectEvidenceId }) {
  const [graphData, setGraphData] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [filterType, setFilterType] = useState('ALL');
  const [viewMode, setViewMode] = useState('3D'); // '3D' or '2D'
  const [loading, setLoading] = useState(true);

  const huntId = activeHunt?.id || 'hunt-demo-ssh-01';

  useEffect(() => {
    fetch(`/api/v1/hunts/${huntId}/graph`)
      .then(res => {
        if (!res.ok) throw new Error("Graph API non-200");
        return res.json();
      })
      .then(data => {
        setGraphData(data);
        if (data?.nodes?.length > 0) {
          setSelectedNode(data.nodes[0]);
        }
      })
      .catch(err => {
        const fallbackGraph = {
          nodes: [
            { id: "ip:192.168.100.99", type: "IP", value: "192.168.100.99", label: "IP: 192.168.100.99", evidenceIds: ["evd-ssh-bruteforce-01"], relatedEvents: [{ eventType: "SSH_FAILED_PASSWORD", timestamp: "2026-08-10T19:30:15Z", relevance: "Detected 40 failed password attempts" }], eventCount: 40, findingsCount: 1 },
            { id: "user:root", type: "USER", value: "root", label: "USER: root", evidenceIds: ["evt-sc2-succ-001"], relatedEvents: [{ eventType: "SSH_ACCEPTED_PASSWORD", timestamp: "2026-08-10T19:33:04Z", relevance: "Successful root password authentication" }], eventCount: 1, findingsCount: 1 },
            { id: "host:web-server-01", type: "HOST", value: "web-server-01", label: "HOST: web-server-01", evidenceIds: ["evd-ssh-bruteforce-01"], relatedEvents: [{ eventType: "SYSTEM_ACCESS", timestamp: "2026-08-10T19:33:04Z", relevance: "Target host compromised" }], eventCount: 41, findingsCount: 1 },
            { id: "process:bash", type: "PROCESS", value: "bash (sudo)", label: "PROCESS: bash", evidenceIds: ["evt-sc3-sudo-001"], relatedEvents: [{ eventType: "SUDO_EXECUTION", timestamp: "2026-08-10T19:34:12Z", relevance: "Privilege escalation to root" }], eventCount: 1, findingsCount: 1 },
            { id: "file:/etc/shadow", type: "FILE", value: "/etc/shadow", label: "FILE: /etc/shadow", evidenceIds: ["evt-sc3-sudo-001"], relatedEvents: [{ eventType: "FILE_READ", timestamp: "2026-08-10T19:34:15Z", relevance: "Accessed shadow password hashes" }], eventCount: 1, findingsCount: 1 }
          ],
          edges: [
            { id: "e1", source: "ip:192.168.100.99", target: "user:root", relationship_type: "TARGETED_USER" },
            { id: "e2", source: "user:root", target: "host:web-server-01", relationship_type: "AUTHENTICATED_TO" },
            { id: "e3", source: "host:web-server-01", target: "process:bash", relationship_type: "EXECUTED_PROCESS" },
            { id: "e4", source: "process:bash", target: "file:/etc/shadow", relationship_type: "ACCESSED_FILE" }
          ]
        };
        setGraphData(fallbackGraph);
        setSelectedNode(fallbackGraph.nodes[0]);
      })
      .finally(() => setLoading(false));
  }, [huntId]);

  const getNodeColor = (type) => {
    switch (type) {
      case 'IP': return '#ef4444';
      case 'HOST': return '#3b82f6';
      case 'USER': return '#fbbf24';
      case 'PROCESS': return '#8b5cf6';
      case 'FILE': return '#10b981';
      case 'DOMAIN': return '#06b6d4';
      case 'HASH': return '#34d399';
      default: return '#94a3b8';
    }
  };

  const filteredNodes = graphData?.nodes?.filter(n => filterType === 'ALL' || n.type === filterType) || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      
      {/* HEADER & VIEW TOGGLE */}
      <div className="soc-card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Network size={20} color="var(--accent-blue)" />
          <h2 style={{ fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
            INVESTIGATION GRAPH & 3D ATTACK RECONSTRUCTION
          </h2>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {/* VIEW MODE TOGGLE (3D VISUALS VS 2D GRAPH) */}
          <div style={{ display: 'flex', background: 'var(--bg-subtle)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', padding: '2px' }}>
            <button
              onClick={() => setViewMode('3D')}
              style={{
                background: viewMode === '3D' ? 'var(--accent-blue)' : 'transparent',
                color: viewMode === '3D' ? '#ffffff' : 'var(--text-dim)',
                padding: '5px 14px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.75rem',
                fontWeight: 800,
                display: 'flex',
                alignItems: 'center',
                gap: '5px'
              }}
            >
              <Box size={14} />
              3D ATTACK VISUALS & COMPARISON
            </button>
            <button
              onClick={() => setViewMode('2D')}
              style={{
                background: viewMode === '2D' ? 'var(--accent-blue)' : 'transparent',
                color: viewMode === '2D' ? '#ffffff' : 'var(--text-dim)',
                padding: '5px 14px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.75rem',
                fontWeight: 800,
                display: 'flex',
                alignItems: 'center',
                gap: '5px'
              }}
            >
              <Layers size={14} />
              2D ENTITY GRAPH
            </button>
          </div>
        </div>
      </div>

      {/* VIEW CONTENT */}
      {viewMode === '3D' ? (
        <Attack3DVisualizer onSelectEvidence={onSelectEvidenceId} />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 360px', gap: '20px' }}>
          
          {/* 2D GRAPH CANVAS / PIPELINE */}
          <div className="soc-card" style={{ minHeight: '520px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', background: '#040406' }}>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 800, color: 'var(--text-dim)', letterSpacing: '0.05em' }}>
                DIRECTIONAL ENTITY RELATIONSHIPS (IP → USER → HOST → PROCESS → FILE)
              </div>

              <div style={{ display: 'flex', gap: '6px' }}>
                {['ALL', 'IP', 'USER', 'HOST', 'PROCESS', 'FILE', 'DOMAIN'].map(type => (
                  <button
                    key={type}
                    onClick={() => setFilterType(type)}
                    style={{
                      background: filterType === type ? 'var(--accent-blue-subtle)' : 'var(--bg-subtle)',
                      color: filterType === type ? '#60a5fa' : 'var(--text-dim)',
                      border: filterType === type ? '1px solid rgba(59,130,246,0.4)' : '1px solid var(--border-color)',
                      padding: '3px 8px',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '0.72rem',
                      fontWeight: 700
                    }}
                  >
                    {type}
                  </button>
                ))}
              </div>
            </div>

            {/* VISUAL PIPELINE FLOW */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', padding: '16px 0' }}>
              
              {/* STAGE 1: INGRESS */}
              <div>
                <div style={{ fontSize: '0.7rem', fontWeight: 800, color: 'var(--text-dim)', marginBottom: '8px', letterSpacing: '0.04em' }}>STAGE 1: INGRESS / ATTACKER ATTRIBUTION</div>
                <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                  {filteredNodes.filter(n => n.type === 'IP' || n.type === 'DOMAIN').map(node => (
                    <div
                      key={node.id}
                      onClick={() => setSelectedNode(node)}
                      style={{
                        background: selectedNode?.id === node.id ? 'var(--bg-hover)' : 'var(--bg-panel)',
                        border: `2px solid ${getNodeColor(node.type)}`,
                        borderRadius: 'var(--radius-md)',
                        padding: '12px 16px',
                        cursor: 'pointer',
                        boxShadow: selectedNode?.id === node.id ? `0 0 14px ${getNodeColor(node.type)}40` : 'none',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '10px'
                      }}
                    >
                      <Globe size={18} color={getNodeColor(node.type)} />
                      <div>
                        <div style={{ fontSize: '0.7rem', fontWeight: 800, color: getNodeColor(node.type) }}>{node.type}</div>
                        <div style={{ fontSize: '0.88rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>{node.value}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'center', color: 'var(--border-active)' }}>
                <ArrowRight size={20} style={{ transform: 'rotate(90deg)' }} />
              </div>

              {/* STAGE 2: TARGETED ENTITIES */}
              <div>
                <div style={{ fontSize: '0.7rem', fontWeight: 800, color: 'var(--text-dim)', marginBottom: '8px', letterSpacing: '0.04em' }}>STAGE 2: TARGETED ENTITIES & HOST INFRASTRUCTURE</div>
                <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                  {filteredNodes.filter(n => n.type === 'USER' || n.type === 'HOST').map(node => (
                    <div
                      key={node.id}
                      onClick={() => setSelectedNode(node)}
                      style={{
                        background: selectedNode?.id === node.id ? 'var(--bg-hover)' : 'var(--bg-panel)',
                        border: `2px solid ${getNodeColor(node.type)}`,
                        borderRadius: 'var(--radius-md)',
                        padding: '12px 16px',
                        cursor: 'pointer',
                        boxShadow: selectedNode?.id === node.id ? `0 0 14px ${getNodeColor(node.type)}40` : 'none',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '10px'
                      }}
                    >
                      {node.type === 'USER' ? <User size={18} color={getNodeColor(node.type)} /> : <Server size={18} color={getNodeColor(node.type)} />}
                      <div>
                        <div style={{ fontSize: '0.7rem', fontWeight: 800, color: getNodeColor(node.type) }}>{node.type}</div>
                        <div style={{ fontSize: '0.88rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>{node.value}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'center', color: 'var(--border-active)' }}>
                <ArrowRight size={20} style={{ transform: 'rotate(90deg)' }} />
              </div>

              {/* STAGE 3: EXECUTION & FILE IMPACT */}
              <div>
                <div style={{ fontSize: '0.7rem', fontWeight: 800, color: 'var(--text-dim)', marginBottom: '8px', letterSpacing: '0.04em' }}>STAGE 3: PROCESS EXECUTION & FILE ARTIFACT IMPACT</div>
                <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                  {filteredNodes.filter(n => n.type === 'PROCESS' || n.type === 'FILE' || n.type === 'HASH').map(node => (
                    <div
                      key={node.id}
                      onClick={() => setSelectedNode(node)}
                      style={{
                        background: selectedNode?.id === node.id ? 'var(--bg-hover)' : 'var(--bg-panel)',
                        border: `2px solid ${getNodeColor(node.type)}`,
                        borderRadius: 'var(--radius-md)',
                        padding: '12px 16px',
                        cursor: 'pointer',
                        boxShadow: selectedNode?.id === node.id ? `0 0 14px ${getNodeColor(node.type)}40` : 'none',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '10px'
                      }}
                    >
                      {node.type === 'PROCESS' ? <Cpu size={18} color={getNodeColor(node.type)} /> : <FileText size={18} color={getNodeColor(node.type)} />}
                      <div>
                        <div style={{ fontSize: '0.7rem', fontWeight: 800, color: getNodeColor(node.type) }}>{node.type}</div>
                        <div style={{ fontSize: '0.88rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>{node.value}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

            </div>

            <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', borderTop: '1px solid var(--border-color)', paddingTop: '10px' }}>
              Total Security Indicator Nodes: <strong>{graphData?.nodes?.length || 0}</strong> | Total Grounded Relationship Edges: <strong>{graphData?.edges?.length || 0}</strong>
            </div>
          </div>

          {/* RIGHT SIDE: SELECTED ENTITY INSPECTOR PANEL */}
          <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {selectedNode ? (
              <>
                <div style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <span className="badge" style={{ background: `${getNodeColor(selectedNode.type)}20`, color: getNodeColor(selectedNode.type), border: `1px solid ${getNodeColor(selectedNode.type)}50` }}>
                      {selectedNode.type} INDICATOR
                    </span>
                    <h3 style={{ fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
                      {selectedNode.value}
                    </h3>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '0.78rem' }}>
                  <div className="soc-card-subtle">
                    <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem', fontWeight: 700 }}>EVENT COUNT</span>
                    <div style={{ fontWeight: 800, fontSize: '0.9rem', color: '#f8fafc', marginTop: '2px' }}>{selectedNode.eventCount} events</div>
                  </div>
                  <div className="soc-card-subtle">
                    <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem', fontWeight: 700 }}>FINDINGS CITED</span>
                    <div style={{ fontWeight: 800, fontSize: '0.9rem', color: 'var(--status-red)', marginTop: '2px' }}>{selectedNode.findingsCount} findings</div>
                  </div>
                </div>

                {/* GROUNDED EVIDENCE CITATIONS */}
                <div>
                  <div style={{ fontSize: '0.72rem', fontWeight: 800, color: 'var(--text-dim)', marginBottom: '6px', letterSpacing: '0.04em' }}>
                    GROUNDED EVIDENCE CITATIONS:
                  </div>
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {selectedNode.evidenceIds?.map(eid => (
                      <span key={eid} style={{ background: 'var(--accent-blue-subtle)', border: '1px solid rgba(59, 130, 246, 0.4)', color: '#60a5fa', padding: '3px 8px', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                        [{eid}]
                      </span>
                    ))}
                  </div>
                </div>

                {/* TELEMETRY EVENTS TIMELINE FOR ENTITY */}
                <div>
                  <div style={{ fontSize: '0.72rem', fontWeight: 800, color: 'var(--text-dim)', marginBottom: '6px', letterSpacing: '0.04em' }}>
                    RELATED TELEMETRY EVENTS ({selectedNode.relatedEvents?.length || 0}):
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '220px', overflowY: 'auto' }}>
                    {selectedNode.relatedEvents?.map((evt, idx) => (
                      <div key={idx} className="code-block" style={{ fontSize: '0.75rem' }}>
                        <div style={{ color: 'var(--accent-blue)', fontWeight: 700 }}>{evt.eventType}</div>
                        <div style={{ color: '#e2e8f0', marginTop: '2px' }}>{evt.relevance}</div>
                        <div style={{ color: 'var(--text-dim)', fontSize: '0.7rem', marginTop: '4px' }}>{evt.timestamp}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            ) : (
              <div style={{ textAlign: 'center', color: 'var(--text-dim)', padding: '40px 0' }}>
                Select an entity node in the graph to inspect metadata.
              </div>
            )}
          </div>

        </div>
      )}

    </div>
  );
}
