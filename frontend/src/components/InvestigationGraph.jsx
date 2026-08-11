import React, { useState, useEffect } from 'react';
import { Layers, Network, Server, User, Globe, FileText, Cpu, Key, ArrowRight, Database, Link as LinkIcon } from 'lucide-react';

export default function InvestigationGraph({ activeHunt }) {
  const [graphData, setGraphData] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [filterType, setFilterType] = useState('ALL');
  const [loading, setLoading] = useState(true);

  const huntId = activeHunt?.id || 'hunt-demo-ssh-01';

  useEffect(() => {
    fetch(`/api/v1/hunts/${huntId}/graph`)
      .then(res => res.json())
      .then(data => {
        setGraphData(data);
        if (data?.nodes?.length > 0) {
          setSelectedNode(data.nodes[0]);
        }
      })
      .catch(err => console.error("Graph fetch error:", err))
      .finally(() => setLoading(false));
  }, [huntId]);

  const getNodeColor = (type) => {
    switch (type) {
      case 'IP': return '#f87171';       // Crimson Red
      case 'HOST': return '#60a5fa';     // Blue
      case 'USER': return '#fbbf24';     // Amber
      case 'PROCESS': return '#c084fc';  // Purple
      case 'FILE': return '#4ade80';     // Emerald Green
      case 'DOMAIN': return '#38bdf8';   // Cyan
      case 'HASH': return '#a7f3d0';     // Mint
      default: return '#a1a1aa';
    }
  };

  const filteredNodes = graphData?.nodes?.filter(n => filterType === 'ALL' || n.type === filterType) || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      
      {/* HEADER & FILTER BAR */}
      <div className="soc-card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Network size={20} color="var(--accent-blue)" />
          <h2 style={{ fontSize: '1.1rem', fontWeight: 800 }}>
            INTERACTIVE SECURITY INDICATOR INVESTIGATION GRAPH
          </h2>
          <span className="badge badge-info">EVIDENCE-GROUNDED ENTITIES</span>
        </div>

        <div style={{ display: 'flex', gap: '6px' }}>
          {['ALL', 'IP', 'USER', 'HOST', 'PROCESS', 'FILE', 'DOMAIN'].map(type => (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              style={{
                background: filterType === type ? '#2563eb' : 'var(--bg-subtle)',
                color: filterType === type ? '#ffffff' : 'var(--text-dim)',
                border: '1px solid var(--border-color)',
                padding: '4px 10px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.75rem',
                fontWeight: 700
              }}
            >
              {type}
            </button>
          ))}
        </div>
      </div>

      {/* GRAPH WORKSPACE GRID */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 360px', gap: '20px' }}>
        
        {/* GRAPH CANVAS / ENTITY PIPELINE VISUALIZER */}
        <div className="soc-card" style={{ minHeight: '520px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', background: '#070709' }}>
          
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-dim)', letterSpacing: '0.05em', marginBottom: '14px' }}>
            DIRECTIONAL ENTITY RELATIONSHIPS (IP → USER → HOST → PROCESS → FILE)
          </div>

          {/* VISUAL PIPELINE FLOW */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '20px 0' }}>
            
            {/* STAGE 1: INGRESS INDICATORS (IP & DOMAIN) */}
            <div>
              <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '8px' }}>STAGE 1: INGRESS / ATTACKER ATTRIBUTION</div>
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
                      boxShadow: selectedNode?.id === node.id ? `0 0 12px ${getNodeColor(node.type)}40` : 'none',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px'
                    }}
                  >
                    <Globe size={18} color={getNodeColor(node.type)} />
                    <div>
                      <div style={{ fontSize: '0.7rem', fontWeight: 700, color: getNodeColor(node.type) }}>{node.type}</div>
                      <div style={{ fontSize: '0.88rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>{node.value}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'center', color: 'var(--border-active)' }}>
              <ArrowRight size={20} style={{ transform: 'rotate(90deg)' }} />
            </div>

            {/* STAGE 2: TARGETED ACCOUNTS & HOSTS (USER & HOST) */}
            <div>
              <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '8px' }}>STAGE 2: TARGETED ENTITIES & HOST INFRASTRUCTURE</div>
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
                      boxShadow: selectedNode?.id === node.id ? `0 0 12px ${getNodeColor(node.type)}40` : 'none',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px'
                    }}
                  >
                    {node.type === 'USER' ? <User size={18} color={getNodeColor(node.type)} /> : <Server size={18} color={getNodeColor(node.type)} />}
                    <div>
                      <div style={{ fontSize: '0.7rem', fontWeight: 700, color: getNodeColor(node.type) }}>{node.type}</div>
                      <div style={{ fontSize: '0.88rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>{node.value}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'center', color: 'var(--border-active)' }}>
              <ArrowRight size={20} style={{ transform: 'rotate(90deg)' }} />
            </div>

            {/* STAGE 3: EXECUTION & FILE SYSTEM IMPACT (PROCESS & FILE) */}
            <div>
              <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '8px' }}>STAGE 3: PROCESS EXECUTION & FILE ARTIFACT IMPACT</div>
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
                      boxShadow: selectedNode?.id === node.id ? `0 0 12px ${getNodeColor(node.type)}40` : 'none',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px'
                    }}
                  >
                    {node.type === 'PROCESS' ? <Cpu size={18} color={getNodeColor(node.type)} /> : <FileText size={18} color={getNodeColor(node.type)} />}
                    <div>
                      <div style={{ fontSize: '0.7rem', fontWeight: 700, color: getNodeColor(node.type) }}>{node.type}</div>
                      <div style={{ fontSize: '0.88rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>{node.value}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

          </div>

          <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', borderTop: '1px solid var(--border-color)', paddingTop: '10px' }}>
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
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#fafafa', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
                    {selectedNode.value}
                  </h3>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '0.78rem' }}>
                <div className="soc-card-subtle">
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem' }}>EVENT COUNT</span>
                  <div style={{ fontWeight: 800, fontSize: '0.9rem', color: '#fafafa' }}>{selectedNode.eventCount} events</div>
                </div>
                <div className="soc-card-subtle">
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem' }}>FINDINGS CITED</span>
                  <div style={{ fontWeight: 800, fontSize: '0.9rem', color: 'var(--status-red)' }}>{selectedNode.findingsCount} findings</div>
                </div>
              </div>

              {/* GROUNDED EVIDENCE CITATIONS */}
              <div>
                <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
                  GROUNDED EVIDENCE CITATIONS:
                </div>
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                  {selectedNode.evidenceIds?.map(eid => (
                    <span key={eid} style={{ background: 'var(--accent-blue-subtle)', border: '1px solid rgba(37, 99, 235, 0.4)', color: '#60a5fa', padding: '3px 8px', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                      [{eid}]
                    </span>
                  ))}
                </div>
              </div>

              {/* TELEMETRY EVENTS TIMELINE FOR ENTITY */}
              <div>
                <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
                  RELATED TELEMETRY EVENTS ({selectedNode.relatedEvents?.length || 0}):
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '220px', overflowY: 'auto' }}>
                  {selectedNode.relatedEvents?.map((evt, idx) => (
                    <div key={idx} className="code-block" style={{ fontSize: '0.75rem' }}>
                      <div style={{ color: 'var(--accent-blue)', fontWeight: 700 }}>{evt.eventType}</div>
                      <div style={{ color: '#e4e4e7', marginTop: '2px' }}>{evt.relevance}</div>
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
    </div>
  );
}
