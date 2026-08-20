import React, { useRef, useEffect, useState, useMemo } from 'react';
import { 
  Box, 
  Layers, 
  Activity, 
  Play, 
  Pause, 
  RotateCw, 
  ZoomIn, 
  ZoomOut, 
  Eye, 
  ShieldAlert, 
  Cpu, 
  Globe, 
  Server, 
  Database, 
  Lock, 
  Zap, 
  BarChart3, 
  Compass, 
  Sliders, 
  ArrowUpRight,
  Maximize2
} from 'lucide-react';

// Multi-scenario comparison dataset
export const ATTACK_SCENARIOS = [
  {
    id: 'ssh-bruteforce',
    name: 'SSH Password Spray & Brute Force',
    shortName: 'SSH Spray',
    targetHost: 'web-server-01',
    targetIp: '10.0.1.10',
    attackerIp: '192.168.100.99',
    mitreTactic: 'Initial Access / Credential Access',
    mitreId: 'T1110.001',
    severity: 'HIGH',
    color: '#ef4444',
    detectionVelocityMs: 184,
    blastRadiusScore: 35,
    evidenceConfidence: 96,
    toolEfficiency: 92,
    packetVolume: 420,
    stagesCount: 3,
    evidenceId: 'evd-ssh-bruteforce-01',
    description: 'High-frequency password spray against OpenSSH port 22, resulting in compromised root credential.',
    nodes3D: [
      { id: 'n1', label: 'Attacker (192.168.100.99)', type: 'ATTACKER', x: -180, y: -40, z: -80, color: '#ef4444' },
      { id: 'n2', label: 'Perimeter FW', type: 'FIREWALL', x: -80, y: -10, z: -30, color: '#f59e0b' },
      { id: 'n3', label: 'web-server-01 (SSH:22)', type: 'TARGET', x: 60, y: 30, z: 20, color: '#ef4444' },
      { id: 'n4', label: 'auth-server-01 (PAM)', type: 'AUTH', x: 160, y: 70, z: 60, color: '#3b82f6' }
    ],
    path3D: [
      { from: 'n1', to: 'n2', label: 'SYN Flood / Spray' },
      { from: 'n2', to: 'n3', label: 'PORT 22 PASS_FAIL' },
      { from: 'n3', to: 'n4', label: 'PAM ACCEPT' }
    ]
  },
  {
    id: 'privilege-escalation',
    name: 'Sudo Abuse / GTFOBins Privilege Escalation',
    shortName: 'Priv Escalation',
    targetHost: 'web-server-01',
    targetIp: '10.0.1.10',
    attackerIp: '10.0.1.10',
    mitreTactic: 'Privilege Escalation',
    mitreId: 'T1548.003',
    severity: 'CRITICAL',
    color: '#ec4899',
    detectionVelocityMs: 240,
    blastRadiusScore: 78,
    evidenceConfidence: 94,
    toolEfficiency: 89,
    packetVolume: 85,
    stagesCount: 4,
    evidenceId: 'evt-sc3-sudo-001',
    description: 'Exploitation of sudoers misconfiguration to spawn privileged root shell from unprivileged user session.',
    nodes3D: [
      { id: 'p1', label: 'Low-Priv User (www-data)', type: 'USER', x: -140, y: -50, z: 60, color: '#fbbf24' },
      { id: 'p2', label: 'Process: /usr/bin/sudo', type: 'PROCESS', x: -30, y: 0, z: 20, color: '#ec4899' },
      { id: 'p3', label: 'Root Shell (/bin/bash)', type: 'TARGET', x: 80, y: 40, z: -20, color: '#ef4444' },
      { id: 'p4', label: 'File: /etc/shadow', type: 'FILE', x: 170, y: 80, z: -70, color: '#10b981' }
    ],
    path3D: [
      { from: 'p1', to: 'p2', label: 'EXEC WITH SUDO' },
      { from: 'p2', to: 'p3', label: 'SPAWN ROOT' },
      { from: 'p3', to: 'p4', label: 'READ SHADOW' }
    ]
  },
  {
    id: 'suspicious-dns',
    name: 'DNS C2 Beaconing & Tunneling',
    shortName: 'DNS Tunneling',
    targetHost: 'db-server-01',
    targetIp: '10.0.1.20',
    attackerIp: '198.51.100.44',
    mitreTactic: 'Command and Control',
    mitreId: 'T1071.004',
    severity: 'HIGH',
    color: '#06b6d4',
    detectionVelocityMs: 260,
    blastRadiusScore: 52,
    evidenceConfidence: 92,
    toolEfficiency: 88,
    packetVolume: 960,
    stagesCount: 3,
    evidenceId: 'evt-sc8-exfil-002',
    description: 'High-frequency base64-encoded DNS TXT queries for covert C2 beaconing and channel establishment.',
    nodes3D: [
      { id: 'd1', label: 'db-server-01', type: 'HOST', x: -160, y: -20, z: -90, color: '#06b6d4' },
      { id: 'd2', label: 'Internal DNS Relay', type: 'SERVICE', x: -40, y: 10, z: -20, color: '#3b82f6' },
      { id: 'd3', label: 'Public DNS Root', type: 'SERVICE', x: 70, y: 40, z: 40, color: '#8b5cf6' },
      { id: 'd4', label: 'C2 ns1.stealth-c2.net', type: 'ATTACKER', x: 180, y: 70, z: 90, color: '#ef4444' }
    ],
    path3D: [
      { from: 'd1', to: 'd2', label: 'TXT BEACON' },
      { from: 'd2', to: 'd3', label: 'RECURSIVE LOOKUP' },
      { from: 'd3', to: 'd4', label: 'COVERT CHANNEL' }
    ]
  },
  {
    id: 'lateral-movement',
    name: 'SSH Key Pivot Lateral Movement',
    shortName: 'Lateral Pivot',
    targetHost: 'db-server-01',
    targetIp: '10.0.1.20',
    attackerIp: '10.0.1.5',
    mitreTactic: 'Lateral Movement',
    mitreId: 'T1021.004',
    severity: 'HIGH',
    color: '#8b5cf6',
    detectionVelocityMs: 310,
    blastRadiusScore: 84,
    evidenceConfidence: 95,
    toolEfficiency: 91,
    packetVolume: 310,
    stagesCount: 4,
    evidenceId: 'evt-sc8-exfil-002',
    description: 'Re-use of stolen SSH identity keys on jump-host-01 to pivot across subnet and access secure db-server-01.',
    nodes3D: [
      { id: 'l1', label: 'web-server-01 (Infected)', type: 'HOST', x: -170, y: -60, z: -40, color: '#ef4444' },
      { id: 'l2', label: 'jump-host-01 (Bastion)', type: 'HOST', x: -50, y: -10, z: 20, color: '#8b5cf6' },
      { id: 'l3', label: 'db-server-01 (Core DB)', type: 'TARGET', x: 70, y: 30, z: 80, color: '#ef4444' },
      { id: 'l4', label: 'Database Service (5432)', type: 'SERVICE', x: 170, y: 70, z: -20, color: '#3b82f6' }
    ],
    path3D: [
      { from: 'l1', to: 'l2', label: 'SSH KEY EXTRACT' },
      { from: 'l2', to: 'l3', label: 'PIVOT JUMP' },
      { from: 'l3', to: 'l4', label: 'ATTACH DB' }
    ]
  },
  {
    id: 'suspicious-exfil',
    name: 'Database Dump & HTTPS Exfiltration',
    shortName: 'DB Exfil',
    targetHost: 'db-server-01',
    targetIp: '10.0.1.20',
    attackerIp: '198.51.100.88',
    mitreTactic: 'Exfiltration',
    mitreId: 'T1048.003',
    severity: 'CRITICAL',
    color: '#f97316',
    detectionVelocityMs: 345,
    blastRadiusScore: 92,
    evidenceConfidence: 98,
    toolEfficiency: 94,
    packetVolume: 1850,
    stagesCount: 4,
    evidenceId: 'evt-sc8-exfil-002',
    description: 'Archive compression of customer database table and encrypted outbound exfiltration to drop server.',
    nodes3D: [
      { id: 'e1', label: 'PostgreSQL Dump', type: 'PROCESS', x: -160, y: -40, z: 70, color: '#f97316' },
      { id: 'e2', label: 'customers.tar.gz', type: 'FILE', x: -50, y: -10, z: -30, color: '#10b981' },
      { id: 'e3', label: 'Perimeter NAT', type: 'FIREWALL', x: 60, y: 20, z: -60, color: '#f59e0b' },
      { id: 'e4', label: 'Exfil Drop (198.51.100.88)', type: 'ATTACKER', x: 180, y: 60, z: 40, color: '#ef4444' }
    ],
    path3D: [
      { from: 'e1', to: 'e2', label: 'PG_DUMP ARCHIVE' },
      { from: 'e2', to: 'e3', label: 'TLS POST' },
      { from: 'e3', to: 'e4', label: 'EGRESS COMPLETED' }
    ]
  }
];

export default function Attack3DVisualizer({ onSelectEvidence, initialScenarioId = 'ssh-bruteforce' }) {
  const canvasRef = useRef(null);
  const [selectedScenarioId, setSelectedScenarioId] = useState(initialScenarioId);
  const [compareMode, setCompareMode] = useState('SINGLE'); // 'SINGLE', 'MULTI_COMPARE', 'METRICS_3D'
  const [activeComparisonIds, setActiveComparisonIds] = useState(['ssh-bruteforce', 'lateral-movement', 'suspicious-exfil']);
  const [isRotating, setIsRotating] = useState(true);
  const [selectedNodeInfo, setSelectedNodeInfo] = useState(null);
  const [viewPreset, setViewPreset] = useState('ISOMETRIC'); // 'ISOMETRIC', 'TOP_DOWN', 'PROFILE'
  
  // 3D Camera Angles & Distance
  const [cameraAngle, setCameraAngle] = useState({ rotX: 0.35, rotY: 0.55, zoom: 1.1 });
  const isDraggingRef = useRef(false);
  const lastMousePosRef = useRef({ x: 0, y: 0 });

  const activeScenario = useMemo(() => {
    return ATTACK_SCENARIOS.find(s => s.id === selectedScenarioId) || ATTACK_SCENARIOS[0];
  }, [selectedScenarioId]);

  // Set Preset Camera Positions
  const applyPreset = (preset) => {
    setViewPreset(preset);
    if (preset === 'ISOMETRIC') {
      setCameraAngle({ rotX: 0.38, rotY: 0.65, zoom: 1.1 });
    } else if (preset === 'TOP_DOWN') {
      setCameraAngle({ rotX: 1.45, rotY: 0.0, zoom: 1.0 });
    } else if (preset === 'PROFILE') {
      setCameraAngle({ rotX: 0.05, rotY: 1.55, zoom: 1.15 });
    }
  };

  // Toggle scenario selection for multi-compare mode
  const toggleCompareScenario = (id) => {
    setActiveComparisonIds(prev => {
      if (prev.includes(id)) {
        if (prev.length <= 1) return prev; // keep at least 1
        return prev.filter(x => x !== id);
      } else {
        return [...prev, id];
      }
    });
  };

  // Render 3D Canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animationFrameId;
    let time = 0;

    const render = () => {
      const width = canvas.width = canvas.clientWidth * window.devicePixelRatio;
      const height = canvas.height = canvas.clientHeight * window.devicePixelRatio;
      const centerX = width / 2;
      const centerY = height / 2;

      ctx.clearRect(0, 0, width, height);

      // Auto rotation
      let currentRotY = cameraAngle.rotY;
      if (isRotating && !isDraggingRef.current) {
        time += 0.008;
        currentRotY += time;
      }
      const currentRotX = cameraAngle.rotX;
      const zoom = cameraAngle.zoom * window.devicePixelRatio;

      // 3D Projection Helper (Rotates around Y then X axis)
      const project3D = (x, y, z) => {
        // Rotate Y
        const cosY = Math.cos(currentRotY);
        const sinY = Math.sin(currentRotY);
        const x1 = x * cosY - z * sinY;
        const z1 = x * sinY + z * cosY;

        // Rotate X
        const cosX = Math.cos(currentRotX);
        const sinX = Math.sin(currentRotX);
        const y2 = y * cosX - z1 * sinX;
        const z2 = y * sinX + z1 * cosX;

        // Perspective projection
        const fov = 420;
        const scale = fov / (fov + z2 + 250) * zoom;
        return {
          px: centerX + x1 * scale,
          py: centerY + y2 * scale,
          scale,
          zDepth: z2
        };
      };

      // 1. Draw 3D Ground Grid
      ctx.strokeStyle = 'rgba(34, 38, 54, 0.45)';
      ctx.lineWidth = 1;
      const gridStep = 45;
      const gridSpan = 220;
      const gridY = 100;

      for (let gx = -gridSpan; gx <= gridSpan; gx += gridStep) {
        const p1 = project3D(gx, gridY, -gridSpan);
        const p2 = project3D(gx, gridY, gridSpan);
        ctx.beginPath();
        ctx.moveTo(p1.px, p1.py);
        ctx.lineTo(p2.px, p2.py);
        ctx.stroke();
      }
      for (let gz = -gridSpan; gz <= gridSpan; gz += gridStep) {
        const p1 = project3D(-gridSpan, gridY, gz);
        const p2 = project3D(gridSpan, gridY, gz);
        ctx.beginPath();
        ctx.moveTo(p1.px, p1.py);
        ctx.lineTo(p2.px, p2.py);
        ctx.stroke();
      }

      // 2. Render Mode Switching
      if (compareMode === 'METRICS_3D') {
        // === 3D METRIC BARS COMPARISON ===
        const scenariosToRender = ATTACK_SCENARIOS;
        const barWidth = 24;

        scenariosToRender.forEach((sc, idx) => {
          const offsetX = (idx - scenariosToRender.length / 2 + 0.5) * 80;
          const barHeight = (sc.blastRadiusScore / 100) * 160;
          const baseY = gridY;
          const topY = gridY - barHeight;

          const bBase = project3D(offsetX, baseY, 0);
          const bTop = project3D(offsetX, topY, 0);

          // 3D Pillar Vertical Line
          ctx.beginPath();
          ctx.moveTo(bBase.px, bBase.py);
          ctx.lineTo(bTop.px, bTop.py);
          ctx.strokeStyle = sc.color;
          ctx.lineWidth = 14 * bTop.scale;
          ctx.lineCap = 'round';
          ctx.stroke();

          // Glowing Crown Sphere
          ctx.beginPath();
          ctx.arc(bTop.px, bTop.py, 10 * bTop.scale, 0, Math.PI * 2);
          ctx.fillStyle = sc.color;
          ctx.shadowColor = sc.color;
          ctx.shadowBlur = 16;
          ctx.fill();
          ctx.shadowBlur = 0;

          // Metric Label
          ctx.fillStyle = '#f8fafc';
          ctx.font = `bold ${10 * bTop.scale}px Inter, sans-serif`;
          ctx.textAlign = 'center';
          ctx.fillText(`${sc.blastRadiusScore}% BLAST`, bTop.px, bTop.py - 16 * bTop.scale);

          ctx.fillStyle = '#94a3b8';
          ctx.font = `${9 * bTop.scale}px JetBrains Mono, monospace`;
          ctx.fillText(sc.shortName, bBase.px, bBase.py + 18 * bBase.scale);
        });

      } else if (compareMode === 'MULTI_COMPARE') {
        // === MULTI-SCENARIO 3D OVERLAY COMPARISON ===
        const activeScs = ATTACK_SCENARIOS.filter(s => activeComparisonIds.includes(s.id));

        activeScs.forEach((sc, scIdx) => {
          const layerOffsetY = (scIdx - activeScs.length / 2 + 0.5) * 60;

          // Edges for scenario
          sc.path3D.forEach(edge => {
            const srcNode = sc.nodes3D.find(n => n.id === edge.from);
            const dstNode = sc.nodes3D.find(n => n.id === edge.to);
            if (!srcNode || !dstNode) return;

            const p1 = project3D(srcNode.x, srcNode.y + layerOffsetY, srcNode.z);
            const p2 = project3D(dstNode.x, dstNode.y + layerOffsetY, dstNode.z);

            ctx.beginPath();
            ctx.moveTo(p1.px, p1.py);
            ctx.lineTo(p2.px, p2.py);
            ctx.strokeStyle = sc.color;
            ctx.lineWidth = 2.5 * p1.scale;
            ctx.stroke();

            // Flow particle
            const progress = (time * 1.5 + scIdx * 0.3) % 1;
            const pfx = p1.px + (p2.px - p1.px) * progress;
            const pfy = p1.py + (p2.py - p1.py) * progress;

            ctx.beginPath();
            ctx.arc(pfx, pfy, 4 * p1.scale, 0, Math.PI * 2);
            ctx.fillStyle = '#ffffff';
            ctx.fill();
          });

          // Nodes for scenario
          sc.nodes3D.forEach(node => {
            const pt = project3D(node.x, node.y + layerOffsetY, node.z);

            ctx.beginPath();
            ctx.arc(pt.px, pt.py, 8 * pt.scale, 0, Math.PI * 2);
            ctx.fillStyle = sc.color;
            ctx.shadowColor = sc.color;
            ctx.shadowBlur = 12;
            ctx.fill();
            ctx.shadowBlur = 0;

            ctx.fillStyle = '#f8fafc';
            ctx.font = `${8 * pt.scale}px Inter, sans-serif`;
            ctx.textAlign = 'center';
            ctx.fillText(node.label, pt.px, pt.py - 12 * pt.scale);
          });
        });

      } else {
        // === SINGLE SCENARIO DETAILED 3D RECONSTRUCTION ===
        const sc = activeScenario;

        // 1. Draw 3D Edges
        sc.path3D.forEach((edge, eIdx) => {
          const srcNode = sc.nodes3D.find(n => n.id === edge.from);
          const dstNode = sc.nodes3D.find(n => n.id === edge.to);
          if (!srcNode || !dstNode) return;

          const p1 = project3D(srcNode.x, srcNode.y, srcNode.z);
          const p2 = project3D(dstNode.x, dstNode.y, dstNode.z);

          // Edge line with glow
          ctx.beginPath();
          ctx.moveTo(p1.px, p1.py);
          ctx.lineTo(p2.px, p2.py);
          ctx.strokeStyle = sc.color;
          ctx.lineWidth = 3 * p1.scale;
          ctx.stroke();

          // Animated particle streams along attack trajectory
          for (let i = 0; i < 3; i++) {
            const progress = (time * 1.2 + i * 0.33) % 1;
            const pfx = p1.px + (p2.px - p1.px) * progress;
            const pfy = p1.py + (p2.py - p1.py) * progress;

            ctx.beginPath();
            ctx.arc(pfx, pfy, 4.5 * p1.scale, 0, Math.PI * 2);
            ctx.fillStyle = '#ffffff';
            ctx.shadowColor = sc.color;
            ctx.shadowBlur = 10;
            ctx.fill();
            ctx.shadowBlur = 0;
          }

          // Edge Label in 3D Space
          const midX = (p1.px + p2.px) / 2;
          const midY = (p1.py + p2.py) / 2;
          ctx.fillStyle = 'rgba(15, 23, 42, 0.85)';
          ctx.fillRect(midX - 40 * p1.scale, midY - 9 * p1.scale, 80 * p1.scale, 18 * p1.scale);
          ctx.strokeStyle = sc.color;
          ctx.strokeRect(midX - 40 * p1.scale, midY - 9 * p1.scale, 80 * p1.scale, 18 * p1.scale);

          ctx.fillStyle = '#f8fafc';
          ctx.font = `${8.5 * p1.scale}px JetBrains Mono, monospace`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(edge.label, midX, midY);
        });

        // 2. Draw 3D Nodes
        sc.nodes3D.forEach(node => {
          const pt = project3D(node.x, node.y, node.z);

          // Pulsing Beacon Halo
          ctx.beginPath();
          ctx.arc(pt.px, pt.py, (16 + 6 * Math.abs(Math.sin(time * 3))) * pt.scale, 0, Math.PI * 2);
          ctx.fillStyle = `${node.color}25`;
          ctx.fill();

          // Core Sphere
          ctx.beginPath();
          ctx.arc(pt.px, pt.py, 12 * pt.scale, 0, Math.PI * 2);
          ctx.fillStyle = '#0f172a';
          ctx.strokeStyle = node.color;
          ctx.lineWidth = 3 * pt.scale;
          ctx.fill();
          ctx.stroke();

          // Inner LED
          ctx.beginPath();
          ctx.arc(pt.px, pt.py, 4.5 * pt.scale, 0, Math.PI * 2);
          ctx.fillStyle = node.color;
          ctx.fill();

          // Node Text Labels
          ctx.fillStyle = '#f8fafc';
          ctx.font = `bold ${11 * pt.scale}px Inter, sans-serif`;
          ctx.textAlign = 'center';
          ctx.fillText(node.label, pt.px, pt.py + 22 * pt.scale);

          ctx.fillStyle = '#94a3b8';
          ctx.font = `${9 * pt.scale}px JetBrains Mono, monospace`;
          ctx.fillText(`[${node.type}]`, pt.px, pt.py + 34 * pt.scale);
        });
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => cancelAnimationFrame(animationFrameId);
  }, [cameraAngle, isRotating, selectedScenarioId, compareMode, activeComparisonIds, activeScenario]);

  // Mouse drag to rotate in 3D
  const handleMouseDown = (e) => {
    isDraggingRef.current = true;
    lastMousePosRef.current = { x: e.clientX, y: e.clientY };
  };

  const handleMouseMove = (e) => {
    if (!isDraggingRef.current) return;
    const deltaX = e.clientX - lastMousePosRef.current.x;
    const deltaY = e.clientY - lastMousePosRef.current.y;
    lastMousePosRef.current = { x: e.clientX, y: e.clientY };

    setCameraAngle(prev => ({
      ...prev,
      rotY: prev.rotY + deltaX * 0.008,
      rotX: Math.max(-1.2, Math.min(1.4, prev.rotX + deltaY * 0.008))
    }));
  };

  const handleMouseUp = () => {
    isDraggingRef.current = false;
  };

  const handleWheel = (e) => {
    e.preventDefault();
    const zoomDelta = e.deltaY * -0.001;
    setCameraAngle(prev => ({
      ...prev,
      zoom: Math.max(0.6, Math.min(2.5, prev.zoom + zoomDelta))
    }));
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
      
      {/* 3D WORKSPACE HEADER & COMPARISON CONTROLS */}
      <div className="soc-card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Box size={22} color="var(--accent-blue)" />
          <div>
            <h2 style={{ fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
              3D ATTACK RECONSTRUCTION & MULTI-VECTOR COMPARISON
            </h2>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Interactive 3D spatial reconstruction comparing blast radiuses, velocity, and multi-host lateral corridors
            </div>
          </div>
        </div>

        {/* MODE SELECTOR */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ display: 'flex', background: 'var(--bg-subtle)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', padding: '2px' }}>
            <button
              onClick={() => setCompareMode('SINGLE')}
              style={{
                background: compareMode === 'SINGLE' ? 'var(--accent-blue)' : 'transparent',
                color: compareMode === 'SINGLE' ? '#ffffff' : 'var(--text-dim)',
                padding: '5px 12px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.75rem',
                fontWeight: 800,
                display: 'flex',
                alignItems: 'center',
                gap: '5px'
              }}
            >
              <Eye size={13} />
              SINGLE ATTACK
            </button>
            <button
              onClick={() => setCompareMode('MULTI_COMPARE')}
              style={{
                background: compareMode === 'MULTI_COMPARE' ? 'var(--accent-blue)' : 'transparent',
                color: compareMode === 'MULTI_COMPARE' ? '#ffffff' : 'var(--text-dim)',
                padding: '5px 12px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.75rem',
                fontWeight: 800,
                display: 'flex',
                alignItems: 'center',
                gap: '5px'
              }}
            >
              <Layers size={13} />
              3D MULTI-COMPARE
            </button>
            <button
              onClick={() => setCompareMode('METRICS_3D')}
              style={{
                background: compareMode === 'METRICS_3D' ? 'var(--accent-blue)' : 'transparent',
                color: compareMode === 'METRICS_3D' ? '#ffffff' : 'var(--text-dim)',
                padding: '5px 12px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.75rem',
                fontWeight: 800,
                display: 'flex',
                alignItems: 'center',
                gap: '5px'
              }}
            >
              <BarChart3 size={13} />
              3D METRICS BARS
            </button>
          </div>
        </div>
      </div>

      {/* 3D CANVAS & SIDEBAR GRID */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: '20px' }}>
        
        {/* 3D INTERACTIVE CANVAS CONTAINER */}
        <div style={{ position: 'relative', width: '100%', height: '560px', background: '#040406', borderRadius: 'var(--radius-md)', overflow: 'hidden', border: '1px solid var(--border-color)', boxShadow: '0 8px 32px rgba(0, 0, 0, 0.8)' }}>
          
          {/* FLOATING 3D VIEWPORT CONTROLS */}
          <div style={{ position: 'absolute', top: 14, left: 16, right: 16, zIndex: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'center', pointerEvents: 'none' }}>
            
            {/* View Presets */}
            <div style={{ display: 'flex', gap: '6px', pointerEvents: 'auto', background: 'rgba(15, 23, 42, 0.85)', padding: '4px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', backdropFilter: 'blur(8px)' }}>
              {['ISOMETRIC', 'TOP_DOWN', 'PROFILE'].map(preset => (
                <button
                  key={preset}
                  onClick={() => applyPreset(preset)}
                  style={{
                    background: viewPreset === preset ? 'var(--accent-blue)' : 'transparent',
                    color: viewPreset === preset ? '#ffffff' : 'var(--text-dim)',
                    padding: '4px 8px',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '0.70rem',
                    fontWeight: 800
                  }}
                >
                  {preset}
                </button>
              ))}
            </div>

            {/* Orbit / Zoom Controls */}
            <div style={{ display: 'flex', gap: '6px', pointerEvents: 'auto' }}>
              <button
                onClick={() => setIsRotating(!isRotating)}
                style={{
                  background: 'rgba(15, 23, 42, 0.85)',
                  border: '1px solid var(--border-color)',
                  color: isRotating ? '#34d399' : '#f87171',
                  padding: '6px 12px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.75rem',
                  fontWeight: 800,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                  backdropFilter: 'blur(8px)'
                }}
              >
                <RotateCw size={13} className={isRotating ? 'spin' : ''} />
                {isRotating ? '3D ORBIT ON' : 'ORBIT PAUSED'}
              </button>

              <button
                onClick={() => setCameraAngle(prev => ({ ...prev, zoom: Math.min(2.2, prev.zoom + 0.15) }))}
                style={{ background: 'rgba(15, 23, 42, 0.85)', border: '1px solid var(--border-color)', color: '#f8fafc', padding: '6px 10px', borderRadius: 'var(--radius-sm)' }}
              >
                <ZoomIn size={14} />
              </button>
              <button
                onClick={() => setCameraAngle(prev => ({ ...prev, zoom: Math.max(0.6, prev.zoom - 0.15) }))}
                style={{ background: 'rgba(15, 23, 42, 0.85)', border: '1px solid var(--border-color)', color: '#f8fafc', padding: '6px 10px', borderRadius: 'var(--radius-sm)' }}
              >
                <ZoomOut size={14} />
              </button>
            </div>
          </div>

          {/* BOTTOM CANVAS HINT */}
          <div style={{ position: 'absolute', bottom: 12, left: 16, zIndex: 10, pointerEvents: 'none', fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
            🖱️ Click & Drag to Rotate in 3D | Scroll Wheel to Zoom
          </div>

          {/* 3D CANVAS */}
          <canvas
            ref={canvasRef}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
            onWheel={handleWheel}
            style={{ width: '100%', height: '100%', cursor: 'grab', display: 'block' }}
          />
        </div>

        {/* RIGHT SIDEBAR: SCENARIOS & COMPARISON METRICS */}
        <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          
          <div>
            <div style={{ fontSize: '0.75rem', fontWeight: 800, color: 'var(--text-dim)', letterSpacing: '0.05em', marginBottom: '10px' }}>
              ATTACK SCENARIOS ({ATTACK_SCENARIOS.length})
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '280px', overflowY: 'auto' }}>
              {ATTACK_SCENARIOS.map(sc => {
                const isSelected = selectedScenarioId === sc.id;
                const isCheckedInCompare = activeComparisonIds.includes(sc.id);

                return (
                  <div
                    key={sc.id}
                    onClick={() => {
                      setSelectedScenarioId(sc.id);
                      if (compareMode === 'MULTI_COMPARE') toggleCompareScenario(sc.id);
                    }}
                    className="soc-card-subtle"
                    style={{
                      border: isSelected ? `1px solid ${sc.color}` : '1px solid var(--border-subtle)',
                      background: isSelected ? `${sc.color}15` : 'var(--bg-subtle)',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      padding: '10px 12px'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <span style={{ fontSize: '0.82rem', fontWeight: 800, color: isSelected ? sc.color : '#f8fafc' }}>
                        {sc.name}
                      </span>
                      <span className={`badge ${sc.severity === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}`} style={{ fontSize: '0.65rem' }}>
                        {sc.severity}
                      </span>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.70rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                      <span>{sc.mitreId}</span>
                      <span>Blast: {sc.blastRadiusScore}%</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* ACTIVE SCENARIO METRIC CARD */}
          <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '14px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 800, color: 'var(--text-dim)', letterSpacing: '0.04em' }}>
                SCENARIO TELEMETRY
              </span>
              <span className="badge badge-info" style={{ fontFamily: 'var(--font-mono)' }}>
                {activeScenario.mitreId}
              </span>
            </div>

            <p style={{ fontSize: '0.80rem', color: '#cbd5e1', lineHeight: 1.4 }}>
              {activeScenario.description}
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '0.76rem' }}>
              <div className="soc-card-subtle">
                <span style={{ color: 'var(--text-dim)', fontSize: '0.68rem', fontWeight: 700 }}>BLAST RADIUS</span>
                <div style={{ fontWeight: 800, fontSize: '0.88rem', color: activeScenario.color, marginTop: '2px' }}>
                  {activeScenario.blastRadiusScore}% Impact
                </div>
              </div>

              <div className="soc-card-subtle">
                <span style={{ color: 'var(--text-dim)', fontSize: '0.68rem', fontWeight: 700 }}>DETECTION SPEED</span>
                <div style={{ fontWeight: 800, fontSize: '0.88rem', color: '#f8fafc', marginTop: '2px' }}>
                  {activeScenario.detectionVelocityMs}ms
                </div>
              </div>

              <div className="soc-card-subtle">
                <span style={{ color: 'var(--text-dim)', fontSize: '0.68rem', fontWeight: 700 }}>EVIDENCE CONF</span>
                <div style={{ fontWeight: 800, fontSize: '0.88rem', color: '#34d399', marginTop: '2px' }}>
                  {activeScenario.evidenceConfidence}%
                </div>
              </div>

              <div className="soc-card-subtle">
                <span style={{ color: 'var(--text-dim)', fontSize: '0.68rem', fontWeight: 700 }}>PACKET VOLUME</span>
                <div style={{ fontWeight: 800, fontSize: '0.88rem', color: '#60a5fa', marginTop: '2px' }}>
                  {activeScenario.packetVolume} evts
                </div>
              </div>
            </div>

            <div style={{ marginTop: '4px' }}>
              <button
                onClick={() => onSelectEvidence && onSelectEvidence(activeScenario.evidenceId)}
                style={{
                  width: '100%',
                  background: 'var(--accent-blue)',
                  color: '#ffffff',
                  padding: '8px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.78rem',
                  fontWeight: 800,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '6px'
                }}
              >
                <ArrowUpRight size={14} />
                INSPECT GROUNDED EVIDENCE [{activeScenario.evidenceId}]
              </button>
            </div>
          </div>

        </div>

      </div>

    </div>
  );
}
