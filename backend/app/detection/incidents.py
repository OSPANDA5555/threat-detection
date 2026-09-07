import uuid
from typing import Dict, List, Optional, Set
from collections import defaultdict

from app.detection.models import (
    ActiveIncident,
    DetectionAlert,
    AttackGraph,
    AttackGraphNode,
    AttackGraphEdge
)

class IncidentStateManager:
    """
    Maintains real-time active incident state, dynamic attack graphs,
    and MITRE ATT&CK kill-chain progression across incoming detections.
    """

    def __init__(self):
        self._incidents: Dict[str, ActiveIncident] = {}
        self._entity_to_incident: Dict[str, str] = {}  # entity_val -> incident_id
        self._incident_counter: int = 0

    def reset(self):
        self._incidents.clear()
        self._entity_to_incident.clear()
        self._incident_counter = 0

    def list_incidents(self) -> List[ActiveIncident]:
        return list(self._incidents.values())

    def get_incident(self, incident_id: str) -> Optional[ActiveIncident]:
        return self._incidents.get(incident_id)

    def correlate_detection(self, alert: DetectionAlert) -> ActiveIncident:
        """
        Correlate a DetectionAlert into an active incident or create a new one.
        Updates attack graph nodes, edges, timeline, and MITRE kill-chain stages.
        """
        # Identify matching incident by entities
        matched_incident_id = None
        entities = []
        if alert.source_ip:
            entities.append(f"ip:{alert.source_ip}")
        if alert.hostname:
            entities.append(f"host:{alert.hostname}")
        if alert.username:
            entities.append(f"user:{alert.username}")

        for ent in entities:
            if ent in self._entity_to_incident:
                matched_incident_id = self._entity_to_incident[ent]
                break

        if matched_incident_id and matched_incident_id in self._incidents:
            incident = self._incidents[matched_incident_id]
        else:
            self._incident_counter += 1
            inc_id = f"inc-live-{self._incident_counter:03d}"
            incident = ActiveIncident(
                incident_id=inc_id,
                title=f"Security Incident: {alert.detection}",
                status="ACTIVE",
                severity=alert.severity,
                confidence=alert.confidence,
                start_time=alert.timestamp,
                last_seen=alert.timestamp,
                affected_hosts=[alert.hostname] if alert.hostname else [],
                source_ips=[alert.source_ip] if alert.source_ip else [],
                users=[alert.username] if alert.username else [],
                mitre_tactics=[alert.tactic],
                mitre_techniques=[alert.technique],
                detections=[alert],
                evidence_event_ids=list(alert.evidenceEventIds),
                timeline=[],
                attack_graph=AttackGraph()
            )
            self._incidents[inc_id] = incident

        # Map entities to this incident
        for ent in entities:
            self._entity_to_incident[ent] = incident.incident_id

        # Update lists if not already present
        if alert.id not in [d.id for d in incident.detections]:
            incident.detections.append(alert)

        for eid in alert.evidenceEventIds:
            if eid not in incident.evidence_event_ids:
                incident.evidence_event_ids.append(eid)

        if alert.hostname and alert.hostname not in incident.affected_hosts:
            incident.affected_hosts.append(alert.hostname)
        if alert.source_ip and alert.source_ip not in incident.source_ips:
            incident.source_ips.append(alert.source_ip)
        if alert.username and alert.username not in incident.users:
            incident.users.append(alert.username)
        if alert.tactic not in incident.mitre_tactics:
            incident.mitre_tactics.append(alert.tactic)
        if alert.technique not in incident.mitre_techniques:
            incident.mitre_techniques.append(alert.technique)

        incident.last_seen = alert.timestamp

        # Elevate severity if multiple stages or CRITICAL detection
        has_critical = any(d.severity == "CRITICAL" for d in incident.detections)
        if has_critical or len(incident.mitre_tactics) >= 3:
            incident.severity = "CRITICAL"
        elif any(d.severity == "HIGH" for d in incident.detections):
            incident.severity = "HIGH"

        # Update Dynamic Title
        if len(incident.mitre_tactics) > 1:
            tactic_summary = " & ".join(incident.mitre_tactics[:3])
            host_summary = incident.affected_hosts[0] if incident.affected_hosts else "Infrastructure"
            incident.title = f"Multi-Stage Attack: {tactic_summary} on {host_summary}"

        # Add to Timeline
        incident.timeline.append({
            "timestamp": alert.timestamp,
            "event": f"[{alert.severity}] {alert.detection} ({alert.technique})",
            "evidence_id": alert.evidenceEventIds[0] if alert.evidenceEventIds else "alert",
            "severity": alert.severity,
            "tactic": alert.tactic,
            "reasoning": alert.reasoning
        })

        # Update Dynamic Attack Graph
        self._update_attack_graph(incident, alert)

        return incident

    def _update_attack_graph(self, incident: ActiveIncident, alert: DetectionAlert):
        """Constructs & links Attack Graph nodes/edges based on entities and tactics."""
        graph = incident.attack_graph
        existing_node_ids = {n.id for n in graph.nodes}
        existing_edge_keys = {f"{e.source}->{e.relationship_type}->{e.target}" for e in graph.edges}

        def add_node(nid: str, ntype: str, label: str, val: str, stage: Optional[str] = None):
            if nid not in existing_node_ids:
                node = AttackGraphNode(
                    id=nid,
                    type=ntype,
                    label=label,
                    value=val,
                    stage=stage,
                    evidence_ids=list(alert.evidenceEventIds)
                )
                graph.nodes.append(node)
                existing_node_ids.add(nid)

        def add_edge(src: str, dst: str, rel: str):
            if not src or not dst or src == dst:
                return
            k = f"{src}->{rel}->{dst}"
            if k not in existing_edge_keys:
                edge = AttackGraphEdge(
                    id=f"edge-{len(graph.edges)+1:03d}",
                    source=src,
                    target=dst,
                    relationship_type=rel,
                    evidence_ids=list(alert.evidenceEventIds)
                )
                graph.edges.append(edge)
                existing_edge_keys.add(k)

        # 1. Attacker IP Node
        ip_nid = None
        if alert.source_ip:
            ip_nid = f"ip:{alert.source_ip}"
            add_node(ip_nid, "IP", f"Attacker IP: {alert.source_ip}", alert.source_ip, stage="INITIAL_ACCESS")

        # 2. Targeted User Node
        user_nid = None
        if alert.username:
            user_nid = f"user:{alert.username}"
            add_node(user_nid, "USER", f"Account: {alert.username}", alert.username, stage="CREDENTIALS")

        # 3. Target Host Node
        host_nid = None
        if alert.hostname:
            host_nid = f"host:{alert.hostname}"
            add_node(host_nid, "HOST", f"Host: {alert.hostname}", alert.hostname, stage="EXECUTION")

        # 4. Attack Stage / Detection Node
        tactic_nid = f"stage:{alert.technique_id}"
        add_node(tactic_nid, "STAGE", alert.technique, alert.technique, stage=alert.tactic.upper())

        # Link Directional Edges
        if ip_nid and user_nid:
            add_edge(ip_nid, user_nid, "TARGETED_USER")
        if user_nid and host_nid:
            add_edge(user_nid, host_nid, "AUTHENTICATED_TO")
        if host_nid:
            add_edge(host_nid, tactic_nid, "EXPLOITED_VIA")
        elif ip_nid:
            add_edge(ip_nid, tactic_nid, "EXECUTED_TECHNIQUE")

        if alert.destination_ip and alert.destination_ip != alert.source_ip:
            dst_nid = f"ip:{alert.destination_ip}"
            add_node(dst_nid, "IP", f"Exfil/Target IP: {alert.destination_ip}", alert.destination_ip, stage="EXFILTRATION")
            if host_nid:
                add_edge(host_nid, dst_nid, "EXFILTRATED_DATA_TO")


# Singleton instance
incident_state_manager = IncidentStateManager()
