from enum import Enum
from typing import List, Dict, Any, Optional, Set
from pydantic import BaseModel, Field
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding

class IndicatorType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    HASH = "HASH"
    USER = "USER"
    HOST = "HOST"
    PROCESS = "PROCESS"
    FILE = "FILE"

class IndicatorNode(BaseModel):
    id: str = Field(description="Unique node identifier e.g. ip:192.168.100.99")
    type: IndicatorType
    value: str
    label: str
    evidenceIds: List[str] = Field(default_factory=list)
    relatedEvents: List[Dict[str, Any]] = Field(default_factory=list)
    relatedFindings: List[str] = Field(default_factory=list)
    eventCount: int = 0
    findingsCount: int = 0

class IndicatorRelationship(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: str
    evidence_ids: List[str] = Field(default_factory=list)

class InvestigationGraph(BaseModel):
    nodes: List[IndicatorNode]
    edges: List[IndicatorRelationship]

class InvestigationGraphBuilder:
    """
    Extracts normalized Security Indicators (IP, DOMAIN, HASH, USER, HOST, PROCESS, FILE)
    from evidence and builds a directional entity relationship graph.
    """

    @staticmethod
    def build_graph(evidence_list: List[Evidence], findings_list: List[Finding] = []) -> InvestigationGraph:
        nodes_map: Dict[str, IndicatorNode] = {}
        edges_set: Set[str] = set()
        edges_list: List[IndicatorRelationship] = []

        def get_or_create_node(node_type: IndicatorType, value: str) -> IndicatorNode:
            if not value or value.lower() in ["unknown", "n/a", "none"]:
                return None
            nid = f"{node_type.value.lower()}:{value}"
            if nid not in nodes_map:
                nodes_map[nid] = IndicatorNode(
                    id=nid,
                    type=node_type,
                    value=value,
                    label=f"{node_type.value}: {value}"
                )
            return nodes_map[nid]

        def add_edge(source_nid: str, target_nid: str, rel_type: str, eid: str):
            if not source_nid or not target_nid or source_nid == target_nid:
                return
            edge_key = f"{source_nid}->{rel_type}->{target_nid}"
            if edge_key not in edges_set:
                edges_set.add(edge_key)
                edges_list.append(IndicatorRelationship(
                    id=f"edge-{len(edges_list):03d}",
                    source=source_nid,
                    target=target_nid,
                    relationship_type=rel_type,
                    evidence_ids=[eid] if eid else []
                ))

        # Extract nodes and edges from evidence records
        for ev in evidence_list:
            ip_node = get_or_create_node(IndicatorType.IP, ev.sourceIp)
            user_node = get_or_create_node(IndicatorType.USER, ev.user)
            host_node = get_or_create_node(IndicatorType.HOST, ev.host)

            raw = ev.normalizedData or {}
            process_val = raw.get("process") or raw.get("process_name") or raw.get("command")
            file_val = raw.get("file") or raw.get("filepath") or raw.get("filename")
            domain_val = raw.get("domain") or raw.get("query_domain")
            hash_val = raw.get("hash") or raw.get("sha256") or raw.get("md5")

            process_node = get_or_create_node(IndicatorType.PROCESS, process_val) if process_val else None
            file_node = get_or_create_node(IndicatorType.FILE, file_val) if file_val else None
            domain_node = get_or_create_node(IndicatorType.DOMAIN, domain_val) if domain_val else None
            hash_node = get_or_create_node(IndicatorType.HASH, hash_val) if hash_val else None

            # Attach evidence reference to nodes
            for n in [ip_node, user_node, host_node, process_node, file_node, domain_node, hash_node]:
                if n:
                    if ev.id not in n.evidenceIds:
                        n.evidenceIds.append(ev.id)
                    n.eventCount += 1
                    n.relatedEvents.append({
                        "id": ev.id,
                        "eventType": ev.eventType,
                        "timestamp": ev.timestamp,
                        "relevance": ev.relevance
                    })

            # Build Directional Graph Edges: IP -> USER -> HOST -> PROCESS -> FILE
            if ip_node and user_node:
                add_edge(ip_node.id, user_node.id, "TARGETED_USER", ev.id)

            if user_node and host_node:
                add_edge(user_node.id, host_node.id, "AUTHENTICATED_TO", ev.id)

            if host_node and process_node:
                add_edge(host_node.id, process_node.id, "EXECUTED_PROCESS", ev.id)

            if process_node and file_node:
                add_edge(process_node.id, file_node.id, "ACCESSED_FILE", ev.id)

            if host_node and domain_node:
                add_edge(host_node.id, domain_node.id, "QUERIED_DOMAIN", ev.id)

            if process_node and hash_node:
                add_edge(process_node.id, hash_node.id, "BINARY_HASH", ev.id)

        # Cross-reference findings metadata
        for fnd in findings_list:
            for nid, node in nodes_map.items():
                if node.value in fnd.affectedHosts or node.value in fnd.sourceIps or any(e in node.evidenceIds for e in fnd.evidenceIds):
                    if fnd.id not in node.relatedFindings:
                        node.relatedFindings.append(fnd.id)
                        node.findingsCount += 1

        return InvestigationGraph(
            nodes=list(nodes_map.values()),
            edges=edges_list
        )
