import pytest
from app.schemas.finding import Finding, Severity, MitreAttackMapping
from app.schemas.evidence import Evidence, EvidenceSource
from app.hunting.graph import IndicatorType, InvestigationGraphBuilder

def test_mitre_attack_mapping_schema():
    mapping = MitreAttackMapping(
        tactic="Credential Access",
        technique_name="Brute Force: Password Spray",
        technique_id="T1110.001",
        description="25 authentication failures observed from IP 192.168.100.99",
        evidence_ids=["evd-ssh-01"]
    )
    assert mapping.tactic == "Credential Access"
    assert mapping.technique_id == "T1110.001"
    assert mapping.evidence_ids == ["evd-ssh-01"]

def test_indicator_graph_extraction_and_relationships():
    evidence_items = [
        Evidence(
            id="evd-001",
            source=EvidenceSource.AUTHENTICATION,
            timestamp="2026-08-10T19:30:00Z",
            host="web-server-01",
            user="root",
            sourceIp="192.168.100.99",
            destinationIp="10.0.1.10",
            eventType="SSH_FAIL",
            rawReference="auth.log:01",
            normalizedData={
                "process_name": "sshd",
                "filepath": "/etc/shadow"
            },
            relevance="Failed root login attempt from 192.168.100.99",
            confidence=0.9
        )
    ]

    finding = Finding(
        title="SSH Password Spray",
        severity=Severity.HIGH,
        confidence=0.9,
        description="High volume failures",
        evidenceIds=["evd-001"],
        affectedHosts=["web-server-01"],
        sourceIps=["192.168.100.99"],
        recommendation="Block IP"
    )

    graph = InvestigationGraphBuilder.build_graph(evidence_items, [finding])

    # Check extracted nodes
    node_types = {n.type for n in graph.nodes}
    assert IndicatorType.IP in node_types
    assert IndicatorType.USER in node_types
    assert IndicatorType.HOST in node_types
    assert IndicatorType.PROCESS in node_types
    assert IndicatorType.FILE in node_types

    # Check extracted node values
    node_vals = {n.value for n in graph.nodes}
    assert "192.168.100.99" in node_vals
    assert "root" in node_vals
    assert "web-server-01" in node_vals
    assert "sshd" in node_vals
    assert "/etc/shadow" in node_vals

    # Check directional relationship edges
    rel_types = {e.relationship_type for e in graph.edges}
    assert "TARGETED_USER" in rel_types
    assert "AUTHENTICATED_TO" in rel_types
    assert "EXECUTED_PROCESS" in rel_types
    assert "ACCESSED_FILE" in rel_types

def test_entity_node_evidence_grounding():
    evidence_items = [
        Evidence(
            id="evd-002",
            source=EvidenceSource.DNS,
            timestamp="2026-08-10T19:35:00Z",
            host="workstation-01",
            user="jdoe",
            sourceIp="10.0.1.50",
            eventType="DNS_QUERY",
            rawReference="dns.log:02",
            normalizedData={
                "domain": "malicious-c2-beacon.com"
            },
            relevance="DNS query for malicious C2 domain",
            confidence=0.95
        )
    ]

    graph = InvestigationGraphBuilder.build_graph(evidence_items)

    domain_node = next(n for n in graph.nodes if n.type == IndicatorType.DOMAIN)
    assert domain_node.value == "malicious-c2-beacon.com"
    assert "evd-002" in domain_node.evidenceIds
    assert len(domain_node.relatedEvents) == 1
    assert domain_node.relatedEvents[0]["id"] == "evd-002"
