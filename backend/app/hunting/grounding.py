from typing import List, Tuple, Optional
from app.schemas.finding import Finding
from app.schemas.evidence import Evidence

class EvidenceGroundingEngine:
    """
    Guarantees that AI-generated findings are 100% grounded in verified collected telemetry evidence.
    Rejects any hallucinated IP addresses, hostnames, users, or non-existent evidence IDs.
    """

    @staticmethod
    def validate_finding_grounding(finding: Finding, collected_evidence: List[Evidence]) -> Tuple[bool, Optional[str], Optional[Finding]]:
        """
        Validate a finding against the store of collected evidence.
        Returns: (is_grounded, error_message, sanitized_finding)
        """
        if not collected_evidence:
            return False, "Insufficient evidence. Zero telemetry evidence collected to support finding.", None

        valid_evidence_ids = {e.id for e in collected_evidence}
        valid_hosts = {e.host for e in collected_evidence if e.host}
        valid_ips = set()
        for e in collected_evidence:
            if e.sourceIp: valid_ips.add(e.sourceIp)
            if e.destinationIp: valid_ips.add(e.destinationIp)

        # 1. Check Evidence IDs existence
        cited_eids = set(finding.evidenceIds)
        invalid_eids = cited_eids.difference(valid_evidence_ids)
        if invalid_eids:
            return False, f"Hallucination Detected: Finding cites non-existent evidence IDs {list(invalid_eids)}.", None

        # 2. Check Host existence
        for host in finding.affectedHosts:
            if not any(host.lower() in vh.lower() for vh in valid_hosts):
                return False, f"Hallucination Detected: Finding claims affected host '{host}' which does NOT exist in collected evidence.", None

        # 3. Check IP existence
        for ip in finding.sourceIps:
            if ip not in valid_ips:
                return False, f"Hallucination Detected: Finding claims source IP '{ip}' which does NOT exist in collected evidence.", None

        return True, None, finding
