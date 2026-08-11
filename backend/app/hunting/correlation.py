from typing import List, Dict, Any
from app.schemas.evidence import Evidence, EvidenceSource

class EvidenceCorrelationEngine:
    """
    Correlates collected security events across hosts, IPs, users, and timestamps.
    Normalizes tool outputs into structured Evidence objects and builds chronological investigation timelines.
    """

    @staticmethod
    def normalize_and_correlate(tool_name: str, records: List[Dict[str, Any]]) -> List[Evidence]:
        """
        Normalize raw telemetry query records into Evidence objects with relevance descriptions.
        """
        evidence_list = []
        source_map = {
            "search_authentication_events": EvidenceSource.AUTHENTICATION,
            "search_network_events": EvidenceSource.NETWORK,
            "search_dns_events": EvidenceSource.DNS,
            "search_process_events": EvidenceSource.PROCESS,
            "search_file_events": EvidenceSource.FILE,
            "get_host_timeline": EvidenceSource.HOST_TIMELINE,
            "get_ip_activity": EvidenceSource.NETWORK,
            "get_domain_activity": EvidenceSource.DNS,
            "get_alerts": EvidenceSource.ALERT
        }
        evd_source = source_map.get(tool_name, EvidenceSource.AUTHENTICATION)

        for rec in records:
            eid = rec.get("eventId") or rec.get("id") or f"evd-{tool_name[:6]}-{len(evidence_list):03d}"
            host = rec.get("host")
            user = rec.get("user")
            src_ip = rec.get("sourceIp") or rec.get("source_ip") or rec.get("src_ip") or rec.get("client_ip")
            dst_ip = rec.get("destinationIp") or rec.get("destination_ip") or rec.get("dest_ip")
            action = rec.get("action") or rec.get("eventType") or tool_name
            status = rec.get("status", "SUCCESS")
            ts = rec.get("timestamp", "2026-08-10T19:30:00Z")

            relevance = f"Detected {action} event (Status: {status}) on host {host or 'unknown'} by user {user or 'unknown'}."
            if src_ip:
                relevance += f" Source IP: {src_ip}."

            evd = Evidence(
                id=eid,
                source=evd_source,
                timestamp=ts,
                host=host,
                user=user,
                sourceIp=src_ip,
                destinationIp=dst_ip,
                eventType=str(action),
                rawReference=f"{tool_name}:{eid}",
                normalizedData=rec,
                relevance=relevance,
                confidence=0.9
            )
            evidence_list.append(evd)

        return evidence_list

    @staticmethod
    def build_timeline(evidence_list: List[Evidence]) -> List[Dict[str, Any]]:
        """Build sorted chronological timeline from evidence items."""
        sorted_evd = sorted(evidence_list, key=lambda x: x.timestamp)
        timeline = []
        for e in sorted_evd:
            timeline.append({
                "timestamp": e.timestamp,
                "event": f"[{e.source.upper()}] {e.eventType} on {e.host or 'N/A'}",
                "evidence_id": e.id,
                "user": e.user,
                "source_ip": e.sourceIp
            })
        return timeline
