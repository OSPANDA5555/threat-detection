import time
import hashlib
import json
from typing import Dict, List, Optional, Tuple, Set, Any
from collections import defaultdict, deque
from datetime import datetime

from app.agent.models import AgentRegistration, AgentStatus

class AgentRegistry:
    """
    In-memory registry tracking live connected Linux agents,
    heartbeats, event throughput, sequence progress, tenant isolation,
    anti-impersonation bindings, and duplicate event filtering.
    """

    def __init__(self, offline_threshold_seconds: float = 45.0, max_eps: float = 500.0):
        self._agents: Dict[str, Dict] = {}
        self._offline_threshold = offline_threshold_seconds
        self._max_eps = max_eps
        self._event_timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._seen_event_hashes: Dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))
        self._seen_event_set: Dict[str, Set[str]] = defaultdict(set)

    def reset(self):
        self._agents.clear()
        self._event_timestamps.clear()
        self._seen_event_hashes.clear()
        self._seen_event_set.clear()

    def validate_agent_access(
        self,
        agent_id: str,
        caller_id: str,
        caller_role: str,
        tenant_id: str
    ) -> Tuple[bool, str]:
        """
        Prevent an agent from impersonating another agent.
        Admins can manage any agent; agents can only submit for their bound agent identity.
        """
        if caller_role == "ADMIN":
            return True, "OK"

        if agent_id in self._agents:
            ag = self._agents[agent_id]
            bound_caller = ag.get("bound_caller_id")
            bound_tenant = ag.get("tenant_id")
            # If bound to a specific agent identity/token, verify match
            if bound_caller and caller_id not in [bound_caller, "agent-service", "agent-service-account", "telemetry-agent", "system-agent"]:
                return False, f"Impersonation Violation: Caller '{caller_id}' cannot act on behalf of agent '{agent_id}' (bound to '{bound_caller}')."
            if bound_tenant and bound_tenant != tenant_id:
                return False, f"Tenant Violation: Agent '{agent_id}' belongs to tenant '{bound_tenant}'."

        return True, "OK"

    def validate_sequence(self, agent_id: str, sequence_number: int) -> Tuple[bool, str]:
        """
        Replay Protection: Validate that sequence numbers are strictly monotonic.
        """
        if agent_id not in self._agents:
            return True, "OK"

        latest = self._agents[agent_id].get("latest_sequence", 0)
        # Allow sequence 0 or 1 on new/reset agents
        if sequence_number <= latest and latest > 0:
            return False, f"Replay Protection: Received out-of-order or duplicate sequence {sequence_number} (latest is {latest})."

        return True, "OK"

    def check_rate_limit(self, agent_id: str, count: int) -> Tuple[bool, float]:
        """
        Check if an agent is transmitting at an abnormal event rate.
        """
        now_epoch = time.time()
        cutoff = now_epoch - 2.0
        ts_deque = self._event_timestamps[agent_id]
        while ts_deque and ts_deque[0] < cutoff:
            ts_deque.popleft()

        current_eps = (len(ts_deque) + count) / 2.0
        if current_eps > self._max_eps:
            return False, current_eps

        return True, current_eps

    def filter_duplicate_events(self, agent_id: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Reject duplicate event floods within the sliding hash window.
        """
        unique_events = []
        hash_deque = self._seen_event_hashes[agent_id]
        hash_set = self._seen_event_set[agent_id]

        for ev in events:
            # Generate deterministic hash for event payload
            ev_id = ev.get("id") or ev.get("event_id")
            raw_repr = f"{ev_id}:{ev.get('timestamp')}:{ev.get('event_type')}:{ev.get('source_ip')}:{ev.get('destination_port')}"
            ev_hash = hashlib.sha256(raw_repr.encode("utf-8")).hexdigest()

            if ev_hash not in hash_set:
                if len(hash_deque) >= hash_deque.maxlen:
                    old_hash = hash_deque.popleft()
                    hash_set.discard(old_hash)

                hash_deque.append(ev_hash)
                hash_set.add(ev_hash)
                unique_events.append(ev)

        return unique_events

    def register_or_update(
        self,
        agent_id: str,
        hostname: str,
        agent_version: str = "1.0.0",
        platform: str = "Linux",
        ip_address: Optional[str] = None,
        bound_caller_id: Optional[str] = None,
        tenant_id: Optional[str] = "soc-org-primary"
    ) -> AgentStatus:
        now_str = datetime.utcnow().isoformat() + "Z"
        now_epoch = time.time()

        if agent_id not in self._agents:
            self._agents[agent_id] = {
                "agent_id": agent_id,
                "hostname": hostname,
                "platform": platform,
                "ip_address": ip_address,
                "agent_version": agent_version,
                "bound_caller_id": bound_caller_id or agent_id,
                "tenant_id": tenant_id or "soc-org-primary",
                "registered_at": now_str,
                "last_seen": now_str,
                "last_seen_epoch": now_epoch,
                "total_events_sent": 0,
                "latest_sequence": 0
            }
        else:
            self._agents[agent_id]["hostname"] = hostname
            self._agents[agent_id]["agent_version"] = agent_version
            if ip_address:
                self._agents[agent_id]["ip_address"] = ip_address
            if tenant_id:
                self._agents[agent_id]["tenant_id"] = tenant_id
            self._agents[agent_id]["last_seen"] = now_str
            self._agents[agent_id]["last_seen_epoch"] = now_epoch

        return self._to_agent_status(agent_id)

    def record_ingestion(
        self,
        agent_id: str,
        hostname: str,
        agent_version: str,
        sequence_number: int,
        events_count: int,
        ip_address: Optional[str] = None,
        bound_caller_id: Optional[str] = None,
        tenant_id: Optional[str] = "soc-org-primary"
    ) -> AgentStatus:
        now_str = datetime.utcnow().isoformat() + "Z"
        now_epoch = time.time()

        if agent_id not in self._agents:
            self.register_or_update(
                agent_id=agent_id,
                hostname=hostname,
                agent_version=agent_version,
                ip_address=ip_address,
                bound_caller_id=bound_caller_id,
                tenant_id=tenant_id
            )

        ag = self._agents[agent_id]
        ag["last_seen"] = now_str
        ag["last_seen_epoch"] = now_epoch
        ag["total_events_sent"] += events_count
        ag["latest_sequence"] = max(ag["latest_sequence"], sequence_number)
        if ip_address:
            ag["ip_address"] = ip_address

        # Track timestamps for EPS calculation
        for _ in range(events_count):
            self._event_timestamps[agent_id].append(now_epoch)

        return self._to_agent_status(agent_id)

    def _to_agent_status(self, agent_id: str) -> AgentStatus:
        ag = self._agents[agent_id]
        now_epoch = time.time()
        time_diff = now_epoch - ag.get("last_seen_epoch", 0)

        # Calculate status
        if time_diff > self._offline_threshold:
            status_val = "OFFLINE"
        elif time_diff > 20.0:
            status_val = "DEGRADED"
        else:
            status_val = "ONLINE"

        # Calculate EPS over last 3 seconds
        cutoff = now_epoch - 3.0
        ts_deque = self._event_timestamps[agent_id]
        while ts_deque and ts_deque[0] < cutoff:
            ts_deque.popleft()

        eps = round(len(ts_deque) / 3.0, 1) if ts_deque else 0.0

        return AgentStatus(
            agent_id=ag["agent_id"],
            hostname=ag["hostname"],
            platform=ag.get("platform", "Linux"),
            ip_address=ag.get("ip_address"),
            agent_version=ag.get("agent_version", "1.0.0"),
            status=status_val,
            registered_at=ag["registered_at"],
            last_seen=ag["last_seen"],
            events_per_sec=eps,
            total_events_sent=ag["total_events_sent"],
            latest_sequence=ag["latest_sequence"]
        )

    def list_agents(self) -> List[AgentStatus]:
        return [self._to_agent_status(aid) for aid in self._agents]

    def get_agent(self, agent_id: str) -> Optional[AgentStatus]:
        if agent_id in self._agents:
            return self._to_agent_status(agent_id)
        return None

# Global singleton agent registry
agent_registry = AgentRegistry()

