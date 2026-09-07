import time
from typing import Dict, List, Optional
from collections import defaultdict, deque
from datetime import datetime

from app.agent.models import AgentRegistration, AgentStatus

class AgentRegistry:
    """
    In-memory registry tracking live connected Linux agents,
    heartbeats, event throughput, and sequence progress.
    """

    def __init__(self, offline_threshold_seconds: float = 45.0):
        self._agents: Dict[str, Dict] = {}
        self._offline_threshold = offline_threshold_seconds
        self._event_timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    def reset(self):
        self._agents.clear()
        self._event_timestamps.clear()

    def register_or_update(
        self,
        agent_id: str,
        hostname: str,
        agent_version: str = "1.0.0",
        platform: str = "Linux",
        ip_address: Optional[str] = None
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
        ip_address: Optional[str] = None
    ) -> AgentStatus:
        now_str = datetime.utcnow().isoformat() + "Z"
        now_epoch = time.time()

        if agent_id not in self._agents:
            self.register_or_update(
                agent_id=agent_id,
                hostname=hostname,
                agent_version=agent_version,
                ip_address=ip_address
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
