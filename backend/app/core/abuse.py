import time
import threading
from typing import Dict, Tuple, Optional, Any
from collections import defaultdict

class AbuseMonitor:
    """
    Centralized In-Memory Abuse Protection and Telemetry Monitor.
    Tracks rate limit violations, payload rejections, concurrent operations,
    and exposes operational abuse metrics for monitoring and alerting.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._active_hunts_by_ip: Dict[str, int] = defaultdict(int)
        self._active_replays_by_ip: Dict[str, int] = defaultdict(int)
        self._active_websockets_by_ip: Dict[str, int] = defaultdict(int)
        
        # Operational Abuse Metrics
        self._metrics = {
            "total_429_rate_limited": 0,
            "total_413_payload_rejected": 0,
            "total_concurrency_rejected": 0,
            "rate_limits_by_category": defaultdict(int),
            "top_flagged_ips": defaultdict(int),
            "start_time": time.time()
        }

    # -------------------------------------------------------------------------
    # Concurrency Tracking
    # -------------------------------------------------------------------------
    def acquire_hunt_slot(self, client_ip: str, max_concurrent: int = 5) -> Tuple[bool, str]:
        """Track active concurrent AI investigations per IP."""
        with self._lock:
            current = self._active_hunts_by_ip[client_ip]
            if current >= max_concurrent:
                self._metrics["total_concurrency_rejected"] += 1
                self._metrics["top_flagged_ips"][client_ip] += 1
                return False, f"Maximum concurrent AI investigations ({max_concurrent}) reached for your IP. Please wait for previous hunts to finish."
            self._active_hunts_by_ip[client_ip] += 1
            return True, "OK"

    def release_hunt_slot(self, client_ip: str) -> None:
        """Release active AI investigation slot."""
        with self._lock:
            if client_ip in self._active_hunts_by_ip:
                self._active_hunts_by_ip[client_ip] = max(0, self._active_hunts_by_ip[client_ip] - 1)
                if self._active_hunts_by_ip[client_ip] == 0:
                    del self._active_hunts_by_ip[client_ip]

    def acquire_replay_slot(self, client_ip: str, max_concurrent: int = 2) -> Tuple[bool, str]:
        """Track active concurrent replay streams per IP."""
        with self._lock:
            current = self._active_replays_by_ip[client_ip]
            if current >= max_concurrent:
                self._metrics["total_concurrency_rejected"] += 1
                self._metrics["top_flagged_ips"][client_ip] += 1
                return False, f"Maximum concurrent scenario replays ({max_concurrent}) reached for your IP."
            self._active_replays_by_ip[client_ip] += 1
            return True, "OK"

    def release_replay_slot(self, client_ip: str) -> None:
        """Release active replay stream slot."""
        with self._lock:
            if client_ip in self._active_replays_by_ip:
                self._active_replays_by_ip[client_ip] = max(0, self._active_replays_by_ip[client_ip] - 1)
                if self._active_replays_by_ip[client_ip] == 0:
                    del self._active_replays_by_ip[client_ip]

    def acquire_websocket_slot(self, client_ip: str, max_concurrent_per_ip: int = 10, max_global: int = 100) -> Tuple[bool, str]:
        """Track active WebSocket connections per IP and globally."""
        with self._lock:
            total_active = sum(self._active_websockets_by_ip.values())
            if total_active >= max_global:
                self._metrics["total_concurrency_rejected"] += 1
                return False, f"Global WebSocket connection capacity ({max_global}) reached."

            current_ip = self._active_websockets_by_ip[client_ip]
            if current_ip >= max_concurrent_per_ip:
                self._metrics["total_concurrency_rejected"] += 1
                self._metrics["top_flagged_ips"][client_ip] += 1
                return False, f"Maximum concurrent WebSocket connections ({max_concurrent_per_ip}) reached for your IP."

            self._active_websockets_by_ip[client_ip] += 1
            return True, "OK"

    def release_websocket_slot(self, client_ip: str) -> None:
        """Release WebSocket connection slot."""
        with self._lock:
            if client_ip in self._active_websockets_by_ip:
                self._active_websockets_by_ip[client_ip] = max(0, self._active_websockets_by_ip[client_ip] - 1)
                if self._active_websockets_by_ip[client_ip] == 0:
                    del self._active_websockets_by_ip[client_ip]

    # -------------------------------------------------------------------------
    # Metrics & Violations Recording
    # -------------------------------------------------------------------------
    def record_rate_limit_hit(self, client_ip: str, category: str) -> None:
        """Record a 429 Rate Limit event."""
        with self._lock:
            self._metrics["total_429_rate_limited"] += 1
            self._metrics["rate_limits_by_category"][category] += 1
            self._metrics["top_flagged_ips"][client_ip] += 1

    def record_payload_too_large(self, client_ip: str, size_bytes: int) -> None:
        """Record a 413 Payload Too Large event."""
        with self._lock:
            self._metrics["total_413_payload_rejected"] += 1
            self._metrics["top_flagged_ips"][client_ip] += 1

    def get_metrics_report(self) -> Dict[str, Any]:
        """Retrieve real-time abuse monitoring statistics."""
        with self._lock:
            uptime = round(time.time() - self._metrics["start_time"], 1)
            total_active_ws = sum(self._active_websockets_by_ip.values())
            total_active_hunts = sum(self._active_hunts_by_ip.values())
            total_active_replays = sum(self._active_replays_by_ip.values())

            # Top 10 flagged IPs
            sorted_ips = sorted(self._metrics["top_flagged_ips"].items(), key=lambda x: x[1], reverse=True)[:10]

            return {
                "status": "HEALTHY",
                "uptime_seconds": uptime,
                "active_concurrency": {
                    "active_websockets": total_active_ws,
                    "active_ai_hunts": total_active_hunts,
                    "active_scenario_replays": total_active_replays,
                },
                "abuse_prevention_stats": {
                    "total_429_rate_limited": self._metrics["total_429_rate_limited"],
                    "total_413_payload_rejected": self._metrics["total_413_payload_rejected"],
                    "total_concurrency_rejected": self._metrics["total_concurrency_rejected"],
                    "rate_limits_by_category": dict(self._metrics["rate_limits_by_category"]),
                    "top_flagged_ips": dict(sorted_ips)
                }
            }

abuse_monitor = AbuseMonitor()
