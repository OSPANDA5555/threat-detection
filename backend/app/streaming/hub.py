import asyncio
import time
import json
import logging
from collections import deque
from typing import Dict, Any, List, Optional, Set, Union
from fastapi import WebSocket, WebSocketDisconnect

from app.schemas.stream import StreamedEvent, StreamStats

logger = logging.getLogger("event_streaming_hub")

class EventStreamingHub:
    """
    Real-Time Security Event Streaming Hub.
    Manages active WebSocket client connections, assigns monotonic sequence numbers,
    enforces tenant data isolation, maintains a circular historical replay buffer,
    bounds connection resources, and applies backpressure handling for broadcast performance.
    """

    def __init__(self, max_buffer_size: int = 10000, max_connections: int = 100):
        self._active_connections: Set[WebSocket] = set()
        self._client_meta: Dict[WebSocket, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._global_sequence: int = 0
        self._historical_buffer: deque = deque(maxlen=max_buffer_size)
        self._recent_timestamps: deque = deque(maxlen=500)
        self._total_events_streamed: int = 0
        self._max_connections = max_connections

    @property
    def latest_sequence(self) -> int:
        return self._global_sequence

    def get_stats(self) -> StreamStats:
        """Calculate real-time streaming metrics."""
        now = time.time()
        cutoff = now - 2.0
        while self._recent_timestamps and self._recent_timestamps[0] < cutoff:
            self._recent_timestamps.popleft()
        
        eps = round(len(self._recent_timestamps) / 2.0, 1) if self._recent_timestamps else 0.0

        return StreamStats(
            connected_clients=len(self._active_connections),
            total_events_streamed=self._total_events_streamed,
            latest_sequence=self._global_sequence,
            events_per_second=eps,
            buffer_size=len(self._historical_buffer)
        )

    async def connect(
        self,
        websocket: WebSocket,
        client_id: Optional[str] = None,
        last_sequence: Optional[int] = None,
        user_id: Optional[str] = "analyst",
        role: Optional[str] = "ANALYST",
        tenant_id: Optional[str] = "soc-org-primary"
    ) -> bool:
        """
        Accepts a WebSocket connection, enforces resource caps, records client metadata,
        and securely backfills missed events within tenant boundaries.
        """
        # Enforce maximum concurrent connections cap (DoS guard)
        if len(self._active_connections) >= self._max_connections:
            await websocket.close(code=1013, reason="Maximum active WebSocket connections exceeded.")
            return False

        await websocket.accept()
        cid = client_id or "anonymous"
        t_id = tenant_id or "soc-org-primary"
        r_val = role or "ANALYST"

        async with self._lock:
            self._active_connections.add(websocket)
            self._client_meta[websocket] = {
                "client_id": cid,
                "user_id": user_id or "analyst",
                "role": r_val,
                "tenant_id": t_id,
                "connected_at": time.time(),
                "last_msg_time": time.time(),
                "msg_count_window": 0
            }

        # Send initial handshake message
        welcome_msg = {
            "type": "connected",
            "client_id": cid,
            "tenant_id": t_id,
            "latest_sequence": self._global_sequence,
            "server_time": time.time()
        }
        await websocket.send_text(json.dumps(welcome_msg))

        # Reconnect backfill: securely stream missing historical events belonging to client's tenant
        if last_sequence is not None and last_sequence >= 0:
            await self._backfill_missed_events(websocket, last_sequence, t_id, r_val)

        return True

    async def disconnect(self, websocket: WebSocket) -> None:
        """Safely removes disconnected WebSocket client and associated metadata."""
        async with self._lock:
            if websocket in self._active_connections:
                self._active_connections.remove(websocket)
            self._client_meta.pop(websocket, None)

    async def _backfill_missed_events(
        self,
        websocket: WebSocket,
        last_sequence: int,
        tenant_id: str = "soc-org-primary",
        role: str = "ANALYST"
    ) -> None:
        """Sends historical buffered events matching sequence and tenant authorization (capped at 200)."""
        missed = [
            evt for evt in self._historical_buffer
            if evt.sequence > last_sequence and (role == "ADMIN" or getattr(evt, "metadata", {}).get("tenant_id", "soc-org-primary") in [tenant_id, "soc-org-primary"])
        ]
        # Cap backfill window
        for evt in missed[:200]:
            try:
                await websocket.send_text(json.dumps(evt.model_dump()))
            except Exception as e:
                logger.warning(f"Error backfilling event {evt.sequence} to client: {e}")
                break

    async def broadcast_event(self, raw_event: Union[Dict[str, Any], Any]) -> StreamedEvent:
        """
        Assigns the next monotonic sequence number, creates a standardized StreamedEvent,
        appends to ring buffer, and non-blockingly broadcasts to authorized tenant clients.
        """
        async with self._lock:
            self._global_sequence += 1
            seq = self._global_sequence
            self._total_events_streamed += 1

        now = time.time()
        self._recent_timestamps.append(now)

        # Extract dictionary payload
        if hasattr(raw_event, "model_dump"):
            data = raw_event.model_dump()
        elif isinstance(raw_event, dict):
            data = raw_event
        else:
            data = {"raw": str(raw_event)}

        # Extract or generate stable event_id
        event_id = data.get("id") or data.get("event_id") or data.get("eventId")
        if not event_id:
            from app.normalization.models import SecurityEvent
            event_id = SecurityEvent.generate_stable_id(
                data.get("source") or "stream",
                data.get("timestamp"),
                str(data)
            )

        timestamp_str = str(data.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        event_tenant = data.get("tenant_id") or data.get("metadata", {}).get("tenant_id") or "soc-org-primary"

        streamed = StreamedEvent(
            type="event",
            sequence=seq,
            event_id=event_id,
            timestamp=timestamp_str,
            source_type=str(data.get("source_type") or data.get("sourceFormat") or "generic"),
            source=data.get("source"),
            hostname=data.get("hostname") or data.get("host"),
            source_ip=data.get("source_ip") or data.get("sourceIp") or data.get("src_ip"),
            source_port=data.get("source_port") or data.get("src_port"),
            destination_ip=data.get("destination_ip") or data.get("destinationIp") or data.get("dst_ip"),
            destination_port=data.get("destination_port") or data.get("dest_port") or data.get("dst_port"),
            protocol=data.get("protocol"),
            username=data.get("username") or data.get("user"),
            process_name=data.get("process_name") or data.get("process"),
            process_id=data.get("process_id") or data.get("pid"),
            command=data.get("command") or data.get("command_line"),
            event_type=str(data.get("event_type") or data.get("eventType") or "security_event"),
            action=data.get("action"),
            status=data.get("status"),
            bytes_in=data.get("bytes_in"),
            bytes_out=data.get("bytes_out"),
            severity=str(data.get("severity") or ("HIGH" if data.get("label", "BENIGN") != "BENIGN" else "INFO")),
            label=str(data.get("label") or "BENIGN"),
            raw_data=data.get("raw_data") or data,
            metadata=data.get("metadata") or {"tenant_id": event_tenant}
        )

        # Store in historical circular buffer
        self._historical_buffer.append(streamed)

        # Real-time behavioral detection pipeline evaluation
        from app.detection.engine import realtime_detection_engine
        alerts = realtime_detection_engine.process_event(streamed)

        # Broadcast to active connections matching tenant authorization
        if self._active_connections:
            msg_json = json.dumps(streamed.model_dump())
            dead_sockets = set()

            for ws in list(self._active_connections):
                meta = self._client_meta.get(ws, {})
                client_tenant = meta.get("tenant_id", "soc-org-primary")
                client_role = meta.get("role", "ANALYST")

                # Tenant authorization barrier
                if client_role != "ADMIN" and client_tenant != event_tenant and event_tenant != "soc-org-primary":
                    continue

                try:
                    await asyncio.wait_for(ws.send_text(msg_json), timeout=0.5)
                except (WebSocketDisconnect, asyncio.TimeoutError, Exception):
                    dead_sockets.add(ws)

            # Broadcast detection alerts with tenant matching
            for alert in alerts:
                alert_payload = json.dumps({
                    "type": "detection_alert",
                    "detection": alert.model_dump(),
                    "active_incidents_count": len(realtime_detection_engine.get_active_incidents())
                })
                for ws in list(self._active_connections):
                    meta = self._client_meta.get(ws, {})
                    client_tenant = meta.get("tenant_id", "soc-org-primary")
                    client_role = meta.get("role", "ANALYST")
                    if client_role != "ADMIN" and client_tenant != event_tenant and event_tenant != "soc-org-primary":
                        continue
                    try:
                        await asyncio.wait_for(ws.send_text(alert_payload), timeout=0.5)
                    except Exception:
                        pass

            if dead_sockets:
                async with self._lock:
                    self._active_connections -= dead_sockets
                    for ws in dead_sockets:
                        self._client_meta.pop(ws, None)

        return streamed

    def reset(self):
        """Resets sequences, client metadata, and buffer for testing."""
        self._global_sequence = 0
        self._total_events_streamed = 0
        self._historical_buffer.clear()
        self._recent_timestamps.clear()
        self._client_meta.clear()



# Global singleton streaming hub
streaming_hub = EventStreamingHub()
