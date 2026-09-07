import pytest
import asyncio
import json
from fastapi.testclient import TestClient

from app.main import app
from app.streaming.hub import streaming_hub
from app.schemas.replay import ReplayConfig, ReplayState
from app.replay.engine import replay_engine
from app.ingestion.service import dataset_service

client = TestClient(app)


def test_websocket_connection_and_handshake():
    """Verify WebSocket connection accepts client and transmits handshake with latest sequence."""
    streaming_hub.reset()

    with client.websocket_connect("/ws/events?client_id=soc-client-01") as ws:
        # 1. Receive handshake
        raw_msg = ws.receive_text()
        handshake = json.loads(raw_msg)
        assert handshake["type"] == "connected"
        assert handshake["client_id"] == "soc-client-01"
        assert "latest_sequence" in handshake

        # 2. Ping-pong check
        ws.send_text(json.dumps({"type": "ping"}))
        pong = json.loads(ws.receive_text())
        assert pong["type"] == "pong"


def test_realtime_event_delivery_and_sequence_ordering():
    """Verify events are broadcast with strictly monotonic sequence numbers, event IDs, and timestamps."""
    streaming_hub.reset()

    with client.websocket_connect("/ws/events") as ws:
        # Handshake
        json.loads(ws.receive_text())

        # Broadcast 3 test security events
        async def broadcast_sample():
            for i in range(3):
                await streaming_hub.broadcast_event({
                    "timestamp": f"2026-08-10T19:30:{10+i:02d}Z",
                    "source_ip": f"192.168.100.{10+i}",
                    "source_port": 49152 + i,
                    "destination_ip": "10.0.1.10",
                    "destination_port": 22,
                    "protocol": "TCP",
                    "event_type": "SSH_AUTHENTICATION",
                    "label": "SSH-Patator",
                    "action": "FAILURE",
                    "status": "FAILURE"
                })

        asyncio.run(broadcast_sample())

        # Receive 3 events over WebSocket
        received_events = []
        for _ in range(3):
            data = json.loads(ws.receive_text())
            received_events.append(data)

        assert len(received_events) == 3
        # Check monotonic sequence numbers
        assert received_events[0]["sequence"] == 1
        assert received_events[1]["sequence"] == 2
        assert received_events[2]["sequence"] == 3

        # Check event structure & event_id
        for evt in received_events:
            assert evt["type"] == "event"
            assert "event_id" in evt
            assert evt["event_id"].startswith("sec-evt-")
            assert "timestamp" in evt
            assert evt["event_type"] == "SSH_AUTHENTICATION"


def test_reconnect_and_duplicate_prevention():
    """Verify client reconnect with last_sequence backfills missed events without duplicates."""
    streaming_hub.reset()

    # 1. First connection: receives event 1
    with client.websocket_connect("/ws/events") as ws1:
        json.loads(ws1.receive_text())  # handshake

        async def send_event(num):
            await streaming_hub.broadcast_event({
                "timestamp": f"2026-08-10T19:00:0{num}Z",
                "source_ip": "10.0.1.5",
                "label": f"Event-{num}"
            })

        asyncio.run(send_event(1))
        evt1 = json.loads(ws1.receive_text())
        assert evt1["sequence"] == 1
        last_seq_seen = evt1["sequence"]

    # 2. Client is disconnected while 2 more events arrive (seq 2, seq 3)
    async def send_offline_events():
        await send_event(2)
        await send_event(3)

    asyncio.run(send_offline_events())

    # 3. Client reconnects with last_sequence=1
    with client.websocket_connect(f"/ws/events?last_sequence={last_seq_seen}") as ws2:
        handshake = json.loads(ws2.receive_text())
        assert handshake["type"] == "connected"

        # Client should receive missed event 2 and event 3, but NOT event 1
        missed_1 = json.loads(ws2.receive_text())
        missed_2 = json.loads(ws2.receive_text())

        assert missed_1["sequence"] == 2
        assert missed_1["label"] == "Event-2"

        assert missed_2["sequence"] == 3
        assert missed_2["label"] == "Event-3"


def test_replay_engine_broadcasts_to_streaming_hub():
    """Verify that running the replay engine automatically pushes events to connected WebSockets."""
    streaming_hub.reset()

    datasets = dataset_service.list_datasets()
    ds_id = datasets[0].dataset_id

    with client.websocket_connect("/ws/events") as ws:
        json.loads(ws.receive_text())  # handshake

        # Start replay and await at least 1 event emission
        async def run_replay():
            config = ReplayConfig(datasetId=ds_id, speedMultiplier=500.0)
            await replay_engine.start(config)
            for _ in range(20):
                await asyncio.sleep(0.02)
                if replay_engine.get_status().eventsEmitted > 0:
                    break

        asyncio.run(run_replay())

        # Receive streamed events from replay
        streamed_event = json.loads(ws.receive_text())
        assert streamed_event["type"] == "event"
        assert streamed_event["sequence"] >= 1
        assert "source_ip" in streamed_event
        assert "timestamp" in streamed_event


def test_event_streaming_stats_endpoint():
    """Verify /api/events/stats returns live metrics."""
    res = client.get("/api/events/stats")
    assert res.status_code == 200
    stats = res.json()
    assert "connected_clients" in stats
    assert "total_events_streamed" in stats
    assert "latest_sequence" in stats
    assert "events_per_second" in stats
    assert "buffer_size" in stats
