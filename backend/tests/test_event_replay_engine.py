import pytest
import asyncio
import httpx
from datetime import datetime
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.replay import ReplayConfig, ReplayStatus, ReplayState
from app.replay.engine import SecurityEventReplayEngine, replay_engine
from app.ingestion.service import dataset_service

client = TestClient(app)


def test_replay_chronological_ordering_and_no_timestamp_modification():
    """Verify events are emitted in strict chronological order with original timestamps preserved."""
    async def _test():
        # Setup test dataset with out-of-order timestamps
        csv_data = (
            "Timestamp, Source IP, Destination IP, Protocol, Label\n"
            "2017-07-07T09:14:11Z, 192.168.10.5, 192.168.10.50, 6, SSH-Patator\n"
            "2017-07-07T09:14:02Z, 192.168.10.5, 192.168.10.50, 6, SSH-Patator\n"
            "2017-07-07T09:14:05Z, 192.168.10.5, 192.168.10.50, 6, SSH-Patator\n"
        )
        report = dataset_service.import_dataset(
            content=csv_data.encode("utf-8"),
            file_name="unordered_test.csv",
            dataset_name="Unordered Test Dataset"
        )
        ds_id = report.dataset.dataset_id

        # Start replay with high speed multiplier for fast test execution
        config = ReplayConfig(
            datasetId=ds_id,
            speedMultiplier=500.0
        )
        status = await replay_engine.start(config)
        assert status.state == ReplayState.RUNNING
        assert status.totalEvents == 3

        # Wait for replay to complete
        for _ in range(50):
            await asyncio.sleep(0.05)
            curr = replay_engine.get_status()
            if curr.state == ReplayState.COMPLETED:
                break

        final_status = replay_engine.get_status()
        assert final_status.state == ReplayState.COMPLETED
        assert final_status.eventsEmitted == 3
        assert final_status.eventsRemaining == 0
        assert final_status.progressPercent == 100.0

        # Check chronological ordering
        emitted = final_status.emittedEvents
        assert len(emitted) == 3
        assert emitted[0]["timestamp"].startswith("2017-07-07T09:14:02")
        assert emitted[1]["timestamp"].startswith("2017-07-07T09:14:05")
        assert emitted[2]["timestamp"].startswith("2017-07-07T09:14:11")

    asyncio.run(_test())


def test_replay_pause_and_resume():
    """Verify pause pauses progress and resume continues accurately."""
    async def _test():
        csv_data = (
            "Timestamp, Source IP, Destination IP, Protocol, Label\n"
            "2017-07-07T09:00:00Z, 10.0.1.5, 10.0.1.10, 6, BENIGN\n"
            "2017-07-07T09:00:10Z, 10.0.1.5, 10.0.1.10, 6, BENIGN\n"
            "2017-07-07T09:00:20Z, 10.0.1.5, 10.0.1.10, 6, BENIGN\n"
            "2017-07-07T09:00:30Z, 10.0.1.5, 10.0.1.10, 6, BENIGN\n"
        )
        report = dataset_service.import_dataset(
            content=csv_data.encode("utf-8"),
            file_name="pause_resume_test.csv",
            dataset_name="Pause Resume Test"
        )
        ds_id = report.dataset.dataset_id

        # Replay at 10x speed (10s sim = 1s real delay)
        config = ReplayConfig(
            datasetId=ds_id,
            speedMultiplier=10.0
        )
        await replay_engine.start(config)
        await asyncio.sleep(0.05)

        # Pause
        paused_status = await replay_engine.pause()
        assert paused_status.state == ReplayState.PAUSED
        emitted_at_pause = paused_status.eventsEmitted

        # Verify no progress happens while paused
        await asyncio.sleep(0.15)
        assert replay_engine.get_status().eventsEmitted == emitted_at_pause
        assert replay_engine.get_status().state == ReplayState.PAUSED

        # Resume at very high speed so it finishes
        replay_engine._speed_multiplier = 500.0
        resumed_status = await replay_engine.resume()
        assert resumed_status.state == ReplayState.RUNNING

        for _ in range(50):
            await asyncio.sleep(0.05)
            if replay_engine.get_status().state == ReplayState.COMPLETED:
                break

        assert replay_engine.get_status().state == ReplayState.COMPLETED
        assert replay_engine.get_status().eventsEmitted == 4

    asyncio.run(_test())


def test_replay_stop():
    """Verify stopping immediately terminates emission and preserves state as stopped."""
    async def _test():
        csv_data = (
            "Timestamp, Source IP, Destination IP, Protocol, Label\n"
            "2017-07-07T09:00:00Z, 10.0.1.5, 10.0.1.10, 6, BENIGN\n"
            "2017-07-07T09:00:50Z, 10.0.1.5, 10.0.1.10, 6, BENIGN\n"
        )
        report = dataset_service.import_dataset(
            content=csv_data.encode("utf-8"),
            file_name="stop_test.csv",
            dataset_name="Stop Test"
        )
        ds_id = report.dataset.dataset_id

        config = ReplayConfig(
            datasetId=ds_id,
            speedMultiplier=1.0  # Slow so we can stop it
        )
        await replay_engine.start(config)
        await asyncio.sleep(0.02)
        stopped_status = await replay_engine.stop()
        assert stopped_status.state == ReplayState.STOPPED
        assert stopped_status.eventsRemaining >= 0

    asyncio.run(_test())


def test_replay_determinism():
    """Verify replaying the same dataset yields the exact same sequence of events."""
    async def _test():
        datasets = dataset_service.list_datasets()
        ds_id = datasets[0].dataset_id

        config = ReplayConfig(datasetId=ds_id, speedMultiplier=500.0)

        # Run 1
        await replay_engine.start(config)
        for _ in range(50):
            await asyncio.sleep(0.05)
            if replay_engine.get_status().state == ReplayState.COMPLETED:
                break
        run1_events = [e["timestamp"] for e in replay_engine.get_status().emittedEvents]

        # Run 2
        await replay_engine.start(config)
        for _ in range(50):
            await asyncio.sleep(0.05)
            if replay_engine.get_status().state == ReplayState.COMPLETED:
                break
        run2_events = [e["timestamp"] for e in replay_engine.get_status().emittedEvents]

        assert len(run1_events) > 0
        assert run1_events == run2_events

    asyncio.run(_test())


def test_replay_api_lifecycle():
    """Test start, pause, resume, stop, and status via FastAPI endpoints."""
    from app.auth.models import UserRole
    from app.auth.security import create_access_token
    token = create_access_token("usr-analyst-01", "analyst", UserRole.ANALYST)
    headers = {"Authorization": f"Bearer {token}"}

    async def _test():
        datasets = dataset_service.list_datasets()
        ds_id = datasets[0].dataset_id

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers=headers) as ac:
            # 1. Start Replay at 1.0x
            res_start = await ac.post("/api/replay/start", json={
                "datasetId": ds_id,
                "speedMultiplier": 1.0
            })
            assert res_start.status_code == 200
            data = res_start.json()
            assert data["state"] == "running"
            assert data["datasetId"] == ds_id
            assert data["speedMultiplier"] == 1.0
            assert data["totalEvents"] > 0

            # 2. Status check
            res_status = await ac.get("/api/replay/status")
            assert res_status.status_code == 200
            status_data = res_status.json()
            assert status_data["state"] in ("running", "completed")

            # 3. Pause
            res_pause = await ac.post("/api/replay/pause")
            assert res_pause.status_code == 200
            assert res_pause.json()["state"] == "paused"

            # 4. Resume
            res_resume = await ac.post("/api/replay/resume")
            assert res_resume.status_code == 200
            assert res_resume.json()["state"] == "running"

            # 5. Stop
            res_stop = await ac.post("/api/replay/stop")
            assert res_stop.status_code == 200
            assert res_stop.json()["state"] == "stopped"

    asyncio.run(_test())


def test_replay_invalid_dataset_returns_400():
    from app.auth.models import UserRole
    from app.auth.security import create_access_token
    token = create_access_token("usr-analyst-01", "analyst", UserRole.ANALYST)
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post("/api/replay/start", json={
        "datasetId": "non-existent-dataset-id",
        "speedMultiplier": 1.0
    }, headers=headers)
    assert res.status_code == 400
    assert "not found" in res.json()["detail"]
