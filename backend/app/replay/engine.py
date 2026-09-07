import asyncio
import time
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

from app.schemas.replay import ReplayConfig, ReplayStatus, ReplayState
from app.schemas.dataset import NormalizedEvent
from app.ingestion.service import dataset_service
from app.ingestion.validator import parse_and_validate_timestamp
from app.streaming.hub import streaming_hub

logger = logging.getLogger("replay_engine")

def _parse_to_epoch(ts_str: Optional[str], default_epoch: float = 0.0) -> float:
    """Parses an ISO or standard timestamp string into epoch seconds (float)."""
    if not ts_str:
        return default_epoch
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        pass
    parsed_iso, err = parse_and_validate_timestamp(ts_str)
    if parsed_iso and not err:
        try:
            return datetime.fromisoformat(parsed_iso.replace("Z", "+00:00")).timestamp()
        except Exception:
            pass
    return default_epoch


class SecurityEventReplayEngine:
    """
    Deterministic Security Event Replay Engine.
    Emits imported dataset events in strictly chronological order over simulated time.
    Strictly preserves the original timestamps of all emitted events.
    """

    def __init__(self):
        self._state: ReplayState = ReplayState.IDLE
        self._dataset_id: Optional[str] = None
        self._dataset_name: Optional[str] = None
        self._speed_multiplier: float = 1.0
        self._start_timestamp: Optional[str] = None
        self._end_timestamp: Optional[str] = None
        
        self._events_queue: List[Tuple[float, int, NormalizedEvent]] = []
        self._current_index: int = 0
        self._emitted_events: List[Dict[str, Any]] = []
        self._last_emitted_event: Optional[Dict[str, Any]] = None
        self._simulated_current_ts: Optional[str] = None
        
        self._real_started_at_str: Optional[str] = None
        self._real_start_time: Optional[float] = None
        self._paused_time: Optional[float] = None
        self._total_paused_duration: float = 0.0
        
        self._task: Optional[asyncio.Task] = None
        self._pause_event: Optional[asyncio.Event] = None
        self._stop_requested: bool = False
        self._last_error: Optional[str] = None

    def _ensure_async_primitives(self):
        """Lazy initialization of event loop-bound primitives."""
        if self._pause_event is None:
            self._pause_event = asyncio.Event()
            self._pause_event.set()

    def get_status(self) -> ReplayStatus:
        """Returns the current status and progress of the replay engine."""
        total = len(self._events_queue)
        emitted = self._current_index
        remaining = max(0, total - emitted)
        progress = round((emitted / total * 100.0), 2) if total > 0 else 0.0

        elapsed_real = 0.0
        if self._real_start_time:
            now = time.time()
            if self._state == ReplayState.PAUSED and self._paused_time:
                elapsed_real = max(0.0, self._paused_time - self._real_start_time - self._total_paused_duration)
            else:
                elapsed_real = max(0.0, now - self._real_start_time - self._total_paused_duration)

        msg_map = {
            ReplayState.IDLE: "Replay engine is idle.",
            ReplayState.RUNNING: f"Replaying dataset '{self._dataset_name or self._dataset_id}' at {self._speed_multiplier}x speed.",
            ReplayState.PAUSED: f"Replay paused at event {emitted}/{total}.",
            ReplayState.STOPPED: f"Replay stopped after emitting {emitted}/{total} events." + (f" Error: {self._last_error}" if self._last_error else ""),
            ReplayState.COMPLETED: f"Replay completed. Emitted all {total} events successfully."
        }

        return ReplayStatus(
            state=self._state,
            datasetId=self._dataset_id,
            datasetName=self._dataset_name,
            speedMultiplier=self._speed_multiplier,
            startTimestamp=self._start_timestamp,
            endTimestamp=self._end_timestamp,
            currentSimulatedTimestamp=self._simulated_current_ts,
            totalEvents=total,
            eventsEmitted=emitted,
            eventsRemaining=remaining,
            progressPercent=progress,
            lastEmittedEvent=self._last_emitted_event,
            emittedEvents=self._emitted_events[-50:],  # Return latest 50 for UI performance
            startedAt=self._real_started_at_str,
            elapsedRealTimeSec=round(elapsed_real, 2),
            elapsedSimulatedTimeSec=0.0,
            message=msg_map.get(self._state, "Replay status.")
        )

    async def start(self, config: ReplayConfig) -> ReplayStatus:
        """Starts or resets a dataset replay with the specified configuration."""
        self._ensure_async_primitives()

        # 1. Cancel previous running task if any
        if self._task and not self._task.done():
            self._stop_requested = True
            if self._pause_event:
                self._pause_event.set()
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass

        # 2. Validate Dataset
        dataset_meta = dataset_service.get_dataset(config.datasetId)
        if not dataset_meta:
            raise ValueError(f"Dataset with ID '{config.datasetId}' not found.")

        raw_events = dataset_service._events.get(config.datasetId, [])
        if not raw_events:
            raise ValueError(f"Dataset '{config.datasetId}' contains 0 events.")

        # 3. Filter and Chronologically Sort Events deterministically
        start_epoch = _parse_to_epoch(config.startTimestamp, 0.0) if config.startTimestamp else None
        end_epoch = _parse_to_epoch(config.endTimestamp, float('inf')) if config.endTimestamp else None

        indexed_events: List[Tuple[float, int, NormalizedEvent]] = []
        base_fallback_time = 1500000000.0  # Stable fallback base epoch
        
        for idx, evt in enumerate(raw_events):
            epoch_val = _parse_to_epoch(evt.timestamp, base_fallback_time + idx)
            if start_epoch is not None and epoch_val < start_epoch:
                continue
            if end_epoch is not None and epoch_val > end_epoch:
                continue
            indexed_events.append((epoch_val, idx, evt))

        # Deterministic stable sort by timestamp epoch, then index
        indexed_events.sort(key=lambda item: (item[0], item[1]))

        if not indexed_events:
            raise ValueError(f"No events match the specified time range [{config.startTimestamp} - {config.endTimestamp}].")

        # 4. Initialize Engine State
        self._dataset_id = config.datasetId
        self._dataset_name = dataset_meta.dataset_name
        self._speed_multiplier = max(0.01, float(config.speedMultiplier))
        self._start_timestamp = config.startTimestamp
        self._end_timestamp = config.endTimestamp
        self._events_queue = indexed_events
        self._current_index = 0
        self._emitted_events = []
        self._last_emitted_event = None
        self._simulated_current_ts = indexed_events[0][2].timestamp
        self._real_started_at_str = datetime.now(timezone.utc).isoformat()
        self._real_start_time = time.time()
        self._paused_time = None
        self._total_paused_duration = 0.0
        self._stop_requested = False
        self._last_error = None
        
        self._pause_event = asyncio.Event()
        self._pause_event.set()
        self._state = ReplayState.RUNNING

        # 5. Launch Background Task
        self._task = asyncio.create_task(self._run_replay_loop())

        return self.get_status()

    async def pause(self) -> ReplayStatus:
        """Pauses the actively running replay."""
        self._ensure_async_primitives()
        if self._state == ReplayState.RUNNING:
            self._state = ReplayState.PAUSED
            if self._pause_event:
                self._pause_event.clear()
            self._paused_time = time.time()
        return self.get_status()

    async def resume(self) -> ReplayStatus:
        """Resumes a paused replay."""
        self._ensure_async_primitives()
        if self._state == ReplayState.PAUSED:
            if self._paused_time:
                self._total_paused_duration += time.time() - self._paused_time
                self._paused_time = None
            self._state = ReplayState.RUNNING
            if self._pause_event:
                self._pause_event.set()
        return self.get_status()

    async def stop(self) -> ReplayStatus:
        """Stops and cancels the current replay."""
        self._ensure_async_primitives()
        if self._state in (ReplayState.RUNNING, ReplayState.PAUSED):
            self._stop_requested = True
            if self._pause_event:
                self._pause_event.set()
            if self._task and not self._task.done():
                self._task.cancel()
            self._state = ReplayState.STOPPED
        return self.get_status()

    async def _run_replay_loop(self):
        """Internal worker task that paces event emission according to speedMultiplier."""
        try:
            total_count = len(self._events_queue)
            if total_count == 0:
                self._state = ReplayState.COMPLETED
                return

            prev_epoch = self._events_queue[0][0]

            while self._current_index < total_count and not self._stop_requested:
                # 1. Handle Pause State
                if self._pause_event:
                    await self._pause_event.wait()
                if self._stop_requested:
                    break

                curr_epoch, orig_idx, event_obj = self._events_queue[self._current_index]

                # 2. Calculate delay between consecutive events
                simulated_delta_sec = max(0.0, curr_epoch - prev_epoch)
                real_delay_sec = simulated_delta_sec / self._speed_multiplier

                # If delay is non-zero, sleep in small chunks to remain responsive to pause/stop
                if real_delay_sec > 0:
                    chunk = min(0.05, real_delay_sec)
                    elapsed = 0.0
                    while elapsed < real_delay_sec and not self._stop_requested:
                        if self._pause_event:
                            await self._pause_event.wait()
                        if self._stop_requested:
                            break
                        sleep_time = min(chunk, real_delay_sec - elapsed)
                        await asyncio.sleep(sleep_time)
                        elapsed += sleep_time

                if self._stop_requested:
                    break

                # 3. Emit event strictly preserving original timestamp and fields
                event_dict = event_obj.model_dump()
                self._last_emitted_event = event_dict
                self._emitted_events.append(event_dict)
                self._simulated_current_ts = event_obj.timestamp
                self._current_index += 1
                prev_epoch = curr_epoch

                # Broadcast to connected real-time SOC clients
                try:
                    await streaming_hub.broadcast_event(event_dict)
                except Exception as b_err:
                    logger.warning(f"Error broadcasting replayed event: {b_err}")

                # Yield control briefly to ensure smooth event loop execution
                await asyncio.sleep(0.001)

            if not self._stop_requested and self._current_index >= total_count:
                self._state = ReplayState.COMPLETED

        except asyncio.CancelledError:
            if not self._stop_requested and self._state != ReplayState.STOPPED:
                self._state = ReplayState.STOPPED
        except Exception as e:
            self._last_error = str(e)
            logger.exception("Error in replay loop")
            self._state = ReplayState.STOPPED


# Global singleton replay engine instance
replay_engine = SecurityEventReplayEngine()
