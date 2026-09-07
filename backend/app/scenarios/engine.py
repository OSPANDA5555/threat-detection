import asyncio
import time
import logging
from typing import Dict, Any, Optional
from pydantic import BaseModel

from app.scenarios.definitions import get_prebuilt_scenarios, PrebuiltScenario
from app.streaming.hub import streaming_hub

logger = logging.getLogger("simulated_scenario_runner")

class SimulatedReplayStatus(BaseModel):
    status: str = "idle"  # idle, running, completed, stopped
    scenario_id: Optional[str] = None
    scenario_name: Optional[str] = None
    category: str = "SIMULATED ATTACK REPLAY"
    events_emitted: int = 0
    total_events: int = 0
    speed_multiplier: float = 2.0
    current_timestamp: Optional[str] = None

class SimulatedScenarioRunner:
    """
    Asynchronously streams prebuilt attack scenarios into the real-time event pipeline.
    Clearly tags all emitted events as SIMULATED ATTACK REPLAY with zero ambiguity.
    """

    def __init__(self):
        self._current_task: Optional[asyncio.Task] = None
        self._status = SimulatedReplayStatus()
        self._lock = asyncio.Lock()

    def get_status(self) -> SimulatedReplayStatus:
        return self._status

    async def stop(self) -> SimulatedReplayStatus:
        async with self._lock:
            if self._current_task and not self._current_task.done():
                self._current_task.cancel()
                try:
                    await self._current_task
                except asyncio.CancelledError:
                    pass
            self._status.status = "stopped"
            return self._status

    async def start(self, scenario_id: str, speed_multiplier: float = 2.0) -> SimulatedReplayStatus:
        scenarios = get_prebuilt_scenarios()
        if scenario_id not in scenarios:
            raise ValueError(f"Unknown scenario ID '{scenario_id}'. Available: {list(scenarios.keys())}")

        await self.stop()

        sc = scenarios[scenario_id]
        self._status = SimulatedReplayStatus(
            status="running",
            scenario_id=sc.scenario_id,
            scenario_name=sc.name,
            events_emitted=0,
            total_events=sc.events_count,
            speed_multiplier=speed_multiplier
        )

        self._current_task = asyncio.create_task(self._run_scenario_loop(sc, speed_multiplier))
        return self._status

    async def _run_scenario_loop(self, scenario: PrebuiltScenario, speed_multiplier: float):
        events = scenario.events
        logger.info(f"Starting simulated attack replay for '{scenario.name}' ({len(events)} events) at {speed_multiplier}x")

        # Delay between events calculated proportionally or default 0.4s / speed
        delay_per_event = max(0.1, min(1.0 / max(0.1, speed_multiplier), 2.0))

        try:
            for i, ev in enumerate(events):
                # Ensure simulated metadata is strictly present
                ev_copy = dict(ev)
                ev_copy["label"] = "SIMULATED ATTACK REPLAY"
                ev_copy["metadata"] = {
                    **(ev_copy.get("metadata") or {}),
                    "telemetry_source": "SIMULATED_SCENARIO",
                    "scenario_id": scenario.scenario_id,
                    "simulated": True
                }

                # Broadcast into real-time pipeline & detection engine
                await streaming_hub.broadcast_event(ev_copy)

                self._status.events_emitted = i + 1
                self._status.current_timestamp = ev_copy.get("timestamp")

                if i < len(events) - 1:
                    await asyncio.sleep(delay_per_event)

            self._status.status = "completed"
            logger.info(f"Completed simulated attack replay for '{scenario.name}'")
        except asyncio.CancelledError:
            self._status.status = "stopped"
            logger.info(f"Simulated attack replay cancelled for '{scenario.name}'")
        except Exception as e:
            logger.error(f"Error during simulated scenario replay: {e}")
            self._status.status = "error"


# Global singleton scenario runner
simulated_scenario_runner = SimulatedScenarioRunner()
