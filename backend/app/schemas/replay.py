from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ConfigDict
from enum import Enum

class ReplayState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    COMPLETED = "completed"

class ReplayConfig(BaseModel):
    datasetId: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_\-\.]{1,64}$", description="ID of the imported dataset to replay")
    speedMultiplier: float = Field(default=1.0, gt=0, le=1000.0, description="Replay speed multiplier (e.g. 0.25, 1, 10, 100)")
    startTimestamp: Optional[str] = Field(default=None, max_length=50, description="Optional ISO start timestamp filter")
    endTimestamp: Optional[str] = Field(default=None, max_length=50, description="Optional ISO end timestamp filter")


    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "datasetId": "ds-sample-01",
                "speedMultiplier": 10.0,
                "startTimestamp": "2017-07-07T08:30:00Z",
                "endTimestamp": "2017-07-07T09:30:00Z"
            }
        }
    )

class ReplayStatus(BaseModel):
    state: ReplayState = ReplayState.IDLE
    datasetId: Optional[str] = None
    datasetName: Optional[str] = None
    speedMultiplier: float = 1.0
    startTimestamp: Optional[str] = None
    endTimestamp: Optional[str] = None
    currentSimulatedTimestamp: Optional[str] = None
    totalEvents: int = 0
    eventsEmitted: int = 0
    eventsRemaining: int = 0
    progressPercent: float = 0.0
    lastEmittedEvent: Optional[Dict[str, Any]] = None
    emittedEvents: List[Dict[str, Any]] = Field(default_factory=list)
    startedAt: Optional[str] = None
    elapsedRealTimeSec: float = 0.0
    elapsedSimulatedTimeSec: float = 0.0
    message: Optional[str] = "Replay engine is idle."

    model_config = ConfigDict(populate_by_name=True)
