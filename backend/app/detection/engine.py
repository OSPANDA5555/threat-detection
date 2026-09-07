import logging
from typing import Dict, Any, List, Union, Optional

from app.detection.rules import BehavioralRuleEngine
from app.detection.incidents import incident_state_manager, IncidentStateManager
from app.detection.evaluation import evaluation_tracker, RealTimeEvaluationTracker
from app.detection.models import DetectionAlert, ActiveIncident, EvaluationMetrics

logger = logging.getLogger("realtime_detection_engine")

class RealTimeDetectionEngine:
    """
    Main Real-Time Threat Detection & Correlation Engine.
    Processes live streamed SecurityEvents, executes multi-event behavioral pattern rules,
    correlates alerts into active incidents and dynamic attack graphs,
    and updates ground-truth evaluation metrics.
    """

    def __init__(
        self,
        rule_engine: Optional[BehavioralRuleEngine] = None,
        incident_manager: Optional[IncidentStateManager] = None,
        eval_tracker: Optional[RealTimeEvaluationTracker] = None
    ):
        self.rule_engine = rule_engine or BehavioralRuleEngine()
        self.incident_manager = incident_manager or incident_state_manager
        self.eval_tracker = eval_tracker or evaluation_tracker

    def reset(self):
        self.rule_engine.reset()
        self.incident_manager.reset()
        self.eval_tracker.reset()

    def process_event(self, raw_event: Union[Dict[str, Any], Any]) -> List[DetectionAlert]:
        """
        Process a single SecurityEvent:
        1. Evaluates behavioral detection rules.
        2. Correlates resulting alerts into ActiveIncidents and Attack Graphs.
        3. Records evaluation metrics against dataset ground truth.
        """
        if hasattr(raw_event, "model_dump"):
            event_dict = raw_event.model_dump()
        elif isinstance(raw_event, dict):
            event_dict = raw_event
        else:
            event_dict = {"raw": str(raw_event)}

        # 1. Behavioral rule evaluation (strictly zero label leakage)
        alerts = self.rule_engine.evaluate_event(event_dict)

        # 2. Incident correlation and attack graph updates
        for alert in alerts:
            self.incident_manager.correlate_detection(alert)

        # 3. Ground truth evaluation update
        actual_label = event_dict.get("label")
        if actual_label is not None:
            self.eval_tracker.record_event_evaluation(
                actual_label=str(actual_label),
                detection_fired=(len(alerts) > 0)
            )

        return alerts

    def get_active_incidents(self) -> List[ActiveIncident]:
        return self.incident_manager.list_incidents()

    def get_incident(self, incident_id: str) -> Optional[ActiveIncident]:
        return self.incident_manager.get_incident(incident_id)

    def get_evaluation_metrics(self) -> EvaluationMetrics:
        return self.eval_tracker.get_metrics()


# Global singleton detection engine
realtime_detection_engine = RealTimeDetectionEngine()
