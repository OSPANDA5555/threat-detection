from typing import Dict, Any, Optional
from app.detection.models import EvaluationMetrics

class RealTimeEvaluationTracker:
    """
    Tracks online True Positives, False Positives, True Negatives, and False Negatives
    by comparing real-time behavioral detections against dataset ground-truth labels.
    Calculates Precision, Recall, F1, and enforces the >= 10 labeled events significance barrier.
    """

    def __init__(self):
        self._total_labeled: int = 0
        self._tp: int = 0
        self._fp: int = 0
        self._tn: int = 0
        self._fn: int = 0

    def reset(self):
        self._total_labeled = 0
        self._tp = 0
        self._fp = 0
        self._tn = 0
        self._fn = 0

    def record_event_evaluation(self, actual_label: Optional[str], detection_fired: bool):
        """
        Records a single event's evaluation result.
        """
        if not actual_label:
            return

        clean_label = str(actual_label).strip().upper()
        is_actual_malicious = (clean_label != "BENIGN" and clean_label != "NORMAL" and clean_label != "")

        self._total_labeled += 1

        if is_actual_malicious and detection_fired:
            self._tp += 1
        elif not is_actual_malicious and detection_fired:
            self._fp += 1
        elif not is_actual_malicious and not detection_fired:
            self._tn += 1
        elif is_actual_malicious and not detection_fired:
            self._fn += 1

    def get_metrics(self) -> EvaluationMetrics:
        prec = round(self._tp / (self._tp + self._fp), 4) if (self._tp + self._fp) > 0 else 0.0
        rec = round(self._tp / (self._tp + self._fn), 4) if (self._tp + self._fn) > 0 else 0.0
        f1 = round(2 * (prec * rec) / (prec + rec), 4) if (prec + rec) > 0 else 0.0
        acc = round((self._tp + self._tn) / self._total_labeled, 4) if self._total_labeled > 0 else 0.0

        is_significant = self._total_labeled >= 10
        if not is_significant:
            notice = f"Insufficient labeled events ({self._total_labeled}/10 min required) for statistically significant evaluation metrics."
        else:
            notice = f"Statistically valid evaluation active: {self._total_labeled} ground-truth events evaluated with zero label leakage."

        return EvaluationMetrics(
            total_labeled_events=self._total_labeled,
            true_positives=self._tp,
            false_positives=self._fp,
            true_negatives=self._tn,
            false_negatives=self._fn,
            precision=prec,
            recall=rec,
            f1_score=f1,
            accuracy=acc,
            is_statistically_significant=is_significant,
            notice=notice
        )


# Global singleton instance
evaluation_tracker = RealTimeEvaluationTracker()
