from abc import ABC, abstractmethod
from typing import List, Tuple, Dict, Any, Optional
from datetime import datetime, timezone
import ipaddress

from app.normalization.models import SecurityEvent, SourceType, NormalizationResult
from app.ingestion.validator import validate_ip, validate_port, parse_and_validate_timestamp, parse_protocol

class BaseEventAdapter(ABC):
    """
    Abstract base adapter for transforming domain-specific log formats
    into canonical SecurityEvent objects.
    """

    @property
    @abstractmethod
    def source_type(self) -> SourceType:
        """The canonical source taxonomy category for this adapter."""
        pass

    @abstractmethod
    def normalize_record(
        self,
        raw_record: Any,
        index: int = 0
    ) -> Tuple[Optional[SecurityEvent], Optional[str]]:
        """
        Normalizes a single log record (string line or dictionary) into a SecurityEvent.
        Returns (SecurityEvent, None) on success or (None, error_message) on malformed record.
        """
        pass

    def normalize_batch(
        self,
        raw_records: List[Any]
    ) -> NormalizationResult:
        """
        Normalizes a collection of log records, isolating errors without failing the batch.
        """
        events: List[SecurityEvent] = []
        errors: List[Dict[str, Any]] = []

        for idx, record in enumerate(raw_records):
            if not record:
                continue
            event, err = self.normalize_record(record, index=idx + 1)
            if err:
                errors.append({
                    "record_index": idx + 1,
                    "error": err,
                    "raw_sample": str(record)[:150]
                })
                if not event:
                    continue
            if event:
                events.append(event)

        return NormalizationResult(
            total_records=len(raw_records),
            successful_events=len(events),
            malformed_records=len(errors),
            source_type=self.source_type,
            events=events,
            errors=errors
        )
