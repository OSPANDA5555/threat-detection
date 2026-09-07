from abc import ABC, abstractmethod
from typing import List, Tuple, Dict, Any
from app.schemas.dataset import NormalizedEvent, ValidationErrorRecord, DatasetMetadata

class BaseDatasetNormalizer(ABC):
    """
    Abstract base class for dataset ingestion parsers and normalizers.
    """

    @abstractmethod
    def parse_and_normalize(
        self,
        content: bytes,
        file_name: str,
        dataset_name: str
    ) -> Tuple[DatasetMetadata, List[NormalizedEvent]]:
        """
        Parses raw dataset bytes and returns normalized metadata and event records.
        """
        pass
