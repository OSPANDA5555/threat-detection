from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from app.schemas.hunt import Hunt, HuntPlanStep
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.schemas.tool import ToolDefinition, ToolExecutionRequest

class BaseAIProvider(ABC):
    """
    Abstract interface for LLM providers (Google Gemini, OpenAI, Claude, Local LLMs).
    Ensures the threat-hunting application remains completely decoupled from specific AI APIs.
    """

    @abstractmethod
    async def generate_hypothesis(self, question: str) -> str:
        """Formulate a structured threat hunting hypothesis from an analyst question."""
        pass

    @abstractmethod
    async def generate_hunt_plan(self, question: str, hypothesis: str, available_tools: List[ToolDefinition]) -> List[HuntPlanStep]:
        """Generate a multi-step investigation hunt plan using available registered read-only tools."""
        pass

    @abstractmethod
    async def select_tools(self, current_step: HuntPlanStep, available_tools: List[ToolDefinition]) -> List[ToolExecutionRequest]:
        """Select appropriate registered tool requests for a specific plan step."""
        pass

    @abstractmethod
    async def correlate_evidence(self, evidence_list: List[Evidence]) -> Dict[str, Any]:
        """Correlate collected evidence across hosts, IPs, timestamps, and event types."""
        pass

    @abstractmethod
    async def generate_finding(self, hunt: Hunt) -> Optional[Finding]:
        """Generate an evidence-backed finding report from validated hunt data."""
        pass


class AbstractHuntPlanner:
    """
    Coordinator responsible for executing the AI reasoning workflow.
    In Phase 1, provides baseline interface contract.
    """
    def __init__(self, provider: BaseAIProvider):
        self.provider = provider

    async def initialize_hunt(self, question: str, available_tools: List[ToolDefinition]) -> Dict[str, Any]:
        """Initialize a new hunt workflow by generating hypothesis and plan."""
        hypothesis = await self.provider.generate_hypothesis(question)
        plan = await self.provider.generate_hunt_plan(question, hypothesis, available_tools)
        return {
            "hypothesis": hypothesis,
            "plan": plan
        }
