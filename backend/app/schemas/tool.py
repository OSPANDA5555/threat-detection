from typing import Dict, Any, List, Optional, Literal
from datetime import datetime, timezone
from pydantic import BaseModel, Field, field_validator, ConfigDict
from app.core.security import sanitize_input_string

class ToolParameterSpec(BaseModel):
    name: str
    type: str  # "string", "integer", "boolean", "datetime"
    description: str
    required: bool = False
    default: Optional[Any] = None

class ToolDefinition(BaseModel):
    name: str = Field(description="Unique tool identifier")
    description: str = Field(description="Clear explanation of tool read-only functionality")
    read_only: Literal[True] = Field(default=True, description="Tool MUST be read-only")
    parameters: List[ToolParameterSpec] = Field(default_factory=list)
    max_results_cap: int = Field(default=500, description="Hard cap on maximum returned records")


    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        valid_pattern = r'^[a-z0-9_]+$'
        import re
        if not re.match(valid_pattern, v):
            raise ValueError("Tool name must contain only lowercase alphanumeric characters and underscores")
        return v

class ToolExecutionRequest(BaseModel):
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    hunt_id: Optional[str] = None

    @field_validator("tool_name")
    @classmethod
    def sanitize_tool_name(cls, v):
        return sanitize_input_string(v)

class ToolExecutionResult(BaseModel):
    tool_name: str
    status: str  # "SUCCESS", "REJECTED", "ERROR", "TIMEOUT"
    record_count: int = 0
    records: List[Dict[str, Any]] = Field(default_factory=list)
    execution_time_ms: float = 0.0
    error_message: Optional[str] = None
    audit_id: Optional[str] = None

class AuditLogEntry(BaseModel):
    audit_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tool_name: str
    arguments: Dict[str, Any]
    status: str
    record_count: int
    execution_time_ms: float
    error: Optional[str] = None
