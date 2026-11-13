from pydantic import BaseModel, Field
from typing import Optional, Literal, Any


class Evidence(BaseModel):
    evidence_id: str
    source: str
    timestamp: Optional[str] = None
    event_type: str
    description: str
    severity: Literal["low", "medium", "high", "critical"] = "low"
    supporting: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)