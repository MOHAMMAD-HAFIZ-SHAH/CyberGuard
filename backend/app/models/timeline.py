
from typing import Optional, Any
from pydantic import BaseModel, Field


class TimelineEvent(BaseModel):
    evidence_id: str
    source: str
    timestamp: Optional[str] = None
    event_type: str
    description: str
    severity: str = "low"
    metadata: dict[str, Any] = Field(default_factory=dict)
