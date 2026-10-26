from pydantic import BaseModel, Field
from typing import Optional


class Evidence(BaseModel):
    evidence_id: str
    source: str
    timestamp: Optional[str] = None
    event_type: str
    description: str
    severity: str = "low"
    supporting: bool = False
    metadata: dict = Field(default_factory=dict)