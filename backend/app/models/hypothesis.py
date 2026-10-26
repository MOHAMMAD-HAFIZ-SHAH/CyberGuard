from pydantic import BaseModel, Field


class Hypothesis(BaseModel):
    hypothesis_id: str
    description: str
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    status: str = "unverified"