
from typing import Literal

from pydantic import BaseModel, Field


HypothesisStatus = Literal[
    "unverified",
    "verified",
    "rejected",
    "requires_review",
    "unsupported",
    "conflicting_evidence_requires_review",
    "evidence_linked_requires_human_review",
]


class Hypothesis(BaseModel):
    hypothesis_id: str
    description: str
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status: HypothesisStatus = "unverified"
