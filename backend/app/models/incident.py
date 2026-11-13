
from typing import Optional, Any

from pydantic import BaseModel, Field

from backend.app.models.evidence import Evidence
from backend.app.models.hypothesis import Hypothesis
from backend.app.models.timeline import TimelineEvent


class IncidentRequest(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=5, max_length=5000)
    log_text: str = ""
    investigation_goal: Optional[str] = None
    image_path: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=1000,
        description=(
            "Optional absolute path to a forensic disk image "
            "on the backend computer"
        ),
    )


class IncidentResult(BaseModel):
    incident_id: str
    title: str
    status: str

    investigation_plan: list[str] = Field(default_factory=list)

    evidence: list[Evidence] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)

    report: str

    evidence_summary: Optional[Any] = None
    forensic_artifact_analyses: list[dict[str, Any]] = Field(
        default_factory=list
    )
    crewai_review: Optional[Any] = None
    crew_agents: list[dict[str, Any]] = Field(default_factory=list)

    agent_findings: dict[str, Any] = Field(default_factory=dict)
    collection_errors: list[dict[str, Any]] = Field(default_factory=list)

    monitoring: dict[str, Any] = Field(default_factory=dict)

    note: Optional[str] = None
