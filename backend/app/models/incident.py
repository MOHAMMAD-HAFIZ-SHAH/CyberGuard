
from pydantic import BaseModel, Field
from typing import Optional


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
    investigation_plan: list[str]
    evidence: list[dict]
    hypotheses: list[dict]
    timeline: list[dict]
    report: str
