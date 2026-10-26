from dataclasses import dataclass, field


@dataclass
class InvestigationState:
    incident_id: str
    plan: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    hypotheses: list[dict] = field(default_factory=list)
    completed_steps: list[str] = field(default_factory=list)
    current_step: str = "initialized"
    status: str = "investigating"