from backend.app.models.evidence import Evidence
from backend.app.tools.timeline_tools import build_timeline


def create_timeline(evidence: list[dict]) -> list[dict]:
    parsed_evidence = [
        Evidence(**item) for item in evidence
    ]

    return build_timeline(parsed_evidence)