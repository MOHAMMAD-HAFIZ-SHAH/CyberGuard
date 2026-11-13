
from backend.app.models.evidence import Evidence
from backend.app.models.timeline import TimelineEvent
from backend.app.tools.timeline_tools import build_timeline


def create_timeline(
    evidence: list[Evidence | dict],
) -> list[TimelineEvent]:

    parsed_evidence = []

    for item in evidence:
        if isinstance(item, Evidence):
            parsed_evidence.append(item)
        elif isinstance(item, dict):
            parsed_evidence.append(Evidence(**item))
        else:
            raise ValueError("Unsupported evidence type in timeline input.")

    timeline_data = build_timeline(parsed_evidence)

    return [
        TimelineEvent(**item)
        for item in timeline_data
    ]
