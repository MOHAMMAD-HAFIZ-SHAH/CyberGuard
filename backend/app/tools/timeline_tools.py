from datetime import datetime
from backend.app.models.evidence import Evidence


def build_timeline(evidence: list[Evidence]) -> list[dict]:
    def sort_key(item):
        if not item.timestamp:
            return (1, "")

        try:
            timestamp = datetime.fromisoformat(
                item.timestamp.replace(" ", "T")
            )
            return (0, timestamp)
        except ValueError:
            return (1, item.timestamp)

    sorted_evidence = sorted(evidence, key=sort_key)

    return [
        item.model_dump()
        for item in sorted_evidence
    ]