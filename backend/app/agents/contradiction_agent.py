def find_contradictions(hypotheses: list[dict], evidence: list[dict]) -> list[dict]:
    contradiction_types = {
        "benign_explanation",
        "authorized_activity"
    }

    for hypothesis in hypotheses:
        contradictions = [
            item["evidence_id"]
            for item in evidence
            if item.get("event_type") in contradiction_types
        ]

        hypothesis["contradicting_evidence"] = contradictions

        if contradictions and hypothesis.get("status") != "unsupported":
            hypothesis["status"] = "conflicting_evidence_requires_review"

    return hypotheses