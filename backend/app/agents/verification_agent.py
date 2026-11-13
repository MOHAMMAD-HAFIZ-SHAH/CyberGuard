
from backend.app.models.hypothesis import Hypothesis
from backend.app.models.evidence import Evidence


def verify_hypotheses(
    hypotheses: list[Hypothesis | dict],
    evidence: list[Evidence | dict],
) -> list[Hypothesis]:

    known_ids = set()

    for item in evidence:
        if isinstance(item, Evidence):
            known_ids.add(item.evidence_id)
        elif isinstance(item, dict):
            validated = Evidence(**item)
            known_ids.add(validated.evidence_id)

    verified: list[Hypothesis] = []

    for hypothesis in hypotheses:

        if isinstance(hypothesis, Hypothesis):
            item = hypothesis.model_copy(deep=True)

        elif isinstance(hypothesis, dict):
            item = Hypothesis(**hypothesis)

        else:
            continue

        supporting = [
            evidence_id
            for evidence_id in item.supporting_evidence
            if evidence_id in known_ids
        ]

        contradicting = [
            evidence_id
            for evidence_id in item.contradicting_evidence
            if evidence_id in known_ids
        ]

        item.supporting_evidence = supporting
        item.contradicting_evidence = contradicting

        if not supporting:
            item.status = "unsupported"
            item.confidence = 0.0

        elif contradicting:
            item.status = "conflicting_evidence_requires_review"

        else:
            item.status = "evidence_linked_requires_human_review"

        verified.append(item)

    return verified
