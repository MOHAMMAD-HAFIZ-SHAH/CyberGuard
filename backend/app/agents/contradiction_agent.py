
from backend.app.models.hypothesis import Hypothesis
from backend.app.models.evidence import Evidence


CONTRADICTION_TYPES = {
    "benign_explanation",
    "authorized_activity",
}


def find_contradictions(
    hypotheses: list[Hypothesis | dict],
    evidence: list[Evidence | dict],
) -> list[Hypothesis]:

    valid_evidence = []

    for item in evidence:
        if isinstance(item, Evidence):
            valid_evidence.append(item.model_dump())
        elif isinstance(item, dict):
            valid_evidence.append(Evidence(**item).model_dump())

    evidence_by_id = {}

    for item in valid_evidence:
        evidence_id = item.get("evidence_id")

        if evidence_id is not None:
            evidence_by_id[str(evidence_id)] = item

    contradiction_evidence = [
        item
        for item in valid_evidence
        if item.get("event_type") in CONTRADICTION_TYPES
        and item.get("evidence_id") is not None
    ]

    updated_hypotheses: list[Hypothesis] = []

    for hypothesis in hypotheses:

        if isinstance(hypothesis, Hypothesis):
            updated = hypothesis.model_copy(deep=True)

        elif isinstance(hypothesis, dict):
            updated = Hypothesis(**hypothesis)

        else:
            continue

        supporting_ids = {
            str(evidence_id)
            for evidence_id in updated.supporting_evidence
            if evidence_id is not None
        }

        existing_contradicting_ids = list(
            updated.contradicting_evidence
        )

        relevant_contradictions = []

        for item in contradiction_evidence:

            evidence_id = str(item["evidence_id"])

            related_ids = item.get(
                "related_evidence_ids",
                item.get("contradicts_evidence_ids", []),
            )

            if not isinstance(related_ids, list):
                related_ids = []

            related_ids = {
                str(value)
                for value in related_ids
                if value is not None
            }

            explicitly_related = (
                bool(related_ids & supporting_ids)
                or evidence_id in supporting_ids
            )

            if explicitly_related:
                relevant_contradictions.append(evidence_id)

        for evidence_id in existing_contradicting_ids:

            if (
                evidence_id is not None
                and str(evidence_id) in evidence_by_id
                and str(evidence_id) not in relevant_contradictions
            ):
                relevant_contradictions.append(str(evidence_id))

        updated.contradicting_evidence = relevant_contradictions

        if (
            relevant_contradictions
            and updated.status != "unsupported"
        ):
            updated.status = "conflicting_evidence_requires_review"

        updated_hypotheses.append(updated)

    return updated_hypotheses
