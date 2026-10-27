
from typing import Any


CONTRADICTION_TYPES = {
    "benign_explanation",
    "authorized_activity",
}


def find_contradictions(
    hypotheses: list[dict],
    evidence: list[dict],
) -> list[dict]:
    """
    Attach relevant contradicting evidence to hypotheses.

    Only evidence explicitly marked as a benign explanation or authorized
    activity is considered. Evidence is associated with a hypothesis only
    when it references the same evidence IDs or shares a relevant event type.

    This is a cautious rule-based check, not proof that a hypothesis is false.
    """

    valid_evidence = [
        item for item in evidence
        if isinstance(item, dict)
    ]

    # Index evidence by ID so explicit references can be checked.
    evidence_by_id: dict[str, dict[str, Any]] = {}

    for item in valid_evidence:
        evidence_id = item.get("evidence_id")
        if evidence_id is not None:
            evidence_by_id[str(evidence_id)] = item

    # Build the list of evidence records eligible to contradict a hypothesis.
    contradiction_evidence = [
        item
        for item in valid_evidence
        if item.get("event_type") in CONTRADICTION_TYPES
        and item.get("evidence_id") is not None
    ]

    updated_hypotheses: list[dict] = []

    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            continue

        # Copy each hypothesis so we do not mutate the caller's object.
        updated = dict(hypothesis)

        supporting_ids = updated.get("supporting_evidence", [])
        existing_contradicting_ids = updated.get(
            "contradicting_evidence",
            [],
        )

        if not isinstance(supporting_ids, list):
            supporting_ids = []

        if not isinstance(existing_contradicting_ids, list):
            existing_contradicting_ids = []

        supporting_ids = {
            str(evidence_id)
            for evidence_id in supporting_ids
            if evidence_id is not None
        }

        # If the hypothesis explicitly references evidence that is itself
        # marked as benign or authorized, include that evidence.
        relevant_contradictions: list[str] = []

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

            # A contradiction must explicitly refer to the hypothesis's
            # supporting evidence, or itself be among its supporting IDs.
            explicitly_related = (
                bool(related_ids & supporting_ids)
                or evidence_id in supporting_ids
            )

            if explicitly_related:
                relevant_contradictions.append(evidence_id)

        # Preserve any existing contradiction references only if they point
        # to actual supplied evidence. This avoids inventing evidence IDs.
        for evidence_id in existing_contradicting_ids:
            if (
                evidence_id is not None
                and str(evidence_id) in evidence_by_id
                and str(evidence_id) not in relevant_contradictions
            ):
                relevant_contradictions.append(str(evidence_id))

        updated["contradicting_evidence"] = relevant_contradictions

        # Do not mark a hypothesis as conflicting solely because unrelated
        # benign or authorized activity exists elsewhere in the case.
        if (
            relevant_contradictions
            and updated.get("status") != "unsupported"
        ):
            updated["status"] = "conflicting_evidence_requires_review"

        updated_hypotheses.append(updated)

    return updated_hypotheses
