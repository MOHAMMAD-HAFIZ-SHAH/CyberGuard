
def verify_hypotheses(
    hypotheses: list[dict],
    evidence: list[dict],
) -> list[dict]:
    """
    Check hypothesis evidence references against known evidence IDs.

    This function validates references only. It does not prove that
    a hypothesis is true or false.
    """

    known_ids = {
        item.get("evidence_id")
        for item in evidence
        if isinstance(item, dict) and item.get("evidence_id") is not None
    }

    verified = []

    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            continue

        item = dict(hypothesis)

        supporting_ids = item.get("supporting_evidence", [])
        contradicting_ids = item.get("contradicting_evidence", [])

        if not isinstance(supporting_ids, list):
            supporting_ids = []

        if not isinstance(contradicting_ids, list):
            contradicting_ids = []

        supporting = [
            evidence_id
            for evidence_id in supporting_ids
            if evidence_id in known_ids
        ]

        contradicting = [
            evidence_id
            for evidence_id in contradicting_ids
            if evidence_id in known_ids
        ]

        item["supporting_evidence"] = supporting
        item["contradicting_evidence"] = contradicting

        if not supporting:
            item["status"] = "unsupported"
            item["confidence"] = 0.0
        elif contradicting:
            item["status"] = "conflicting_evidence_requires_review"
        else:
            item["status"] = "evidence_linked_requires_human_review"

        item["verification_note"] = (
            "Evidence references were checked against the supplied evidence IDs. "
            "This check does not establish the truth of the hypothesis. "
            "Human review is required."
        )

        verified.append(item)

    return verified
