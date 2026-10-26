def verify_hypotheses(hypotheses: list[dict], evidence: list[dict]) -> list[dict]:
    known_ids = {item["evidence_id"] for item in evidence}
    verified = []

    for hypothesis in hypotheses:
        item = dict(hypothesis)

        supporting = [
            eid for eid in item.get("supporting_evidence", [])
            if eid in known_ids
        ]

        contradicting = [
            eid for eid in item.get("contradicting_evidence", [])
            if eid in known_ids
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

        verified.append(item)

    return verified