def evidence_coverage_score(
    supporting_ids: list[str],
    contradicting_ids: list[str]
) -> float:
    total = len(supporting_ids) + len(contradicting_ids)

    if total == 0:
        return 0.0

    return round(len(supporting_ids) / total, 2)