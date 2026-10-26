def summarize_evidence(evidence: list[dict]) -> dict:
    counts = {}

    for item in evidence:
        event_type = item.get("event_type", "unknown")
        counts[event_type] = counts.get(event_type, 0) + 1

    severity_counts = {}

    for item in evidence:
        severity = item.get("severity", "unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    return {
        "total": len(evidence),
        "by_type": counts,
        "by_severity": severity_counts
    }