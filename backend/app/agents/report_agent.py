def generate_report(
    title: str,
    description: str,
    evidence: list[dict],
    hypotheses: list[dict]
) -> str:
    lines = [
        "CYBERGUARD INVESTIGATION REPORT",
        "=" * 36,
        f"Incident: {title}",
        f"Description: {description}",
        "",
        "1. EVIDENCE"
    ]

    if not evidence:
        lines.append("No recognized events found in the supplied logs.")

    for item in evidence:
        lines.append(
            f'{item["evidence_id"]} | '
            f'{item.get("timestamp") or "Time unknown"} | '
            f'{item["event_type"]} | '
            f'{item["severity"]} | '
            f'{item["description"]}'
        )

    lines.extend(["", "2. HYPOTHESES"])

    if not hypotheses:
        lines.append("No hypotheses generated from recognized patterns.")

    for item in hypotheses:
        lines.extend([
            f'{item["hypothesis_id"]}: {item["description"]}',
            f'Status: {item["status"]}',
            f'Heuristic score: {item["confidence"]:.0%}',
            "Supporting evidence: " +
            (", ".join(item["supporting_evidence"]) or "None"),
            "Contradicting evidence: " +
            (", ".join(item["contradicting_evidence"]) or "None"),
            ""
        ])

    lines.extend([
        "3. LIMITATIONS",
        "This report covers only the supplied logs and recognized patterns.",
        "Scores are heuristic indicators, not calibrated probabilities.",
        "Missing evidence does not prove that an incident did not occur.",
        "A qualified analyst should validate findings before taking action."
    ])

    return "\n".join(lines)