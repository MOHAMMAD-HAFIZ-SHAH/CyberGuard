
from typing import Any


def analyze_forensic_evidence(evidence: list[dict]) -> dict:
    """
    Prepare extracted forensic evidence for investigation.

    This function does not extract files from disk images.
    It summarizes evidence already collected by CyberGuard.
    """

    if not evidence:
        return {
            "status": "no_evidence",
            "message": "No extracted evidence was provided for analysis.",
            "evidence_count": 0,
            "findings": [],
        }

    findings: list[dict[str, Any]] = []

    for index, item in enumerate(evidence, start=1):
        if not isinstance(item, dict):
            continue

        description = item.get("description", "")
        source = item.get("source", "")
        event_type = item.get("event_type", "unknown")
        timestamp = item.get("timestamp")

        metadata = item.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        # Evidence collected from disk images may store its content
        # in metadata or directly in a text_content field.
        text_content = (
            item.get("text_content")
            or metadata.get("text_content")
            or ""
        )

        findings.append({
            "finding_id": f"FE-{index:03d}",
            "source": str(source or "Unknown source"),
            "event_type": str(event_type),
            "timestamp": timestamp,
            "description": str(description or ""),
            "extracted_text": str(text_content),
            "metadata": metadata,
        })

    return {
        "status": "completed",
        "message": (
            "Extracted evidence has been organized for investigation. "
            "This step does not independently verify suspicious activity."
        ),
        "evidence_count": len(evidence),
        "findings": findings,
    }
