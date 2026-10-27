
from typing import Any


THREAT_PATTERNS = {
    "failed_login": {
        "assessment": (
            "Authentication failure observed. Review failure frequency, "
            "account context, source address, and any subsequent successful login."
        ),
        "severity": "medium",
    },
    "suspicious_command": {
        "assessment": (
            "Potentially suspicious command execution. Review the command, "
            "parent process, user account, and surrounding activity."
        ),
        "severity": "medium",
    },
    "malware_detection": {
        "assessment": (
            "A malware-related alert was recorded. Validate the detection "
            "and examine the artifact using safe forensic procedures."
        ),
        "severity": "high",
    },
    "possible_data_transfer": {
        "assessment": (
            "A possible data transfer was recorded. Verify destination, "
            "volume, authorization, and available network evidence."
        ),
        "severity": "medium",
    },
}


def map_known_patterns(evidence: list[dict]) -> list[dict]:
    """Map recognized evidence event types to cautious threat assessments."""

    results: list[dict[str, Any]] = []

    for index, item in enumerate(evidence, start=1):
        if not isinstance(item, dict):
            continue

        event_type = item.get("event_type")
        pattern = THREAT_PATTERNS.get(event_type)

        if pattern is None:
            continue

        results.append({
            "evidence_id": item.get("evidence_id", f"UNKNOWN-{index:03d}"),
            "event_type": event_type,
            "assessment": pattern["assessment"],
            "severity": pattern["severity"],
            "requires_verification": True,
        })

    return results
