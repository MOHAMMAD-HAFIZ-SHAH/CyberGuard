
from datetime import datetime, timezone

from backend.app.models.evidence import Evidence


def analyze_logs(log_text: str) -> list[dict]:
    """Extract basic security indicators from supplied log text.

    This rule-based helper is not a complete forensic analysis.
    Original log lines are preserved in metadata. The analysis time
    is not represented as the original event timestamp.
    """
    if not isinstance(log_text, str):
        raise ValueError("log_text must be a string.")

    evidence_items: list[dict] = []

    patterns = [
        (
            "failed_login",
            ("failed login", "login failed", "authentication failure"),
            "Multiple or failed authentication activity",
        ),
        (
            "successful_login",
            ("successful login", "login successful", "logged in"),
            "Successful authentication activity",
        ),
        (
            "unauthorized_access",
            ("unauthorized", "access denied", "permission denied"),
            "Possible unauthorized access",
        ),
        (
            "malware_detection",
            ("malware", "trojan", "ransomware", "mimikatz"),
            "Possible malware-related indicator",
        ),
        (
            "suspicious_command",
            ("powershell", "encodedcommand"),
            "PowerShell activity requiring context",
        ),
        (
            "usb_activity",
            ("usb device", "removable drive", "usb storage"),
            "Removable-device activity",
        ),
    ]

    for line_number, line in enumerate(log_text.splitlines(), start=1):
        normalized = line.casefold()

        for category, terms, description in patterns:
            matched_terms = [
                term for term in terms if term in normalized
            ]

            if not matched_terms:
                continue

            evidence = Evidence(
                evidence_id=f"LOG-{line_number:05d}-{category}",
                source=f"input log, line {line_number}",
                timestamp=None,
                event_type=category,
                description=description,
                severity="medium" if category in {
                    "malware_detection",
                    "suspicious_command",
                    "unauthorized_access",
                } else "low",
                supporting=False,
                metadata={
                    "raw_line": line,
                    "line_number": line_number,
                    "matched_terms": matched_terms,
                    "timestamp_note": (
                        "No event timestamp was parsed by this rule."
                    ),
                },
            )

            evidence_items.append(evidence.model_dump())

            # Avoid duplicate findings for the same line.
            break

    return evidence_items
