
from datetime import datetime, timezone

from backend.app.models.evidence import Evidence


def analyze_logs(log_text: str) -> list[dict]:
    """Extract basic security indicators from supplied log text.

    This rule-based helper is not a complete forensic analysis.
    Original log lines are preserved in metadata. Timestamps are
    parsed only when a supported timestamp format is present.
    """
    if not isinstance(log_text, str):
        raise ValueError("log_text must be a string.")

    evidence_items: list[dict] = []

    patterns = [
        (
            "failed_login",
            (
                "failed login",
                "login failed",
                "authentication failure",
                "failed_login",
                "login_failure",
            ),
            "Failed authentication activity",
        ),
        (
            "successful_login",
            (
                "successful login",
                "login successful",
                "logged in",
                "successful_login",
                "login_success",
            ),
            "Successful authentication activity",
        ),
        (
            "unauthorized_access",
            (
                "unauthorized",
                "access denied",
                "permission denied",
            ),
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
        normalized = line.casefold().replace("_", " ").replace("-", " ")

        for category, terms, description in patterns:
            matched_terms = [
                term
                for term in terms
                if term.replace("_", " ").replace("-", " ")
                in normalized
            ]

            if not matched_terms:
                continue

            # Parse only the timestamp format used by the current test:
            # YYYY-MM-DD HH:MM:SS
            parsed_timestamp = None
            timestamp_note = (
                "No event timestamp was parsed by this rule."
            )

            try:
                timestamp_text = line[:19]
                parsed = datetime.strptime(
                    timestamp_text,
                    "%Y-%m-%d %H:%M:%S",
                )
                parsed_timestamp = parsed.replace(
                    tzinfo=timezone.utc
                ).isoformat()
                timestamp_note = (
                    "Timestamp parsed from the original log line. "
                    "Timezone was not specified in the log; UTC was "
                    "assumed for normalized storage and must be verified."
                )
            except ValueError:
                pass

            evidence = Evidence(
                evidence_id=f"LOG-{line_number:05d}-{category}",
                source=f"input log, line {line_number}",
                timestamp=parsed_timestamp,
                event_type=category,
                description=description,
                severity=(
                    "medium"
                    if category in {
                        "malware_detection",
                        "suspicious_command",
                        "unauthorized_access",
                    }
                    else "low"
                ),
                supporting=False,
                metadata={
                    "raw_line": line,
                    "line_number": line_number,
                    "matched_terms": matched_terms,
                    "timestamp_note": timestamp_note,
                },
            )

            evidence_items.append(evidence.model_dump())

            # Avoid duplicate findings for the same line.
            break

    return evidence_items
