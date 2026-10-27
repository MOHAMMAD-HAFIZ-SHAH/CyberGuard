
from datetime import datetime, timezone

from backend.app.models.evidence import Evidence


def _parse_timestamp(line: str) -> tuple[str | None, str]:
    """
    Parse supported timestamps from the beginning of a log line.

    The source timezone is not assumed to be known. UTC is used for
    normalized storage, and that assumption is documented in metadata.
    """
    timestamp_formats = (
        (19, "%Y-%m-%d %H:%M:%S"),
        (19, "%Y/%m/%d %H:%M:%S"),
    )

    for length, timestamp_format in timestamp_formats:
        try:
            parsed = datetime.strptime(
                line[:length],
                timestamp_format,
            )
            normalized = parsed.replace(
                tzinfo=timezone.utc
            ).isoformat()

            return (
                normalized,
                "Timestamp parsed from the original log line. "
                "The source timezone was not specified; UTC was "
                "assumed for normalized storage and must be verified.",
            )
        except ValueError:
            continue

    return (
        None,
        "No supported timestamp was parsed. The original log line "
        "has been preserved.",
    )


def analyze_logs(log_text: str) -> list[dict]:
    """
    Extract rule-based security evidence from supplied log text.

    This helper is not a complete forensic analysis. It preserves each
    matched original log line in metadata and does not establish that
    a suspicious activity was malicious or successful.
    """
    if not isinstance(log_text, str):
        raise ValueError("log_text must be a string.")

    evidence_items: list[dict] = []

    # More specific patterns should appear before broad patterns.
    patterns = [
        (
            "failed_login",
            (
                "failed login",
                "login failed",
                "authentication failure",
                "failed_login",
                "login_failure",
                "authentication failed",
            ),
            "Failed authentication activity",
            "medium",
        ),
        (
            "credential_related_activity",
            (
                "credential",
                "password=",
                "passwd=",
                "pass=",
                "user=",
                "username=",
                "login credentials",
                "authentication data",
            ),
            "Credential-related indicator requiring secure review",
            "medium",
        ),
        (
            "ftp_connection_opened",
            (
                "ftp connection opened",
                "ftp connection established",
                "ftp connected",
                "connection opened",
            ),
            "Network connection opened; protocol and context require review",
            "low",
        ),
        (
            "ftp_file_upload",
            (
                "file upload",
                "upload command",
                "ftp stor ",
                "command stor ",
                "uploaded file",
            ),
            "File-upload activity indicated by the log",
            "medium",
        ),
        (
            "ftp_file_download",
            (
                "download command",
                "ftp retr ",
                "command retr ",
                "downloaded file",
            ),
            "File-download activity indicated by the log",
            "medium",
        ),
        (
            "connection_closed",
            (
                "ftp connection closed",
                "connection closed",
                "connection terminated",
                "disconnected",
            ),
            "Connection closure or termination",
            "low",
        ),
        (
            "logout",
            (
                "logged out",
                "user logout",
                "user logged out",
                "logout successful",
                "session ended",
            ),
            "User logout or session termination activity",
            "low",
        ),
        (
            "successful_login",
            (
                "successful login",
                "login successful",
                "logged in",
                "login_success",
            ),
            "Successful authentication activity",
            "low",
        ),
        (
            "unauthorized_access",
            (
                "unauthorized",
                "access denied",
                "permission denied",
                "forbidden",
            ),
            "Possible unauthorized access",
            "medium",
        ),
        (
            "malware_detection",
            ("malware", "trojan", "ransomware", "mimikatz"),
            "Possible malware-related indicator",
            "high",
        ),
        (
            "suspicious_command",
            ("powershell", "encodedcommand"),
            "PowerShell activity requiring context",
            "medium",
        ),
        (
            "usb_activity",
            ("usb device", "removable drive", "usb storage"),
            "Removable-device activity",
            "low",
        ),
    ]

    for line_number, line in enumerate(log_text.splitlines(), start=1):
        if not line.strip():
            continue

        normalized = line.casefold().replace("_", " ").replace("-", " ")

        matched_pattern = None

        for category, terms, description, severity in patterns:
            matched_terms = [
                term
                for term in terms
                if term.casefold().replace("_", " ").replace("-", " ")
                in normalized
            ]

            if matched_terms:
                matched_pattern = (
                    category,
                    matched_terms,
                    description,
                    severity,
                )
                break

        # Ignore lines that do not match any recognized event category.
        if matched_pattern is None:
            continue

        category, matched_terms, description, severity = matched_pattern

        parsed_timestamp, timestamp_note = _parse_timestamp(line)

        evidence = Evidence(
            evidence_id=f"LOG-{line_number:05d}-{category}",
            source=f"input log, line {line_number}",
            timestamp=parsed_timestamp,
            event_type=category,
            description=description,
            severity=severity,
            supporting=False,
            metadata={
                # Preserve the original evidence without redaction here.
                "raw_line": line,
                "line_number": line_number,
                "matched_terms": matched_terms,
                "timestamp_note": timestamp_note,
                "analysis_method": "rule_based_keyword_matching",
                "requires_human_validation": True,
            },
        )

        evidence_items.append(evidence.model_dump())

    return evidence_items
