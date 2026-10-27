
import re
from typing import Any


# These are investigation indicators, not proof of malicious activity.
CREDENTIAL_PATTERNS = (
    r"\bpassword\b",
    r"\bpasswd\b",
    r"\bcredentials?\b",
    r"\blogin\s+(?:id|details|information)\b",
    r"\busername\b",
    r"\baccess\s+token\b",
    r"\bapi[_ -]?key\b",
)

TRANSFER_PATTERNS = (
    r"\bftp://",
    r"\bsftp://",
    r"\bupload(?:ing)?\b",
    r"\bdownload(?:ing)?\b",
    r"\btransfer(?:ring)?\s+files?\b",
    r"\bsend\s+(?:the\s+)?files?\b",
    r"\bfile\s+sharing\b",
)

NETWORK_PATTERNS = (
    r"\bhttps?://",
    r"\bftp\b",
    r"\bsftp\b",
    r"\bserver\b",
    r"\bremote\s+(?:host|server|location)\b",
)


def _matches_any(text: str, patterns: tuple[str, ...]) -> bool:
    """Return whether text matches at least one indicator pattern."""
    return any(
        re.search(pattern, text, flags=re.IGNORECASE)
        for pattern in patterns
    )


def _detect_indicators(text: str) -> list[dict[str, str]]:
    """
    Identify possible credential and data-transfer indicators.

    Detection is based on text patterns only. It does not establish
    that credentials are valid or that a transfer actually occurred.
    """
    indicators: list[dict[str, str]] = []

    has_credentials = _matches_any(text, CREDENTIAL_PATTERNS)
    has_transfer = _matches_any(text, TRANSFER_PATTERNS)
    has_network = _matches_any(text, NETWORK_PATTERNS)

    if has_credentials:
        indicators.append({
            "type": "possible_credential_reference",
            "significance": (
                "The artifact appears to refer to passwords, "
                "credentials, tokens, or account access information."
            ),
        })

    if has_transfer:
        indicators.append({
            "type": "possible_file_transfer",
            "significance": (
                "The artifact appears to refer to uploading, "
                "downloading, sending, or transferring files."
            ),
        })

    if has_network:
        indicators.append({
            "type": "network_service_reference",
            "significance": (
                "The artifact appears to mention a network protocol, "
                "URL, server, or remote location."
            ),
        })

    if has_credentials and has_transfer:
        indicators.append({
            "type": "possible_credential_transfer_context",
            "significance": (
                "Credential-related language and file-transfer "
                "language occur in the same artifact. Review the "
                "original evidence to determine their relationship."
            ),
        })

    return indicators


def analyze_forensic_evidence(evidence: list[dict]) -> dict:
    """
    Organize extracted forensic evidence and flag review indicators.

    Original extracted text is preserved for authorized forensic review.
    Indicators are leads for investigation, not verified conclusions.
    This function does not extract files from disk images.
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

        # Accept text from either supported location without modifying it.
        text_content = (
            item.get("text_content")
            or metadata.get("text_content")
            or ""
        )

        original_text = str(text_content)
        indicators = _detect_indicators(original_text)

        findings.append({
            "finding_id": f"FE-{index:03d}",
            "source": str(source or "Unknown source"),
            "event_type": str(event_type),
            "timestamp": timestamp,
            "description": str(description or ""),
            # Preserve original text for authorized evidence examination.
            "extracted_text": original_text,
            "metadata": metadata,
            "indicators": indicators,
            "requires_human_review": bool(indicators),
            "verification_status": "not_independently_verified",
        })

    return {
        "status": "completed",
        "message": (
            "Extracted evidence has been organized and screened for "
            "possible credential and file-transfer indicators. "
            "Original text is preserved. Indicators do not prove that "
            "credentials are valid, activity was unauthorized, or a "
            "file transfer succeeded."
        ),
        "evidence_count": len(findings),
        "findings": findings,
    }
