
from typing import Any


def generate_hypotheses(evidence: list[dict]) -> list[dict]:
    """
    Generate evidence-linked investigative hypotheses.

    These are rule-based investigative leads, not proof of an incident.
    Confidence values are heuristic scores, not calibrated probabilities.
    """

    hypotheses: list[dict[str, Any]] = []

    # Ignore malformed evidence records instead of crashing.
    valid_evidence = [
        item
        for item in evidence
        if isinstance(item, dict)
    ]

    def matching(event_type: str) -> list[dict]:
        return [
            item
            for item in valid_evidence
            if item.get("event_type") == event_type
        ]

    def evidence_ids(items: list[dict]) -> list[str]:
        return [
            str(item["evidence_id"])
            for item in items
            if item.get("evidence_id") is not None
        ]

    failed_logins = matching("failed_login")
    successful_logins = matching("successful_login")
    malware_events = matching("malware_detection")
    suspicious_commands = matching("suspicious_command")
    data_transfers = matching("possible_data_transfer")
    filesystem_artifacts = matching("filesystem_artifact")

    # HYP-001: repeated failed logins.
    if len(failed_logins) >= 3:
        hypotheses.append({
            "hypothesis_id": "HYP-001",
            "description": (
                "Repeated failed login attempts may indicate a "
                "brute-force attempt."
            ),
            "supporting_evidence": evidence_ids(failed_logins),
            "contradicting_evidence": [],
            "confidence": 0.65,
            "status": "requires_review",
        })

    # HYP-002: failed logins and a successful login.
    if failed_logins and successful_logins:
        combined_logins = failed_logins + successful_logins

        hypotheses.append({
            "hypothesis_id": "HYP-002",
            "description": (
                "Failed login attempts and a successful login were both "
                "observed. Review their timestamps, account, source "
                "addresses, and authorization context to assess whether "
                "the activity could indicate account compromise."
            ),
            "supporting_evidence": evidence_ids(combined_logins),
            "contradicting_evidence": [],
            "confidence": 0.55,
            "status": "requires_review",
        })

    # HYP-003: malware-related alert.
    if malware_events:
        hypotheses.append({
            "hypothesis_id": "HYP-003",
            "description": (
                "A malware-related detection was recorded. Validate "
                "the alert and examine the associated artifact using "
                "safe forensic procedures."
            ),
            "supporting_evidence": evidence_ids(malware_events),
            "contradicting_evidence": [],
            "confidence": 0.75,
            "status": "requires_review",
        })

    # HYP-004: suspicious command execution.
    if suspicious_commands:
        hypotheses.append({
            "hypothesis_id": "HYP-004",
            "description": (
                "Suspicious command execution was observed and may "
                "require further endpoint investigation."
            ),
            "supporting_evidence": evidence_ids(suspicious_commands),
            "contradicting_evidence": [],
            "confidence": 0.60,
            "status": "requires_review",
        })

    # HYP-005: possible data movement.
    if data_transfers:
        hypotheses.append({
            "hypothesis_id": "HYP-005",
            "description": (
                "A possible data transfer event was recorded. Review "
                "the destination, volume, authorization, and related "
                "network records to determine whether the activity "
                "was authorized."
            ),
            "supporting_evidence": evidence_ids(data_transfers),
            "contradicting_evidence": [],
            "confidence": 0.50,
            "status": "requires_review",
        })

    # HYP-006: forensic artifacts contain potentially sensitive data.
    #
    # Do not include the artifact's actual contents in the hypothesis.
    # The content remains in the original evidence record.
    sensitive_terms = (
        "password",
        "passwd",
        "credential",
        "credentials",
        "username",
        "user name",
        "api_key",
        "api key",
        "access token",
        "secret key",
        "private key",
    )

    sensitive_artifacts = []

    for item in filesystem_artifacts:
        metadata = item.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        content = str(
            item.get("text_content")
            or metadata.get("text_content")
            or ""
        ).lower()

        if any(term in content for term in sensitive_terms):
            sensitive_artifacts.append(item)

    if sensitive_artifacts:
        hypotheses.append({
            "hypothesis_id": "HYP-006",
            "description": (
                "One or more extracted filesystem artifacts contain "
                "text that may refer to credentials or other sensitive "
                "information. Determine whether the information is "
                "valid, exposed, authorized to be stored there, or "
                "relevant to the investigation. The presence of such "
                "text alone does not establish unauthorized access."
            ),
            "supporting_evidence": evidence_ids(sensitive_artifacts),
            "contradicting_evidence": [],
            "confidence": 0.50,
            "status": "requires_review",
        })

    # HYP-007: filesystem artifacts reference network services.
    network_terms = (
        "ftp://",
        "sftp://",
        "http://",
        "https://",
        "server",
        "remote host",
        "upload",
        "download",
    )

    network_artifacts = []

    for item in filesystem_artifacts:
        metadata = item.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        content = str(
            item.get("text_content")
            or metadata.get("text_content")
            or ""
        ).lower()

        if any(term in content for term in network_terms):
            network_artifacts.append(item)

    if network_artifacts:
        hypotheses.append({
            "hypothesis_id": "HYP-007",
            "description": (
                "One or more extracted filesystem artifacts refer to "
                "network services or possible remote data movement. "
                "Review surrounding context, timestamps if available, "
                "and authorized network or application logs to determine "
                "whether the references relate to actual activity."
            ),
            "supporting_evidence": evidence_ids(network_artifacts),
            "contradicting_evidence": [],
            "confidence": 0.45,
            "status": "requires_review",
        })

    # HYP-008: an artifact exists but has no matching rule.
    #
    # This ensures relevant artifacts remain visible as investigative
    # leads without inventing a suspicious interpretation.
    classified_ids = {
        evidence_id
        for hypothesis in hypotheses
        for evidence_id in hypothesis["supporting_evidence"]
    }

    unclassified_artifacts = [
        item
        for item in filesystem_artifacts
        if (
            item.get("evidence_id") is not None
            and str(item["evidence_id"]) not in classified_ids
        )
    ]

    if unclassified_artifacts:
        hypotheses.append({
            "hypothesis_id": "HYP-008",
            "description": (
                "Extracted filesystem artifacts are available for "
                "review, but their significance is not established "
                "by the current rule-based checks. Examine their "
                "contents, provenance, metadata, and case context "
                "before deciding whether they support an incident theory."
            ),
            "supporting_evidence": evidence_ids(unclassified_artifacts),
            "contradicting_evidence": [],
            "confidence": 0.30,
            "status": "requires_review",
        })

    return hypotheses
