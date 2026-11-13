
from backend.app.models.hypothesis import Hypothesis
from backend.app.models.evidence import Evidence


def generate_hypotheses(
    evidence: list[dict | Evidence],
) -> list[Hypothesis]:

    hypotheses: list[Hypothesis] = []

    valid_evidence = []

    for item in evidence:
        if isinstance(item, Evidence):
            valid_evidence.append(item.model_dump())
        elif isinstance(item, dict):
            valid_evidence.append(Evidence(**item).model_dump())

    def matching(event_type: str) -> list[dict]:
        return [
            item for item in valid_evidence
            if item.get("event_type") == event_type
        ]

    def evidence_ids(items: list[dict]) -> list[str]:
        return list(dict.fromkeys(
            str(item["evidence_id"])
            for item in items
            if item.get("evidence_id") is not None
        ))

    def add_hypothesis(
        hypothesis_id: str,
        description: str,
        supporting_items: list[dict],
        confidence: float,
    ) -> None:

        references = evidence_ids(supporting_items)

        if not references:
            return

        hypotheses.append(
            Hypothesis(
                hypothesis_id=hypothesis_id,
                description=description,
                supporting_evidence=references,
                contradicting_evidence=[],
                confidence=confidence,
                status="requires_review",
            )
        )

    failed_logins = matching("failed_login")
    successful_logins = matching("successful_login")
    malware_events = matching("malware_detection")
    suspicious_commands = matching("suspicious_command")
    data_transfers = matching("possible_data_transfer")
    filesystem_artifacts = matching("filesystem_artifact")

    ftp_connections = matching("ftp_connection_opened")
    credential_events = matching("credential_related_activity")
    ftp_uploads = matching("ftp_file_upload")
    ftp_downloads = matching("ftp_file_download")
    connection_closures = matching("connection_closed")
    logouts = matching("logout")

    if len(failed_logins) >= 3:
        add_hypothesis(
            "HYP-001",
            "Repeated failed login attempts may indicate a brute-force "
            "attempt. Review account names, source addresses, time intervals, "
            "and authentication policy before drawing a conclusion.",
            failed_logins,
            0.65,
        )

    if failed_logins and successful_logins:
        add_hypothesis(
            "HYP-002",
            "Failed login attempts and a successful login were both "
            "observed. Review timestamps, accounts, source addresses, "
            "and authorization context to assess whether the activity "
            "could indicate account compromise.",
            failed_logins + successful_logins,
            0.55,
        )

    if malware_events:
        add_hypothesis(
            "HYP-003",
            "A malware-related detection was recorded. Validate the alert "
            "and examine the associated artifact using safe forensic "
            "procedures.",
            malware_events,
            0.75,
        )

    if suspicious_commands:
        add_hypothesis(
            "HYP-004",
            "Suspicious command execution was observed and may require "
            "further endpoint investigation. Review process context, "
            "execution history, and authorization.",
            suspicious_commands,
            0.60,
        )

    if data_transfers:
        add_hypothesis(
            "HYP-005",
            "A possible data transfer event was recorded. Review the "
            "destination, volume, authorization, and related network "
            "records to determine whether the activity was authorized "
            "and whether a transfer completed.",
            data_transfers,
            0.50,
        )

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
            or metadata.get("raw_line")
            or ""
        ).casefold()

        if any(term in content for term in sensitive_terms):
            sensitive_artifacts.append(item)

    if sensitive_artifacts:
        add_hypothesis(
            "HYP-006",
            "One or more extracted filesystem artifacts contain text that "
            "may refer to credentials or other sensitive information. "
            "Determine whether the information is valid, exposed, "
            "authorized to be stored there, or relevant to the case. "
            "The presence of such text alone does not establish "
            "unauthorized access.",
            sensitive_artifacts,
            0.50,
        )

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
            or metadata.get("raw_line")
            or ""
        ).casefold()

        if any(term in content for term in network_terms):
            network_artifacts.append(item)

    if network_artifacts:
        add_hypothesis(
            "HYP-007",
            "Extracted filesystem artifacts refer to network services or "
            "possible remote data movement. Review surrounding context, "
            "timestamps, and related network or application logs to "
            "determine whether the references relate to actual activity.",
            network_artifacts,
            0.45,
        )

    classified_ids = {
        evidence_id
        for hypothesis in hypotheses
        for evidence_id in hypothesis.supporting_evidence
    }

    unclassified_artifacts = [
        item for item in filesystem_artifacts
        if (
            item.get("evidence_id") is not None
            and str(item["evidence_id"]) not in classified_ids
        )
    ]

    if unclassified_artifacts:
        add_hypothesis(
            "HYP-008",
            "Extracted filesystem artifacts are available for review, "
            "but their significance is not established by current "
            "rule-based checks. Examine contents, provenance, metadata, "
            "and case context before deciding whether they support "
            "an incident theory.",
            unclassified_artifacts,
            0.30,
        )

    transfer_activity = (
        ftp_connections
        + ftp_uploads
        + ftp_downloads
        + data_transfers
    )

    if ftp_connections and (ftp_uploads or ftp_downloads):
        related_transfer_evidence = (
            ftp_connections
            + ftp_uploads
            + ftp_downloads
            + connection_closures
        )

        add_hypothesis(
            "HYP-009",
            "The logs record an FTP connection and a file-transfer command. "
            "This may represent an attempted or completed file transfer. "
            "The available events alone do not establish successful "
            "transfer, authorization, or the contents transferred. "
            "Review server-side transfer results, byte counts, file "
            "metadata, and corresponding network records.",
            related_transfer_evidence,
            0.60,
        )

    elif transfer_activity:
        add_hypothesis(
            "HYP-009",
            "FTP or other possible data-transfer activity was recorded. "
            "Determine whether a transfer was attempted, completed, "
            "authorized, and relevant to the incident by examining "
            "corroborating server and network records.",
            transfer_activity + connection_closures,
            0.45,
        )

    if credential_events and (
        ftp_connections or ftp_uploads or ftp_downloads
    ):
        related_credential_evidence = (
            credential_events
            + ftp_connections
            + ftp_uploads
            + ftp_downloads
        )

        add_hypothesis(
            "HYP-010",
            "Credential-related indicators and FTP activity appear in the "
            "same supplied log set. Investigate whether authentication "
            "data was transmitted, exposed, or merely referenced in a "
            "warning. The supplied events do not by themselves prove "
            "that credentials were transmitted or compromised.",
            related_credential_evidence,
            0.60,
        )

    elif credential_events:
        add_hypothesis(
            "HYP-010",
            "A credential-related indicator was recorded. Determine what "
            "the log actually represents and whether sensitive information "
            "was exposed. The indicator alone does not prove credential "
            "transmission, validity, or compromise.",
            credential_events,
            0.40,
        )

    session_events = connection_closures + logouts

    if session_events and (
        ftp_connections or ftp_uploads or ftp_downloads
    ):
        add_hypothesis(
            "HYP-011",
            "Connection closure or logout events provide context for the "
            "observed network activity. Correlate timestamps and session "
            "identifiers where available. A closed connection or logout "
            "does not establish whether a file transfer succeeded or "
            "whether the activity was malicious.",
            ftp_connections
            + ftp_uploads
            + ftp_downloads
            + session_events,
            0.35,
        )

    return hypotheses
