def generate_hypotheses(evidence: list[dict]) -> list[dict]:
    hypotheses = []

    failed_logins = [
        item for item in evidence
        if item["event_type"] == "failed_login"
    ]

    successful_logins = [
        item for item in evidence
        if item["event_type"] == "successful_login"
    ]

    malware_events = [
        item for item in evidence
        if item["event_type"] == "malware_detection"
    ]

    suspicious_commands = [
        item for item in evidence
        if item["event_type"] == "suspicious_command"
    ]

    data_transfers = [
        item for item in evidence
        if item["event_type"] == "possible_data_transfer"
    ]

    if len(failed_logins) >= 3:
        hypotheses.append({
            "hypothesis_id": "HYP-001",
            "description": "Repeated failed login attempts may indicate a brute-force attempt.",
            "supporting_evidence": [
                item["evidence_id"] for item in failed_logins
            ],
            "contradicting_evidence": [],
            "confidence": 0.65,
            "status": "requires_review"
        })

    if failed_logins and successful_logins:
        hypotheses.append({
            "hypothesis_id": "HYP-002",
            "description": "Repeated failed logins followed by a successful login may indicate a possible account compromise.",
            "supporting_evidence": [
                item["evidence_id"]
                for item in failed_logins + successful_logins
            ],
            "contradicting_evidence": [],
            "confidence": 0.55,
            "status": "requires_review"
        })

    if malware_events:
        hypotheses.append({
            "hypothesis_id": "HYP-003",
            "description": "The system may have experienced a malware-related incident.",
            "supporting_evidence": [
                item["evidence_id"] for item in malware_events
            ],
            "contradicting_evidence": [],
            "confidence": 0.75,
            "status": "requires_review"
        })

    if suspicious_commands:
        hypotheses.append({
            "hypothesis_id": "HYP-004",
            "description": "Suspicious command execution may require further endpoint investigation.",
            "supporting_evidence": [
                item["evidence_id"] for item in suspicious_commands
            ],
            "contradicting_evidence": [],
            "confidence": 0.60,
            "status": "requires_review"
        })

    if data_transfers:
        hypotheses.append({
            "hypothesis_id": "HYP-005",
            "description": "A data transfer event was observed and should be investigated for possible unauthorized data movement.",
            "supporting_evidence": [
                item["evidence_id"] for item in data_transfers
            ],
            "contradicting_evidence": [],
            "confidence": 0.50,
            "status": "requires_review"
        })

    return hypotheses