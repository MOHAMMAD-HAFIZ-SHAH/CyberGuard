def map_known_patterns(evidence: list[dict]) -> list[dict]:
    mappings = {
        "failed_login": "Repeated authentication failures; investigate account access patterns.",
        "suspicious_command": "Suspicious command execution; review process context.",
        "malware_detection": "Validate the malware alert and examine the artifact safely.",
        "possible_data_transfer": "Investigate the destination and authorization of the transfer."
    }

    results = []

    for item in evidence:
        event_type = item.get("event_type")

        if event_type in mappings:
            results.append({
                "evidence_id": item["evidence_id"],
                "assessment": mappings[event_type]
            })

    return results