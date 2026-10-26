def analyze_endpoint_evidence(evidence: list[dict]) -> list[dict]:
    endpoint_types = {
        "suspicious_command",
        "malware_detection",
        "usb_connection"
    }

    return [
        item for item in evidence
        if item.get("event_type") in endpoint_types
    ]