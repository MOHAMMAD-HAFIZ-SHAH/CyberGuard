def analyze_forensic_evidence(evidence: list[dict]) -> dict:
    return {
        "status": "not_configured",
        "message": "Full disk-image analysis is not enabled yet.",
        "evidence_count": len(evidence)
    }