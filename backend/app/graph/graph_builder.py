from app.graph.neo4j_client import Neo4jClient


def persist_evidence_graph(
    incident_id: str,
    evidence: list[dict]
) -> dict:
    client = Neo4jClient()

    try:
        saved = client.save_evidence(
            incident_id,
            evidence
        )

        return {
            "saved": saved,
            "reason": None if saved else "Neo4j credentials are not configured"
        }

    finally:
        client.close()