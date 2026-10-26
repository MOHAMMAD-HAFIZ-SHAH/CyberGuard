from neo4j import GraphDatabase

from app.config.settings import (
    NEO4J_URI,
    NEO4J_USERNAME,
    NEO4J_PASSWORD
)


class Neo4jClient:
    def __init__(self):
        self.driver = None

        if NEO4J_PASSWORD:
            self.driver = GraphDatabase.driver(
                NEO4J_URI,
                auth=(NEO4J_USERNAME, NEO4J_PASSWORD)
            )

    def close(self):
        if self.driver:
            self.driver.close()

    def save_evidence(
        self,
        incident_id: str,
        evidence: list[dict]
    ) -> bool:
        if not self.driver:
            return False

        query = """
        MERGE (i:Incident {id: $incident_id})
        WITH i
        UNWIND $items AS item
        MERGE (e:Evidence {
            id: item.evidence_id,
            incident_id: $incident_id
        })
        SET e.source = item.source,
            e.event_type = item.event_type,
            e.description = item.description,
            e.timestamp = item.timestamp,
            e.severity = item.severity
        MERGE (i)-[:HAS_EVIDENCE]->(e)
        """

        with self.driver.session() as session:
            session.run(
                query,
                incident_id=incident_id,
                items=evidence
            )

        return True