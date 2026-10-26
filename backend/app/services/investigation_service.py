
from backend.app.core.orchestrator import run_investigation


def create_investigation(incident_data):
    """Run the existing CyberGuard investigation orchestrator."""
    return run_investigation(incident_data)
