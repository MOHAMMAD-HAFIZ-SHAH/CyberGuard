
from backend.app.core.orchestrator import run_investigation as orchestrate_investigation


def run_investigation(incident_data):
    """Run the CyberGuard investigation orchestrator."""
    return orchestrate_investigation(incident_data)


def create_investigation(incident_data):
    """Compatibility wrapper for existing callers."""
    return run_investigation(incident_data)
