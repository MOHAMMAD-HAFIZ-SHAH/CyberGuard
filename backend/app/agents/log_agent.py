
from backend.app.tools.log_tools import analyze_logs


def investigate_logs(log_text: str):
    """Analyze supplied logs using CyberGuard's existing log tools."""
    return analyze_logs(log_text)
