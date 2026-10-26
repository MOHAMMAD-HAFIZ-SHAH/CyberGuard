def create_case(title: str, description: str, goal: str | None = None) -> dict:
    return {
        "title": title,
        "description": description,
        "goal": goal or "Determine what the available evidence suggests happened.",
        "status": "investigating"
    }