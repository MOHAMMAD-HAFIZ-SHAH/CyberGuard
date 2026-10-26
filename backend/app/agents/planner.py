def create_investigation_plan(description: str, log_text: str) -> list[str]:
    plan = [
        "Understand the incident description and investigation objective.",
        "Inspect the supplied logs for suspicious events.",
        "Extract relevant timestamps and evidence.",
        "Build a chronological event timeline.",
        "Generate possible explanations for the incident.",
        "Check hypotheses against the available evidence.",
        "Prepare an investigation report."
    ]

    if not log_text.strip():
        plan.insert(
            1,
            "Request relevant system, authentication, or network logs."
        )

    return plan