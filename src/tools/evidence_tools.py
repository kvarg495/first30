from src.state import GuidanceArtifact, IncidentState, ToolResult


def create_evidence_summary(state: IncidentState) -> ToolResult:
    """Prepare preservation guidance; evidence stays with the user and is never uploaded."""
    facts = state.facts
    available = ", ".join(item.replace("_", " ") for item in facts.evidence_available) or "No evidence items identified yet"
    steps = [
        "Save original screenshots of chats, webpages, transaction alerts, and transfer instructions.",
        "Save the call log, caller number, usernames, and suspicious URLs.",
        "Keep the original files unedited; make copies in a dated local folder such as First30 Evidence - YYYY-MM-DD.",
        "Do not delete chats, uninstall a suspicious app, or continue communicating with the scammer.",
        "Record the approximate date and time of the incident while it is fresh.",
    ]
    return ToolResult(
        success=True,
        action="create_evidence_summary",
        message="Evidence-preservation guidance prepared locally; nothing was collected, uploaded, or submitted.",
        artifact=GuidanceArtifact(
            summary=f"Preserve the original files before reporting. Already mentioned: {available}.",
            instructions=steps,
        ),
        metadata={
            "mode": "mock",
            "evidence_available": available,
            "preservation_steps": "\n".join(steps),
        },
    )
