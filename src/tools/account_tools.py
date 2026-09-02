from src.state import IncidentState, ToolResult


def prepare_email_security(state: IncidentState) -> ToolResult:
    return ToolResult(
        success=True,
        action="prepare_email_security",
        message="Official email-provider security workflow prepared.",
        requires_confirmation=True,
        metadata={"mode": "mock", "handoff": "official-provider-channel"},
    )


def prepare_singpass_security(state: IncidentState) -> ToolResult:
    return ToolResult(
        success=True,
        action="prepare_singpass_security",
        message="Official Singpass security hand-off prepared.",
        requires_confirmation=True,
        metadata={"mode": "mock", "handoff": "official-singpass-channel"},
    )

