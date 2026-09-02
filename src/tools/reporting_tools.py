from src.state import IncidentState, ToolResult


def prepare_police_report(state: IncidentState) -> ToolResult:
    return ToolResult(
        success=True,
        action="prepare_police_report",
        message="Draft police-report information package prepared for user review.",
        metadata={"mode": "mock", "submission": "not-submitted"},
    )

