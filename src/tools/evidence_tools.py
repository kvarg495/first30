from src.state import IncidentState, ToolResult


def create_evidence_summary(state: IncidentState) -> ToolResult:
    return ToolResult(
        success=True,
        action="create_evidence_summary",
        message="Structured evidence summary prepared from the incident state.",
        metadata={"mode": "mock", "risk_count": str(len(state.risks))},
    )

