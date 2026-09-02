from src.state import IncidentState, ToolResult


def prepare_bank_freeze(state: IncidentState) -> ToolResult:
    return ToolResult(
        success=True,
        action="prepare_bank_freeze",
        message="Official bank/card freeze workflow prepared for user review.",
        requires_confirmation=True,
        metadata={"mode": "mock", "handoff": "official-bank-channel"},
    )

