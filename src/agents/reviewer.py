from __future__ import annotations

from src.state import IncidentState, RecoveryAction


def next_pending_action(state: IncidentState) -> RecoveryAction | None:
    pending = [action for action in state.actions if action.status == "pending"]
    return max(pending, key=lambda action: action.priority, default=None)


def plan_is_complete(state: IncidentState) -> bool:
    return all(action.status == "completed" for action in state.actions)


def review_incident(state: IncidentState) -> tuple[str, str]:
    """Review the latest observation and choose whether to finish or replan."""
    if state.loop_count >= state.max_steps:
        return "stopped_safely", "Stopped after reaching the safe loop limit"

    if plan_is_complete(state):
        return "completed", "Response plan completed"

    if state.tool_results and not state.tool_results[-1].success:
        return "stopped_safely", "The latest tool failed, so the workflow stopped for safe manual review"

    return "replanning", "Observed the tool result and reassessed remaining exposure"
