from __future__ import annotations

from src.state import IncidentState, RecoveryAction


def next_pending_action(state: IncidentState) -> RecoveryAction | None:
    pending = [action for action in state.actions if action.status == "pending"]
    return max(pending, key=lambda action: action.priority, default=None)


def plan_is_complete(state: IncidentState) -> bool:
    return all(action.status == "completed" for action in state.actions)

