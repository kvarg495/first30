from __future__ import annotations

from src.data.singapore_guidance import ACTION_CATALOG, SCAM_RESPONSE_GUIDE
from src.state import RecoveryAction, Risk


def create_plan(risks: list[Risk], completed_action_ids: list[str] | None = None) -> list[RecoveryAction]:
    completed = set(completed_action_ids or [])
    tool_names: set[str] = set()
    for risk in risks:
        tool_names.update(SCAM_RESPONSE_GUIDE[risk.source_exposure]["actions"])

    actions = []
    for tool_name in tool_names:
        definition = ACTION_CATALOG[tool_name]
        action_id = f"action-{tool_name}"
        actions.append(
            RecoveryAction(
                id=action_id,
                title=definition["title"],
                description=definition["description"],
                tool_name=tool_name,
                priority=definition["priority"],
                requires_confirmation=definition["requires_confirmation"],
                status="completed" if action_id in completed else "pending",
            )
        )
    return sorted(actions, key=lambda item: item.priority, reverse=True)

