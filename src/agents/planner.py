from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from src.data.singapore_guidance import ACTION_CATALOG, SCAM_RESPONSE_GUIDE
from src.state import RecoveryAction, Risk


ToolName = Literal[
    "prepare_bank_freeze",
    "prepare_email_security",
    "prepare_singpass_security",
    "create_evidence_summary",
    "prepare_police_report",
    "draft_contact_notification",
]


class PlanDecision(BaseModel):
    """A model can order tools, but only from this allow-list."""

    ordered_tools: list[ToolName] = Field(default_factory=list)
    rationale: str = ""


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


def create_plan_with_model(
    risks: list[Risk],
    completed_action_ids: list[str] | None = None,
    model: Any | None = None,
) -> tuple[list[RecoveryAction], str]:
    """Create a complete safe plan, optionally using a model to order it."""
    deterministic_plan = create_plan(risks, completed_action_ids)
    if model is None or not deterministic_plan:
        return deterministic_plan, "Ordered actions using curated urgency priorities."

    required_tools = [action.tool_name for action in deterministic_plan]
    risk_summary = [
        {
            "title": risk.title,
            "severity": risk.severity.value,
            "exposure": risk.source_exposure,
        }
        for risk in risks
    ]
    prompt = f"""You prioritise recovery actions for a scam-response prototype.
Return only the requested structured output. Order every allowed tool exactly once.
Never invent a tool and never place reporting or documentation ahead of urgent account containment.

Risks: {risk_summary}
Allowed tools for this incident: {required_tools}
Completed action IDs: {completed_action_ids or []}
"""

    try:
        response = model.with_structured_output(PlanDecision).invoke(prompt)
        decision = PlanDecision.model_validate(response)
        model_order = list(dict.fromkeys(tool for tool in decision.ordered_tools if tool in required_tools))
        proposed_order = [*model_order, *(tool for tool in required_tools if tool not in model_order)]
        proposed_rank = {tool: index for index, tool in enumerate(proposed_order)}

        # Containment always precedes documentation/notification, even if a model
        # proposes an unsafe order. The model can still prioritise within a tier.
        safe_order = sorted(
            proposed_order,
            key=lambda tool: (
                0 if ACTION_CATALOG[tool]["priority"] >= 8 else 1,
                proposed_rank[tool],
            ),
        )
        order_rank = {tool: len(safe_order) - index for index, tool in enumerate(safe_order)}
        for action in deterministic_plan:
            action.priority = order_rank[action.tool_name]
        deterministic_plan.sort(key=lambda item: item.priority, reverse=True)
        rationale = decision.rationale or "The model prioritised the approved recovery tools."
        return deterministic_plan, rationale
    except Exception:
        return deterministic_plan, "The optional model was unavailable; curated priorities were preserved."
