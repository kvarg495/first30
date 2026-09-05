from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from src.data.singapore_guidance import ACTION_CATALOG, SCAM_RESPONSE_GUIDE
from src.state import IncidentFacts, RecoveryAction, Risk


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


def create_plan(
    risks: list[Risk],
    completed_action_ids: list[str] | None = None,
    prepared_action_ids: list[str] | None = None,
    skipped_action_ids: list[str] | None = None,
    facts: IncidentFacts | None = None,
) -> list[RecoveryAction]:
    completed = set(completed_action_ids or [])
    prepared = set(prepared_action_ids or [])
    skipped = set(skipped_action_ids or [])
    if facts is None:
        tool_names: set[str] = set()
        for risk in risks:
            tool_names.update(SCAM_RESPONSE_GUIDE[risk.source_exposure]["actions"])
    else:
        tool_names = {"create_evidence_summary", "prepare_police_report"}
        # A generic OTP never creates a bank action. Containment follows the
        # channel the OTP was actually used for.
        if facts.bank_or_card_details_exposed or facts.money_transferred == "yes" or facts.otp_context == "bank_transaction":
            tool_names.add("prepare_bank_freeze")
        if facts.singpass_access_exposed or facts.otp_context == "singpass":
            tool_names.add("prepare_singpass_security")
        if facts.email_account_exposed or facts.otp_context == "account_recovery":
            tool_names.add("prepare_email_security")
        if facts.personal_data_types or facts.email_account_exposed or facts.singpass_access_exposed:
            tool_names.add("draft_contact_notification")

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
                status=(
                    "completed"
                    if action_id in completed
                    else "skipped"
                    if action_id in skipped
                    else "prepared"
                    if action_id in prepared
                    else "pending"
                ),
            )
        )
    return sorted(actions, key=lambda item: item.priority, reverse=True)


def create_plan_with_model(
    risks: list[Risk],
    completed_action_ids: list[str] | None = None,
    model: Any | None = None,
    prepared_action_ids: list[str] | None = None,
    skipped_action_ids: list[str] | None = None,
    facts: IncidentFacts | None = None,
) -> tuple[list[RecoveryAction], str]:
    """Create a complete safe plan, optionally using a model to order it."""
    deterministic_plan = create_plan(
        risks,
        completed_action_ids,
        prepared_action_ids,
        skipped_action_ids,
        facts,
    )
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
Incident facts: {facts.model_dump(exclude_none=True) if facts else {}}
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
