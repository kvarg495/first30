from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from src.agents.assessor import assess_incident_with_model
from src.agents.planner import create_plan_with_model
from src.agents.reviewer import next_pending_action, review_incident
from src.state import IncidentState
from src.tools.registry import TOOL_REGISTRY
from src.utils.llm import get_optional_chat_model


def assess_node(state: IncidentState, model: Any | None = None) -> dict:
    narrative = "\n".join([state.description, *state.incident_updates])
    exposures, risks, source, rationale, facts = assess_incident_with_model(
        narrative,
        state.selected_exposures,
        model,
    )
    return {
        "compromised_assets": exposures,
        "facts": facts,
        "risks": risks,
        "assessment_source": source,
        "status": "planning",
        "activity_log": [
            *state.activity_log,
            f"Assessed {len(risks)} risk area(s) using {source.replace('_', ' ')}",
            rationale,
        ],
    }


def plan_node(state: IncidentState, model: Any | None = None) -> dict:
    actions, rationale = create_plan_with_model(
        state.risks,
        state.completed_action_ids,
        model,
        state.prepared_action_ids,
        state.skipped_action_ids,
        state.facts,
    )
    remaining = sum(action.status == "pending" for action in actions)
    return {
        "actions": actions,
        "plan_version": state.plan_version + 1,
        "status": "acting",
        "activity_log": [
            *state.activity_log,
            f"Plan v{state.plan_version + 1}: prioritised {remaining} remaining recovery action(s)",
            rationale,
        ],
    }


def select_action_node(state: IncidentState) -> dict:
    action = next_pending_action(state)
    if action is None:
        return {"current_action_id": None, "status": "completed"}
    if state.loop_count >= state.max_steps:
        return {
            "current_action_id": None,
            "status": "stopped_safely",
            "activity_log": [*state.activity_log, "Stopped after reaching the safe loop limit"],
        }
    if action.id not in state.approved_action_ids:
        return {
            "current_action_id": action.id,
            "status": "awaiting_preparation",
            "activity_log": [*state.activity_log, f"Waiting to prepare: {action.title}"],
        }
    return {
        "current_action_id": action.id,
        "status": "acting",
        "activity_log": [*state.activity_log, f"Selected next action: {action.title}"],
    }


def route_after_selection(state: IncidentState) -> str:
    return "execute" if state.status == "acting" and state.current_action_id else "end"


def execute_tool_node(state: IncidentState) -> dict:
    action = next(item for item in state.actions if item.id == state.current_action_id)
    result = TOOL_REGISTRY[action.tool_name](state)
    updated_actions = [item.model_copy() for item in state.actions]
    prepared = list(state.prepared_action_ids)
    if result.success:
        for item in updated_actions:
            if item.id == action.id:
                item.status = "prepared"
        if action.id not in prepared:
            prepared.append(action.id)
    return {
        "actions": updated_actions,
        "prepared_action_ids": prepared,
        "tool_results": [*state.tool_results, result],
        "loop_count": state.loop_count + 1,
        "status": "awaiting_user_confirmation" if result.success else "stopped_safely",
        "activity_log": [
            *state.activity_log,
            result.message,
            "Guidance is prepared. Waiting for the user to confirm the next step.",
        ],
    }


def review_node(state: IncidentState) -> dict:
    status, message = review_incident(state)
    return {
        "current_action_id": None,
        "status": status,
        "activity_log": [*state.activity_log, message],
    }


def route_after_review(state: IncidentState) -> str:
    return "end" if state.status in {"completed", "stopped_safely"} else "plan"


def build_graph(model: Any | None = None):
    builder = StateGraph(IncidentState)
    builder.add_node("assess", lambda state: assess_node(state, model))
    builder.add_node("plan", lambda state: plan_node(state, model))
    builder.add_node("select_action", select_action_node)
    builder.add_node("execute", execute_tool_node)
    builder.add_node("review", review_node)

    builder.add_edge(START, "assess")
    builder.add_edge("assess", "plan")
    builder.add_edge("plan", "select_action")
    builder.add_conditional_edges("select_action", route_after_selection, {"execute": "execute", "end": END})
    # Tools prepare only local artifacts. Pausing here ensures the user, not the
    # agent, confirms any real-world bank, identity, email, or reporting step.
    builder.add_edge("execute", END)
    builder.add_conditional_edges("review", route_after_review, {"plan": "plan", "end": END})
    return builder.compile()


GRAPH = build_graph()


def run_incident(
    description: str,
    selected_exposures: list[str] | None = None,
    approved_action_ids: list[str] | None = None,
    completed_action_ids: list[str] | None = None,
    use_llm: bool | None = None,
) -> IncidentState:
    initial = IncidentState(
        description=description,
        selected_exposures=selected_exposures or [],
        approved_action_ids=approved_action_ids or [],
        completed_action_ids=completed_action_ids or [],
    )
    model = get_optional_chat_model() if use_llm is not False else None
    graph = build_graph(model) if model is not None else GRAPH
    return IncidentState.model_validate(graph.invoke(initial))


def continue_incident(
    state: IncidentState,
    additional_information: str | None = None,
    selected_exposures: list[str] | None = None,
    approved_action_ids: list[str] | None = None,
    completed_action_ids: list[str] | None = None,
    skipped_action_ids: list[str] | None = None,
    use_llm: bool | None = None,
) -> IncidentState:
    """Resume an existing incident after approval or newly discovered exposure."""
    initial = state.model_copy(deep=True)
    if additional_information and additional_information.strip():
        initial.incident_updates.append(additional_information.strip())
        initial.activity_log.append("Received new incident information; reassessing the response plan")
    initial.selected_exposures = list(
        dict.fromkeys([*initial.selected_exposures, *(selected_exposures or [])])
    )
    initial.approved_action_ids = list(
        dict.fromkeys([*initial.approved_action_ids, *(approved_action_ids or [])])
    )
    initial.completed_action_ids = list(
        dict.fromkeys([*initial.completed_action_ids, *(completed_action_ids or [])])
    )
    initial.skipped_action_ids = list(
        dict.fromkeys([*initial.skipped_action_ids, *(skipped_action_ids or [])])
    )
    initial.current_action_id = None
    initial.status = "assessing"

    model = get_optional_chat_model() if use_llm is not False else None
    graph = build_graph(model) if model is not None else GRAPH
    return IncidentState.model_validate(graph.invoke(initial))
