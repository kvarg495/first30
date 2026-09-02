from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from src.agents.assessor import assess_incident
from src.agents.planner import create_plan
from src.agents.reviewer import next_pending_action, plan_is_complete
from src.state import IncidentState
from src.tools.registry import TOOL_REGISTRY


def assess_node(state: IncidentState) -> dict:
    exposures, risks = assess_incident(state.description, state.selected_exposures)
    return {
        "compromised_assets": exposures,
        "risks": risks,
        "status": "planning",
        "activity_log": [*state.activity_log, f"Assessed {len(risks)} risk area(s)"],
    }


def plan_node(state: IncidentState) -> dict:
    actions = create_plan(state.risks, state.completed_action_ids)
    return {
        "actions": actions,
        "status": "acting",
        "activity_log": [*state.activity_log, f"Prioritised {len(actions)} recovery action(s)"],
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
    if action.requires_confirmation and action.id not in state.approved_action_ids:
        return {
            "current_action_id": action.id,
            "status": "awaiting_confirmation",
            "activity_log": [*state.activity_log, f"Requested approval for: {action.title}"],
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
    completed = list(state.completed_action_ids)
    if result.success:
        for item in updated_actions:
            if item.id == action.id:
                item.status = "completed"
        if action.id not in completed:
            completed.append(action.id)
    return {
        "actions": updated_actions,
        "completed_action_ids": completed,
        "loop_count": state.loop_count + 1,
        "activity_log": [*state.activity_log, result.message],
    }


def review_node(state: IncidentState) -> dict:
    status = "completed" if plan_is_complete(state) else "acting"
    message = "Response plan completed" if status == "completed" else "Reassessed remaining exposure"
    return {
        "current_action_id": None,
        "status": status,
        "activity_log": [*state.activity_log, message],
    }


def route_after_review(state: IncidentState) -> str:
    return "end" if state.status in {"completed", "stopped_safely"} else "select_action"


def build_graph():
    builder = StateGraph(IncidentState)
    builder.add_node("assess", assess_node)
    builder.add_node("plan", plan_node)
    builder.add_node("select_action", select_action_node)
    builder.add_node("execute", execute_tool_node)
    builder.add_node("review", review_node)

    builder.add_edge(START, "assess")
    builder.add_edge("assess", "plan")
    builder.add_edge("plan", "select_action")
    builder.add_conditional_edges("select_action", route_after_selection, {"execute": "execute", "end": END})
    builder.add_edge("execute", "review")
    builder.add_conditional_edges("review", route_after_review, {"select_action": "select_action", "end": END})
    return builder.compile()


GRAPH = build_graph()


def run_incident(
    description: str,
    selected_exposures: list[str] | None = None,
    approved_action_ids: list[str] | None = None,
    completed_action_ids: list[str] | None = None,
) -> IncidentState:
    initial = IncidentState(
        description=description,
        selected_exposures=selected_exposures or [],
        approved_action_ids=approved_action_ids or [],
        completed_action_ids=completed_action_ids or [],
    )
    return IncidentState.model_validate(GRAPH.invoke(initial))

