from src.agents.assessor import assess_incident
from src.agents.planner import create_plan
from src.state import IncidentState
from src.tools.bank_tools import prepare_bank_freeze


def test_demo_scenario_prioritises_financial_risk() -> None:
    exposures, risks = assess_incident(
        "I entered my DBS card number, OTP and Gmail password into a fake website.",
        [],
    )

    assert {"card_details", "otp", "email_password"}.issubset(exposures)
    assert risks[0].severity.value == "critical"

    actions = create_plan(risks)
    assert actions[0].tool_name == "prepare_bank_freeze"
    assert actions[0].requires_confirmation is True


def test_mock_bank_tool_never_performs_real_freeze() -> None:
    state = IncidentState(description="Card details exposed", selected_exposures=["card_details"])
    result = prepare_bank_freeze(state)

    assert result.success is True
    assert result.requires_confirmation is True
    assert result.metadata["mode"] == "mock"


def test_completed_actions_are_preserved_when_replanning() -> None:
    _, risks = assess_incident("My email password was exposed", [])
    actions = create_plan(risks, completed_action_ids=["action-create_evidence_summary"])

    evidence = next(action for action in actions if action.id == "action-create_evidence_summary")
    assert evidence.status == "completed"

