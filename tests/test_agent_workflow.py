from src.agents.assessor import ExposureAssessment, assess_incident_with_model
from src.agents.planner import PlanDecision, create_plan_with_model
from src.graph import continue_incident, run_incident


class FakeModel:
    """Small structured-output fake; no API or network is used by these tests."""

    def __init__(self) -> None:
        self.schema = None

    def with_structured_output(self, schema):
        self.schema = schema
        return self

    def invoke(self, _prompt):
        if self.schema is ExposureAssessment:
            return {
                "exposures": ["singpass_details"],
                "rationale": "Identity access was disclosed in the narrative.",
            }
        if self.schema is PlanDecision:
            # Deliberately suggest documentation before containment. The planner
            # must enforce the safety tier rather than trusting this order.
            return {
                "ordered_tools": ["prepare_police_report", "prepare_singpass_security"],
                "rationale": "Prioritised the relevant approved tools.",
            }
        raise AssertionError("Unexpected structured-output schema")


def test_model_classification_is_constrained_to_curated_risks() -> None:
    exposures, risks, source, _ = assess_incident_with_model(
        "I gave the scammer access to my national digital identity account.",
        [],
        FakeModel(),
    )

    assert exposures == ["singpass_details"]
    assert risks[0].id == "risk-singpass_details"
    assert source == "curated_rules_plus_llm"


def test_model_cannot_put_reporting_before_account_containment() -> None:
    _, risks, _, _ = assess_incident_with_model("Identity account exposed", [], FakeModel())
    actions, _ = create_plan_with_model(risks, model=FakeModel())

    tool_names = [action.tool_name for action in actions]
    assert tool_names[0] == "prepare_singpass_security"
    assert tool_names.index("prepare_singpass_security") < tool_names.index("prepare_police_report")


def test_graph_prepares_guidance_but_does_not_claim_external_completion() -> None:
    state = run_incident(
        "My email password was exposed",
        approved_action_ids=["action-prepare_email_security"],
        use_llm=False,
    )

    assert state.status == "awaiting_user_confirmation"
    assert state.current_action_id == "action-prepare_email_security"
    assert state.prepared_action_ids == ["action-prepare_email_security"]
    assert state.completed_action_ids == []
    assert state.tool_results[-1].metadata["security_checklist"]


def test_user_confirmation_replans_to_the_next_action() -> None:
    prepared = run_incident(
        "My email password was exposed",
        approved_action_ids=["action-prepare_email_security"],
        use_llm=False,
    )
    resumed = continue_incident(
        prepared,
        completed_action_ids=["action-prepare_email_security"],
        use_llm=False,
    )

    assert "action-prepare_email_security" in resumed.completed_action_ids
    assert resumed.status == "awaiting_preparation"
    assert resumed.current_action_id == "action-create_evidence_summary"


def test_new_information_reassesses_without_losing_completed_work() -> None:
    original = run_incident(
        "My email password was exposed",
        approved_action_ids=["action-prepare_email_security"],
        use_llm=False,
    )
    updated = continue_incident(
        original,
        additional_information="I also exposed my Singpass details.",
        use_llm=False,
    )

    assert "singpass_details" in updated.compromised_assets
    assert updated.status == "awaiting_preparation"
    assert updated.current_action_id == "action-prepare_singpass_security"
    assert set(original.prepared_action_ids).issubset(updated.prepared_action_ids)
    assert updated.plan_version > original.plan_version
