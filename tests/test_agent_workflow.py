from src.agents.assessor import ExposureAssessment, assess_incident_with_model
from src.agents.planner import PlanDecision, create_plan_with_model
from src.graph import advance_incident, continue_incident, prepare_current_action, reopen_action, run_incident
from src.state import IncidentIntake
from src.utils.images import NormalizedImage


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
    exposures, risks, source, _, facts = assess_incident_with_model(
        "I gave the scammer access to my national digital identity account.",
        [],
        FakeModel(),
    )

    assert exposures == ["singpass_details"]
    assert risks[0].id == "risk-singpass_details"
    assert source == "curated_rules_plus_llm"
    assert facts.singpass_access_exposed is True


def test_model_cannot_put_reporting_before_account_containment() -> None:
    _, risks, _, _, _ = assess_incident_with_model("Identity account exposed", [], FakeModel())
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


def test_singpass_otp_without_money_or_card_details_does_not_offer_bank_freeze() -> None:
    state = run_incident(
        "A caller impersonating the Police asked me to verify my identity. I entered my NRIC, "
        "Singpass username and OTP, but stopped before making any transfer. I have WhatsApp screenshots.",
        selected_exposures=["singpass_details", "otp", "personal_information"],
        use_llm=False,
    )

    assert state.facts.otp_context == "singpass"
    assert state.facts.money_transferred == "no"
    assert "prepare_bank_freeze" not in [action.tool_name for action in state.actions]
    assert state.current_action_id == "action-prepare_singpass_security"


def test_plain_language_no_money_statement_is_not_misread_as_a_transfer() -> None:
    state = run_incident(
        "A caller requested Singpass verification. No money was transferred during the incident.",
        use_llm=False,
    )
    assert state.facts.money_transferred == "no"
    assert "prepare_bank_freeze" not in [action.tool_name for action in state.actions]


def test_preparing_and_advancing_do_not_reassess_or_repeat_the_plan() -> None:
    initial = run_incident("My email password was exposed", use_llm=False)
    prepared = prepare_current_action(initial)
    advanced = advance_incident(prepared, completed_action_ids=[prepared.current_action_id])

    assert prepared.plan_version == initial.plan_version
    assert advanced.plan_version == initial.plan_version
    assert advanced.current_action_id == "action-create_evidence_summary"


def test_explicit_transfer_status_overrides_model_inference_and_marks_conflict() -> None:
    class TransferModel(FakeModel):
        def invoke(self, prompt):
            if self.schema is ExposureAssessment:
                return {"exposures": ["singpass_details"], "money_transferred": "yes", "singpass_access_exposed": True}
            return super().invoke(prompt)

    intake = IncidentIntake(
        narrative="A caller asked me to verify Singpass, but I definitely did not transfer money.",
        money_transfer_status="no",
    )
    _, _, _, _, facts = assess_incident_with_model(intake.narrative, [], TransferModel(), intake=intake)
    assert facts.money_transferred == "no"
    assert facts.needs_review


def test_skipped_step_prevents_completion_and_can_be_reopened() -> None:
    state = run_incident("My email password was exposed during a scam call.", use_llm=False)
    prepared = prepare_current_action(state)
    skipped = advance_incident(prepared, skipped_action_ids=[prepared.current_action_id])
    while skipped.current_action_id:
        current_id = skipped.current_action_id
        skipped = prepare_current_action(skipped)
        skipped = advance_incident(skipped, completed_action_ids=[current_id])
    assert skipped.status == "needs_attention"
    reopened = reopen_action(skipped, skipped.skipped_action_ids[0])
    assert reopened.status == "awaiting_user_confirmation"
    assert reopened.current_action_id not in reopened.skipped_action_ids


def test_new_case_revision_resets_progress_and_artifacts() -> None:
    first = run_incident("My email password was exposed during a scam call.", case_revision=1, use_llm=False)
    first = prepare_current_action(first)
    first = advance_incident(first, completed_action_ids=[first.current_action_id])
    second = run_incident("My card details were exposed on a fake website.", case_revision=2, use_llm=False)
    assert first.completed_action_ids
    assert second.case_revision == 2
    assert second.completed_action_ids == []
    assert second.prepared_action_ids == []
    assert second.tool_results == []


def test_multimodal_failure_retains_safe_text_plan_and_marks_image_unanalysed() -> None:
    image = NormalizedImage("evidence.png", "image/png", b"safe-test-bytes", 10, 10)
    state = run_incident(
        "A caller requested Singpass verification, but I stopped and transferred no money.",
        images=[image],
        use_llm=False,
    )
    assert state.actions
    assert state.images_analyzed is False
    assert state.image_metadata[0].analysis_status == "not_analysed"
    assert state.intake.image_metadata[0].name == "evidence.png"
    assert "not analysed" in state.analysis_warning.lower()


def test_plan_completes_only_when_every_required_step_is_confirmed() -> None:
    state = run_incident("My email password was exposed during a scam call.", use_llm=False)
    while state.current_action_id:
        current_id = state.current_action_id
        state = prepare_current_action(state)
        state = advance_incident(state, completed_action_ids=[current_id])
    assert state.status == "completed"
    assert len(state.completed_action_ids) == len(state.actions)
