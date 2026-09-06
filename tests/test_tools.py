from src.data.singapore_guidance import OFFICIAL_HANDOFFS
from src.state import IncidentState
from src.tools.account_tools import prepare_singpass_security
from src.tools.bank_tools import prepare_bank_freeze
from src.tools.evidence_tools import create_evidence_summary
from src.tools.notification_tools import draft_contact_notification
from src.tools.reporting_tools import prepare_police_report
from src.tools.registry import TOOL_REGISTRY


def sample_state() -> IncidentState:
    return IncidentState(
        description="I entered card details and an OTP on a fake delivery website.",
        selected_exposures=["card_details", "otp", "email_password"],
        compromised_assets=["card_details", "otp", "email_password"],
    )


def test_all_registered_tools_return_the_shared_result_shape() -> None:
    state = sample_state()

    for name, tool in TOOL_REGISTRY.items():
        result = tool(state)
        assert result.action == name
        assert result.success is True
        assert result.metadata["mode"] == "mock"


def test_consequential_handoffs_require_explicit_confirmation() -> None:
    state = sample_state()

    assert prepare_bank_freeze(state).requires_confirmation is True
    assert prepare_singpass_security(state).requires_confirmation is True


def test_evidence_summary_is_local_and_contains_incident_details() -> None:
    result = create_evidence_summary(sample_state())

    assert "nothing was collected, uploaded, or submitted" in result.message
    assert "Save original screenshots" in result.metadata["preservation_steps"]
    assert "Do not delete chats" in result.metadata["preservation_steps"]


def test_police_report_is_a_draft_with_official_handoff() -> None:
    result = prepare_police_report(sample_state())

    assert result.metadata["submission"] == "not-submitted"
    assert result.metadata["official_report_url"] == OFFICIAL_HANDOFFS["police_report"]
    assert result.metadata["report_type"] == "Scam"
    assert "field_what_happened" in result.metadata
    assert "field_attachments" in result.metadata
    assert result.metadata["attachment_checklist"] == [
        "Screenshots of scam messages, chats, or webpages",
        "Call logs and the scammer's contact details",
        "Transaction alerts, receipts, or bank references, if relevant",
    ]


def test_contact_notification_is_never_sent() -> None:
    result = draft_contact_notification(sample_state())

    assert result.metadata["delivery"] == "not-sent"
    assert "Do not send money" in result.metadata["content"]
