from src.data.singapore_guidance import OFFICIAL_HANDOFFS
from src.state import IncidentState, ToolResult


def prepare_email_security(state: IncidentState) -> ToolResult:
    checklist = (
        "Use the email provider's official site or app; change the password; "
        "review recovery details and active sessions; enable multi-factor authentication; "
        "and remove unfamiliar forwarding rules."
    )
    return ToolResult(
        success=True,
        action="prepare_email_security",
        message="Email-security checklist prepared for user review; no account was accessed.",
        requires_confirmation=True,
        metadata={
            "mode": "mock",
            "handoff": "official-provider-channel",
            "security_checklist": checklist,
        },
    )


def prepare_singpass_security(state: IncidentState) -> ToolResult:
    return ToolResult(
        success=True,
        action="prepare_singpass_security",
        message="Official Singpass scam-support hand-off prepared; no Singpass account was accessed.",
        requires_confirmation=True,
        metadata={
            "mode": "mock",
            "handoff": "official-singpass-channel",
            "official_contact_url": OFFICIAL_HANDOFFS["singpass_contact"],
            "support_note": "Use the official Singpass contact route; scam support is available 24/7.",
        },
    )
