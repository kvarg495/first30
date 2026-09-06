from src.data.singapore_guidance import OFFICIAL_HANDOFFS
from src.state import CopyBlock, GuidanceArtifact, IncidentState, OfficialRoute, ToolResult


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
        artifact=GuidanceArtifact(
            summary="Secure the affected email account through the provider's official app or website.",
            instructions=[item.strip().capitalize() for item in checklist.split("; ")],
        ),
        metadata={
            "mode": "mock",
            "handoff": "official-provider-channel",
            "security_checklist": checklist,
        },
    )


def prepare_singpass_security(state: IncidentState) -> ToolResult:
    intake = state.intake
    organisation = state.facts.impersonated_organisation
    timing = f" around {intake.incident_date_time}" if intake and intake.incident_date_time else ""
    impersonation = f" by someone impersonating {organisation}" if organisation else " during an impersonation scam"
    script = (
        f"I believe I disclosed Singpass-related identity information and an OTP{impersonation}{timing}. "
        "I need guidance to secure my account. I will use only this verified official support route and will not share any further codes."
    )
    return ToolResult(
        success=True,
        action="prepare_singpass_security",
        message="Official Singpass scam-support hand-off prepared; no Singpass account was accessed.",
        requires_confirmation=True,
        artifact=GuidanceArtifact(
            summary="Use Singpass's verified support route immediately and do not approve further login requests.",
            instructions=[
                "Open Singpass support using the official link below, not the suspicious message or website.",
                "Tell support when the incident happened and that a Singpass-related OTP or identity detail may have been disclosed.",
                "Review recent login or approval activity and follow support's account-securing instructions.",
            ],
            official_routes=[OfficialRoute(label="Singpass support", url=OFFICIAL_HANDOFFS["singpass_contact"], note="Scam support is available 24/7.")],
            copy_blocks=[CopyBlock(id="singpass-call-script", title="Suggested support script", text=script)],
        ),
        metadata={
            "mode": "mock",
            "handoff": "official-singpass-channel",
            "official_contact_url": OFFICIAL_HANDOFFS["singpass_contact"],
            "support_note": "Use the official Singpass contact route; scam support is available 24/7.",
            "call_script": script,
        },
    )
