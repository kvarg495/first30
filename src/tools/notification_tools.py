from src.state import IncidentState, ToolResult


def draft_contact_notification(state: IncidentState) -> ToolResult:
    """Prepare, but never send, a warning for a user-selected trusted contact."""
    exposures = ", ".join(state.compromised_assets or state.selected_exposures) or "some personal information"
    template = f"""Please be alert: I may have been affected by a scam involving {exposures}.

Please be cautious of unexpected messages, payment requests, links, or account-recovery requests that appear to come from me. Do not send money or share passwords, OTPs, or personal details.

I will confirm any urgent request through a separate trusted channel.
"""
    return ToolResult(
        success=True,
        action="draft_contact_notification",
        message="Trusted-contact notification drafted for review; it has not been sent.",
        metadata={"mode": "mock", "delivery": "not-sent", "format": "email", "content": template},
    )
