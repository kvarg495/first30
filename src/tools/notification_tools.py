from src.state import IncidentState, ToolResult


def draft_contact_notification(state: IncidentState) -> ToolResult:
    """Prepare, but never send, a warning for a user-selected trusted contact."""
    exposures = ", ".join(state.compromised_assets or state.selected_exposures) or "some personal information"
    organisation = state.facts.impersonated_organisation
    context = f" after someone impersonated {organisation}" if organisation else ""
    short_message = f"Please be alert: I may have been affected by a scam{context} involving {exposures}. Do not trust unexpected messages, payment requests, links, or account-recovery requests appearing to come from me. Do not send money or share passwords, OTPs, or personal details. I will confirm urgent requests through a separate trusted channel."
    template = f"""Subject: Please be alert for suspicious messages using my details

Hi [Name],

{short_message}

Please do not send money or share passwords, OTPs, or personal details in response.

Thanks,
[Your name]
"""
    if state.notification_channel in {"WhatsApp", "SMS", "Telegram"}:
        template = short_message
    return ToolResult(
        success=True,
        action="draft_contact_notification",
        message="Trusted-contact notification drafted for review; it has not been sent.",
        metadata={"mode": "mock", "delivery": "not-sent", "format": state.notification_channel.lower(), "content": template},
    )
