from src.data.singapore_guidance import OFFICIAL_HANDOFFS
from src.state import IncidentState, ToolResult


def prepare_police_report(state: IncidentState) -> ToolResult:
    """Create copyable SPF-style suggestions from the original case facts only."""
    facts = state.facts
    report_type = "Unauthorised card transaction" if facts.bank_or_card_details_exposed else "Scam"
    identifiers = ", ".join([*facts.suspect_identifiers, *facts.suspicious_urls]) or "Not recorded in the initial account"
    attachments = ", ".join(item.replace("_", " ") for item in facts.evidence_available) or "Add locally saved screenshots, call logs, and messages"
    money = "No transfer reported" if facts.money_transferred == "no" else "A transfer may have occurred; confirm amount, time, and reference number" if facts.money_transferred == "yes" else "Not recorded"
    narrative = (
        f"I believe I was targeted through {', '.join(facts.scam_channels) or 'an unrecorded channel'}. "
        f"The caller/message impersonated {facts.impersonated_organisation or 'an unrecorded organisation'}. "
        f"Information potentially exposed: OTP context {facts.otp_context.replace('_', ' ')}, "
        f"Singpass access {'possibly exposed' if facts.singpass_access_exposed else 'not reported'}, "
        f"and personal data {', '.join(facts.personal_data_types) or 'not reported'}. {money}."
    )
    return ToolResult(
        success=True,
        action="prepare_police_report",
        message="SPF-style report suggestions prepared for review; no police report was submitted.",
        metadata={
            "mode": "mock",
            "submission": "not-submitted",
            "official_report_url": OFFICIAL_HANDOFFS["police_report"],
            "report_type": report_type,
            "field_when_where": "Use the approximate date/time and channel from your original account. Add the exact location or website if known.",
            "field_what_happened": narrative,
            "field_discovery": "Describe how you discovered the suspicious activity or why you stopped the interaction.",
            "field_money_transactions": money,
            "field_items_involved": "Potentially exposed: " + ", ".join(filter(None, ["Singpass-related access" if facts.singpass_access_exposed else "", "OTP" if facts.otp_context != "not_disclosed" else "", *facts.personal_data_types])),
            "field_suspect_details": identifiers,
            "field_attachments": attachments,
        },
    )
