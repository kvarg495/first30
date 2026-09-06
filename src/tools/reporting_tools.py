from src.data.singapore_guidance import OFFICIAL_HANDOFFS
from src.state import IncidentState, ToolResult


def prepare_police_report(state: IncidentState) -> ToolResult:
    """Create copyable SPF-style suggestions from the original case facts only."""
    facts = state.facts
    intake = state.intake
    report_type = "Unauthorised card transaction" if facts.bank_or_card_details_exposed else "Scam"
    identifiers = ", ".join([*facts.suspect_identifiers, *facts.suspicious_urls]) or "Not recorded in the initial account"
    attachments = ", ".join(item.replace("_", " ") for item in facts.evidence_available) or "Add locally saved screenshots, call logs, and messages"
    money = "No transfer reported" if facts.money_transferred == "no" else "A transfer may have occurred; confirm amount, time, and reference number" if facts.money_transferred == "yes" else "Not recorded"
    narrative = intake.narrative if intake else state.description
    when_where = (
        f"Date/time: {intake.incident_date_time or 'Not recorded'}. "
        f"Channel/location: {', '.join(intake.scam_channels) or ', '.join(facts.scam_channels) or 'Not recorded'}."
        if intake
        else "Use the approximate date/time and channel from your original account. Add the exact location or website if known."
    )
    discovery = intake.discovery_method if intake and intake.discovery_method else "Not recorded — add how you discovered the scam or why you stopped."
    if intake and intake.amount:
        money = f"Transfer status: {facts.money_transferred}. Amount entered by user: {intake.amount}. Confirm transaction references in the official form."
    return ToolResult(
        success=True,
        action="prepare_police_report",
        message="SPF-style report suggestions prepared for review; no police report was submitted.",
        metadata={
            "mode": "mock",
            "submission": "not-submitted",
            "official_report_url": OFFICIAL_HANDOFFS["police_report"],
            "report_type": report_type,
            "field_when_where": when_where,
            "field_what_happened": narrative,
            "field_discovery": discovery,
            "field_money_transactions": money,
            "field_items_involved": "Potentially exposed: " + ", ".join(filter(None, ["Singpass-related access" if facts.singpass_access_exposed else "", "OTP" if facts.otp_context != "not_disclosed" else "", *facts.personal_data_types])),
            "field_suspect_details": identifiers,
            "field_attachments": attachments,
            "field_victims": "Your details will be collected by the official SPF form. If reporting for someone else, answer on their behalf and identify that person.",
            "field_suspects": identifiers,
        },
    )
