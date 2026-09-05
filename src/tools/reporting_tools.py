from src.data.singapore_guidance import EVIDENCE_CHECKLIST, OFFICIAL_HANDOFFS
from src.state import IncidentState, ToolResult


def prepare_police_report(state: IncidentState) -> ToolResult:
    exposures = ", ".join(state.compromised_assets or state.selected_exposures) or "Not yet known"
    completed = ", ".join(state.completed_action_ids) or "None recorded"
    evidence = "\n".join(f"- [ ] {item}" for item in EVIDENCE_CHECKLIST)
    report_labels = {
        "unauthorised_card_transaction": "Unauthorised card transaction",
        "scam": "Scam",
        "other_cheating": "Other cheating case",
    }
    fields = state.report_fields
    report = f"""# Police report draft — review before submission ({report_labels[state.report_type]})

## What happened
{state.description}

## Report fields captured
{chr(10).join(f'- **{key.replace("_", " ").title()}**: {value}' for key, value in fields.items() if value) or '- Complete the guided fields in First30 before using the official form.'}

## Information that may have been exposed
{exposures}

## Actions already taken
{completed}

## Evidence available or to attach
{evidence}

## Details to check before you use the official form
- When the incident or unauthorised use happened, and where/how it took place
- How it was discovered; transaction count, total amount, time period, and last legitimate card use where relevant
- Items involved, victim details, suspect details, and attachments

This is a factual draft only. Review it for accuracy before using an official reporting channel.
"""
    return ToolResult(
        success=True,
        action="prepare_police_report",
        message="Police-report draft prepared for review; it has not been submitted.",
        metadata={
            "mode": "mock",
            "submission": "not-submitted",
            "official_report_url": OFFICIAL_HANDOFFS["police_report"],
            "report_type": state.report_type,
            "format": "markdown",
            "content": report,
        },
    )
