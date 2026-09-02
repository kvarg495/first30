from src.data.singapore_guidance import EVIDENCE_CHECKLIST, OFFICIAL_HANDOFFS
from src.state import IncidentState, ToolResult


def prepare_police_report(state: IncidentState) -> ToolResult:
    exposures = ", ".join(state.compromised_assets or state.selected_exposures) or "Not yet known"
    completed = ", ".join(state.completed_action_ids) or "None recorded"
    evidence = "\n".join(f"- [ ] {item}" for item in EVIDENCE_CHECKLIST)
    report = f"""# Police report draft — review before submission

## What happened
{state.description}

## Information that may have been exposed
{exposures}

## Actions already taken
{completed}

## Evidence available or to attach
{evidence}

## Details still needed
- Date and approximate time of the incident
- Scammer contact details, account identifiers, or URLs
- Transaction amounts and reference numbers, if applicable

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
            "format": "markdown",
            "content": report,
        },
    )
