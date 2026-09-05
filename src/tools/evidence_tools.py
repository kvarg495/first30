from src.data.singapore_guidance import EVIDENCE_CHECKLIST
from src.state import IncidentState, ToolResult


def create_evidence_summary(state: IncidentState) -> ToolResult:
    risks = ", ".join(risk.title for risk in state.risks) or "Not assessed yet"
    exposures = ", ".join(state.compromised_assets or state.selected_exposures) or "Not yet known"
    completed = ", ".join(state.completed_action_ids) or "None yet"
    checklist = "\n".join(f"- [ ] {item}" for item in EVIDENCE_CHECKLIST)
    facts = state.facts
    recorded = state.evidence_fields
    summary = f"""# First30 evidence summary (draft)

## Incident narrative
{state.description}

## Potential exposure
{exposures}

## Case facts captured
- OTP context: {facts.otp_context.replace('_', ' ')}
- Money transferred: {facts.money_transferred}
- Scam channel(s): {', '.join(facts.scam_channels) or 'Not recorded'}
- Impersonated organisation: {facts.impersonated_organisation or 'Not recorded'}
- Suspect identifiers: {', '.join(facts.suspect_identifiers) or 'Not recorded'}
- Suspicious URLs: {', '.join(facts.suspicious_urls) or 'Not recorded'}
- Evidence already available: {', '.join(facts.evidence_available) or 'Not recorded'}

## Details added by the user
{chr(10).join(f'- {key.replace("_", " ")}: {value}' for key, value in recorded.items() if value) or '- None yet'}

## Assessed risks
{risks}

## Actions already recorded
{completed}

## Evidence to preserve
{checklist}

## Missing details to add before reporting
- [ ] Scam date and approximate time
- [ ] Scammer contact or account details
- [ ] Relevant URL or platform
- [ ] Transaction reference, if money was transferred
"""
    return ToolResult(
        success=True,
        action="create_evidence_summary",
        message="Structured evidence summary drafted locally; nothing was uploaded or submitted.",
        metadata={
            "mode": "mock",
            "risk_count": str(len(state.risks)),
            "format": "markdown",
            "content": summary,
        },
    )
