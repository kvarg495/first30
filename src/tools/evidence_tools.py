from src.data.singapore_guidance import EVIDENCE_CHECKLIST
from src.state import IncidentState, ToolResult


def create_evidence_summary(state: IncidentState) -> ToolResult:
    risks = ", ".join(risk.title for risk in state.risks) or "Not assessed yet"
    exposures = ", ".join(state.compromised_assets or state.selected_exposures) or "Not yet known"
    completed = ", ".join(state.completed_action_ids) or "None yet"
    checklist = "\n".join(f"- [ ] {item}" for item in EVIDENCE_CHECKLIST)
    summary = f"""# First30 evidence summary (draft)

## Incident narrative
{state.description}

## Potential exposure
{exposures}

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
