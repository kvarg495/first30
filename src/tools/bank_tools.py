from src.data.singapore_guidance import OFFICIAL_HANDOFFS
from src.state import IncidentState, ToolResult


def prepare_bank_freeze(state: IncidentState) -> ToolResult:
    script = (
        "I believe my card or banking details may have been exposed in a scam. "
        "Please guide me through your urgent card or account-security process. "
        "I will verify my identity only through your official channel."
    )
    return ToolResult(
        success=True,
        action="prepare_bank_freeze",
        message="Urgent bank/card-security hand-off prepared for user review; no bank action was performed.",
        requires_confirmation=True,
        metadata={
            "mode": "mock",
            "handoff": "official-bank-channel",
            "official_guidance_url": OFFICIAL_HANDOFFS["scamshield_victim_guidance"],
            "call_script": script,
        },
    )
