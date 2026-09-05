from src.data.singapore_guidance import OFFICIAL_HANDOFFS
from src.state import IncidentState, ToolResult


BANK_HANDOFFS = {
    "DBS / POSB": {
        "url": "https://www.dbs.com.sg/personal/support/bank-ssb-safety-switch.html",
        "phone": "DBS Fraud Hotline: 1800 339 6963 (Singapore), 24/7",
    },
}


def prepare_bank_freeze(state: IncidentState) -> ToolResult:
    bank = BANK_HANDOFFS.get(state.selected_bank)
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
            "official_guidance_url": bank["url"] if bank else OFFICIAL_HANDOFFS["scamshield_victim_guidance"],
            "contact_route": bank["phone"] if bank else "Choose your bank above, or use ScamShield's official bank-hotline directory to verify the right number.",
            "call_script": script,
        },
    )
