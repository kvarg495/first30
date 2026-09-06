from src.state import CopyBlock, GuidanceArtifact, IncidentState, OfficialRoute, ToolResult


BANK_HANDOFFS = {
    "DBS / POSB": {
        "url": "https://www.dbs.com.sg/personal/support/bank-ssb-safety-switch.html",
        "phone": "DBS Fraud Hotline: 1800 339 6963 (Singapore), 24/7",
    },
    "OCBC": {
        "url": "https://www.ocbc.com/personal-banking/security/secure-banking-ways/ocbc-killswitch",
        "phone": "OCBC Personal Banking: 6363 3333 (press 8 for Kill Switch)",
    },
    "UOB": {
        "url": "https://www.uob.com.sg/personal/digital-banking/pib/security/what-to-do-if-you-have-been-scammed/index.page",
        "phone": "UOB 24/7 Fraud Hotline: 6255 0160 (press 3 to block cards or 4 for Kill Switch)",
    },
}


def prepare_bank_freeze(state: IncidentState) -> ToolResult:
    bank = BANK_HANDOFFS.get(state.selected_bank)
    intake = state.intake
    timing = f" The incident happened around {intake.incident_date_time}." if intake and intake.incident_date_time else ""
    transfer = {
        "yes": " I believe money may already have been transferred.",
        "no": " I have not identified a transfer, but I want the account checked.",
        "unknown": " I am not yet sure whether a transfer occurred.",
    }[state.facts.money_transferred]
    script = (
        f"I believe my {state.selected_bank + ' ' if state.selected_bank else ''}card or banking details may have been exposed in a scam."
        f"{timing}{transfer} "
        "Please guide me through your urgent card or account-security process. "
        "I will verify my identity only through your official channel."
    )
    url = bank["url"] if bank else "https://www.scamshield.gov.sg/bank-s-anti-scam-hotline/"
    route = bank["phone"] if bank else "Use ScamShield's official directory to identify your bank's anti-scam hotline."
    return ToolResult(
        success=True,
        action="prepare_bank_freeze",
        message="Urgent bank/card-security hand-off prepared for user review; no bank action was performed.",
        requires_confirmation=True,
        artifact=GuidanceArtifact(
            summary="Contact the bank through a verified channel and ask it to secure the affected account or card.",
            instructions=[
                "Do not use the number or link supplied by the suspected scammer.",
                f"Use the verified route below for {state.selected_bank or 'your bank'}.",
                "Explain what information may have been exposed and ask the bank to check for unauthorised activity.",
                "Record the time of the call and any case or reference number the bank provides.",
            ],
            official_routes=[OfficialRoute(label=state.selected_bank or "Bank anti-scam hotline directory", url=url, phone=route)],
            copy_blocks=[CopyBlock(id="bank-call-script", title="Suggested support script", text=script)],
        ),
        metadata={
            "mode": "mock",
            "handoff": "official-bank-channel",
            "official_guidance_url": url,
            "contact_route": route,
            "call_script": script,
        },
    )
