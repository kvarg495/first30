"""Prototype response mappings. Verify all guidance before production use."""

SCAM_RESPONSE_GUIDE = {
    "card_details": {
        "title": "Bank or card details exposed",
        "severity": "critical",
        "rationale": "Payment credentials may enable unauthorised transactions.",
        "actions": ["prepare_bank_freeze", "create_evidence_summary", "prepare_police_report"],
    },
    "otp": {
        "title": "One-time password disclosed",
        "severity": "critical",
        "rationale": "An OTP may allow an attacker to complete an immediate transaction or login.",
        "actions": ["prepare_bank_freeze", "create_evidence_summary", "prepare_police_report"],
    },
    "email_password": {
        "title": "Email account at risk",
        "severity": "high",
        "rationale": "Email access can be used to reset other accounts and hide security alerts.",
        "actions": [
            "prepare_email_security",
            "create_evidence_summary",
            "draft_contact_notification",
        ],
    },
    "singpass_details": {
        "title": "Singpass identity access at risk",
        "severity": "critical",
        "rationale": "Compromised identity access can expose multiple government-linked services.",
        "actions": ["prepare_singpass_security", "create_evidence_summary", "prepare_police_report"],
    },
    "personal_information": {
        "title": "Personal information exposed",
        "severity": "medium",
        "rationale": "Exposed identity information can enable impersonation and follow-on scams.",
        "actions": ["create_evidence_summary", "prepare_police_report", "draft_contact_notification"],
    },
    "unsure": {
        "title": "Exposure is not yet fully known",
        "severity": "high",
        "rationale": "Unknown exposure requires evidence preservation and careful reassessment.",
        "actions": ["create_evidence_summary", "prepare_police_report"],
    },
}

# These links are presented to the user for an explicit hand-off. The prototype does
# not sign in, submit forms, call hotlines, or transmit any incident information.
OFFICIAL_HANDOFFS = {
    "scamshield_victim_guidance": "https://www.scamshield.gov.sg/i-have-been-scammed/",
    "scamshield_check": "https://guide.scamshield.gov.sg/using-scamshield/check-for-scams",
    "scamshield_report": "https://guide.scamshield.gov.sg/using-scamshield/submit-a-scam-report",
    "bank_hotlines": "https://www.scamshield.gov.sg/bank-s-anti-scam-hotline/",
    "police_report": "https://www.police.gov.sg/e-services/lodge-police-report/",
    "police_contact": "https://www.police.gov.sg/contact-us",
    "singpass_contact": "https://portal.singpass.gov.sg/home/ui/contact-us",
}

EVIDENCE_CHECKLIST = (
    "Screenshots of messages or webpages",
    "Scammer phone numbers, usernames, email addresses, and account identifiers",
    "Suspicious URLs, app names, or social-media profile links",
    "Transaction dates, amounts, recipient details, and reference numbers",
    "A timeline of what happened and actions already taken",
)

KEYWORD_EXPOSURES = {
    "card_details": ("card", "credit card", "debit card", "bank details", "bank account"),
    "otp": ("otp", "one-time password", "one time password"),
    "email_password": ("email password", "gmail password", "email login"),
    "singpass_details": ("singpass",),
    "personal_information": ("nric", "passport", "address", "date of birth", "personal information"),
}

ACTION_CATALOG = {
    "prepare_bank_freeze": {
        "title": "Secure your bank or card",
        "description": "Prepare the official bank/card freeze workflow for your review.",
        "priority": 10,
        "requires_confirmation": True,
    },
    "prepare_singpass_security": {
        "title": "Secure Singpass access",
        "description": "Prepare a hand-off to the official Singpass security flow.",
        "priority": 9,
        "requires_confirmation": True,
    },
    "prepare_email_security": {
        "title": "Secure the affected email account",
        "description": "Prepare account-security steps using the provider's official flow.",
        "priority": 8,
        "requires_confirmation": True,
    },
    "create_evidence_summary": {
        "title": "Preserve scam evidence",
        "description": "Compile a structured incident and evidence summary locally.",
        "priority": 6,
        "requires_confirmation": False,
    },
    "prepare_police_report": {
        "title": "Prepare a scam report",
        "description": "Draft the information needed for an official police report.",
        "priority": 5,
        "requires_confirmation": False,
    },
    "draft_contact_notification": {
        "title": "Draft a trusted-contact notification",
        "description": "Prepare a message you can review before warning affected contacts.",
        "priority": 4,
        "requires_confirmation": False,
    },
}
