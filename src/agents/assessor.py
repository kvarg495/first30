from __future__ import annotations

import base64
import re
from typing import Any, Literal

from pydantic import BaseModel, Field

from src.data.singapore_guidance import SCAM_RESPONSE_GUIDE
from src.state import IncidentFacts, IncidentIntake, Risk, Severity
from src.utils.images import NormalizedImage


SEVERITY_ORDER = {Severity.critical: 4, Severity.high: 3, Severity.medium: 2, Severity.low: 1}
ExposureName = Literal["card_details", "otp", "email_password", "singpass_details", "personal_information", "unsure"]


class ExposureAssessment(BaseModel):
    """The only LLM output accepted by the assessor; no secrets or free-form tools."""

    exposures: list[ExposureName] = Field(default_factory=list)
    otp_context: Literal["bank_transaction", "singpass", "account_recovery", "unknown", "not_disclosed"] = "not_disclosed"
    money_transferred: Literal["yes", "no", "unknown"] = "unknown"
    bank_or_card_details_exposed: bool = False
    singpass_access_exposed: bool = False
    email_account_exposed: bool = False
    personal_data_types: list[Literal["nric", "address", "phone", "date_of_birth", "passport", "other"]] = Field(default_factory=list)
    scam_channels: list[Literal["phone_call", "whatsapp", "sms", "telegram", "website", "email", "social_media", "other"]] = Field(default_factory=list)
    impersonated_organisation: str | None = None
    suspect_identifiers: list[str] = Field(default_factory=list)
    suspicious_urls: list[str] = Field(default_factory=list)
    evidence_available: list[Literal["call_log", "chat_screenshots", "website_screenshot", "transaction_alert", "transfer_instructions", "other"]] = Field(default_factory=list)
    image_observations: list[str] = Field(default_factory=list)
    risk_evidence: dict[ExposureName, list[str]] = Field(default_factory=dict)
    uncertainties: list[str] = Field(default_factory=list)
    rationale: str = ""


def _has(text: str, *phrases: str) -> bool:
    return any(phrase in text for phrase in phrases)


def _redact_sensitive_numbers(value: str) -> str:
    return re.sub(r"\b\d{4,19}\b", "[redacted number]", value).strip()


def detect_facts(
    description: str,
    selected_exposures: list[str],
    intake: IncidentIntake | None = None,
) -> IncidentFacts:
    context = " ".join(
        filter(
            None,
            [
                description,
                intake.discovery_method if intake else "",
                intake.actions_already_taken if intake else "",
                intake.suspicious_contact if intake else "",
                intake.suspicious_url if intake else "",
                intake.impersonated_organisation if intake else "",
            ],
        )
    )
    text = context.casefold()
    no_transfer = _has(
        text,
        "stopped before",
        "did not transfer",
        "didn't transfer",
        "no transfer",
        "no money was transferred",
        "no money transferred",
        "did not send money",
        "didn't send money",
    )
    transferred = _has(text, "transferred", "sent $", "sent s$", "paid ")
    inferred_transfer = "no" if no_transfer else "yes" if transferred else "unknown"
    money_transferred = (
        intake.money_transfer_status
        if intake and intake.money_transfer_status != "unknown"
        else inferred_transfer
    )
    singpass = "singpass_details" in selected_exposures or "singpass" in text
    card = "card_details" in selected_exposures or _has(text, "credit-card", "credit card", "debit-card", "debit card", "card details", "card number", "bank account details")
    email = "email_password" in selected_exposures or _has(text, "gmail password", "email password", "email login")
    if "otp" not in selected_exposures and not _has(text, "otp", "one-time password", "one time password", "verification code"):
        otp_context = "not_disclosed"
    elif singpass or _has(text, "identity verification", "verify my identity"):
        otp_context = "singpass"
    elif card or _has(text, "bank transaction", "bank app", "banking"):
        otp_context = "bank_transaction"
    elif email:
        otp_context = "account_recovery"
    else:
        otp_context = "unknown"
    personal = []
    for label, phrases in {"nric": ("nric",), "address": ("address", "home address"), "phone": ("mobile number", "phone number"), "date_of_birth": ("date of birth",), "passport": ("passport",)}.items():
        if _has(text, *phrases):
            personal.append(label)
    if "personal_information" in selected_exposures and not personal:
        personal.append("other")
    channels = [name for name, phrases in {
        "phone_call": ("phone call", "received a call", "caller"), "whatsapp": ("whatsapp",), "sms": ("sms",),
        "telegram": ("telegram",), "website": ("website", "http://", "https://", " link"), "email": ("email",),
        "social_media": ("facebook", "instagram", "social media"),
    }.items() if _has(text, *phrases)]
    if intake:
        channels = list(dict.fromkeys([*intake.scam_channels, *channels]))
    evidence = [name for name, phrases in {
        "call_log": ("call log",), "chat_screenshots": ("chat", "whatsapp", "telegram"),
        "website_screenshot": ("website", "screenshot"), "transaction_alert": ("transaction alert",),
        "transfer_instructions": ("transfer instructions", "safe account"),
    }.items() if _has(text, *phrases)]
    urls = re.findall(r"https?://[^\s)]+|\b[\w.-]+\.(?:com|sg|net|org)\b", context)
    suspects = re.findall(r"\+65\s?\d{4}\s?\d{4}", context)
    if intake and intake.suspicious_contact:
        suspects.append(intake.suspicious_contact)
    organisation = (
        intake.impersonated_organisation.strip()
        if intake and intake.impersonated_organisation.strip()
        else "Singapore Police Force" if _has(text, "police") else None
    )
    if intake and intake.suspicious_url:
        urls.append(intake.suspicious_url)
    return IncidentFacts(
        otp_context=otp_context, money_transferred=money_transferred, bank_or_card_details_exposed=card,
        singpass_access_exposed=singpass, email_account_exposed=email, personal_data_types=personal,
        scam_channels=channels, impersonated_organisation=organisation, suspect_identifiers=suspects,
        suspicious_urls=list(dict.fromkeys(urls)), evidence_available=list(dict.fromkeys(evidence)),
    )


def facts_to_exposures(facts: IncidentFacts) -> list[str]:
    exposures: list[str] = []
    if facts.bank_or_card_details_exposed:
        exposures.append("card_details")
    if facts.otp_context != "not_disclosed":
        exposures.append("otp")
    if facts.singpass_access_exposed:
        exposures.append("singpass_details")
    if facts.email_account_exposed:
        exposures.append("email_password")
    if facts.personal_data_types:
        exposures.append("personal_information")
    return exposures or ["unsure"]


def _risks(exposures: list[str]) -> list[Risk]:
    results = [Risk(id=f"risk-{e}", title=SCAM_RESPONSE_GUIDE[e]["title"], severity=Severity(SCAM_RESPONSE_GUIDE[e]["severity"]), rationale=SCAM_RESPONSE_GUIDE[e]["rationale"], source_exposure=e) for e in exposures]
    return sorted(results, key=lambda item: SEVERITY_ORDER[item.severity], reverse=True)


def assess_incident(description: str, selected_exposures: list[str]) -> tuple[list[str], list[Risk]]:
    exposures = facts_to_exposures(detect_facts(description, selected_exposures))
    return exposures, _risks(exposures)


def assess_incident_with_model(
    description: str,
    selected_exposures: list[str],
    model: Any | None = None,
    intake: IncidentIntake | None = None,
    images: list[NormalizedImage] | None = None,
) -> tuple[list[str], list[Risk], str, str, IncidentFacts]:
    facts = detect_facts(description, selected_exposures, intake)
    source, rationale = "curated_rules", "Used incident context to choose safe, relevant recovery routes."
    if model is not None:
        structured_intake = intake.model_dump(exclude={"narrative"}) if intake else {}
        prompt = f"""Extract only the requested structured incident facts for a Singapore scam-response prototype.
Do not request, repeat, or infer passwords, OTP values, PINs, or full card numbers. Do not invent events.
An OTP is not automatically a bank OTP: classify its context from the narrative.
Explicit user-entered fields outrank screenshot inferences. If an image conflicts with an explicit field,
record the conflict in uncertainties instead of overriding the field. Image observations must be concise,
must not reproduce authentication secrets, and must distinguish visible facts from uncertainty.
Narrative: {description}
Explicit structured fields: {structured_intake}
User-selected categories: {selected_exposures}
"""
        try:
            request: Any = prompt
            if images:
                from langchain_core.messages import HumanMessage

                content: list[dict[str, Any]] = [{"type": "text", "text": prompt}]
                content.extend(
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": image.media_type,
                            "data": base64.b64encode(image.data).decode("ascii"),
                        },
                    }
                    for image in images
                )
                request = [HumanMessage(content=content)]
            parsed = ExposureAssessment.model_validate(model.with_structured_output(ExposureAssessment).invoke(request))
            needs_review = list(parsed.uncertainties)
            if intake and intake.money_transfer_status != "unknown" and parsed.money_transferred not in {"unknown", intake.money_transfer_status}:
                needs_review.append(
                    f"Screenshot/model interpretation of transfer status conflicts with your '{intake.money_transfer_status}' selection."
                )
            facts = facts.model_copy(update={
                "otp_context": facts.otp_context if facts.otp_context != "not_disclosed" else (parsed.otp_context if parsed.otp_context != "not_disclosed" else "unknown" if "otp" in parsed.exposures else "not_disclosed"),
                "money_transferred": (
                    intake.money_transfer_status
                    if intake and intake.money_transfer_status != "unknown"
                    else facts.money_transferred if facts.money_transferred != "unknown" else parsed.money_transferred
                ),
                "bank_or_card_details_exposed": facts.bank_or_card_details_exposed or parsed.bank_or_card_details_exposed or "card_details" in parsed.exposures,
                "singpass_access_exposed": facts.singpass_access_exposed or parsed.singpass_access_exposed or "singpass_details" in parsed.exposures,
                "email_account_exposed": facts.email_account_exposed or parsed.email_account_exposed or "email_password" in parsed.exposures,
                "personal_data_types": list(dict.fromkeys([*facts.personal_data_types, *parsed.personal_data_types, *( ["other"] if "personal_information" in parsed.exposures else [])])),
                "scam_channels": list(dict.fromkeys([*facts.scam_channels, *parsed.scam_channels])),
                "impersonated_organisation": facts.impersonated_organisation or parsed.impersonated_organisation,
                "suspect_identifiers": list(dict.fromkeys([*facts.suspect_identifiers, *parsed.suspect_identifiers])),
                "suspicious_urls": list(dict.fromkeys([*facts.suspicious_urls, *parsed.suspicious_urls])),
                "evidence_available": list(dict.fromkeys([*facts.evidence_available, *parsed.evidence_available])),
                "image_observations": [_redact_sensitive_numbers(item) for item in parsed.image_observations if _redact_sensitive_numbers(item)] if images else [],
                "risk_evidence": {
                    exposure: [_redact_sensitive_numbers(item) for item in items if _redact_sensitive_numbers(item)]
                    for exposure, items in parsed.risk_evidence.items()
                },
                "uncertainties": [_redact_sensitive_numbers(item) for item in parsed.uncertainties if _redact_sensitive_numbers(item)],
                "needs_review": list(dict.fromkeys(needs_review)),
            })
            source = "curated_rules_plus_llm"
            rationale = parsed.rationale or "Extracted bounded incident facts and kept recovery choices grounded in verified rules."
        except Exception:
            source, rationale = "curated_rules_fallback", "The optional model was unavailable; curated incident rules were used."
    exposures = facts_to_exposures(facts)
    return exposures, _risks(exposures), source, rationale, facts
