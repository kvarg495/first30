from __future__ import annotations

import base64
import re
from typing import Any, Literal

from pydantic import BaseModel, Field

from src.data.singapore_guidance import SCAM_RESPONSE_GUIDE
from src.state import EvidenceRef, ExposureFinding, IncidentFacts, IncidentIntake, Risk, Severity
from src.utils.images import NormalizedImage


SEVERITY_ORDER = {Severity.critical: 4, Severity.high: 3, Severity.medium: 2, Severity.low: 1}
ExposureName = Literal["card_details", "otp", "email_password", "singpass_details", "personal_information", "unsure"]


class ModelEvidence(BaseModel):
    source: Literal["narrative", "structured_field", "image"]
    field: str = "narrative"
    excerpt: str


class ModelExposureFinding(BaseModel):
    category: ExposureName
    status: Literal["confirmed", "possible", "ruled_out"] = "possible"
    evidence: list[ModelEvidence] = Field(default_factory=list)
    conflict_notes: list[str] = Field(default_factory=list)


class ExposureAssessment(BaseModel):
    """The only LLM output accepted by the assessor; no secrets or free-form tools."""

    exposures: list[ExposureName] = Field(default_factory=list)
    findings: list[ModelExposureFinding] = Field(default_factory=list)
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


def _excerpt(text: str, phrases: tuple[str, ...]) -> str:
    """Return the user's sentence containing a matched phrase, never model prose."""
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", text):
        if _has(sentence.casefold(), *phrases):
            return _redact_sensitive_numbers(sentence.strip())
    return ""


def _normalise(value: str) -> str:
    return " ".join(value.casefold().split())


def _dedupe_evidence(items: list[EvidenceRef]) -> list[EvidenceRef]:
    seen: set[tuple[str, str, str]] = set()
    result: list[EvidenceRef] = []
    for item in items:
        identity = (item.source, item.field, item.excerpt)
        if identity not in seen:
            seen.add(identity)
            result.append(item)
    return result


def _valid_model_evidence(
    evidence: ModelEvidence,
    description: str,
    intake: IncidentIntake | None,
    images: list[NormalizedImage] | None,
) -> EvidenceRef | None:
    excerpt = _redact_sensitive_numbers(evidence.excerpt)
    if not excerpt:
        return None
    if evidence.source == "narrative":
        if _normalise(evidence.excerpt) not in _normalise(description):
            return None
        return EvidenceRef(source="narrative", field="narrative", excerpt=excerpt)
    if evidence.source == "structured_field" and intake:
        allowed = {
            "incident_date_time", "scam_channels", "impersonated_organisation",
            "suspicious_contact", "suspicious_url", "money_transfer_status",
            "amount", "discovery_method", "actions_already_taken",
        }
        if evidence.field not in allowed:
            return None
        raw = getattr(intake, evidence.field, "")
        rendered = ", ".join(raw) if isinstance(raw, list) else str(raw)
        if _normalise(evidence.excerpt) not in _normalise(rendered):
            return None
        return EvidenceRef(source="structured_field", field=evidence.field, excerpt=excerpt)
    if evidence.source == "image" and images:
        return EvidenceRef(source="image", field=evidence.field or "screenshot", excerpt=excerpt)
    return None


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
    card_phrases = ("credit-card", "credit card", "debit-card", "debit card", "card details", "card number", "bank account details", "banking login", "bank password")
    card_negative_phrases = (
        "did not enter bank", "didn't enter bank", "did not provide bank", "didn't provide bank",
        "did not share bank", "didn't share bank", "no bank details", "bank details were not",
        "did not enter card", "didn't enter card", "did not provide card", "didn't provide card",
        "did not share card", "didn't share card", "no card details", "card details were not",
    )
    card_negation_patterns = (
        r"\b(?:did not|didn't|never)\s+(?:enter|provide|share|disclose)\s+(?:any\s+)?(?:bank(?:ing)?|card)(?:\s+or\s+(?:bank(?:ing)?|card))?\s+(?:details|credentials|information)\b",
        r"\bno\s+(?:bank(?:ing)?|card)(?:\s+or\s+(?:bank(?:ing)?|card))?\s+(?:details|credentials|information)(?:\s+were)?\s+(?:entered|provided|shared|disclosed)?\b",
    )
    card_ruled_out = _has(text, *card_negative_phrases) or any(re.search(pattern, text) for pattern in card_negation_patterns)
    card_selected = "card_details" in selected_exposures
    card_mentioned = _has(text, *card_phrases)
    card = (card_selected or card_mentioned) and not card_ruled_out
    singpass = "singpass_details" in selected_exposures or "singpass" in text
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
    evidence_available = [name for name, phrases in {
        "call_log": ("call log",), "chat_screenshots": ("chat", "whatsapp", "telegram"),
        "website_screenshot": ("website", "screenshot"), "transaction_alert": ("transaction alert",),
        "transfer_instructions": ("transfer instructions", "safe account"),
    }.items() if _has(text, *phrases)]
    urls = re.findall(r"https?://[^\s)]+|\b(?:[\w-]+\.)+[a-z]{2,63}(?:/[^\s)]*)?", context, flags=re.IGNORECASE)
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
    findings: list[ExposureFinding] = []
    if card_ruled_out:
        conflict = ["The selected bank/card category conflicts with the written statement that no bank/card details were shared."] if card_selected else []
        findings.append(ExposureFinding(
            category="card_details", status="possible" if conflict else "ruled_out",
            evidence=[EvidenceRef(source="narrative", field="narrative", excerpt=_excerpt(context, card_negative_phrases) or "You stated that bank/card details were not shared.")],
            conflict_notes=conflict,
        ))
    elif card:
        finding_evidence = []
        if card_selected:
            finding_evidence.append(EvidenceRef(source="user_tag", field="exposure_tags", excerpt="Card or bank details"))
        mentioned = _excerpt(context, card_phrases)
        if mentioned:
            finding_evidence.append(EvidenceRef(source="narrative", field="narrative", excerpt=mentioned))
        findings.append(ExposureFinding(category="card_details", status="confirmed", evidence=finding_evidence))
    for category, confirmed in (
        ("otp", otp_context != "not_disclosed"),
        ("singpass_details", singpass),
        ("email_password", email),
        ("personal_information", bool(personal)),
    ):
        if confirmed:
            finding_evidence = []
            if category in selected_exposures:
                finding_evidence.append(EvidenceRef(source="user_tag", field="exposure_tags", excerpt=category.replace("_", " ").title()))
            finding_evidence.append(EvidenceRef(source="narrative", field="narrative", excerpt=_excerpt(context, {
                "otp": ("otp", "one-time password", "one time password", "verification code"),
                "singpass_details": ("singpass",),
                "email_password": ("gmail password", "email password", "email login"),
                "personal_information": ("nric", "address", "mobile number", "phone number", "date of birth", "passport"),
            }[category]) or "Identified from your submitted incident details."))
            findings.append(ExposureFinding(category=category, status="confirmed", evidence=finding_evidence))
    return IncidentFacts(
        otp_context=otp_context, money_transferred=money_transferred, bank_or_card_details_exposed=card,
        singpass_access_exposed=singpass, email_account_exposed=email, personal_data_types=personal,
        scam_channels=channels, impersonated_organisation=organisation, suspect_identifiers=suspects,
        suspicious_urls=list(dict.fromkeys(urls)), evidence_available=list(dict.fromkeys(evidence_available)),
        exposure_findings=findings,
        conflicted_findings=sum(bool(item.conflict_notes) for item in findings),
        rules_only_findings=sum(item.status == "confirmed" for item in findings),
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
For every exposure finding, include short evidence copied from the narrative or a named structured field.
Naming a bank or service provider is not evidence that credentials were exposed. A statement that no money
was transferred does not prove credentials were exposed. If evidence is incomplete, use status 'possible'.
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
            finding_map = {item.category: item.model_copy(deep=True) for item in facts.exposure_findings}
            accepted_model_findings = 0
            rejected_model_findings = 0
            model_confirmed: set[str] = set()
            candidates = list(parsed.findings)
            if not candidates:
                candidates = [
                    ModelExposureFinding(
                        category=category,
                        status="confirmed",
                        evidence=[ModelEvidence(source="narrative", excerpt=item) for item in parsed.risk_evidence.get(category, [])],
                    )
                    for category in parsed.exposures
                ]
            for candidate in candidates:
                valid = [
                    ref for item in candidate.evidence
                    if (ref := _valid_model_evidence(item, description, intake, images)) is not None
                ]
                existing = finding_map.get(candidate.category)
                if existing and existing.status == "ruled_out" and candidate.status != "ruled_out":
                    note = f"The model suggested {candidate.category.replace('_', ' ')}, but your written details explicitly ruled it out."
                    existing.conflict_notes.append(note)
                    needs_review.append(note)
                    rejected_model_findings += 1
                    continue
                if candidate.category == "card_details" and valid:
                    bank_evidence = " ".join(item.excerpt.casefold() for item in valid)
                    if not _has(bank_evidence, "card details", "card number", "bank account details", "banking login", "bank password", "unauthorised transaction", "unauthorized transaction"):
                        valid = []
                if candidate.status == "confirmed" and valid:
                    model_confirmed.add(candidate.category)
                    accepted_model_findings += 1
                    if existing:
                        existing.status = "confirmed"
                        existing.evidence = _dedupe_evidence([*existing.evidence, *valid])
                    else:
                        finding_map[candidate.category] = ExposureFinding(category=candidate.category, status="confirmed", evidence=valid)
                elif candidate.status == "ruled_out" and valid and not existing:
                    finding_map[candidate.category] = ExposureFinding(category=candidate.category, status="ruled_out", evidence=valid)
                    accepted_model_findings += 1
                elif candidate.status != "ruled_out":
                    rejected_model_findings += 1
                    if not existing:
                        finding_map[candidate.category] = ExposureFinding(
                            category=candidate.category,
                            status="possible",
                            evidence=valid,
                            conflict_notes=["The model suggested this exposure without enough submitted evidence to confirm it."],
                        )
            facts = facts.model_copy(update={
                "otp_context": facts.otp_context if facts.otp_context != "not_disclosed" else (parsed.otp_context if "otp" in model_confirmed else "not_disclosed"),
                "money_transferred": (
                    intake.money_transfer_status
                    if intake and intake.money_transfer_status != "unknown"
                    else facts.money_transferred if facts.money_transferred != "unknown" else parsed.money_transferred
                ),
                "bank_or_card_details_exposed": facts.bank_or_card_details_exposed or "card_details" in model_confirmed,
                "singpass_access_exposed": facts.singpass_access_exposed or "singpass_details" in model_confirmed,
                "email_account_exposed": facts.email_account_exposed or "email_password" in model_confirmed,
                "personal_data_types": list(dict.fromkeys([*facts.personal_data_types, *(parsed.personal_data_types if "personal_information" in model_confirmed else [])])),
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
                "exposure_findings": list(finding_map.values()),
                "accepted_model_findings": accepted_model_findings,
                "rejected_model_findings": rejected_model_findings,
                "conflicted_findings": sum(bool(item.conflict_notes) for item in finding_map.values()),
            })
            source = "curated_rules_plus_llm"
            rationale = parsed.rationale or "Extracted bounded incident facts and kept recovery choices grounded in verified rules."
        except Exception as exc:
            source, rationale = "curated_rules_fallback", "The optional model was unavailable; curated incident rules were used."
            message = str(exc).casefold()
            if "expired" in message or "expiredtoken" in message:
                diagnostic = "AWS IAM Identity Center session expired; run aws sso login for the configured profile"
            elif "accessdenied" in message or "not authorized" in message:
                diagnostic = "AWS Bedrock access was denied"
            elif "proxy" in message or "127.0.0.1:9" in message:
                diagnostic = "Network proxy prevented the Bedrock request"
            elif "credential" in message:
                diagnostic = "AWS credentials were unavailable"
            else:
                diagnostic = f"Model request failed: {type(exc).__name__}"
            facts = facts.model_copy(update={"model_diagnostic": diagnostic})
    exposures = facts_to_exposures(facts)
    return exposures, _risks(exposures), source, rationale, facts
