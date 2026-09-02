from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from src.data.singapore_guidance import KEYWORD_EXPOSURES, SCAM_RESPONSE_GUIDE
from src.state import Risk, Severity


SEVERITY_ORDER = {
    Severity.critical: 4,
    Severity.high: 3,
    Severity.medium: 2,
    Severity.low: 1,
}

ExposureName = Literal[
    "card_details",
    "otp",
    "email_password",
    "singpass_details",
    "personal_information",
    "unsure",
]


class ExposureAssessment(BaseModel):
    """Constrained output accepted from the optional LLM assessor."""

    exposures: list[ExposureName] = Field(default_factory=list)
    rationale: str = ""


def detect_exposures(description: str, selected_exposures: list[str]) -> list[str]:
    detected = set(selected_exposures)
    normalised = description.casefold()
    for exposure, keywords in KEYWORD_EXPOSURES.items():
        if any(keyword in normalised for keyword in keywords):
            detected.add(exposure)
    if not detected:
        detected.add("unsure")
    return sorted(detected)


def assess_incident(description: str, selected_exposures: list[str]) -> tuple[list[str], list[Risk]]:
    exposures = detect_exposures(description, selected_exposures)
    risks = [
        Risk(
            id=f"risk-{exposure}",
            title=SCAM_RESPONSE_GUIDE[exposure]["title"],
            severity=Severity(SCAM_RESPONSE_GUIDE[exposure]["severity"]),
            rationale=SCAM_RESPONSE_GUIDE[exposure]["rationale"],
            source_exposure=exposure,
        )
        for exposure in exposures
    ]
    risks.sort(key=lambda item: SEVERITY_ORDER[item.severity], reverse=True)
    return exposures, risks


def assess_incident_with_model(
    description: str,
    selected_exposures: list[str],
    model: Any | None = None,
) -> tuple[list[str], list[Risk], str, str]:
    """Assess an incident with safe deterministic fallback.

    The model may classify the narrative into known exposure categories, but it
    cannot invent severities, recovery guidance, or tool names. Those remain
    grounded in ``SCAM_RESPONSE_GUIDE``.
    """
    rule_exposures = detect_exposures(description, selected_exposures)
    exposures = set(rule_exposures)
    source = "curated_rules"
    rationale = "Matched the incident against the curated exposure guide."

    if model is not None:
        prompt = f"""You classify scam incident descriptions for a Singapore recovery prototype.
Return only the structured schema requested by the caller.

Choose zero or more of these exposure categories:
- card_details: payment-card or bank information
- otp: a one-time password or verification code
- email_password: email credentials or email-account access
- singpass_details: Singpass credentials or access
- personal_information: NRIC, passport, address, date of birth, or identity data
- unsure: the narrative is too unclear to classify safely

Do not request, repeat, or infer actual passwords, OTP values, PINs, or full card numbers.
Incident narrative: {description}
User-selected categories: {selected_exposures}
"""
        try:
            response = model.with_structured_output(ExposureAssessment).invoke(prompt)
            parsed = ExposureAssessment.model_validate(response)
            exposures.update(parsed.exposures)
            if len(exposures) > 1:
                exposures.discard("unsure")
            source = "curated_rules_plus_llm"
            rationale = parsed.rationale or "The model classified the narrative into approved exposure categories."
        except Exception:
            # A model or network failure must never prevent emergency guidance.
            source = "curated_rules_fallback"
            rationale = "The optional model was unavailable, so curated rules were used."

    if not exposures:
        exposures.add("unsure")

    ordered_exposures = sorted(exposures)
    risks = [
        Risk(
            id=f"risk-{exposure}",
            title=SCAM_RESPONSE_GUIDE[exposure]["title"],
            severity=Severity(SCAM_RESPONSE_GUIDE[exposure]["severity"]),
            rationale=SCAM_RESPONSE_GUIDE[exposure]["rationale"],
            source_exposure=exposure,
        )
        for exposure in ordered_exposures
    ]
    risks.sort(key=lambda item: SEVERITY_ORDER[item.severity], reverse=True)
    return ordered_exposures, risks, source, rationale
