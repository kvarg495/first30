from __future__ import annotations

from src.data.singapore_guidance import KEYWORD_EXPOSURES, SCAM_RESPONSE_GUIDE
from src.state import Risk, Severity


SEVERITY_ORDER = {
    Severity.critical: 4,
    Severity.high: 3,
    Severity.medium: 2,
    Severity.low: 1,
}


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

