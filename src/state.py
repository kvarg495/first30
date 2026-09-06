from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Risk(BaseModel):
    id: str
    title: str
    severity: Severity
    rationale: str
    source_exposure: str


class EvidenceRef(BaseModel):
    """A user-visible fact that supports or contradicts an exposure finding."""

    source: Literal["user_tag", "narrative", "structured_field", "image"]
    field: str
    excerpt: str


class ExposureFinding(BaseModel):
    """A bounded finding; only confirmed findings may create required actions."""

    category: str
    status: Literal["confirmed", "possible", "ruled_out"]
    evidence: list[EvidenceRef] = Field(default_factory=list)
    conflict_notes: list[str] = Field(default_factory=list)


class RecoveryAction(BaseModel):
    id: str
    title: str
    description: str
    tool_name: str
    priority: int
    requires_confirmation: bool = False
    status: str = "pending"


class ToolResult(BaseModel):
    success: bool
    action: str
    message: str
    requires_confirmation: bool = False
    artifact: "GuidanceArtifact | None" = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class OfficialRoute(BaseModel):
    label: str
    url: str = ""
    phone: str = ""
    note: str = ""


class CopyBlock(BaseModel):
    id: str
    title: str
    text: str


class GuidanceArtifact(BaseModel):
    summary: str
    instructions: list[str] = Field(default_factory=list)
    official_routes: list[OfficialRoute] = Field(default_factory=list)
    copy_blocks: list[CopyBlock] = Field(default_factory=list)
    report_fields: dict[str, str] = Field(default_factory=dict)


class ImageMetadata(BaseModel):
    """Non-sensitive upload metadata retained with a case revision."""

    name: str
    media_type: Literal["image/png", "image/jpeg", "image/webp"]
    size_bytes: int
    width: int
    height: int
    analysis_status: Literal["analysed", "not_analysed"] = "not_analysed"


class IncidentIntake(BaseModel):
    """Structured, optional context supplied explicitly by the user."""

    narrative: str = Field(min_length=1)
    incident_date_time: str = ""
    scam_channels: list[str] = Field(default_factory=list)
    impersonated_organisation: str = ""
    suspicious_contact: str = ""
    suspicious_url: str = ""
    bank_or_provider: str = ""
    money_transfer_status: Literal["yes", "no", "unknown"] = "unknown"
    amount: str = ""
    discovery_method: str = ""
    actions_already_taken: str = ""
    exposure_tags: list[str] = Field(default_factory=list)
    image_metadata: list[ImageMetadata] = Field(default_factory=list)


class IncidentFacts(BaseModel):
    """Bounded, redacted facts used to choose context-specific recovery work."""

    otp_context: Literal["bank_transaction", "singpass", "account_recovery", "unknown", "not_disclosed"] = "not_disclosed"
    money_transferred: Literal["yes", "no", "unknown"] = "unknown"
    bank_or_card_details_exposed: bool = False
    singpass_access_exposed: bool = False
    email_account_exposed: bool = False
    personal_data_types: list[str] = Field(default_factory=list)
    scam_channels: list[str] = Field(default_factory=list)
    impersonated_organisation: str | None = None
    suspect_identifiers: list[str] = Field(default_factory=list)
    suspicious_urls: list[str] = Field(default_factory=list)
    evidence_available: list[str] = Field(default_factory=list)
    image_observations: list[str] = Field(default_factory=list)
    risk_evidence: dict[str, list[str]] = Field(default_factory=dict)
    uncertainties: list[str] = Field(default_factory=list)
    needs_review: list[str] = Field(default_factory=list)
    exposure_findings: list[ExposureFinding] = Field(default_factory=list)
    accepted_model_findings: int = 0
    rejected_model_findings: int = 0
    conflicted_findings: int = 0
    rules_only_findings: int = 0
    model_diagnostic: str = ""


class IncidentState(BaseModel):
    description: str
    intake: IncidentIntake | None = None
    case_revision: int = 0
    image_metadata: list[ImageMetadata] = Field(default_factory=list)
    images_analyzed: bool = False
    analysis_warning: str | None = None
    incident_updates: list[str] = Field(default_factory=list)
    selected_exposures: list[str] = Field(default_factory=list)
    facts: IncidentFacts = Field(default_factory=IncidentFacts)
    selected_bank: str = ""
    notification_channel: Literal["WhatsApp", "SMS", "Telegram", "Email"] = "WhatsApp"
    evidence_fields: dict[str, str] = Field(default_factory=dict)
    report_type: Literal["unauthorised_card_transaction", "scam", "other_cheating"] = "scam"
    report_fields: dict[str, str] = Field(default_factory=dict)
    compromised_assets: list[str] = Field(default_factory=list)
    risks: list[Risk] = Field(default_factory=list)
    actions: list[RecoveryAction] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    # A prepared action means First30 generated local guidance or a draft. It
    # never means an external account or report was changed or submitted.
    prepared_action_ids: list[str] = Field(default_factory=list)
    completed_action_ids: list[str] = Field(default_factory=list)
    skipped_action_ids: list[str] = Field(default_factory=list)
    approved_action_ids: list[str] = Field(default_factory=list)
    current_action_id: str | None = None
    activity_log: list[str] = Field(default_factory=list)
    assessment_source: str = "curated_rules"
    plan_version: int = 0
    status: str = "assessing"
    loop_count: int = 0
    max_steps: int = 12
