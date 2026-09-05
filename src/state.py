from __future__ import annotations

from enum import Enum
from typing import Literal

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
    metadata: dict[str, str] = Field(default_factory=dict)


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


class IncidentState(BaseModel):
    description: str
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
