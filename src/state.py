from __future__ import annotations

from enum import Enum

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


class IncidentState(BaseModel):
    description: str
    incident_updates: list[str] = Field(default_factory=list)
    selected_exposures: list[str] = Field(default_factory=list)
    compromised_assets: list[str] = Field(default_factory=list)
    risks: list[Risk] = Field(default_factory=list)
    actions: list[RecoveryAction] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    completed_action_ids: list[str] = Field(default_factory=list)
    approved_action_ids: list[str] = Field(default_factory=list)
    current_action_id: str | None = None
    activity_log: list[str] = Field(default_factory=list)
    assessment_source: str = "curated_rules"
    plan_version: int = 0
    status: str = "assessing"
    loop_count: int = 0
    max_steps: int = 12
