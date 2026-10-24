"""Typed records of AgentShield (design.md sections 1, 2A and 2B).

Pydantic models for everything that crosses a trust boundary or is persisted (events, evidence,
findings, grants, routing records, outcomes). Facts carry their status, source and age; model
estimates and untrusted text are kept apart from verified evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

Label = Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "UNKNOWN"]
LABEL_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
Provider = Literal["inline_hook_vendor", "audit_only_vendor", "simulator"]
Mode = Literal["inline", "native_policy", "audit_only"]
FactStatus = Literal["verified", "unknown", "stale", "conflicted", "untrusted"]
ResolutionStatus = Literal["SUFFICIENT_DENY", "SUFFICIENT_ALLOW_CANDIDATE", "NEEDS_MORE_EVIDENCE",
                           "NEEDS_OTHER_SPECIALIST", "CONFLICTING", "UNRESOLVED_BUDGET"]
Disposition = Literal["ALLOW", "BLOCK", "REQUIRE_APPROVAL", "RECORD_ONLY", "AUDIT_ALERT", "CREATE_REVIEW_CASE"]
OutcomeType = Literal["attempted_access", "completed_access", "attempted_disclosure", "confirmed_disclosure"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def label_rank(label: str | None) -> int | None:
    return LABEL_RANK.get(label or "UNKNOWN")


def max_label(labels: list[str]) -> str:
    known = [x for x in labels if x in LABEL_RANK]
    return max(known, key=LABEL_RANK.__getitem__) if known else "UNKNOWN"


class ToolCall(BaseModel):
    """One tool call inside a grouped inline frame."""
    call_id: str
    tool_name: str
    operation: str
    resource_id: str | None = None
    artifact_id: str | None = None
    destination: str | None = None
    excerpt: str | None = None
    t0: dict[str, Any] = Field(default_factory=dict)


class SecurityEvent(BaseModel):
    """A normalized observation. Only verified identity goes into actor_id / trusted_identity_context;
    everything the agent says about itself (claimed ids, reasons, excerpts, tool results) is untrusted."""
    event_id: str
    provider: Provider
    provider_event_type: str = "tool_call"
    interception_mode: Mode = "inline"
    observed_at: datetime = Field(default_factory=utcnow)
    actor_id: str | None = None
    claimed_actor_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    step: int | None = None
    task_summary: str | None = None
    operation: str | None = None
    tool_name: str | None = None
    resource_id: str | None = None
    artifact_id: str | None = None
    data_label: Label = "UNKNOWN"
    destination: str | None = None
    text_excerpt: str | None = None
    stated_reason: str | None = None
    tool_result: dict[str, Any] | None = None
    provenance_ids: list[str] = Field(default_factory=list)
    coverage_notes: list[str] = Field(default_factory=list)
    trusted_identity_context: dict[str, Any] = Field(default_factory=dict)
    t0: dict[str, Any] = Field(default_factory=dict)
    t0_lineage: str | None = None
    deadline_ms: int | None = None
    unavailable_tools: list[str] = Field(default_factory=list)
    native_policy_effect: str | None = None
    retry_of: str | None = None
    calls: list[ToolCall] = Field(default_factory=list)

    @property
    def target_id(self) -> str | None:
        return self.artifact_id or self.resource_id


class EvidenceFact(BaseModel):
    fact_id: str
    name: str
    status: FactStatus
    value: str | None = None
    source_system: str | None = None
    observed_at: datetime | None = None
    age_days: float | None = None
    value_ref: str | None = None
    note: str | None = None


class SecurityState(BaseModel):
    event_id: str
    impact: Literal["low", "moderate", "high", "critical", "unknown"]
    required_fact_names: list[str]
    evidence: list[EvidenceFact]
    semantic_complexity: Literal["simple", "ambiguous", "complex", "unknown"] = "unknown"
    provider_mode: Mode
    applicable_hard_rules: list[str]
    remaining_deadline_ms: int
    evidence_calls_remaining: int
    specialist_calls_remaining: int


class DeciderActionChoice(BaseModel):
    """What the Decider proposed and what the code made of it (never directly executable)."""
    stage: Literal["first_pass", "reroute"]
    proposed: str | None
    effective: str
    confidence: float
    raw_probabilities: dict[str, dict[str, float]]
    masked_probabilities: dict[str, dict[str, float]]
    eligible: dict[str, list[str]]
    plan: list[str]
    low_confidence: bool = False
    veto: str | None = None
    notes: list[str] = Field(default_factory=list)


class SecurityAction(BaseModel):
    action_id: str
    target: str | None = None
    reason: str = ""


class PolicyDecision(BaseModel):
    disposition: Disposition
    rule_id: str | None = None
    reason: str = ""
    advisory: list[str] = Field(default_factory=list)


class AdapterCapabilities(BaseModel):
    integration: str
    label: str
    mode: Mode
    visibility: list[str]
    supported_verdicts: list[str]
    internal_action_mapping: dict[str, str]
    can_pause: bool
    can_redact: bool
    can_prevent: bool
    latency_budget_ms: int | None
    enforcement_evidence: str
    coverage_notes: list[str]


class ApprovalGrant(BaseModel):
    grant_id: str
    kind: Literal["EMPLOYEE_CONFIRMATION", "DATA_OWNER_AUTHORIZATION"]
    approver_id: str
    approver_role: str
    actor_id: str
    operation: str
    target_id: str
    destination: str | None
    policy_version: str
    digest: str
    issued_at: datetime
    expires_at: datetime
    single_use: bool = True
    used: bool = False
    scope_note: str = ""


class AnalyzerSpec(BaseModel):
    analyzer_id: str
    supported_risks: list[str]
    data_classification_clearance: Label
    available: bool = True
    expected_latency_ms: int
    max_input_bytes: int = 8192
    emits: str = "finding-v1"
    finding_codes: list[str]
    description: str


class AnalyzerFinding(BaseModel):
    """Structured output of a downstream analyzer: evidence, never authorization."""
    analyzer_id: str
    finding_code: str
    self_reported_confidence: float = 0.0   # uncalibrated; never a probability of harm
    evidence_refs: list[str] = Field(default_factory=list)
    limitations: str = ""
    untrusted_note: str = ""                # analyzer prose: quoted as untrusted data only
    schema_version: str = "finding-v1"
    backend: str = "fixture"
    model_id: str | None = None
    latency_ms: float = 0.0
    tokens: int = 0
    cached: bool = False
    error: str | None = None


class ResultResolution(BaseModel):
    status: ResolutionStatus
    rule_id: str | None = None
    disposition: Disposition | None = None
    reason: str = ""
    needs: list[str] = Field(default_factory=list)


class RoutingRecord(BaseModel):
    event_id: str
    step_index: int
    eligible_options: list[str]
    decider_selected_option: str | None = None
    decider_option_probabilities: dict[str, float] | None = None
    effective_option: str
    override_rule: str | None = None
    analyzer_or_evidence_tool: str | None = None
    deadline_ms_remaining: int
    result_evidence_ids: list[str] = Field(default_factory=list)
    resolution_status: str | None = None
    resolution_rule_id: str | None = None
    reroute_reason: str | None = None
    decider_reinvoked: bool = False


class EnforcementOutcome(BaseModel):
    integration: str
    internal_action: str
    vendor_verdict: str | None             # "allow" / "deny" for the inline-hook vendor; None for audit-only
    prevented: bool                        # True only for an inline deny before execution
    outcome_type: OutcomeType
    report_class: str                      # blocked_by_verdict | allowed | recorded | alerted | review_case | ...
    remediation: list[str] = Field(default_factory=list)
    native_policy_effect: str | None = None
    note: str = ""


class EventOutcome(BaseModel):
    event_id: str
    mode: Mode
    disposition: Disposition
    rule_id: str | None = None
    reason: str = ""
    tier0: bool = False
    resolution_status: str | None = None
    fallback_reason: str | None = None
    enforcement: EnforcementOutcome | None = None
    approval_request: dict[str, Any] | None = None
    advisory: list[str] = Field(default_factory=list)
    evidence_calls: list[str] = Field(default_factory=list)
    failed_evidence_calls: list[str] = Field(default_factory=list)
    analyzer_calls: list[str] = Field(default_factory=list)
    findings: list[AnalyzerFinding] = Field(default_factory=list)
    decider_calls: int = 0
    decider_questions: int = 0
    routing_model_calls: int = 0
    decider_calls_saved: int = 0
    queued_steps_skipped: list[str] = Field(default_factory=list)
    decider_calls_after_downstream: int = 0
    first_pass_resolved: bool = False
    low_confidence: bool = False
    ineligible_proposals: int = 0
    repeat_suppressed: int = 0
    route_overrides: list[str] = Field(default_factory=list)
    vetoes: list[str] = Field(default_factory=list)
    first_route: str | None = None
    steps: int = 0
    stage_ms: dict[str, float] = Field(default_factory=dict)
    service_ms: float = 0.0
    wall_ms: float = 0.0
    throttle_wait_ms: float = 0.0
    llm_tokens: int = 0
    routing_records: list[RoutingRecord] = Field(default_factory=list)
    decision_records: list[dict[str, Any]] = Field(default_factory=list)
    trace: list[dict[str, Any]] = Field(default_factory=list)
    coverage_notes: list[str] = Field(default_factory=list)
    frame_calls: list[str] = Field(default_factory=list)
