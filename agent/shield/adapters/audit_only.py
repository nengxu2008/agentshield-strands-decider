"""Simulated audit-only vendor adapter (fixture-driven, R3.5, R6a.9).

Models a vendor that exposes audit records AFTER an AI step ran, with no inline control. AgentShield
can record, alert, open a review case or draft an advisory policy recommendation; it can never
block, redact or claim that anything was prevented. Effects of the vendor's own native policies
are reported separately, as the vendor's, never as AgentShield's.
"""

from __future__ import annotations

from typing import Any

from ..schemas import AdapterCapabilities, EnforcementOutcome, PolicyDecision, SecurityEvent
from .base import outcome_type

REPORT = {"RECORD_ONLY": "recorded", "AUDIT_ALERT": "alerted", "CREATE_REVIEW_CASE": "review_case"}


class AuditOnlyAdapter:
    integration = "audit_only_vendor"

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            integration=self.integration, label="audit-only vendor", mode="audit_only",
            visibility=["audit records after the step ran", "sensitivity labels already on files"],
            supported_verdicts=[], internal_action_mapping={"RECORD_ONLY": "record", "AUDIT_ALERT": "alert", "CREATE_REVIEW_CASE": "review case",
                                                            "RECOMMEND_POLICY_CHANGE": "advisory text for administrators"},
            can_pause=False, can_redact=False, can_prevent=False, latency_budget_ms=None,
            enforcement_evidence="none: retrospective only (fixture-driven tests)",
            coverage_notes=["events arrive after the action: nothing can be blocked or called prevented",
                            "the vendor's native policies may act on their own; reported separately"])

    def normalize(self, record: dict[str, Any]) -> SecurityEvent:
        if record.get("provider") not in (None, "audit_only_vendor"):
            raise ValueError("not an audit-only record")
        return SecurityEvent(event_id=record["event_id"], provider="audit_only_vendor", provider_event_type="audit_record",
                             interception_mode="audit_only", actor_id=record.get("actor_id"), session_id=record.get("session_id"),
                             step=record.get("step"), operation=record.get("operation"), tool_name=record.get("tool_name"),
                             resource_id=record.get("resource_id"), artifact_id=record.get("artifact_id"),
                             destination=record.get("destination"), text_excerpt=record.get("excerpt"),
                             stated_reason=record.get("stated_reason"), t0=record.get("t0", {}), t0_lineage=record.get("t0_lineage"),
                             native_policy_effect=record.get("native_policy_effect"))

    def enforce(self, ctx: Any, decision: PolicyDecision) -> EnforcementOutcome:
        d = decision.disposition
        if d not in REPORT:
            raise ValueError(f"the audit-only vendor cannot carry out {d}")
        return EnforcementOutcome(integration=self.integration, internal_action=d, vendor_verdict=None, prevented=False,
                                  outcome_type=outcome_type(ctx, True), report_class=REPORT[d], remediation=list(decision.advisory),
                                  native_policy_effect=ctx.event.native_policy_effect or "none reported",
                                  note="observed after it happened: nothing was blocked or prevented by AgentShield")
