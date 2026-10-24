"""Deterministic simulator: a fake agent runtime whose actions run only after an `allow` verdict,
plus a simulated inline vendor with configurable failure behaviour.

- `SimulatorAdapter` executes a fake read/send (appends to `actions`) only after ALLOW, which
  proves BLOCK happens before execution.
- `SimulatedInlineVendor` models the vendor side of an inline hook: if AgentShield fails to
  answer, the VENDOR's configured failure mode decides (fail_open runs the step, fail_closed
  stops it). Reports distinguish blocked_by_verdict, vendor_failed_open and vendor_failed_closed;
  AgentShield never claims to control the vendor's fail-open setting.
"""

from __future__ import annotations

from typing import Any, Callable

from ..schemas import AdapterCapabilities, EnforcementOutcome, PolicyDecision
from .base import outcome_type


class SimulatorAdapter:
    integration = "simulator"

    def __init__(self) -> None:
        self.actions: list[dict[str, Any]] = []

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(integration=self.integration, label="local simulator", mode="inline",
                                   visibility=["every simulated read and send"], supported_verdicts=["allow", "deny"],
                                   internal_action_mapping={"ALLOW": "execute", "BLOCK": "skip"}, can_pause=False, can_redact=False,
                                   can_prevent=True, latency_budget_ms=None, enforcement_evidence="unit tests",
                                   coverage_notes=["synthetic runtime only"])

    def enforce(self, ctx: Any, decision: PolicyDecision) -> EnforcementOutcome:
        if decision.disposition == "ALLOW":
            self.actions.append({"event_id": ctx.event.event_id, "operation": ctx.op, "target": ctx.target,
                                 "destination": ctx.event.destination})
            return EnforcementOutcome(integration=self.integration, internal_action="ALLOW", vendor_verdict="allow", prevented=False,
                                      outcome_type=outcome_type(ctx, True), report_class="allowed")
        return EnforcementOutcome(integration=self.integration, internal_action=decision.disposition, vendor_verdict="deny", prevented=True,
                                  outcome_type=outcome_type(ctx, False), report_class="blocked_by_verdict", note="never executed")


class SimulatedInlineVendor:
    def __init__(self, failure_mode: str = "fail_closed"):
        if failure_mode not in ("fail_open", "fail_closed"):
            raise ValueError("failure_mode is fail_open or fail_closed")
        self.failure_mode = failure_mode
        self.executed: list[str] = []

    def submit(self, step_id: str, service: Callable[[], str]) -> dict[str, Any]:
        """Ask AgentShield for a verdict; on failure the vendor's own setting decides."""
        try:
            verdict = service()
        except Exception as e:  # noqa: BLE001 - the vendor sees a failed hook call
            if self.failure_mode == "fail_open":
                self.executed.append(step_id)
                return {"step": step_id, "report": "vendor_failed_open", "executed": True, "prevented": False, "error": type(e).__name__}
            return {"step": step_id, "report": "vendor_failed_closed", "executed": False, "prevented": False,
                    "note": "stopped by the vendor's own fail-closed setting, not by an AgentShield verdict", "error": type(e).__name__}
        if verdict == "allow":
            self.executed.append(step_id)
            return {"step": step_id, "report": "allowed", "executed": True, "prevented": False}
        return {"step": step_id, "report": "blocked_by_verdict", "executed": False, "prevented": True}
