"""What every vendor adapter provides: verify + normalize observations, declare capabilities, enforce
only the actions the vendor really supports (R3.6, R6.2)."""

from __future__ import annotations

from typing import Any, Protocol

from ..schemas import AdapterCapabilities, EnforcementOutcome, PolicyDecision


class Adapter(Protocol):
    integration: str

    def capabilities(self) -> AdapterCapabilities: ...

    def enforce(self, ctx: Any, decision: PolicyDecision) -> EnforcementOutcome: ...


def outcome_type(ctx: Any, executed: bool) -> str:
    egress = ctx.is_egress()
    if executed:
        return "confirmed_disclosure" if egress else "completed_access"
    return "attempted_disclosure" if egress else "attempted_access"
