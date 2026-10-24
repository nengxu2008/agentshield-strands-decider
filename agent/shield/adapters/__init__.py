"""Vendor adapters and the capability registry (R3.6). Neutral names only: the inline-hook vendor
(allow/deny before a step runs) and the audit-only vendor (records after the fact)."""

from __future__ import annotations

from .audit_only import AuditOnlyAdapter
from .inline_hook import InlineHookAdapter
from .simulator import SimulatedInlineVendor, SimulatorAdapter


def default_adapters() -> dict[str, object]:
    return {"inline_hook_vendor": InlineHookAdapter(), "audit_only_vendor": AuditOnlyAdapter(), "simulator": SimulatorAdapter()}


def capability_registry() -> dict[str, dict]:
    return {k: a.capabilities().model_dump() for k, a in default_adapters().items()}  # type: ignore[attr-defined]


__all__ = ["AuditOnlyAdapter", "InlineHookAdapter", "SimulatedInlineVendor", "SimulatorAdapter", "capability_registry", "default_adapters"]
