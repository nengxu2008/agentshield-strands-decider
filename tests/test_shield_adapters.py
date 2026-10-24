"""Vendor capabilities: the inline-hook vendor gets only allow/deny; the audit-only vendor never 'prevents'."""

from __future__ import annotations

import pytest
from shield_support import ctx, router, run_decider

from agent.shield.adapters import AuditOnlyAdapter, InlineHookAdapter, SimulatedInlineVendor, SimulatorAdapter, capability_registry
from agent.shield.schemas import PolicyDecision


def test_capability_registry_is_honest():
    caps = capability_registry()
    inline, audit = caps["inline_hook_vendor"], caps["audit_only_vendor"]
    assert inline["supported_verdicts"] == ["allow", "deny"] and not inline["can_pause"] and not inline["can_redact"]
    assert audit["supported_verdicts"] == [] and not audit["can_prevent"] and audit["mode"] == "audit_only"


@pytest.mark.parametrize("disp", ["REQUIRE_APPROVAL", "REDACT", "GUIDE", "WARN", "ASK_CLARIFICATION", "BLOCK"])
def test_inline_hook_maps_everything_but_allow_to_deny(disp):
    out = InlineHookAdapter().enforce(ctx("EVT-105"), PolicyDecision.model_construct(disposition=disp, rule_id=None, reason="", advisory=[]))
    assert out.vendor_verdict == "deny" and out.prevented and out.report_class == "blocked_by_verdict"
    if disp != "BLOCK":
        assert out.remediation, disp   # deny now, remediation out of band for a NEW request


def test_inline_hook_allow():
    out = InlineHookAdapter().enforce(ctx("EVT-101"), PolicyDecision(disposition="ALLOW"))
    assert out.vendor_verdict == "allow" and not out.prevented and out.outcome_type == "completed_access"


@pytest.mark.parametrize("disp,report", [("RECORD_ONLY", "recorded"), ("AUDIT_ALERT", "alerted"), ("CREATE_REVIEW_CASE", "review_case")])
def test_audit_only_never_prevented(disp, report):
    c = ctx("AUD-201")
    out = AuditOnlyAdapter().enforce(c, PolicyDecision(disposition=disp))
    assert out.prevented is False and out.vendor_verdict is None and out.report_class == report
    assert out.outcome_type == "confirmed_disclosure" and out.native_policy_effect == "none"


def test_audit_only_refuses_inline_actions():
    with pytest.raises(ValueError):
        AuditOnlyAdapter().enforce(ctx("AUD-201"), PolicyDecision(disposition="BLOCK"))


def test_audit_outcomes_from_the_pipeline_are_never_prevented():
    for sid in ("AUD-201", "AUD-202", "AUD-203"):
        out, _ = run_decider(sid)
        assert out.enforcement.prevented is False and out.disposition in ("RECORD_ONLY", "AUDIT_ALERT", "CREATE_REVIEW_CASE"), sid
    out, _ = run_decider("AUD-202")
    assert out.advisory and out.advisory[0].startswith("RECOMMEND_POLICY_CHANGE")


def test_simulator_blocks_before_execution():
    sim = SimulatorAdapter()
    r = router(adapters={"inline_hook_vendor": sim, "audit_only_vendor": AuditOnlyAdapter(), "simulator": sim})
    from shield_support import oracle

    from agent.shield.strategies import DeciderStrategy

    out = r.evaluate("EVT-102", DeciderStrategy(oracle("EVT-102")))      # unauthorized read
    assert out.disposition == "BLOCK" and sim.actions == []                   # never executed
    out = r.evaluate("EVT-101", DeciderStrategy(oracle("EVT-101")))
    assert out.disposition == "ALLOW" and [a["event_id"] for a in sim.actions] == ["EVT-101"]


def test_vendor_failure_modes_are_reported_as_the_vendors():
    def broken():
        raise TimeoutError("AgentShield did not answer in time")

    assert SimulatedInlineVendor("fail_open").submit("s1", broken) == {"step": "s1", "report": "vendor_failed_open", "executed": True,
                                                                        "prevented": False, "error": "TimeoutError"}
    r = SimulatedInlineVendor("fail_closed").submit("s2", broken)
    assert r["report"] == "vendor_failed_closed" and not r["executed"] and r["prevented"] is False
    assert SimulatedInlineVendor().submit("s3", lambda: "deny")["report"] == "blocked_by_verdict"
