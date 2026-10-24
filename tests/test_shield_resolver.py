"""The deterministic resolver: every status, and the "When NOT to reinvoke Strands Decider" rules as tests."""

from __future__ import annotations

from shield_support import W, ctx, run_decider

from agent.shield.analyzers import AnalyzerRegistry, FixtureBackend
from agent.shield.evidence import EvidenceService
from agent.shield.policy import DeterministicPolicyEngine
from agent.shield.resolver import resolve
from agent.shield.schemas import AnalyzerFinding

P = DeterministicPolicyEngine(W, AnalyzerRegistry(FixtureBackend(W)))
E = EvidenceService(W)


def after(eid, *tools):
    c = ctx(eid)
    for t in tools:
        E.run(c, t)
    return c


def test_rule1_verified_iam_deny_is_sufficient_deny():
    r = resolve(after("EVT-123", "CHECK_IAM_PERMISSION"), P)
    assert (r.status, r.rule_id, r.disposition) == ("SUFFICIENT_DENY", "H1", "BLOCK")


def test_rule2_recipient_deny_is_sufficient_deny():
    r = resolve(after("EVT-105", "VERIFY_RECIPIENT"), P)
    assert r.status == "SUFFICIENT_DENY" and r.rule_id in ("H3", "H4")


def test_rule3_complete_allow_facts_give_an_allow_candidate():
    for eid, tool in (("EVT-103", "CHECK_IAM_PERMISSION"), ("EVT-106", "VERIFY_RECIPIENT"), ("EVT-124", "GET_RESOURCE_LABEL")):
        r = resolve(after(eid, tool), P)
        assert (r.status, r.disposition) == ("SUFFICIENT_ALLOW_CANDIDATE", "ALLOW"), eid


def test_rule4_mapped_specialist_deny_is_enforced_directly():
    c = ctx("EVT-109")
    c.findings.append(AnalyzerFinding(analyzer_id="SEMANTIC_DLP", finding_code="CONFIDENTIAL_CONTENT_DETECTED"))
    r = resolve(c, P)
    assert r.status == "SUFFICIENT_DENY" and r.rule_id.endswith("CONFIDENTIAL_CONTENT_DETECTED")


def test_rule5_unknown_with_and_without_an_eligible_tool():
    c = ctx("EVT-129")
    E.run(c, "VERIFY_RECIPIENT")
    r = resolve(c, P)
    assert r.status == "NEEDS_MORE_EVIDENCE" and r.needs == ["GET_PROVENANCE"]
    E.run(c, "GET_PROVENANCE")                       # the gap remains: only an analyzer deny (rule LG1) can add evidence
    r = resolve(c, P)
    assert r.status == "NEEDS_OTHER_SPECIALIST" and r.rule_id == "LG1"
    c.budget.analyzers_used = 1                      # ... and with no analyzer budget left: safe fallback
    assert resolve(c, P).status == "UNRESOLVED_BUDGET"


def test_unavailable_tool_leaves_unresolved_budget():
    c = after("EVT-119", "CHECK_IAM_PERMISSION")
    assert c.facts["permission"].status == "unknown" and resolve(c, P).status == "UNRESOLVED_BUDGET"


def test_stale_vs_fresh_latest_signed_authority_wins():
    c = ctx("EVT-117")
    assert c.facts["permission"].status == "stale" and c.facts["permission"].value == "ALLOW"
    E.run(c, "CHECK_IAM_PERMISSION")
    assert c.facts["permission"].value == "DENY" and c.conflicts
    assert resolve(c, P).rule_id == "H1"


def test_conflicted_fact_is_conflicting_never_allow():
    c = ctx("EVT-101")
    c.facts["permission"] = c.facts["permission"].model_copy(update={"status": "conflicted"})
    assert resolve(c, P).status == "CONFLICTING"


def test_planned_analyzer_must_run_before_an_allow():
    c = after("EVT-106", "VERIFY_RECIPIENT")
    r = resolve(c, P, queued=["SEMANTIC_DLP"], planned_analyzers=["SEMANTIC_DLP"])
    assert r.status == "NEEDS_OTHER_SPECIALIST" and r.needs == ["SEMANTIC_DLP"]


def test_inconclusive_finding_is_never_an_allow():
    c = ctx("EVT-128")
    c.used_analyzers.append("SEMANTIC_DLP")
    c.budget.analyzers_used = 1
    c.findings.append(AnalyzerFinding(analyzer_id="SEMANTIC_DLP", finding_code="INCONCLUSIVE"))
    assert resolve(c, P, planned_analyzers=["SEMANTIC_DLP"]).status in ("CONFLICTING", "UNRESOLVED_BUDGET")


def test_negative_findings_never_set_a_permission():
    c = ctx("EVT-130")                                # identity and permission unknown
    f = AnalyzerFinding(analyzer_id="SEMANTIC_DLP", finding_code="NO_SENSITIVE_CONTENT")
    c.findings.append(f)
    assert c.facts["permission"].status == "unknown" and resolve(c, P).status == "UNRESOLVED_BUDGET"


def test_approval_hold_is_deterministic():
    r = resolve(after("EVT-126", "VERIFY_RECIPIENT"), P)
    assert (r.status, r.rule_id, r.disposition) == ("SUFFICIENT_DENY", "H5", "REQUIRE_APPROVAL")


def test_no_post_tool_decider_call_on_conclusive_results():
    for sid in ("EVT-103", "EVT-105", "EVT-109", "EVT-117", "EVT-123", "AUD-201"):
        out, dec = run_decider(sid)
        assert out.decider_calls == 1 and out.decider_calls_after_downstream == 0 and len(dec.states) == 1, sid
        assert out.decider_calls_saved >= 1
