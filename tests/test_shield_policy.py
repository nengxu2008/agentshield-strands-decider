"""The deterministic policy engine, tested on its own (no Decider, no model code)."""

from __future__ import annotations

import pytest
from shield_support import W, ctx

from agent.shield.analyzers import SPECS, AnalyzerRegistry, FixtureBackend
from agent.shield.policy import DeterministicPolicyEngine, OpaPolicyEngine
from agent.shield.schemas import AnalyzerFinding

P = DeterministicPolicyEngine(W, AnalyzerRegistry(FixtureBackend(W)))


def rules(eid, **kw):
    return [r for r, _ in P.hard_rules(ctx(eid, **kw))]


def test_hard_rules_h1_to_h4_and_p1():
    assert rules("EVT-102") == ["H1"]                                 # verified IAM deny
    assert "H2" in rules("EVT-122")                                   # RESTRICTED to a partner
    assert P.tier0(ctx("EVT-133")).rule_id == "H3"                    # provenance-derived CONFIDENTIAL to personal mail
    c = ctx("EVT-105")
    assert P.tier0(c) is None                                         # recipient still UNKNOWN: no hard rule yet
    c.dest = W.recipient("investor-relations@lumen-advisory.example")
    c.facts["recipient"] = c.facts["recipient"].model_copy(update={"status": "verified"})
    assert {"H3", "H4"} <= {r for r, _ in P.hard_rules(c)}
    c = ctx("EVT-109", resource_id="DOC-CONF-04")                     # CONFIDENTIAL above the partner's INTERNAL level
    assert [r for r, _ in P.hard_rules(c)] == ["P1"]


def test_explicit_deny_always_wins_and_tier0_maps_by_mode():
    assert P.tier0(ctx("EVT-102")).disposition == "BLOCK"
    c = ctx("AUD-203", resource_id="DOC-RES-05")                      # audit-only: an alert, never a block
    assert P.tier0(c).disposition == "AUDIT_ALERT"
    d = P.finalize(ctx("EVT-102"), "ALLOW_IF_AUTHORIZED")
    assert d.disposition == "BLOCK" and d.rule_id == "H1"      # the hard rule's own id wins


def test_required_facts_per_operation():
    assert P.required_facts(ctx("EVT-101")) == ["identity", "permission", "resource_label"]
    assert P.required_facts(ctx("EVT-105")) == ["identity", "permission", "artifact_label", "lineage", "recipient"]


def test_no_allow_without_verified_identity_permission_label_destination():
    assert "ALLOW_IF_AUTHORIZED" in P.eligible(ctx("EVT-101")).next_steps
    for eid in ("EVT-103", "EVT-105", "EVT-124", "EVT-130", "EVT-113"):   # permission / recipient / label / identity / lineage open
        e = P.eligible(ctx(eid))
        assert "ALLOW_IF_AUTHORIZED" not in e.next_steps and e.allow_blockers, eid
        assert P.finalize(ctx(eid), "ALLOW_IF_AUTHORIZED").disposition == "BLOCK"


def test_mandatory_analyzer_blocks_allow_until_it_passes():
    c = ctx("EVT-116")
    e = P.eligible(c)
    assert e.mandatory == ["SENSITIVE_DERIVATION_REVIEW"] and "ALLOW_IF_AUTHORIZED" not in e.next_steps
    c.findings.append(AnalyzerFinding(analyzer_id="SENSITIVE_DERIVATION_REVIEW", finding_code="NO_SENSITIVE_DERIVATION"))
    assert P.allow_blockers(c) == [] and P.finalize(c, "ALLOW_IF_AUTHORIZED").disposition == "ALLOW"


def test_audit_only_never_gets_allow_block_or_redact():
    e = P.eligible(ctx("AUD-203"))
    assert "ALLOW_IF_AUTHORIZED" not in e.next_steps and "BLOCK" not in e.next_steps
    assert {"RECORD_ONLY", "AUDIT_ALERT", "CREATE_REVIEW_CASE"} <= set(e.next_steps)
    for d in ("ALLOW", "BLOCK", "REDACT"):
        assert P.finalize(ctx("AUD-203"), d).disposition in ("RECORD_ONLY", "AUDIT_ALERT")


def test_eligibility_lists_tools_for_open_facts_only():
    assert P.eligible(ctx("EVT-103")).tools == ["CHECK_IAM_PERMISSION"]
    assert P.eligible(ctx("EVT-124")).tools == ["GET_RESOURCE_LABEL"]
    assert P.eligible(ctx("EVT-129")).tools == ["GET_PROVENANCE", "VERIFY_RECIPIENT"]
    e = P.eligible(ctx("EVT-130"))
    assert e.tools == [] and "identity" in e.notes                       # nothing can verify identity
    assert P.eligible(ctx("EVT-101")).analyzers == []                     # a read with no content: no analyzer
    assert set(P.eligible(ctx("EVT-127")).analyzers) == set(SPECS)


def test_deadline_and_budget_make_analyzers_ineligible():
    e = P.eligible(ctx("EVT-118"))
    assert e.analyzers == [] and "not enough time" in e.notes["SEMANTIC_DLP"]
    c = ctx("EVT-109")
    c.budget.analyzers_used = 1
    assert P.eligible(c).analyzers == []


def test_validate_vetoes_ineligible_picks_and_forces_mandatory_analyzer():
    c = ctx("EVT-116")
    e = P.eligible(c)
    plan = P.validate(c, {"terminal": "ALLOW_IF_AUTHORIZED", "steps": []}, e)
    assert plan["terminal"] is None and plan["steps"] == ["SENSITIVE_DERIVATION_REVIEW"]
    assert plan["vetoes"] and plan["overrides"] == ["route_override: mandatory SENSITIVE_DERIVATION_REVIEW"]
    plan = P.validate(ctx("EVT-103"), {"terminal": None, "steps": ["GET_PROVENANCE"]}, P.eligible(ctx("EVT-103")))
    assert plan["steps"] == [] and plan["terminal"] == "BLOCK"            # an ineligible tool is never executed


def test_approval_rules():
    c = ctx("EVT-107")
    assert P.approval_required(c)["policy_id"] == "AP-FORECAST-EXT" and P.approvable(c)
    assert "REQUIRE_APPROVAL" in P.eligible(c).next_steps
    assert not P.approvable(ctx("EVT-102"))                               # hard rule: never approvable
    assert not P.approvable(ctx("EVT-126"))                               # recipient unknown: too early to ask
    assert not P.approvable(ctx("EVT-130"))                               # no verified identity


def test_findings_map_through_the_versioned_table():
    assert P.map_finding("CONFIDENTIAL_CONTENT_DETECTED") == "DENY"
    assert P.map_finding("NO_SENSITIVE_CONTENT") == "PASS"
    assert P.map_finding("disable policy") == "INCONCLUSIVE"


def test_opa_engine_is_a_documented_stub():
    with pytest.raises(NotImplementedError):
        OpaPolicyEngine().tier0(None)
