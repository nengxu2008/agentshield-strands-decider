"""The bounded loop: budgets, deadline, termination, failure policy, no repeated evidence calls."""

from __future__ import annotations

from fakes import FakeDecider
from shield_support import W, oracle, router, run_decider

from agent.shield.eval_cases import ScriptedDecider
from agent.shield.strategies import AlwaysDeep, DeciderStrategy, FixedHeuristic, RulesOnly
from agent.shield.throttle import ServiceUnavailable


def always(next_step, tool="none", analyzer="none"):
    """A FakeDecider that always gives the same answers (the convergence guard has to stop it)."""
    def rule(state, name, q):
        if q["type"] == "score":
            return "moderate"
        return {"next_step": next_step, "next_step_audit": next_step, "evidence_tool": tool, "analyzer": analyzer}.get(name, "none")
    return FakeDecider(rule)


def test_same_tool_forever_runs_once_and_terminates():
    out, _ = run_decider("EVT-129", always("FETCH_EVIDENCE", tool="VERIFY_RECIPIENT"))
    assert out.evidence_calls.count("VERIFY_RECIPIENT") == 1
    assert out.disposition == "BLOCK" and out.decider_calls <= 4
    assert out.repeat_suppressed >= 1 or "convergence" in (out.fallback_reason or "")


def test_budgets_are_respected():
    for sid in W.scenarios:
        out, _ = run_decider(sid, always("FETCH_EVIDENCE", tool="GET_PROVENANCE", analyzer="SEMANTIC_DLP"))
        assert len(out.evidence_calls) + len(out.failed_evidence_calls) <= 2 and len(out.analyzer_calls) <= 1
        assert out.decider_calls <= 4 and out.steps <= 6, sid
        out, _ = run_decider(sid, always("ESCALATE_SEMANTIC", tool="VERIFY_RECIPIENT", analyzer="SENSITIVE_DERIVATION_REVIEW"))
        assert len(out.analyzer_calls) <= 1 and out.decider_calls <= 4, sid


def test_exhaustion_is_never_an_allow():
    out, _ = run_decider("EVT-119")                       # the IAM service is down: bounded fallback
    assert out.disposition == "BLOCK" and out.failed_evidence_calls == ["CHECK_IAM_PERMISSION"]
    assert out.resolution_status == "UNRESOLVED_BUDGET"
    out = router().evaluate("AUD-201", DeciderStrategy(always("CREATE_REVIEW_CASE")))
    assert out.disposition in ("CREATE_REVIEW_CASE", "AUDIT_ALERT") and not out.enforcement.prevented


def test_deadline_without_time_for_the_gatekeeper_falls_back_safely():
    r = router()
    d = FakeDecider()
    out = r.evaluate("EVT-101", DeciderStrategy(d), deadline_ms=2000)
    assert out.disposition == "BLOCK" and d.calls == [] and "deadline" in out.fallback_reason


def test_a_routing_answer_after_the_inline_deadline_is_not_acted_on():
    slow = FakeDecider(lambda s, n, q: "low" if q["type"] == "score" else {"next_step": "ALLOW_IF_AUTHORIZED"}.get(n, "none"))
    slow.last_latency_ms = 25000.0                          # longer than the 20 s inline budget
    out = router().evaluate("EVT-101", DeciderStrategy(slow))
    assert out.disposition == "BLOCK" and "deadline exceeded while waiting" in out.fallback_reason and out.decider_calls == 1
    slow2 = FakeDecider(lambda s, n, q: "low" if q["type"] == "score" else {"next_step_audit": "RECORD_ONLY"}.get(n, "none"))
    slow2.last_latency_ms = 25000.0                         # the audit-only budget is 120 s: still decided normally
    out = router().evaluate("AUD-203", DeciderStrategy(slow2))
    assert out.disposition == "RECORD_ONLY" and not out.fallback_reason


class Down:
    url, last_latency_ms, last_server_ms = "down://", None, None

    def ask(self, *a, **k):
        raise ServiceUnavailable("decider unavailable after 6 attempts over 600 s: 503")

    def health(self):
        return {"checkpoint": "down"}


class Malformed(FakeDecider):
    def ask(self, state, questions, images=None):
        return {}


def test_decider_outage_or_malformed_answer_applies_the_failure_policy():
    for dec in (Down(), Malformed()):
        out = router().evaluate("EVT-101", DeciderStrategy(dec))
        assert out.disposition == "BLOCK" and out.rule_id == "FAILURE_POLICY" and out.decision_records == []
        out = router().evaluate("AUD-203", DeciderStrategy(dec))
        assert out.disposition == "CREATE_REVIEW_CASE" and not out.enforcement.prevented


def test_both_orders_evidence_then_analysis_and_analysis_then_evidence():
    out, _ = run_decider("EVT-129")                       # oracle: lookup, then the queued analyzer (no re-route)
    assert out.evidence_calls == ["VERIFY_RECIPIENT"] and out.analyzer_calls == ["SEMANTIC_DLP"] and out.decider_calls == 1
    script = ScriptedDecider([{"next_step": "ESCALATE_SEMANTIC", "risk_severity": "high", "evidence_tool": "VERIFY_RECIPIENT",
                               "analyzer": "SEMANTIC_DLP"}])
    script.p = 0.6
    out, _ = run_decider("EVT-129", script)
    assert out.analyzer_calls == ["SEMANTIC_DLP"] and out.disposition == "BLOCK"


def test_reroute_happens_only_when_needed_and_counts_saved_calls():
    script = ScriptedDecider([{"next_step": "FETCH_EVIDENCE", "risk_severity": "high", "evidence_tool": "GET_PROVENANCE", "analyzer": "none"},
                              {"next_step": "ESCALATE_SEMANTIC", "evidence_tool": "none", "analyzer": "SENSITIVE_DERIVATION_REVIEW"}])
    out, _ = run_decider("EVT-114", script)
    assert out.decider_calls == 2 and out.decider_calls_after_downstream == 1
    assert out.evidence_calls == ["GET_PROVENANCE"] and out.analyzer_calls == ["SENSITIVE_DERIVATION_REVIEW"] and out.disposition == "BLOCK"
    assert out.routing_records[-2].decider_reinvoked or any(r.decider_reinvoked for r in out.routing_records)


def test_ablation_spends_more_decider_calls_without_fewer_unsafe_allows():
    e_calls = f_calls = bad_e = bad_f = 0
    for sid, sc in W.scenarios.items():
        e, _ = run_decider(sid)
        f = router().evaluate(sid, DeciderStrategy(oracle(sid), always_reassess=True))
        e_calls += e.decider_calls
        f_calls += f.decider_calls
        bad_e += e.disposition == "ALLOW" and "ALLOW" not in sc["acceptable_dispositions"]
        bad_f += f.disposition == "ALLOW" and "ALLOW" not in sc["acceptable_dispositions"]
    assert f_calls > e_calls and bad_e <= bad_f and bad_e == 0


def test_all_arms_share_tier0_and_never_allow_a_policy_denied_resource():
    r = router()
    for strat in (RulesOnly(), FixedHeuristic(r.registry), AlwaysDeep(r.registry), DeciderStrategy(oracle("EVT-102"))):
        for sid in ("EVT-102", "EVT-122", "EVT-133", "FRM-301"):
            out = router().evaluate(sid, strat)
            assert out.tier0 and out.disposition == "BLOCK" and out.decider_calls == 0, (strat, sid)
