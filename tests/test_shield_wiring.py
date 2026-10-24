"""The reusable decision pattern wired with tests/fakes.py:FakeDecider, and the HackathonAgent.chat contract."""

from __future__ import annotations

import json

from fakes import FakeDecider
from shield_support import W, router, run_decider

import agent.decision as D
from agent.shield.analyzers import FixtureBackend
from agent.shield.strategies import DeciderStrategy


def test_first_pass_asks_four_questions_by_mode_and_reroute_three():
    d = FakeDecider()
    run_decider("EVT-103", d)
    state, qs = d.calls[0]
    assert list(qs) == ["next_step", "risk_severity", "evidence_tool", "analyzer"]
    d = FakeDecider()
    run_decider("AUD-201", d)
    assert list(d.calls[0][1]) == ["next_step_audit", "risk_severity", "evidence_tool", "analyzer"]
    assert all(len(q) <= 4 for _, q in d.calls)
    assert list(D.questions_for("reroute", "inline")) == ["next_step", "evidence_tool", "analyzer"]


def test_masking_renormalises_over_eligible_options():
    m = D.mask({"ALLOW_IF_AUTHORIZED": 0.6, "BLOCK": 0.1, "FETCH_EVIDENCE": 0.3}, ["BLOCK", "FETCH_EVIDENCE"])
    assert abs(m["FETCH_EVIDENCE"] - 0.75) < 1e-9 and abs(sum(m.values()) - 1) < 1e-9
    assert D.mask({}, ["BLOCK", "FETCH_EVIDENCE"]) == {"BLOCK": 0.5, "FETCH_EVIDENCE": 0.5}


def plan(next_p, sev=None, tool=None, an=None, elig=None, mode="inline"):
    e = elig or {"next_steps": ["ALLOW_IF_AUTHORIZED", "BLOCK", "FETCH_EVIDENCE", "ESCALATE_SEMANTIC"], "tools": ["VERIFY_RECIPIENT"],
                 "analyzers": ["SEMANTIC_DLP"]}
    probs = {"next": next_p, "tool": tool or {"none": 1.0}, "analyzer": an or {"none": 1.0}}
    if sev:
        probs["severity"] = sev
    return D.plan_from_answers(probs, e, mode, "first_pass")


def test_plan_rules_use_the_axes_separately():
    low_sev = {"low": 0.9, "moderate": 0.1, "high": 0.0, "critical": 0.0}
    assert plan({"ALLOW_IF_AUTHORIZED": 0.9, "BLOCK": 0.1}, low_sev)["terminal"] == "ALLOW_IF_AUTHORIZED"
    hi = plan({"ALLOW_IF_AUTHORIZED": 0.9, "BLOCK": 0.1}, {"high": 0.7, "low": 0.3})        # severe: no fast allow
    assert hi["terminal"] is None and hi["demoted_allow"] and hi["low_confidence"] and hi["steps"][0] == "VERIFY_RECIPIENT"
    both = plan({"FETCH_EVIDENCE": 0.8, "BLOCK": 0.2}, low_sev, {"VERIFY_RECIPIENT": 0.9, "none": 0.1}, {"SEMANTIC_DLP": 0.7, "none": 0.3})
    assert both["steps"] == ["VERIFY_RECIPIENT", "SEMANTIC_DLP"]                           # evidence AND semantic analysis
    sem = plan({"ESCALATE_SEMANTIC": 0.8, "BLOCK": 0.2}, low_sev, {"VERIFY_RECIPIENT": 0.2, "none": 0.8}, {"SEMANTIC_DLP": 0.9, "none": 0.1})
    assert sem["steps"] == ["SEMANTIC_DLP"]
    blk = plan({"BLOCK": 0.9, "ALLOW_IF_AUTHORIZED": 0.1}, low_sev)
    assert blk["terminal"] == "BLOCK"


def test_low_confidence_prefers_evidence_else_falls_back():
    p = plan({"BLOCK": 0.4, "ALLOW_IF_AUTHORIZED": 0.35, "FETCH_EVIDENCE": 0.25}, {"moderate": 1.0})
    assert p["low_confidence"] and p["steps"] == ["VERIFY_RECIPIENT"]
    e = {"next_steps": ["ALLOW_IF_AUTHORIZED", "BLOCK", "ESCALATE_SEMANTIC"], "tools": [], "analyzers": ["SEMANTIC_DLP"]}
    p = plan({"ALLOW_IF_AUTHORIZED": 0.45, "BLOCK": 0.3, "ESCALATE_SEMANTIC": 0.25}, {"low": 0.7, "moderate": 0.3}, elig=e)
    assert p["demoted_allow"] and p["steps"] == ["SEMANTIC_DLP"] and p["terminal"] is None   # an unsure allow gets checked, not blocked
    assert "not decisive" in D.verdict_text(p) and p["pick"] == "ALLOW_IF_AUTHORIZED"
    e = {"next_steps": ["ALLOW_IF_AUTHORIZED", "BLOCK"], "tools": [], "analyzers": []}
    p = plan({"BLOCK": 0.45, "ALLOW_IF_AUTHORIZED": 0.55}, {"moderate": 1.0}, elig=e)
    assert p["terminal"] == "BLOCK" and p["fallback"]                                       # 0.55 < ALLOW_MIN_CONF
    e = {"next_steps": ["RECORD_ONLY", "AUDIT_ALERT", "CREATE_REVIEW_CASE"], "tools": [], "analyzers": []}
    p = plan({"RECORD_ONLY": 0.4, "AUDIT_ALERT": 0.3, "CREATE_REVIEW_CASE": 0.3}, {"low": 1.0}, elig=e, mode="audit_only")
    assert p["terminal"] == "CREATE_REVIEW_CASE"


def test_ineligible_raw_pick_is_recorded_and_never_executed():
    p = plan({"REQUIRE_APPROVAL": 0.7, "FETCH_EVIDENCE": 0.3}, {"high": 1.0}, {"VERIFY_RECIPIENT": 1.0})
    assert p["ineligible_proposal"] and p["proposed"] == "REQUIRE_APPROVAL" and p["effective"] == "FETCH_EVIDENCE"


def test_records_have_probabilities_verdict_latency_model_and_question_set():
    out, d = run_decider("EVT-105", FakeDecider(lambda s, n, q: "high" if q["type"] == "score" else
                                                {"next_step": "FETCH_EVIDENCE", "evidence_tool": "VERIFY_RECIPIENT"}.get(n, "none")))
    rec = out.decision_records[0]
    floats = [k for k, v in rec.items() if isinstance(v, float)]
    assert floats[:3] == ["confidence", "high_risk", "needs_lookup"] and all(0 <= rec[k] <= 1 for k in floats)
    assert isinstance(rec["decider_ms"], int) and rec["verdict"] == "investigate: verify recipient"
    assert rec["model"] == "fake" and rec["question_set"] == D.QUESTION_SET_VERSION and rec["questions_asked"] == 4
    assert rec["pattern"] == "#tool-selection" and "tool" not in rec and rec["outcome"].startswith("BLOCK")
    assert not any(isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 1 and not k.endswith("_ms") for k, v in rec.items())


def test_state_has_the_three_sections_and_respects_the_caps():
    out, d = run_decider("EVT-127", FakeDecider())
    state = d.calls[0][0]
    a, b, c = (state.index(x) for x in ("== VERIFIED", "== MODEL ESTIMATES", "== UNTRUSTED"))
    assert a < b < c and len(state) <= D.STATE_MAX_CHARS
    assert "key-rotation" in state[c:] and "key-rotation" not in state[a:b]      # tool-result text stays untrusted
    long_view = {"event_id": "X", "vendor_line": "v", "session_line": "s", "step_text": "t", "untrusted": [("x", "y" * 9000)]}
    s = D.render_state(long_view)
    assert len(s) <= D.STATE_MAX_CHARS and "excerpt truncated" in s
    assert len(state) + len(json.dumps(D.questions_for("first_pass", "inline"))) <= D.INPUT_MAX_CHARS


def test_convergence_guard_caps_calls_per_event():
    gk = D.DeciderGatekeeper(FakeDecider(), max_calls=1)
    e = {"next_steps": ["BLOCK", "FETCH_EVIDENCE"], "tools": ["VERIFY_RECIPIENT"], "analyzers": []}
    view = {"event_id": "E", "vendor_line": "v", "session_line": "s", "step_text": "t"}
    gk.first_pass(view, e, "inline", "E")
    p = gk.reroute(view, e, "inline", "E")
    assert p["terminal"] == "BLOCK" and "convergence guard" in p["fallback"] and len(gk.log) == 1


def test_chat_contract_with_fake_decider_and_stub_llm(monkeypatch):
    from agent.agent import NAME, HackathonAgent

    a = HackathonAgent(decider=FakeDecider(lambda s, n, q: "low" if q["type"] == "score" else
                                           {"next_step": "ALLOW_IF_AUTHORIZED"}.get(n, "none")),
                       model_id="stub-model", analyzer_backend=FixtureBackend(W))
    calls = []

    class StubAgent:
        def __call__(self, prompt, invocation_state=None, limits=None):
            assert limits and limits["turns"] <= 4 and limits["total_tokens"] <= 24000   # the chat turn is bounded
            calls.append((prompt, invocation_state))
            return "<think>x</think>EVT-101 was allowed after the gatekeeper's fast path."

    monkeypatch.setattr(a, "_chat_agent", lambda sid: StubAgent())
    out = a.chat("Evaluate EVT-101 and EVT-999 please")
    assert {"reply", "decisions", "model_id", "latency_ms"} <= set(out) and out["agent"] == NAME
    assert out["reply"].startswith("EVT-101 was allowed") and out["model_id"] == "stub-model"
    assert len(out["decisions"]) == 1 and out["decisions"][0]["event_id"] == "EVT-101"
    assert "EVT-999" in calls[0][0] and '"unknown_ids": ["EVT-999"]' in calls[0][0]       # unknown ids are reported, never guessed
    assert calls[0][1]["shield"] is not None and out["outcomes"][0]["outcome"] == "ALLOW"
    again = a.chat("Evaluate EVT-101 again")                                              # idempotent: no new decision
    assert again["decisions"] == [] and "already evaluated" in again["outcomes"][0]["note"]


def test_chat_without_llm_falls_back_to_a_deterministic_explanation():
    from agent.agent import HackathonAgent

    a = HackathonAgent(decider=FakeDecider(), model_id="m", analyzer_backend=FixtureBackend(W), explain_with_llm=False)
    out = a.chat("EVT-102")
    assert out["decisions"] == [] and "blocked" in out["reply"] and "H1" in out["reply"]


def test_tools_reject_unknown_ids_and_are_idempotent():
    from types import SimpleNamespace

    from agent.shield.workspace import ShieldWorkspace
    from agent.tools import evaluate_event, list_pending_events, show_event

    ws = ShieldWorkspace(router(), DeciderStrategy(FakeDecider()))
    tc = SimpleNamespace(invocation_state={"shield": ws})
    assert "error" in evaluate_event._tool_func("EVT-999", tool_context=tc)
    first = evaluate_event._tool_func("EVT-101", tool_context=tc)
    again = evaluate_event._tool_func("EVT-101", tool_context=tc)
    assert first["outcome"] == again["outcome"] and "already evaluated" in again["note"] and len(ws.records) == 1
    ids = [e["event_id"] for e in list_pending_events._tool_func(tool_context=tc)]
    assert ids and all(W.scenarios.get(i, {"split": "tune"})["split"] == "tune" for i in ids)
    assert show_event._tool_func("EVT-111", tool_context=tc)["untrusted_tool_result"].startswith("SYSTEM NOTE")
