"""The 5-arm benchmark offline: fixture analyzers, scripted/fake routers, outputs in a temp dir."""

from __future__ import annotations

import json

import pytest
from shield_support import W, oracle

from agent.shield import bench
from agent.shield.analyzers import FixtureBackend
from agent.shield.eval_cases import ScriptedDecider
from agent.shield.metrics import annotate, pct, score_row, summarize
from agent.shield.router import ShieldRouter
from agent.shield.strategies import DeciderStrategy, LLMRouterStrategy

IDS = ["EVT-101", "EVT-102", "EVT-105", "EVT-109", "EVT-114", "AUD-201"]


class OracleByState:
    """Routes each call to the scenario's ground-truth script by reading the event id from the state."""

    def __init__(self):
        self.calls, self.last_latency_ms, self.last_server_ms, self.url = 0, 5.0, 4.0, "oracle://"
        self.scripts: dict[str, ScriptedDecider] = {}
        self.live_decisions = 0

    def health(self):
        return {"checkpoint": "oracle"}

    def ask(self, state, questions, images=None):
        sid = state.split("Event ", 1)[1].split(" ", 1)[0]
        self.calls += 1
        self.live_decisions += len(questions)
        return self.scripts.setdefault(sid, oracle(sid)).ask(state, questions)


def stub_llm_answer(state, qs, model_id=None, cache=None):
    ans = {}
    for n, q in qs.items():
        opts = list(q["criteria"])
        ans[n] = {"label": "BLOCK" if "BLOCK" in opts else ("CREATE_REVIEW_CASE" if "CREATE_REVIEW_CASE" in opts else ("moderate" if n == "risk_severity" else "none")),
                  "confidence": 0.8}
    return ans, {"latency_ms": 7.0, "input_tokens": 100, "output_tokens": 10, "cached": False}


def test_all_arms_share_one_router_and_write_outputs(tmp_path):
    res = bench.run(W, IDS, list(bench.LABELS), "tune", decider=OracleByState(),
                    llm_router=LLMRouterStrategy(model_id="stub", answer_fn=stub_llm_answer), analyzer_backend=FixtureBackend(W),
                    out_dir=tmp_path, components={"decider_model": "oracle", "notes": ["offline test"]}, progress=False)
    bench.write_outputs(res, tmp_path)
    assert set(res["arms"]) == set(bench.LABELS)
    for arm, v in res["arms"].items():
        assert v["summary"]["n"] == len(IDS) and v["summary"]["tier0"] == 1, arm     # same Tier 0 in every arm
    e, c, f = (res["arms"][a]["summary"] for a in ("decider", "always_deep", "ablation"))
    assert e["unsafe_allows"] == 0 and e["disposition_accuracy"] == 1.0 and e["routing_accuracy"] == 1.0
    assert c["specialist_calls"] >= e["specialist_calls"] and f["decider_calls"] > e["decider_calls"]
    assert res["arms"]["llm_router"]["summary"]["routing_model_calls"] >= 5
    assert res["compare"]["decider_calls_saved_vs_ablation"] > 0
    md = (tmp_path / "results.md").read_text()
    assert "E Strands Decider" in md and "AWS User Group Madurai" in md and "first pass alone" in md
    assert (tmp_path / "traces" / "tune" / "decider" / "EVT-105.json").exists()
    assert json.loads((tmp_path / "results.json").read_text())["splits"] == ["tune"]


def test_metrics_on_a_tiny_hand_computed_set():
    r = ShieldRouter(W)
    rows = []
    for sid in ("EVT-101", "EVT-109"):
        out = r.evaluate(sid, DeciderStrategy(ScriptedDecider([{"next_step": "ALLOW_IF_AUTHORIZED", "risk_severity": "low"}])))
        rows.append(score_row(W.scenarios[sid], out, "x"))
    annotate(rows, W.scenarios)
    s = summarize(rows)
    assert s["unsafe_allows"] == 1 and s["unsafe_allow_rate"] == 1.0          # EVT-109 allowed: the semantic leak got through
    assert s["disposition_accuracy"] == 0.5 and s["legit_disruption_rate"] == 0.0 and s["first_pass_resolution_share"] == 1.0
    assert pct([1, 2, 3, 4], 0.5) in (2, 3) and pct([], 0.5) is None


def test_caps_stop_an_arm_cleanly(tmp_path):
    dec = OracleByState()
    res = bench.run(W, IDS, ["decider"], "tune", decider=dec, llm_router=None, analyzer_backend=FixtureBackend(W), out_dir=tmp_path,
                    components={}, max_decisions=8, progress=False)
    assert res["arms"]["decider"]["stopped"].startswith("stopped before") and res["arms"]["decider"]["summary"]["n"] < len(IDS)


def test_a_decider_outage_aborts_instead_of_scoring_fallbacks(tmp_path):
    from agent.shield.throttle import ServiceUnavailable

    class Down(OracleByState):
        def ask(self, state, questions, images=None):
            raise ServiceUnavailable("503 for ten minutes")

    with pytest.raises(bench.Aborted):
        bench.run(W, ["EVT-101"], ["decider"], "tune", decider=Down(), llm_router=None, analyzer_backend=FixtureBackend(W),
                  out_dir=tmp_path, components={}, progress=False)


def test_unusable_llm_router_answers_are_scored_but_code_errors_abort(tmp_path):
    def no_answer(state, qs, model_id=None, cache=None):
        raise ValueError("LLM router returned no structured answer (stop_reason limit_turns)")

    res = bench.run(W, ["EVT-101", "EVT-102"], ["llm_router"], "tune", decider=None, llm_router=LLMRouterStrategy(model_id="stub", answer_fn=no_answer),
                    analyzer_backend=FixtureBackend(W), out_dir=tmp_path, components={}, progress=False)
    s = res["arms"]["llm_router"]["summary"]
    assert s["router_failures"] == 1 and s["legit_disrupted"] == 1           # EVT-101 blocked by the failure policy; EVT-102 is Tier 0

    def bug(state, qs, model_id=None, cache=None):
        raise TypeError("unexpected keyword")

    with pytest.raises(bench.Aborted):
        bench.run(W, ["EVT-101"], ["llm_router"], "tune", decider=None, llm_router=LLMRouterStrategy(model_id="stub", answer_fn=bug),
                  analyzer_backend=FixtureBackend(W), out_dir=tmp_path, components={}, progress=False)


def test_an_analyzer_outage_aborts_instead_of_scoring_inconclusive_findings(tmp_path):
    from agent.shield.analyzers import LLMBackend

    def quota_gone(*a, **k):
        raise RuntimeError("APIStatusError: Error code: 402 - token_quota_exhausted")

    with pytest.raises(bench.Aborted):
        bench.run(W, ["EVT-109"], ["always_deep"], "tune", decider=None, llm_router=None, analyzer_backend=LLMBackend(model_id="m", ask=quota_gone),
                  out_dir=tmp_path, components={}, progress=False)


def test_estimate_is_offline_and_counts_first_passes(tmp_path):
    est = bench.estimate(W, IDS, ["decider", "ablation", "llm_router", "always_deep"], tmp_path)
    assert est["decider_requests"] >= 5 and est["decider_decisions"] >= 20 and est["llm_router_calls"] >= 5
    assert est["decider_requests_cached"] >= 5                                # F reuses E's first passes
    assert est["analyzer_calls_live"] >= 2 and est["llm_tokens"] > 0
