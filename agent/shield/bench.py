"""The AgentShield 5-arm routing benchmark (+ the v0.4 always-reassess ablation).

    python -m agent.shield.bench --estimate --split tune          # projected Decider calls and LLM tokens; calls nothing
    python -m agent.shield.bench --estimate --quota --split test   # ... plus the hosted API's free usage counters
    python -m agent.shield.bench --split tune                      # all arms on the tune split (live)
    python -m agent.shield.bench --split test --update-agent-md    # held-out split; writes the table into agent/AGENT.md
    python -m agent.shield.bench --scenarios EVT-101,EVT-105 --arms decider,llm_router   # a smoke run

All arms share one ShieldRouter design: the same policy bundle, Tier 0, eligibility, evidence
tools, analyzers, budgets, resolver, final validation and adapters. Only the routing strategy
differs (see strategies.py). Outputs go to submission/bench/agentshield/: results-<split>.json/.md,
an index results.json/.md, and traces/<split>/<arm>/<scenario>.json.

Honesty rules built in: no artificial sleeps; measured service time (rate-limit waits excluded and
reported); live vs memoised vs fixture components recorded; caps stop an arm cleanly instead of
overrunning the free quotas; a Decider outage aborts the run instead of scoring failure-policy
outcomes as decisions.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from ..decision import ALLOW_MIN_CONF, LOW_CONF, NEED_P, QUESTION_SET_VERSION, SEVERE_P, questions_for
from .analyzers import SPECS, AnalyzerRegistry, FixtureBackend, LLMBackend, MemoBackend, minimized_payload, payload_hash, render_prompt
from .catalog import CATALOG_VERSION
from .data import World
from .metrics import annotate, compare, score_row, summarize
from .router import INFRASTRUCTURE_MARKERS, MODEL_MISBEHAVIOR, ShieldRouter
from .strategies import AlwaysDeep, DeciderStrategy, FixedHeuristic, LLMRouterStrategy, RulesOnly
from .throttle import LLM_STATS, BenchCache, ThrottledDecider, cache_key, quota

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "submission" / "bench" / "agentshield"
RUN_ORDER = ["rules", "heuristic", "always_deep", "decider", "ablation", "llm_router"]   # E before F: F reuses E's identical calls
SHOW = ["rules", "heuristic", "always_deep", "llm_router", "decider", "ablation"]
LABELS = {"rules": "A rules-only", "heuristic": "B fixed heuristic", "always_deep": "C always-deep", "llm_router": "D LLM router",
          "decider": "E Strands Decider", "ablation": "F always-reassess (v0.4)"}
CREDIT = "Built with the AWS User Group Madurai Strands Decider hackathon kit"


class Aborted(RuntimeError):
    pass


def select(world: World, split: str, scenarios: str | None, limit: int | None) -> list[str]:
    ids = world.scenario_ids(split)
    if scenarios:
        want = [s.strip().upper() for s in scenarios.split(",") if s.strip()]
        bad = [s for s in want if s not in world.scenarios]
        if bad:
            raise SystemExit(f"[bench] unknown scenarios: {bad}")
        held = [s for s in want if world.scenarios[s]["split"] == "test" and split != "test"]
        if held:
            print(f"[bench] note: {held} are held-out test scenarios; use them only for the reported run")
        ids = want
    return ids[:limit] if limit else ids


# ---- estimate (offline) ---------------------------------------------------------------------------

def _oracle_script(sc: dict[str, Any]) -> list[dict[str, str]]:
    fp = {"next_step": sc["primary_recommended_route"] if sc["primary_recommended_route"] != "TIER0" else "BLOCK",
          "next_step_audit": sc["primary_recommended_route"], "risk_severity": sc["risk_severity"],
          "evidence_tool": (sc["minimal_sufficient_evidence_tools"] or ["none"])[0],
          "analyzer": sc["acceptable_analyzers"][0] if sc["specialist_needed"] else "none"}
    re = {"next_step": "ESCALATE_SEMANTIC" if sc["specialist_needed"] else "BLOCK", "next_step_audit": "CREATE_REVIEW_CASE",
          "evidence_tool": "none", "analyzer": sc["acceptable_analyzers"][0] if sc["specialist_needed"] else "none"}
    return [fp, re, re, re]


def estimate(world: World, ids: list[str], arms: list[str], cache_dir: Path) -> dict[str, Any]:
    """Project live calls assuming the routers follow the annotated routes; subtract what the caches already hold."""
    from .eval_cases import ScriptedDecider

    meta = json.loads((cache_dir / "meta.json").read_text()) if (cache_dir / "meta.json").exists() else {}
    dcache = BenchCache(cache_dir / "decider.jsonl")
    lcache = BenchCache(cache_dir / "llm.jsonl")
    scache = BenchCache(cache_dir / "specialist.jsonl")
    model = meta.get("decider_model")
    tok_llm = meta.get("avg_router_tokens") or 2300
    tok_an = meta.get("avg_analyzer_tokens") or 1100
    est = {"scenarios": len(ids), "arms": arms, "decider_requests": 0, "decider_decisions": 0, "decider_requests_cached": 0,
           "llm_router_calls": 0, "llm_router_calls_cached": 0, "analyzer_calls_live": 0, "analyzer_calls_memo": 0,
           "llm_tokens": 0, "worst_case_decider_decisions": 0, "assumptions": []}
    pairs: set[str] = set()
    for arm in arms:
        for sid in ids:
            sc = world.scenarios[sid]
            dec = ScriptedDecider(_oracle_script(sc))
            r = ShieldRouter(world, registry=AnalyzerRegistry(FixtureBackend(world)))
            strat = {"rules": lambda: RulesOnly(), "heuristic": lambda: FixedHeuristic(r.registry), "always_deep": lambda: AlwaysDeep(r.registry),
                     "decider": lambda: DeciderStrategy(dec), "ablation": lambda: DeciderStrategy(dec, always_reassess=True),
                     "llm_router": lambda: DeciderStrategy(dec)}[arm]()
            out = r.evaluate(sid, strat)
            for i, (state, qs) in enumerate(dec.states):
                if arm in ("decider", "ablation"):
                    k = cache_key("decider", model, state, qs) if model else None
                    if (k and dcache.get(k)) or (arm == "ablation" and i == 0 and "decider" in arms):
                        est["decider_requests_cached"] += 1
                    else:
                        est["decider_requests"] += 1
                        est["decider_decisions"] += len(qs)
                elif arm == "llm_router":
                    from decider_kit import llm

                    k = cache_key("llm_answer", meta.get("llm_router_model") or llm.default_model_id(), llm.provider(), state, qs)
                    if lcache.get(k):
                        est["llm_router_calls_cached"] += 1
                    else:
                        est["llm_router_calls"] += 1
                        est["llm_tokens"] += tok_llm
            if arm in ("decider", "ablation") and not out.tier0:
                est["worst_case_decider_decisions"] += 4 + 3 * 3
            if arm in ("heuristic", "always_deep", "decider", "ablation", "llm_router"):
                for f in out.findings:
                    pairs.add(f"{sid}|{f.analyzer_id}")
    from .analyzers import specialist_model_id

    smodel = meta.get("specialist_model") or specialist_model_id()
    for p in sorted(pairs):
        sid, aid = p.split("|")
        from .context import build_context

        ctx = build_context(world, world.event(sid))
        key = f"{sid}|{aid}|{payload_hash(minimized_payload(ctx, aid))}|{smodel}"
        if scache.get(key):
            est["analyzer_calls_memo"] += 1
        else:
            est["analyzer_calls_live"] += 1
            est["llm_tokens"] += tok_an
    est["assumptions"] = [f"routers follow the annotated routes (actual counts vary with the models' choices)",
                          f"~{tok_llm} tokens per LLM-router call and ~{tok_an} per analyzer call ("
                          + ("measured averages from the cache" if meta.get("avg_router_tokens") else "defaults until a live run measures them") + ")",
                          "analyzer findings are memoised per (scenario, analyzer, payload): one live call per pair across all arms",
                          "F reuses E's first-pass answers (identical state and questions)",
                          "the payload of an analyzer can differ after lookups; the estimate uses the first-pass payload"]
    est["minutes_at_rate_limit"] = round(max(est["decider_requests"], est["llm_router_calls"] + est["analyzer_calls_live"]) / 10, 1)
    return est


def print_estimate(est: dict[str, Any], q: dict[str, Any] | None) -> None:
    print(f"[bench] estimate for {est['scenarios']} scenarios, arms {', '.join(est['arms'])}")
    print(f"  Decider: {est['decider_requests']} live requests, {est['decider_decisions']} decisions "
          f"({est['decider_requests_cached']} requests from cache); worst case {est['worst_case_decider_decisions']} decisions")
    print(f"  LLM router: {est['llm_router_calls']} live calls ({est['llm_router_calls_cached']} cached); analyzers: "
          f"{est['analyzer_calls_live']} live calls ({est['analyzer_calls_memo']} memoised)")
    print(f"  LLM tokens: ~{est['llm_tokens']:,}; at least ~{est['minutes_at_rate_limit']} min at 10 requests/min")
    from decider_kit.llm import default_model_id, price, provider

    if q:
        u, lim = q.get("usage", {}), q.get("limits", {})
        left_d = lim.get("monthly_decisions", 0) - u.get("decisions", 0)
        print(f"  Hosted Decider quota left this month: {left_d} decisions; this run would use "
              f"{100 * est['decider_decisions'] / max(1, left_d):.0f}% (worst case {100 * est['worst_case_decider_decisions'] / max(1, left_d):.0f}%)")
        if provider() == "ugmdu":
            left_t = (lim.get("llm_monthly_tokens") or 0) - u.get("llm_input_tokens", 0) - u.get("llm_output_tokens", 0)
            print(f"  User group LLM quota left: {left_t:,} tokens; this run would use {100 * est['llm_tokens'] / max(1, left_t):.0f}%")
    if provider() != "ugmdu":
        pin, pout = price(default_model_id())
        usd = est["llm_tokens"] * 0.9 / 1e6 * pin + est["llm_tokens"] * 0.1 / 1e6 * pout   # ~90 % input tokens (measured mix)
        print(f"  LLM on {provider()} ({default_model_id()}): ~${usd:.2f} for ~{est['llm_tokens']:,} tokens at on-demand prices")
    for a in est["assumptions"]:
        print(f"  - {a}")


# ---- the run ----------------------------------------------------------------------------------------

def make_strategy(arm: str, router: ShieldRouter, decider: Any, llm_router: Any) -> Any:
    return {"rules": lambda: RulesOnly(), "heuristic": lambda: FixedHeuristic(router.registry), "always_deep": lambda: AlwaysDeep(router.registry),
            "decider": lambda: DeciderStrategy(decider), "ablation": lambda: DeciderStrategy(decider, always_reassess=True),
            "llm_router": lambda: llm_router}[arm]()


def run(world: World, ids: list[str], arms: list[str], split: str, *, decider: Any, llm_router: Any, analyzer_backend: Any,
        out_dir: Path, components: dict[str, Any], max_decisions: int | None = None, max_llm_tokens: int | None = None,
        progress: bool = True) -> dict[str, Any]:
    results: dict[str, Any] = {"split": split, "scenarios": ids, "arms": {}, "started_at": time.time()}
    traces = out_dir / "traces" / split
    order = [a for a in RUN_ORDER if a in arms]
    for arm in order:
        rows: list[dict[str, Any]] = []
        stopped = None
        for sid in ids:
            used_d = getattr(decider, "live_decisions", 0)
            used_t = LLM_STATS.get("tokens", 0)   # router (llm_answer) and analyzers (llm.ask) both count here
            if max_decisions is not None and arm in ("decider", "ablation") and used_d >= max_decisions:
                stopped = f"stopped before {sid}: --max-decisions {max_decisions} reached"
                break
            if max_llm_tokens is not None and used_t >= max_llm_tokens:
                stopped = f"stopped before {sid}: --max-llm-tokens {max_llm_tokens} reached"
                break
            router = ShieldRouter(world, registry=AnalyzerRegistry(analyzer_backend))
            strat = make_strategy(arm, router, decider, llm_router)
            out = router.evaluate(sid, strat)
            reason = out.fallback_reason or ""
            if out.rule_id == "FAILURE_POLICY":
                etype = next((t.get("error_type") for t in out.trace if t.get("stage") == "failure_policy"), None)
                infra = any(m in reason for m in INFRASTRUCTURE_MARKERS) or etype not in MODEL_MISBEHAVIOR
                if arm in ("decider", "ablation") or infra:
                    raise Aborted(f"{arm} on {sid}: {reason}. Not scoring an outage or a code error as a routing decision.")
            bad = [f.error for f in out.findings if f.error and f.error.startswith("call failed")]
            if bad:
                raise Aborted(f"{arm} on {sid}: analyzer service failed ({bad[0][:160]}). Not scoring an outage as a finding.")
            row = score_row(world.scenarios[sid], out, arm)
            rows.append(row)
            p = traces / arm / f"{sid}.json"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({"scenario": world.scenarios[sid], "row": row, "outcome": out.model_dump(mode="json")}, indent=1, default=str))
            if progress:
                print(f"[bench] {LABELS[arm]:26} {sid:8} -> {out.disposition:18} {'ok ' if row['acceptable'] else 'MISS'} "
                      f"routing {'ok ' if row['routing_ok'] else 'miss'} lookups={len(row['evidence_calls']) + len(row['failed_evidence_calls'])} "
                      f"analyzers={len(row['analyzer_calls'])} decider={row['decider_calls']} {row['service_ms']:.0f} ms", flush=True)
        annotate(rows, world.scenarios)
        results["arms"][arm] = {"label": LABELS[arm], "summary": summarize(rows), "rows": rows, "stopped": stopped}
    results["compare"] = compare({a: v["summary"] for a, v in results["arms"].items()})
    results["components"] = components
    results["finished_at"] = time.time()
    results["config"] = {"question_set": QUESTION_SET_VERSION, "policy": world.bundle["version"], "catalog": CATALOG_VERSION,
                         "finding_map": world.bundle["finding_map"]["version"], "budgets": world.bundle["budgets"],
                         "thresholds": {"LOW_CONF": LOW_CONF, "ALLOW_MIN_CONF": ALLOW_MIN_CONF, "SEVERE_P": SEVERE_P, "NEED_P": NEED_P}}
    return results


def _fmt(v: Any, kind: str = "") -> str:
    if v is None:
        return "-"
    if kind == "pct":
        return f"{100 * v:.1f}%"
    if kind == "ms":
        return f"{v:,.0f} ms"
    return f"{v:,}" if isinstance(v, int) else str(v)


def markdown(res: dict[str, Any]) -> str:
    arms = [a for a in SHOW if a in res["arms"]]
    S = {a: res["arms"][a]["summary"] for a in arms}
    c = res.get("components", {})
    lines = [f"## AgentShield routing benchmark: {res['split']} split ({len(res['scenarios'])} scenarios)", "",
             f"Strands Decider: `{c.get('decider_model', '?')}` ({c.get('decider_where', '?')}). LLM router: `{c.get('llm_router_model', '-')}` "
             f"({c.get('llm_provider_where', '-')}). Analyzers: {c.get('analyzers', '?')}. Question set `{res['config']['question_set']}`, "
             f"policy `{res['config']['policy']}`.", "",
             "| Metric | " + " | ".join(LABELS[a] for a in arms) + " |", "|---|" + "---|" * len(arms)]
    rows = [("Unsafe-allow rate (inline)", "unsafe_allow_rate", "pct"), ("Severity-weighted unsafe-allow rate", "severity_weighted_unsafe_allow_rate", "pct"),
            ("Missed incidents (audit-only)", "missed_incidents", ""), ("Disposition accuracy", "disposition_accuracy", "pct"),
            ("Routing accuracy (disposition + minimal investigation)", "routing_accuracy", "pct"),
            ("First-route accuracy", "first_route_accuracy", "pct"), ("Legitimate-task disruption", "legit_disruption_rate", "pct"),
            ("Held for approval correctly", "held_correct", ""), ("Specialist (analyzer) calls", "specialist_calls", ""),
            ("Evidence lookups", "evidence_lookups", ""), ("Routing-model calls", "routing_model_calls", ""),
            ("Decider decisions (questions)", "decider_questions", ""),
            ("LLM tokens (router + analyzers; memoised calls charged to every arm that uses them)", "llm_tokens", ""),
            ("Router answers unusable (failure policy applied)", "router_failures", "")]
    for label, k, kind in rows:
        lines.append(f"| {label} | " + " | ".join(_fmt(S[a].get(k), kind) for a in arms) + " |")
    lines.append("| Latency median (measured service time) | " + " | ".join(_fmt(S[a]["latency_ms"]["median"], "ms") for a in arms) + " |")
    lines.append("| Latency p90 | " + " | ".join(_fmt(S[a]["latency_ms"]["p90"], "ms") for a in arms) + " |")
    lines.append("| Rate-limit waits (excluded above) | " + " | ".join(_fmt(S[a]["throttle_wait_ms_total"], "ms") for a in arms) + " |")
    lines.append("")
    if "decider" in S:
        e = S["decider"]
        cmp = res.get("compare", {})
        lines += ["### Strands Decider as the first-pass gatekeeper (arm E)", "",
                  f"- Events that reached the Decider: {e['reached_routing']} of {e['n']} ({e['tier0']} ended at Tier 0 with no model call).",
                  f"- Resolved by the first pass alone (fast allow, fast block, approval hold): {_fmt(e['first_pass_resolution_share'], 'pct')} of the events that reached it.",
                  f"- Low-confidence handling applied: {e['low_confidence_events']} events ({_fmt(e['low_confidence_rate'], 'pct')}).",
                  f"- Ineligible raw proposals vetoed by masking: {e['ineligible_proposals']}; mandatory-analyzer overrides: {e['route_overrides']}; repeat suppressions: {e['repeat_suppressed']}.",
                  f"- Decider calls saved by the deterministic resolver (downstream results not followed by a Decider call): {e['decider_calls_saved_by_resolver']}."]
        if "specialist_calls_avoided_vs_always_deep" in cmp:
            lines.append(f"- Versus always-deep: {cmp['specialist_calls_avoided_vs_always_deep']} specialist calls avoided "
                         f"({_fmt(cmp['specialist_calls_avoided_pct'])}%), {cmp['evidence_lookups_avoided_vs_always_deep']} evidence lookups avoided "
                         f"({_fmt(cmp['evidence_lookups_avoided_pct'])}%).")
        if "decider_calls_saved_vs_ablation" in cmp:
            lines.append(f"- Versus the always-reassess ablation (F): {cmp['decider_calls_E']} vs {cmp['decider_calls_F']} Decider calls "
                         f"({cmp['decider_calls_saved_vs_ablation']} saved); unsafe allows E vs F: {cmp['unsafe_allows_E_vs_F'][0]} vs {cmp['unsafe_allows_E_vs_F'][1]}.")
        lines.append("")
    lines += ["### Per scenario", "", "| Scenario | Family | Truth | " + " | ".join(LABELS[a].split(" ")[0] for a in arms) + " |",
              "|---|---|---|" + "---|" * len(arms)]
    by = {a: {r["scenario_id"]: r for r in res["arms"][a]["rows"]} for a in arms}
    for sid in res["scenarios"]:
        cells = []
        for a in arms:
            r = by[a].get(sid)
            if not r:
                cells.append("-")
                continue
            inv = "+".join([x.replace("CHECK_IAM_PERMISSION", "IAM").replace("GET_RESOURCE_LABEL", "LABEL").replace("VERIFY_RECIPIENT", "RCPT")
                            .replace("GET_PROVENANCE", "PROV") for x in r["evidence_calls"] + r["failed_evidence_calls"]]
                           + [x.replace("SEMANTIC_DLP", "DLP").replace("PROMPT_INJECTION_FORENSICS", "PIF").replace("SENSITIVE_DERIVATION_REVIEW", "SDR")
                              for x in r["analyzer_calls"]])
            cells.append(f"{r['disposition']}{'' if r['acceptable'] else ' ✗'}" + (f" [{inv}]" if inv else ""))
        sc = by[arms[0]][sid] if sid in by[arms[0]] else None
        lines.append(f"| {sid} | {sc['family'] if sc else ''} | {'/'.join(sc['truth']) if sc else ''} | " + " | ".join(cells) + " |")
    stopped = [f"{LABELS[a]}: {res['arms'][a]['stopped']}" for a in arms if res["arms"][a].get("stopped")]
    lines += ["", "### Conditions and caveats", ""]
    lines += [f"- {x}" for x in c.get("notes", [])]
    if stopped:
        lines += [f"- STOPPED EARLY: {x}" for x in stopped]
    lines += ["- Latency is measured service time per event (policy, routing, evidence, analyzer, resolver, enforcement); "
              "free-tier rate-limit waits are excluded and reported in their own row. No artificial delays anywhere.",
              "- Model confidence is not a probability of harm; thresholds were set on the tune split only.",
              "", CREDIT]
    return "\n".join(lines) + "\n"


def write_outputs(res: dict[str, Any], out_dir: Path, smoke: bool = False) -> None:
    """Full runs: results-<split>.* plus the index. Smoke runs (--scenarios/--limit): results-<split>-smoke.*, never the index."""
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"results-{res['split']}" + ("-smoke" if smoke else "")
    (out_dir / f"{name}.json").write_text(json.dumps(res, indent=1, default=str))
    (out_dir / f"{name}.md").write_text(markdown(res))
    if not smoke:
        write_index(out_dir)


def write_index(out_dir: Path) -> None:
    """results.json / results.md: every split run so far, the held-out test split first."""
    runs = {}
    for split in ("test", "tune", "all"):
        p = out_dir / f"results-{split}.json"
        if p.exists():
            runs[split] = json.loads(p.read_text())
    if not runs:
        return
    (out_dir / "results.json").write_text(json.dumps({"splits": list(runs), "runs": runs}, indent=1, default=str))
    md = ["# AgentShield 5-arm routing benchmark", "",
          "Reported numbers are the held-out test split; the tune split was used to set thresholds and wording.", ""]
    for split, r in runs.items():
        md.append((out_dir / f"results-{split}.md").read_text())
    (out_dir / "results.md").write_text("\n".join(md))


def update_agent_md(res: dict[str, Any]) -> None:
    p = ROOT / "agent" / "AGENT.md"
    text = p.read_text()
    a, b = "<!-- agentshield-bench:start -->", "<!-- agentshield-bench:end -->"
    if a not in text or b not in text:
        return
    md = markdown(res)
    table = md.split("### Per scenario")[0].strip()
    head, rest = text.split(a, 1)
    _, tail = rest.split(b, 1)
    p.write_text(head + a + "\n" + table + "\n\nFull per-scenario results: `submission/bench/agentshield/results.md`.\n" + b + tail)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="AgentShield 5-arm routing benchmark")
    ap.add_argument("--split", default="tune", choices=["tune", "test", "all"])
    ap.add_argument("--arms", default=",".join(SHOW))
    ap.add_argument("--scenarios", default=None, help="comma-separated scenario ids (smoke runs)")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--estimate", action="store_true", help="print the projected calls and tokens; call nothing")
    ap.add_argument("--quota", action="store_true", help="also read GET /v1/usage (free, not counted)")
    ap.add_argument("--specialist", default="live", choices=["live", "fixture"])
    ap.add_argument("--max-decisions", type=int, default=int(os.environ.get("SHIELD_MAX_DECISIONS", 300)))
    ap.add_argument("--max-llm-tokens", type=int, default=int(os.environ.get("SHIELD_MAX_LLM_TOKENS", 80000)))
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--update-agent-md", action="store_true")
    a = ap.parse_args(argv)
    world = World()
    ids = select(world, a.split, a.scenarios, a.limit)
    arms = [x.strip() for x in a.arms.split(",") if x.strip()]
    bad = [x for x in arms if x not in LABELS]
    if bad:
        raise SystemExit(f"[bench] unknown arms {bad}; use {list(LABELS)}")
    out_dir = Path(a.out)
    cache_dir = out_dir / "cache"
    if a.estimate:
        print_estimate(estimate(world, ids, arms, cache_dir), quota() if a.quota else None)
        return 0
    from decider_kit import Decider
    from decider_kit.config import settings
    from decider_kit.llm import default_model_id, describe, provider

    use_cache = not a.no_cache
    os.environ.setdefault("SHIELD_LLM_TOKEN_BUDGET", str(a.max_llm_tokens))   # checked before EVERY LLM call, not only between events
    dec = ThrottledDecider(Decider(), cache=BenchCache(cache_dir / "decider.jsonl") if use_cache else None, window_s=600)
    needs_decider = any(x in arms for x in ("decider", "ablation"))
    dmodel = dec.model_id() if needs_decider else None
    if needs_decider and dmodel == "unknown":
        print("[bench] Strands Decider is not answering (GET /v1/models failed). Not running.")
        return 3
    llm_model = os.environ.get("BENCH_LLM_MODEL_ID") or default_model_id()
    router_cache = BenchCache(cache_dir / "llm.jsonl") if use_cache else None
    llm_router = LLMRouterStrategy(model_id=llm_model, cache=router_cache)
    if a.specialist == "fixture":
        backend: Any = FixtureBackend(world)
        an_desc = "deterministic fixtures (MOCKED; not live findings)"
        smodel = None
    else:
        inner = LLMBackend()
        smodel = inner.model_id
        backend = MemoBackend(inner, store=BenchCache(cache_dir / "specialist.jsonl") if use_cache else None)
        an_desc = f"live `{smodel}` on {describe(model_id=smodel)}, memoised per (scenario, analyzer, payload)"
    q_before = quota()
    s = settings()
    components = {"decider_model": dmodel, "decider_where": f"{s.decider_mode} ({s.decider_url.split('//')[-1].split('/')[0]})",
                  "llm_router_model": llm_model, "llm_provider": provider(), "llm_provider_where": describe(model_id=llm_model),
                  "analyzers": an_desc, "specialist_model": smodel, "evidence_tools": "local synthetic trusted services (in-process)",
                  "vendors": "simulated (inline-hook vendor protocol simulator, audit-only fixtures)", "policy_engine": "deterministic Python (OPA deferred)",
                  "notes": ["Every arm uses the same policy bundle, Tier 0, eligibility, evidence tools, analyzers, budgets, resolver and adapters.",
                            "Analyzer findings are memoised per (scenario, analyzer, minimised payload): every arm that asks for the same analysis gets "
                            "the same finding and is charged the latency measured on the live call.",
                            "The ablation (F) reuses the Strands Decider answers of arm E when the state and questions are identical (same call), charged the measured latency.",
                            "The LLM router (D) answers the same typed questions about the same state with the kit's llm_answer prompt and "
                            "schema (Strands structured output, bounded to 2 model turns per call); its label and self-reported confidence "
                            "become a distribution (confidence on the label, the rest spread evenly). An unusable answer gets the same "
                            "failure policy as an unavailable Decider and is counted.",
                            "Cached answers from an earlier run of the same inputs are reused for reruns and marked cached in the traces."]}
    smoke = bool(a.scenarios or a.limit)
    try:
        res = run(world, ids, arms, a.split + ("-smoke" if smoke else ""), decider=dec, llm_router=llm_router, analyzer_backend=backend,
                  out_dir=out_dir, components=components, max_decisions=a.max_decisions, max_llm_tokens=a.max_llm_tokens)
        res["split"] = a.split
    except Aborted as e:
        print(f"[bench] ABORTED: {e}")
        return 3
    res["quota_before"], res["quota_after"] = q_before, quota()
    res["live_calls"] = {"decider_requests": dec.live_requests, "decider_decisions": dec.live_decisions, "decider_cached_requests": dec.cached_requests,
                         "decider_retries": dec.retries, "llm_router_live": LLM_STATS["live_calls"], "llm_cached": LLM_STATS["cached_calls"],
                         "analyzer_live": getattr(backend, "live_calls", 0), "llm_tokens_live": LLM_STATS["tokens"], "llm_retries": LLM_STATS["retries"]}
    meta_p = cache_dir / "meta.json"
    if use_cache:
        cache_dir.mkdir(parents=True, exist_ok=True)
        meta = json.loads(meta_p.read_text()) if meta_p.exists() else {}
        meta.update({"decider_model": dmodel or meta.get("decider_model"), "llm_router_model": llm_model, "specialist_model": smodel})
        rt = [r.get("tokens", 0) for r in llm_router.log if not r.get("cached") and r.get("tokens")]
        if rt:
            meta["avg_router_tokens"] = round(sum(rt) / len(rt))
        if isinstance(backend, MemoBackend):
            toks = [f.tokens for f in backend.memo.values() if f.tokens]
            if toks:
                meta["avg_analyzer_tokens"] = round(sum(toks) / len(toks))
        meta_p.write_text(json.dumps(meta, indent=1))
    write_outputs(res, out_dir, smoke=smoke)
    if a.update_agent_md and a.split == "test" and not smoke:
        update_agent_md(res)
    print(markdown(res))
    print(f"[bench] live: {res['live_calls']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
