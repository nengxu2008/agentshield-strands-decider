"""Generate agent/eval_cases.jsonl (the kit benchmark's labelled cases) from the AgentShield scenarios.

    python -m agent.shield.eval_cases --write     # regenerate the file
    python -m agent.shield.eval_cases --check     # exit 1 if the committed file differs

Every state is rendered by the same router and `render_state` the agent uses at run time, so the
kit benchmark measures exactly the states the Decider sees. First-pass states come from every
scenario that reaches the Decider; re-route states are reached by applying the annotated minimal
first step(s) deterministically. Labels come from the scenario ground truth (scenarios.json);
questions without a single defensible answer are left out (`kit_case_omit`), never guessed.

`ScriptedDecider` answers from a fixed script (to reach re-route states). It is a generator and
test helper only; it is never used to route at run time or in either benchmark.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from decider_kit.client import Decision

from .data import World

OUT = Path(__file__).resolve().parent.parent / "eval_cases.jsonl"


class ScriptedDecider:
    """Answers each call from `script` (a list of {question: option}); records every state it was asked about."""

    def __init__(self, script: list[dict[str, str]], p: float = 0.9):
        self.script, self.p = list(script), p
        self.states: list[tuple[str, dict[str, Any]]] = []
        self.last_latency_ms = 0.0
        self.last_server_ms = 0.0
        self.url = "scripted://"

    def health(self) -> dict[str, Any]:
        return {"checkpoint": "scripted"}

    def ask(self, state: Any, questions: dict[str, dict[str, Any]], images: Any = None) -> dict[str, Decision]:
        self.states.append((state, questions))
        want = self.script[min(len(self.states) - 1, len(self.script) - 1)] if self.script else {}
        out = {}
        for name, q in questions.items():
            opts = list(q["criteria"])
            pick = want.get(name, "none" if "none" in opts else opts[0])
            if pick not in opts:
                pick = opts[0]
            if q["type"] == "score":
                i = opts.index(pick)
                probs = {str(k): (self.p if k == i else (1 - self.p) / (len(opts) - 1)) for k in range(len(opts))}
                out[name] = Decision.parse({"type": "score", "score": float(i), "probabilities": probs,
                                            "legend": {str(k): lv for k, lv in enumerate(opts)}})
            else:
                probs = {o: (self.p if o == pick else (1 - self.p) / (len(opts) - 1)) for o in opts}
                out[name] = Decision.parse({"type": "choice", "choice": pick, "probabilities": probs})
        return out


def first_pass_labels(sc: dict[str, Any], audit: bool) -> dict[str, str]:
    route = sc["primary_recommended_route"]
    tools = sc["minimal_sufficient_evidence_tools"]
    lab = {("next_step_audit" if audit else "next_step"): route, "risk_severity": sc["risk_severity"],
           "evidence_tool": tools[0] if route == "FETCH_EVIDENCE" and tools else "none",
           "analyzer": sc["acceptable_analyzers"][0] if sc["specialist_needed"] else "none"}
    return {k: v for k, v in lab.items() if k not in sc.get("kit_case_omit", [])}


def states_for(world: World, sid: str, after: list[str] | None = None) -> list[str]:
    """Run the router with a script that applies `after` as the first lookups; return the states the Decider saw."""
    from .router import ShieldRouter
    from .strategies import DeciderStrategy

    after = after or []
    sc = world.scenarios[sid]
    script = []
    for i, step in enumerate(after):
        nxt = "FETCH_EVIDENCE"
        script.append({"next_step": nxt, "next_step_audit": nxt, "evidence_tool": step, "analyzer": "none",
                       "risk_severity": sc["risk_severity"]})
    script.append({"next_step": "BLOCK", "next_step_audit": "CREATE_REVIEW_CASE"})
    dec = ScriptedDecider(script)
    ShieldRouter(world).evaluate(sid, DeciderStrategy(dec))
    return [s for s, _ in dec.states]


def build_cases(world: World | None = None) -> list[dict[str, Any]]:
    w = world or World()
    cases: list[dict[str, Any]] = []
    for sid, sc in w.scenarios.items():
        if sc.get("tier0"):
            continue
        audit = w.events_raw[sid].get("provider") == "audit_only_vendor"
        st = states_for(w, sid)
        cases.append({"id": sid, "stage": "first_pass", "split": sc["split"], "expected": first_pass_labels(sc, audit), "state": st[0]})
        for rc in sc.get("kit_reroute_cases", []):
            st = states_for(w, sid, rc["after"])
            if len(st) <= len(rc["after"]):
                raise RuntimeError(f"{sid}: no re-route state after {rc['after']}")
            exp = dict(rc["expected"])
            if audit and "next_step" in exp:
                exp["next_step_audit"] = exp.pop("next_step")
            cases.append({"id": f"{sid}~after-{'+'.join(rc['after'])}", "stage": "reroute", "split": sc["split"], "expected": exp,
                          "state": st[len(rc["after"])]})
    return cases


def render(cases: list[dict[str, Any]]) -> str:
    return "".join(json.dumps({"id": c["id"], "stage": c["stage"], "split": c["split"], "expected": c["expected"], "state": c["state"]}) + "\n"
                   for c in cases)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    text = render(build_cases())
    if a.write:
        OUT.write_text(text)
        n = text.count("\n")
        print(f"[eval_cases] wrote {OUT} ({n} cases)")
    if a.check or not a.write:
        same = OUT.exists() and OUT.read_text() == text
        print("[eval_cases] committed file matches the generator" if same else "[eval_cases] committed file differs from the generator")
        sys.exit(0 if same else 1)


if __name__ == "__main__":
    main()
