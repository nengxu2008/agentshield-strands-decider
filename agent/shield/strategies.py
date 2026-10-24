"""Routing strategies: the ONLY thing that differs between the benchmark arms.

Every arm runs inside the same ShieldRouter: same policy bundle and Tier 0, same eligibility,
evidence tools, analyzers (and memoised findings), budgets, resolver, final validation and
adapters. A strategy only proposes the first plan and, when asked, a re-route.

    rules        A  no routing model, no lookups, no analyzers: the resolver on the facts at t0, else safe fallback
    heuristic    B  fixed lookup order over unresolved facts + keyword / structure rules for one analyzer
    always_deep  C  every unresolved fact looked up and the default analyzer always run, regardless of results
    llm_router   D  the same state, questions, masking and plan rules as E, answered by an LLM (structured output)
    decider      E  Strands Decider first-pass gatekeeper + conditional re-routing (the product)
    ablation     F  E, but the Decider re-assesses after every downstream result (v0.4 behaviour)
"""

from __future__ import annotations

from typing import Any

from decider_kit.llm import options_of

from ..decision import (DeciderGatekeeper, QUESTION_SET_VERSION, mask, plan_from_answers, questions_for, render_state,
                        verdict_text)
from .catalog import DECIDER_TOOLS
from .analyzers import applicable

ORDER = ("CHECK_IAM_PERMISSION", "GET_RESOURCE_LABEL", "VERIFY_RECIPIENT", "GET_PROVENANCE")
# Generic prompt-injection markers (a stock keyword list, not tuned to the scenarios)
INSTRUCTION_PHRASES = ("ignore previous", "ignore all", "system note", "system prompt", "ai assistant", "assistants", "instructions",
                       "you must", "do not tell", "override", "report no_")
STOPWORDS = {"about", "after", "their", "there", "these", "those", "which", "while", "would", "where", "never", "other", "under",
             "within", "without", "planned", "terms", "small", "teams", "field", "internal", "outside", "shared", "customers"}


def protected_keywords(bundle: dict[str, Any]) -> tuple[str, ...]:
    """Keyword DLP: content words of the trusted protected-topic summaries (the same metadata every arm can see)."""
    import re

    words: set[str] = set()
    for t in bundle.get("protected_topics", []):
        for w in re.findall(r"[a-z][a-z-]{4,}", t["summary"].lower()):
            if w not in STOPWORDS:
                words.add(w)
    return tuple(sorted(words))


def _base(**kw: Any) -> dict[str, Any]:
    p = {"terminal": None, "steps": [], "proposed": None, "effective": None, "low_confidence": False, "record": None,
         "routing_ms": 0.0, "throttle_wait_ms": 0.0, "tokens": 0, "fallback": None, "resolve_now": False,
         "ineligible_proposal": False, "repeat_suppressed": [], "cached": False, "questions": []}
    p.update(kw)
    return p


class RulesOnly:
    name, label, routing_model, always_reassess, exhaustive = "rules", "A rules-only", None, False, False

    def first_pass(self, ctx: Any, elig: Any, view: dict[str, Any]) -> dict[str, Any]:
        return _base(resolve_now=True, effective="RESOLVE")

    def reroute(self, ctx: Any, elig: Any, view: dict[str, Any]) -> dict[str, Any] | None:
        return None


class FixedHeuristic:
    name, label, routing_model, always_reassess, exhaustive = "heuristic", "B fixed heuristic", None, False, False

    def __init__(self, registry: Any):
        self.registry = registry

    def analyzer_rule(self, ctx: Any, elig: Any) -> tuple[str | None, bool]:
        """(analyzer, a rule fired) from fixed keyword and structure rules; no language model."""
        if elig.mandatory:
            return elig.mandatory[0], True
        untrusted = " ".join(t for _, t in ctx.untrusted).lower()
        if ctx.session_read_untrusted() and any(p in untrusted for p in INSTRUCTION_PHRASES):
            return "PROMPT_INJECTION_FORENSICS", True
        if ctx.is_artifact and ctx.lineage and not ctx.lineage.complete and ctx.is_egress():
            return "SENSITIVE_DERIVATION_REVIEW", True
        text = (ctx.event.text_excerpt or "").lower()
        if ctx.is_egress() and ctx.label() != "PUBLIC" and any(k in text for k in protected_keywords(ctx.world.bundle)):
            return "SEMANTIC_DLP", True
        return None, False

    def first_pass(self, ctx: Any, elig: Any, view: dict[str, Any]) -> dict[str, Any]:
        tools = [t for t in ORDER if t in elig.tools][: max(0, ctx.budget.evidence_left)]
        an, fired = self.analyzer_rule(ctx, elig)
        if fired and an not in elig.analyzers:
            return _base(terminal="CREATE_REVIEW_CASE" if ctx.mode == "audit_only" else "BLOCK", effective="RULE_FAIL_CLOSED",
                         fallback=f"rule wants {an} but it is not eligible")
        steps = tools + ([an] if an else [])
        if not steps:
            return _base(resolve_now=True, effective="RESOLVE")
        return _base(steps=steps, effective="FETCH_EVIDENCE" if tools else "ESCALATE_SEMANTIC")

    def reroute(self, ctx: Any, elig: Any, view: dict[str, Any]) -> dict[str, Any] | None:
        return None


class AlwaysDeep:
    name, label, routing_model, always_reassess, exhaustive = "always_deep", "C always-deep", None, False, True

    def __init__(self, registry: Any):
        self.registry = registry

    def first_pass(self, ctx: Any, elig: Any, view: dict[str, Any]) -> dict[str, Any]:
        tools = [t for t in ORDER if t in elig.tools][: max(0, ctx.budget.evidence_left)]
        an = self.registry.default_for(ctx, elig.analyzers, elig.mandatory)
        wanted = [s.analyzer_id for s in self.registry.specs() if applicable(ctx, s)]
        if wanted and not an:   # the design always analyzes content; if no analyzer can run in time, fail closed
            return _base(terminal="CREATE_REVIEW_CASE" if ctx.mode == "audit_only" else "BLOCK", effective="DEEP_FAIL_CLOSED",
                         fallback="no analyzer can run within the deadline or budget")
        steps = tools + ([an] if an else [])
        if not steps:
            return _base(resolve_now=True, effective="RESOLVE")
        return _base(steps=steps, effective="FETCH_EVIDENCE" if tools else "ESCALATE_SEMANTIC")

    def reroute(self, ctx: Any, elig: Any, view: dict[str, Any]) -> dict[str, Any] | None:
        return None


def _used(ctx: Any) -> set[str]:
    return set(ctx.used_tools) | set(ctx.failed_tools) | set(ctx.used_analyzers)


class DeciderStrategy:
    """E (and F with always_reassess=True): Strands Decider 2B through the reusable gatekeeper."""

    routing_model, exhaustive = "decider", False

    def __init__(self, decider: Any, always_reassess: bool = False):
        self.decider = decider
        self.gk = DeciderGatekeeper(decider)
        self.always_reassess = always_reassess
        self.name = "ablation" if always_reassess else "decider"
        self.label = "F always-reassess (v0.4)" if always_reassess else "E Strands Decider adaptive"

    def _call(self, stage: str, ctx: Any, elig: Any, view: dict[str, Any]) -> dict[str, Any]:
        fn = self.gk.first_pass if stage == "first_pass" else self.gk.reroute
        plan = _base(**fn(view, elig.as_dict(), ctx.mode, ctx.event.event_id, used=_used(ctx)))
        if plan.get("record") is not None:
            stats = getattr(self.decider, "last_stats", {}) or {}
            plan["routing_ms"] = float(getattr(self.decider, "last_latency_ms", 0) or 0)
            plan["throttle_wait_ms"] = 1000.0 * (stats.get("throttle_wait_s", 0.0) + stats.get("retry_wait_s", 0.0))
            plan["cached"] = bool(getattr(self.decider, "last_cached", False))
        return plan

    def first_pass(self, ctx: Any, elig: Any, view: dict[str, Any]) -> dict[str, Any]:
        return self._call("first_pass", ctx, elig, view)

    def reroute(self, ctx: Any, elig: Any, view: dict[str, Any]) -> dict[str, Any] | None:
        return self._call("reroute", ctx, elig, view)


def distribution(label: Any, confidence: float, options: list[str]) -> dict[str, float]:
    """An LLM label + self-reported confidence as a distribution: confidence on the label, the rest spread evenly."""
    if label not in options:
        return {o: 1.0 / len(options) for o in options}
    c = max(0.0, min(1.0, float(confidence or 0.0)))
    rest = (1.0 - c) / max(1, len(options) - 1)
    return {o: (c if o == label else rest) for o in options}


class LLMRouterStrategy:
    """D: the same typed questions answered by a generative LLM (decider_kit.llm.llm_answer, Strands structured output)."""

    name, label, routing_model, always_reassess, exhaustive = "llm_router", "D LLM router", "llm", False, False

    def __init__(self, model_id: str | None = None, answer_fn: Any = None, cache: Any = None):
        from decider_kit.llm import default_model_id

        self.model_id = model_id or default_model_id()
        self.cache = cache
        if answer_fn is None:
            from .throttle import throttled_llm_answer

            answer_fn = throttled_llm_answer
        self.answer_fn = answer_fn
        self.log: list[dict[str, Any]] = []

    def _call(self, stage: str, ctx: Any, elig: Any, view: dict[str, Any]) -> dict[str, Any]:
        qs = questions_for(stage, ctx.mode)
        state = render_state(view)
        ans, usage = self.answer_fn(state, qs, model_id=self.model_id, cache=self.cache)
        nxt = "next_step_audit" if ctx.mode == "audit_only" else "next_step"
        dist = {n: distribution((ans.get(n) or {}).get("label"), (ans.get(n) or {}).get("confidence", 0.0), options_of(q)) for n, q in qs.items()}
        probs = {"next": dist[nxt], "tool": dist["evidence_tool"], "analyzer": dist["analyzer"]}
        if "risk_severity" in dist:
            probs["severity"] = dist["risk_severity"]
        plan = _base(**plan_from_answers(probs, elig.as_dict(), ctx.mode, stage, _used(ctx)))
        rec = {"router": "llm", "stage": f"{'first pass' if stage == 'first_pass' else 're-route'} · {ctx.event.event_id}",
               "verdict": verdict_text(plan), "confidence": round(plan["confidence"], 3), "llm_ms": int(usage.get("latency_ms", 0) or 0),
               "proposed": plan["proposed"], "effective": plan["effective"], "plan": plan["steps"] or [plan["terminal"]],
               "answers": ans, "low_confidence": plan["low_confidence"], "model": self.model_id, "question_set": QUESTION_SET_VERSION,
               "questions_asked": len(qs), "cached": bool(usage.get("cached")), "tokens": int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))}
        self.log.append(rec)
        plan.update(record=rec, routing_ms=float(usage.get("latency_ms", 0) or 0), tokens=rec["tokens"], cached=rec["cached"],
                    throttle_wait_ms=1000.0 * (usage.get("throttle_wait_s", 0.0) + usage.get("retry_wait_s", 0.0)), state=state, questions=list(qs))
        return plan

    def first_pass(self, ctx: Any, elig: Any, view: dict[str, Any]) -> dict[str, Any]:
        return self._call("first_pass", ctx, elig, view)

    def reroute(self, ctx: Any, elig: Any, view: dict[str, Any]) -> dict[str, Any] | None:
        return self._call("reroute", ctx, elig, view)


__all__ = ["AlwaysDeep", "DeciderStrategy", "FixedHeuristic", "LLMRouterStrategy", "RulesOnly", "distribution", "mask", "DECIDER_TOOLS"]
