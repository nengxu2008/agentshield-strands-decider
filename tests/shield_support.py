"""Shared helpers for the AgentShield tests (offline only: fakes and fixtures, never live models)."""

from __future__ import annotations

from typing import Any

from agent.shield.analyzers import AnalyzerRegistry, FixtureBackend
from agent.shield.context import build_context
from agent.shield.data import World
from agent.shield.eval_cases import ScriptedDecider
from agent.shield.router import ShieldRouter
from agent.shield.strategies import DeciderStrategy

W = World()


def ctx(event_id: str, **overrides: Any):
    ev = W.event(event_id)
    if overrides:
        ev = ev.model_copy(update=overrides)
    return build_context(W, ev)


def router(**kw: Any) -> ShieldRouter:
    kw.setdefault("registry", AnalyzerRegistry(FixtureBackend(W)))
    return ShieldRouter(W, **kw)


def oracle(sid: str) -> ScriptedDecider:
    """Answers with the annotated ground truth (first pass), then escalation / block on re-routes."""
    sc = W.scenarios[sid]
    route = sc["primary_recommended_route"]
    fp = {"next_step": route, "next_step_audit": route, "risk_severity": sc["risk_severity"],
          "evidence_tool": (sc["minimal_sufficient_evidence_tools"] or ["none"])[0],
          "analyzer": sc["acceptable_analyzers"][0] if sc["specialist_needed"] else "none"}
    re = {"next_step": "ESCALATE_SEMANTIC" if sc["specialist_needed"] else "BLOCK", "next_step_audit": "CREATE_REVIEW_CASE",
          "evidence_tool": "none", "analyzer": sc["acceptable_analyzers"][0] if sc["specialist_needed"] else "none"}
    return ScriptedDecider([fp, re, re, re])


def run_decider(sid: str, decider: Any = None, **kw: Any):
    d = decider or oracle(sid)
    return router(**kw).evaluate(sid, DeciderStrategy(d)), d
