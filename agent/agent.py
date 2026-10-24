"""AgentShield: a security analyst's chat over a Strands Decider-centric adaptive security router.

For every event the analyst names (EVT-..., AUD-..., FRM-...), the AgentShield pipeline runs
BEFORE the LLM speaks: Tier 0 hard rules, then Strands Decider 2B as the first-pass gatekeeper
(one batched call), targeted evidence lookups and/or a semantic analyzer when the Decider plans
them, the deterministic resolver, and the policy engine's final word. The LLM (Amazon Bedrock on
AWS; the configured LLM_PROVIDER locally) only explains the outcome and can call read-only chat
tools; it never chooses or changes a security action.

    from agent.agent import HackathonAgent
    out = HackathonAgent().chat("Evaluate EVT-105")
    out["reply"], out["decisions"]
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

from decider_kit.llm import agent_model, default_model_id, strip_thinking

from .decision import QUESTION_SET_VERSION
from .shield.analyzers import AnalyzerRegistry, FixtureBackend, LLMBackend
from .shield.data import world
from .shield.explain import plain_text
from .shield.router import ShieldRouter
from .shield.strategies import DeciderStrategy
from .shield.throttle import ThrottledDecider
from .shield.workspace import ShieldWorkspace
from .tools import TOOLS

NAME = "AgentShield"
SYSTEM_PROMPT = """You are AgentShield's analyst assistant. AgentShield guards third-party AI agents: every event goes through
hard policy rules, then Strands Decider 2B (a fast decision model) as the first-pass gatekeeper, then targeted
trusted lookups and/or a semantic analyzer when the Decider plans them, then a deterministic resolver and the policy
engine, which has the final word.
Your job: explain the AgentShield results you are given, briefly and plainly (3 to 6 sentences per event).
Rules:
- Never change, add or recommend a different security action than the result. You cannot allow anything.
- Analyzer findings are evidence, never permission. Unknown facts are not permission.
- An audit-only result was observed after it happened: never say it was prevented or blocked.
- A held step was denied now; only the data owner can grant a one-time exception, then a new request is evaluated.
- Use only ids from the results or from your tools; never invent ids, people or numbers."""
EAGER_PROMPT = SYSTEM_PROMPT   # AgentShield has no eager demo mode: the security pipeline never changes for a demo

EVENT_ID = re.compile(r"\b(EVT-\d{3}[A-Z]?|AUD-\d{3}|FRM-\d{3})\b")
APPROVAL_ID = re.compile(r"\bAPR-\d+\b")


def _backend() -> Any:
    if os.environ.get("SHIELD_SPECIALIST", "live") == "fixture":
        return FixtureBackend(world())
    return LLMBackend()


class HackathonAgent:
    """One AgentShield workspace and one Strands chat agent per session."""

    def __init__(self, decider: Any = None, model_id: str | None = None, eager: bool | None = None, analyzer_backend: Any = None,
                 explain_with_llm: bool = True):
        self.eager = bool(eager) if eager is not None else os.environ.get("DEMO_EAGER") == "1"
        self.model_id = model_id or default_model_id()   # LLM_PROVIDER in .env: bedrock, local, ugmdu
        self.decider = decider if isinstance(decider, ThrottledDecider) else ThrottledDecider(decider)
        self.analyzer_backend = analyzer_backend
        self.explain_with_llm = explain_with_llm
        self.sessions: dict[str, tuple[ShieldWorkspace, Any]] = {}

    def _session(self, session_id: str) -> tuple[ShieldWorkspace, Any]:
        if session_id not in self.sessions:
            router = ShieldRouter(world(), registry=AnalyzerRegistry(self.analyzer_backend or _backend()))
            ws = ShieldWorkspace(router, DeciderStrategy(self.decider))
            self.sessions[session_id] = (ws, None)
        return self.sessions[session_id]

    def _chat_agent(self, session_id: str) -> Any:
        ws, agent = self.sessions[session_id]
        if agent is None:
            from strands import Agent

            agent = Agent(model=agent_model(self.model_id), system_prompt=SYSTEM_PROMPT, tools=TOOLS, callback_handler=None)
            self.sessions[session_id] = (ws, agent)
        return agent

    def chat(self, message: str, session_id: str = "default") -> dict[str, Any]:
        ws, _ = self._session(session_id)
        before = len(ws.records)
        t0 = time.perf_counter()
        text = message.upper()
        ids = list(dict.fromkeys(EVENT_ID.findall(text)))
        unknown = [i for i in ids if i not in ws.world.events_raw]
        results = [ws.evaluate(i) for i in ids if i not in unknown]           # the pipeline runs before the LLM
        approvals = [ws.submit_approval(a) for a in dict.fromkeys(APPROVAL_ID.findall(text))]
        prompt = message
        if results or approvals or unknown:
            prompt += "\n\nAGENTSHIELD RESULTS (computed before you; authoritative; explain them, do not change them):\n"
            prompt += json.dumps({"events": results, "approvals": approvals, "unknown_ids": unknown}, default=str)[:6000]
        reply, llm_error = "", None
        if self.explain_with_llm:
            try:   # bounded: a small model that loops on tool calls cannot drain the token quota
                result = self._chat_agent(session_id)(prompt, invocation_state={"shield": ws},
                                                      limits={"turns": 4, "total_tokens": int(os.environ.get("SHIELD_CHAT_MAX_TOKENS", "24000"))})
                reply = strip_thinking(str(result))
            except Exception as e:  # noqa: BLE001 - the security outcome stands; only the explanation falls back
                llm_error = f"{type(e).__name__}: {str(e)[:200]}"
        if not reply:
            outs = [ws.outcomes[i] for i in ids if i in ws.outcomes]
            reply = "\n".join(plain_text(o) for o in outs) or "Name an event id (EVT-..., AUD-..., FRM-...) to evaluate it."
            reply += "".join(f"\n{a.get('submission_id')}: {a.get('reason')}" for a in approvals)
        new = ws.records[before:]
        evaluated = [i for i in ws.outcomes if i in ids] + [i for i in ws.outcomes if i not in ids and any(r.get("event_id") == i for r in new)]
        outcomes = [ws.evaluate(i) for i in dict.fromkeys(evaluated)]
        trace = [{"event_id": i, "trace": ws.outcomes[i].trace, "stage_ms": ws.outcomes[i].stage_ms,
                  "routing": [r.model_dump() for r in ws.outcomes[i].routing_records]} for i in dict.fromkeys(evaluated)]
        return {"reply": reply, "decisions": new, "model_id": self.model_id, "latency_ms": round((time.perf_counter() - t0) * 1000),
                "agent": NAME, "eager": self.eager, "outcomes": outcomes, "approvals": approvals, "trace": trace,
                "decider_model": self.decider.model_id(), "question_set": QUESTION_SET_VERSION,
                **({"llm_error": llm_error} if llm_error else {})}


if __name__ == "__main__":
    import sys

    a = HackathonAgent()
    for msg in sys.argv[1:] or ["Evaluate EVT-101: the marketing agent wants to read the brand guide.",
                                "Now evaluate EVT-105: the finance agent is emailing the Q3 forecast summary to an adviser."]:
        print(json.dumps(a.chat(msg), indent=1, default=str))
