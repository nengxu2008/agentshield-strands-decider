"""AgentShield's chat tools: read-only views of the event queue plus one tool that runs the pipeline.

The chat LLM may pick these (they are chat-level tools). None of them lets it choose a security
action: `evaluate_event` runs the AgentShield pipeline, where Strands Decider 2B makes the routing
decisions and the policy engine has the final word; it is idempotent per chat session. Ids are
validated against the synthetic registries; unknown ids are rejected, never guessed.
"""

from __future__ import annotations

from typing import Any

from strands import ToolContext, tool

from .shield.adapters import capability_registry
from .shield.data import world


def _ws(tool_context: ToolContext) -> Any:
    ws = (getattr(tool_context, "invocation_state", None) or {}).get("shield")
    if ws is None:
        raise RuntimeError("no AgentShield workspace in this call")
    return ws


def _summary(event_id: str) -> dict[str, Any]:
    w = world()
    e = w.events_raw[event_id]
    vendor = "audit-only vendor (already happened)" if e.get("provider") == "audit_only_vendor" else "inline-hook vendor (pending)"
    tgt = e.get("artifact_id") or e.get("resource_id") or ("frame of %d calls" % len(e.get("calls", [])))
    return {"event_id": event_id, "vendor": vendor, "actor": e.get("actor_id") or "unverified", "operation": e.get("operation") or "frame",
            "target": tgt, "destination": e.get("destination"), "session": e.get("session_id")}


@tool(context=True)
def list_pending_events(tool_context: ToolContext) -> list[dict[str, Any]]:
    """List the AI-agent events waiting in the demo queue (ids, vendor, actor, operation, target, destination)."""
    return [_summary(i) for i in _ws(tool_context).queue()]


@tool(context=True)
def show_event(event_id: str, tool_context: ToolContext) -> dict[str, Any]:
    """Show one observed event by id (EVT-..., AUD-..., FRM-...); the agent's own words are marked untrusted."""
    eid = event_id.strip().upper()
    w = world()
    if eid not in w.events_raw:
        return {"error": f"unknown event id {event_id!r}"}
    e = w.events_raw[eid]
    sess = w.sessions.get(e.get("session_id") or "", {})
    return {**_summary(eid), "business_task": sess.get("task"), "untrusted_stated_reason": e.get("stated_reason"),
            "untrusted_content": e.get("excerpt"), "untrusted_tool_result": (e.get("tool_result") or {}).get("text")}


@tool(context=True)
def show_capabilities(tool_context: ToolContext) -> dict[str, Any]:
    """What each vendor integration can enforce (inline-hook vendor: allow/deny only; audit-only vendor: never prevents)."""
    caps = capability_registry()
    return {k: {f: v[f] for f in ("label", "mode", "supported_verdicts", "can_pause", "can_redact", "can_prevent", "coverage_notes")}
            for k, v in caps.items() if k != "simulator"}


@tool(context=True)
def evaluate_event(event_id: str, tool_context: ToolContext) -> dict[str, Any]:
    """Run the AgentShield pipeline on one event by id; returns the stored outcome if it was already evaluated in this chat."""
    return _ws(tool_context).evaluate(event_id.strip().upper())


@tool(context=True)
def submit_approval(submission_id: str, tool_context: ToolContext) -> dict[str, Any]:
    """Process one approval submission from the synthetic approvals inbox by id (APR-...)."""
    return _ws(tool_context).submit_approval(submission_id.strip().upper())


TOOLS = [list_pending_events, show_event, show_capabilities, evaluate_event, submit_approval]
