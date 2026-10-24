"""One chat session's AgentShield state: the router, the Decider strategy, stored outcomes and approvals."""

from __future__ import annotations

from typing import Any

from .explain import brief
from .schemas import EventOutcome


class ShieldWorkspace:
    def __init__(self, router: Any, strategy: Any):
        self.router, self.strategy = router, strategy
        self.world = router.world
        self.outcomes: dict[str, EventOutcome] = {}
        self.approval_results: list[dict[str, Any]] = []

    @property
    def records(self) -> list[dict[str, Any]]:
        return self.strategy.gk.log

    def queue(self) -> list[str]:
        """The demo queue: tune-split events and their follow-ups (held-out test events stay out of chat during development)."""
        tune = [s for s, v in self.world.scenarios.items() if v["split"] == "tune"]
        follow = [e for e, v in self.world.events_raw.items() if v.get("retry_of") in tune]
        return tune + follow

    def evaluate(self, event_id: str) -> dict[str, Any]:
        if event_id not in self.world.events_raw:
            return {"error": f"unknown event id {event_id!r}: ids come from the event queue, never guessed"}
        if event_id in self.outcomes:
            return {**brief(self.outcomes[event_id]), "note": "already evaluated in this chat; stored outcome (no new decision)"}
        out = self.router.evaluate(event_id, self.strategy)
        self.outcomes[event_id] = out
        return brief(out)

    def submit_approval(self, submission_id: str) -> dict[str, Any]:
        sub = self.world.inbox.get(submission_id)
        if not sub:
            return {"error": f"unknown approval submission {submission_id!r}"}
        if sub["for_event"] not in self.outcomes:
            return {"submission_id": submission_id, "accepted": False,
                    "reason": f"evaluate {sub['for_event']} first: there is no pending approval request yet"}
        r = self.router.approvals.submit(sub)
        self.approval_results.append(r)
        return r
