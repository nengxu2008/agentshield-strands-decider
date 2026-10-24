"""Trusted context builder: the facts code can establish before any model runs.

For one event it merges the verified identity, cached IAM / label / directory facts (with source
and age), the session's tracked history (original business task, resources read, artifacts
derived) and provenance-derived labels. Unknown facts stay UNKNOWN; stale facts are marked stale.
The agent's own words (stated reason, excerpts, tool results it read) are kept as untrusted content.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .budget import Budget
from .provenance import Lineage, ProvenanceGraph, replay_session
from .schemas import AnalyzerFinding, ApprovalGrant, EvidenceFact, SecurityEvent


@dataclass
class EventContext:
    event: SecurityEvent
    world: Any
    mode: str                                   # inline | audit_only
    task: str | None
    session_lines: list[str]
    graph: ProvenanceGraph
    facts: dict[str, EvidenceFact]
    lineage: Lineage | None
    dest: dict[str, Any] | None                 # directory row once the destination is verified
    untrusted: list[tuple[str, str]]
    budget: Budget
    now: datetime
    done: list[dict[str, Any]] = field(default_factory=list)
    findings: list[AnalyzerFinding] = field(default_factory=list)
    estimates: list[str] = field(default_factory=list)
    used_tools: list[str] = field(default_factory=list)
    failed_tools: list[str] = field(default_factory=list)
    used_analyzers: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    grant: ApprovalGrant | None = None
    grant_note: str | None = None
    unavailable_tools: list[str] = field(default_factory=list)
    unavailable_analyzers: list[str] = field(default_factory=list)
    tool_cache: dict[str, Any] = field(default_factory=dict)

    # ---- convenience views ----------------------------------------------------------------------

    @property
    def op(self) -> str:
        return self.event.operation or ""

    def is_egress(self) -> bool:
        return self.op in self.world.bundle["egress_operations"]

    @property
    def target(self) -> str | None:
        return self.event.target_id

    @property
    def is_artifact(self) -> bool:
        return bool(self.event.artifact_id)

    def fact(self, name: str) -> EvidenceFact | None:
        return self.facts.get(name)

    def verified(self, name: str) -> bool:
        f = self.facts.get(name)
        return bool(f and f.status == "verified")

    def label(self) -> str:
        """The label policy applies: stored label for resources, provenance-derived label for artifacts."""
        f = self.facts.get("artifact_label" if self.is_artifact else "resource_label")
        return f.value if f and f.status == "verified" and f.value else "UNKNOWN"

    def dest_class(self) -> str | None:
        return self.dest["class"] if self.dest else None

    def source_ids(self) -> list[str]:
        if self.is_artifact:
            return list(self.lineage.known_sources) if self.lineage else []
        return [self.event.resource_id] if self.event.resource_id else []

    def session_read_untrusted(self) -> bool:
        return any(n.get("kind") == "untrusted_source" for n in self.graph.nodes.values()) or bool(self.event.tool_result)


def _fact(name: str, status: str, value: str | None, source: str | None, age: float | None, now: datetime, note: str | None = None) -> EvidenceFact:
    return EvidenceFact(fact_id=f"{name}", name=name, status=status, value=value, source_system=source,  # type: ignore[arg-type]
                        observed_at=now if status == "verified" else None, age_days=age, note=note)


def build_context(world: Any, event: SecurityEvent, now: datetime | None = None, deadline_ms: int | None = None) -> EventContext:
    now = now or datetime.now(timezone.utc)
    t0 = event.t0 or {}
    mode = "audit_only" if event.interception_mode == "audit_only" else "inline"
    graph, lines = replay_session(world, event.session_id, event.step)
    facts: dict[str, EvidenceFact] = {}
    ttl = world.bundle.get("freshness_ttl_days", {})

    # identity: only the vendor-verified id counts; a claimed id is untrusted text
    if event.actor_id and t0.get("identity", "verified") == "verified":
        a = world.actors.get(event.actor_id, {})
        facts["identity"] = _fact("identity", "verified", f"{event.actor_id} ({a.get('title', '?')}, {a.get('kind', '?')})",
                                  "signed hook identity", 0, now)
    else:
        facts["identity"] = _fact("identity", "unknown", None, None, None, now,
                                  note="the hook carried no verified user id" + (f"; it claims {event.claimed_actor_id} (untrusted)" if event.claimed_actor_id else ""))

    # permission for the pending operation
    p = t0.get("permission", "unknown")
    if facts["identity"].status != "verified":
        facts["permission"] = _fact("permission", "unknown", None, None, None, now, note="no verified actor id to check")
    elif isinstance(p, dict) and p.get("status") == "stale":
        facts["permission"] = _fact("permission", "stale", p.get("value"), "iam cache", p.get("age_days"), now,
                                    note=f"cached decision older than the {ttl.get('permission', 30)} d freshness limit")
    elif p == "verified":
        g = world.iam(event.actor_id, event.target_id or "*", event.operation or "")
        facts["permission"] = (_fact("permission", "verified", g["effect"], "iam", 0, now) if g
                               else _fact("permission", "unknown", None, None, None, now, note="no IAM decision cached"))
    else:
        facts["permission"] = _fact("permission", "unknown", None, None, None, now, note="not checked yet")

    # label of the target: stored label (resource) or provenance-derived label (artifact)
    lineage: Lineage | None = None
    if event.artifact_id:
        lineage = graph.lineage(event.artifact_id)
        if lineage is None:
            lineage = Lineage(event.artifact_id, [], ["origin not recorded" if event.t0_lineage == "untracked" else "artifact not seen in this session"],
                              [], False, "UNKNOWN", "UNKNOWN", None)
        facts["lineage"] = _fact("lineage", "verified" if lineage.complete else "unknown", lineage.describe(world), lineage.source, 0, now)
        if lineage.derived_label != "UNKNOWN":
            facts["artifact_label"] = _fact("artifact_label", "verified", lineage.derived_label, "provenance", 0, now,
                                            note=None if lineage.complete else "elevated source label retained despite the gap")
        else:
            facts["artifact_label"] = _fact("artifact_label", "unknown", None, None, None, now,
                                            note="derived artifact, no stored label" + (f"; highest known source {lineage.provisional_label}" if lineage.provisional_label != "UNKNOWN" else ""))
    elif event.resource_id:
        if t0.get("resource_label") == "verified":
            facts["resource_label"] = _fact("resource_label", "verified", world.label_of(event.resource_id), "dlp_labels", 0, now)
        else:
            facts["resource_label"] = _fact("resource_label", "unknown", None, None, None, now, note="label cache miss")

    # destination: company mail and personal webmail are code rules; everything else needs the directory
    dest = None
    if event.destination:
        code = world.code_rule_recipient(event.destination)
        if code:
            dest = code
            facts["recipient"] = _fact("recipient", "verified", f"{code['class']} (allowed up to {code['max_label']})", "policy code rule", 0, now)
        elif t0.get("recipient") == "verified" and world.recipient(event.destination):
            dest = world.recipient(event.destination)
            facts["recipient"] = _fact("recipient", "verified", f"{dest['class']} (allowed up to {dest.get('max_label') or 'nothing'})",
                                       "directory", 2, now)
        else:
            facts["recipient"] = _fact("recipient", "unknown", None, None, None, now, note="not checked yet")

    untrusted: list[tuple[str, str]] = []
    if event.stated_reason:
        untrusted.append(("Agent's stated reason", event.stated_reason))
    if event.tool_result:
        untrusted.append((f"Tool result the agent read ({event.tool_result.get('source', '?')})", event.tool_result.get("text", "")))
    if event.text_excerpt:
        untrusted.append((f"Content of {event.target_id or 'the step'}", event.text_excerpt))
    if event.claimed_actor_id and not event.actor_id:
        untrusted.append(("Claimed actor", event.claimed_actor_id))

    budget = Budget.for_event(world.bundle, mode, deadline_override=deadline_ms or event.deadline_ms)
    return EventContext(event=event, world=world, mode=mode, task=event.task_summary, session_lines=lines, graph=graph,
                        facts=facts, lineage=lineage, dest=dest, untrusted=untrusted, budget=budget, now=now,
                        unavailable_tools=list(event.unavailable_tools))


def call_event(frame: SecurityEvent, call: Any) -> SecurityEvent:
    """One exposed call of a grouped inline frame, as an event of its own (same actor and session)."""
    return frame.model_copy(update={"event_id": call.call_id, "tool_name": call.tool_name, "operation": call.operation,
                                    "resource_id": call.resource_id, "artifact_id": call.artifact_id, "destination": call.destination,
                                    "text_excerpt": call.excerpt, "t0": call.t0, "calls": []})
