"""Provenance tracking: resource -> tool_result -> agent_context -> derived_output -> destination.

Labels propagate conservatively (design.md section 3): a derived artifact with complete lineage
gets the highest label of its sources; with a gap (an untracked input) it keeps the label UNKNOWN,
unless a known source is already CONFIDENTIAL or above, which is retained. Web pages and other
untrusted sources are tracked as context (they can carry instructions) but never lower a label.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .schemas import LABEL_RANK, max_label


@dataclass
class Lineage:
    artifact_id: str
    known_sources: list[str]
    untracked: list[str]
    context_sources: list[str]
    complete: bool
    derived_label: str          # the label policy uses ("UNKNOWN" when a gap keeps it open)
    provisional_label: str      # highest known source label (used only through policy rule LG1)
    transformation: str | None = None
    source: str = "session tracking"

    def describe(self, world: Any) -> str:
        srcs = ", ".join(f"{s} ({world.label_of(s) or '?'})" for s in self.known_sources) or "no tracked source"
        gap = f" + {len(self.untracked)} untracked input" + ("s" if len(self.untracked) != 1 else "") if self.untracked else ""
        state = "COMPLETE" if self.complete else "PARTIAL"
        return f"{state} - {srcs}{gap}"


def derive_label(world: Any, known: list[str], untracked: list[str]) -> tuple[str, str]:
    labels = [world.label_of(s) for s in known]
    top = max_label([x for x in labels if x])
    if not untracked:
        return top, top
    if top != "UNKNOWN" and LABEL_RANK[top] >= LABEL_RANK["CONFIDENTIAL"]:
        return top, top   # an elevated label is retained even with a gap
    return "UNKNOWN", top


@dataclass
class ProvenanceGraph:
    """Edges observed by AgentShield in one session (plus what the provenance service records)."""
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[tuple[str, str, str]] = field(default_factory=list)   # (src, dst, relation)
    artifacts: dict[str, Lineage] = field(default_factory=dict)

    def _node(self, kind: str, ident: str, **attrs: Any) -> str:
        key = f"{kind}:{ident}"
        self.nodes.setdefault(key, {"kind": kind, "id": ident, **attrs})
        return key

    def add_read(self, session_id: str, resource_id: str, ref: str, untrusted: bool = False) -> None:
        src = self._node("untrusted_source" if untrusted else "resource", resource_id)
        tr = self._node("tool_result", ref)
        ctx = self._node("agent_context", session_id)
        self.edges += [(src, tr, "read"), (tr, ctx, "loaded")]

    def add_untracked(self, session_id: str, note: str, ref: str) -> None:
        u = self._node("untracked", ref, note=note)
        self.edges.append((u, self._node("agent_context", session_id), "pasted"))

    def context_inputs(self, session_id: str) -> tuple[list[str], list[str], list[str]]:
        ctx = f"agent_context:{session_id}"
        known, untracked, untrusted = [], [], []
        for src, dst, _ in self.edges:
            if dst != ctx:
                continue
            if src.startswith("tool_result:"):
                for s2, d2, _ in self.edges:
                    if d2 == src:
                        n = self.nodes[s2]
                        (untrusted if n["kind"] == "untrusted_source" else known).append(n["id"])
            elif src.startswith("untracked:"):
                untracked.append(self.nodes[src]["note"])
        return sorted(set(known)), untracked, sorted(set(untrusted))

    def derive(self, world: Any, session_id: str, artifact_id: str, transformation: str) -> Lineage:
        known, untracked, untrusted = self.context_inputs(session_id)
        label, provisional = derive_label(world, known, untracked)
        self.edges.append((f"agent_context:{session_id}", self._node("derived_output", artifact_id), transformation))
        lin = Lineage(artifact_id, known, untracked, untrusted, not untracked, label, provisional, transformation)
        self.artifacts[artifact_id] = lin
        return lin

    def add_send(self, artifact_or_resource: str, destination: str) -> None:
        kind = "derived_output" if artifact_or_resource in self.artifacts else "resource"
        self.edges.append((self._node(kind, artifact_or_resource), self._node("destination", destination), "sent"))

    def lineage(self, artifact_id: str) -> Lineage | None:
        return self.artifacts.get(artifact_id)


def replay_session(world: Any, session_id: str | None, before_step: int | None) -> tuple[ProvenanceGraph, list[str]]:
    """Rebuild the session's provenance graph from the steps observed before `before_step`.

    Returns the graph and one human-readable line per step (the "Session so far" context)."""
    g = ProvenanceGraph()
    lines: list[str] = []
    sess = world.sessions.get(session_id or "")
    if not sess:
        return g, lines
    for st in sess["steps"]:
        if before_step is not None and st["step"] >= before_step:
            break
        k, n = st["kind"], st["step"]
        if k == "read":
            g.add_read(session_id, st["resource_id"], f"{session_id}.{n}")
            lines.append(f"step {n}: read {st['resource_id']} ({world.label_of(st['resource_id'])})")
        elif k == "web_read":
            g.add_read(session_id, st["resource_id"], f"{session_id}.{n}", untrusted=True)
            lines.append(f"step {n}: read untrusted {st['resource_id']} ({world.resources[st['resource_id']]['title']})")
        elif k == "untracked_input":
            g.add_untracked(session_id, st.get("note", "untracked input"), f"{session_id}.{n}")
            lines.append(f"step {n}: {st.get('note', 'untracked input')} entered the context (origin not recorded)")
        elif k == "derive":
            lin = g.derive(world, session_id, st["artifact_id"], st.get("transformation", "derived"))
            lines.append(f"step {n}: derived {st['artifact_id']} by {lin.transformation} from {lin.describe(world)}")
        elif k == "event":
            ev = world.events_raw.get(st["event_id"], {})
            if st.get("observed_effect") == "completed" and ev.get("operation") in world.bundle["read_operations"] and ev.get("resource_id"):
                g.add_read(session_id, ev["resource_id"], st["event_id"])
                lines.append(f"step {n}: {st['event_id']} read {ev['resource_id']} ({world.label_of(ev['resource_id'])}), allowed")
            else:
                lines.append(f"step {n}: {st['event_id']} {ev.get('operation', 'event')}")
    return g, lines


def service_lineage(world: Any, artifact_id: str) -> Lineage | None:
    """What the trusted provenance service records for an artifact (GET_PROVENANCE)."""
    rec = world.provenance_record(artifact_id)
    if not rec:
        return None
    known, untracked = list(rec.get("sources", [])), list(rec.get("untracked_inputs", []))
    label, provisional = derive_label(world, known, untracked)
    return Lineage(artifact_id, known, untracked, list(rec.get("context_sources", [])), not untracked, label, provisional,
                   rec.get("transformation"), source="provenance service")
