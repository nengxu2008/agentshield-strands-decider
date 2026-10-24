"""Trusted, read-only evidence tools (design.md 2A allowlist): IAM, labels, recipient directory, provenance.

Strands Decider only picks WHICH tool runs. Arguments are built here from normalized ids already
in the trusted context (verified actor id, registered resource/artifact id, the observed
destination address) and validated against the registries; anything else is rejected. Results are
trusted facts with source and time. Each tool runs at most once per event; an unavailable service
leaves the fact UNKNOWN and is not retried within the event.
"""

from __future__ import annotations

import re
import time
from typing import Any

from .catalog import EVIDENCE_TOOLS
from .provenance import service_lineage

ADDRESS = re.compile(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$")


class EvidenceError(ValueError):
    """A tool was asked to run with arguments that are not normalized, registered ids."""


def build_args(ctx: Any, tool_id: str) -> dict[str, str]:
    """Arguments come only from the trusted context: never from model output or agent text."""
    w = ctx.world
    if tool_id not in EVIDENCE_TOOLS:
        raise EvidenceError(f"unknown tool {tool_id!r}")
    if tool_id in ("CHECK_IAM_PERMISSION", "LOOKUP_APPROVAL_POLICY"):
        actor = ctx.event.actor_id
        if not (actor and ctx.verified("identity") and actor in w.actors):
            raise EvidenceError("no verified, registered actor id")
        target = ctx.target
        if not (target and (target in w.resources or target in w.provenance)):
            raise EvidenceError(f"unregistered target {target!r}")
        return {"actor_id": actor, "target_id": target, "operation": ctx.op}
    if tool_id == "GET_RESOURCE_LABEL":
        rid = ctx.event.resource_id
        if not (rid and rid in w.resources):
            raise EvidenceError(f"unregistered resource {rid!r}")
        return {"resource_id": rid}
    if tool_id == "VERIFY_RECIPIENT":
        dest = (ctx.event.destination or "").strip().lower()
        if not ADDRESS.match(dest):
            raise EvidenceError("destination is not a normalized address")
        return {"destination": dest, "label": ctx.label()}
    if tool_id == "GET_PROVENANCE":
        aid = ctx.event.artifact_id
        if not (aid and aid in w.provenance):
            raise EvidenceError(f"unregistered artifact {aid!r}")
        return {"artifact_id": aid}
    raise EvidenceError(f"no argument builder for {tool_id}")


def validate_args(ctx: Any, tool_id: str, args: dict[str, Any]) -> None:
    """Reject anything that is not exactly what the trusted builder produces (no model-made arguments)."""
    if args != build_args(ctx, tool_id):
        raise EvidenceError(f"{tool_id}: arguments must be built from the trusted context")


class EvidenceService:
    """The read-only lookups over the synthetic registries, with a per-event cache."""

    def __init__(self, world: Any):
        self.world = world
        self.calls = 0

    def run(self, ctx: Any, tool_id: str) -> dict[str, Any]:
        cache = ctx.tool_cache
        if tool_id in cache:   # idempotent within one event: never a second lookup
            return {**cache[tool_id], "repeat": True}
        args = build_args(ctx, tool_id)
        t0 = time.perf_counter()
        if tool_id in ctx.unavailable_tools:
            res = {"tool": tool_id, "args": args, "error": "unavailable", "source": EVIDENCE_TOOLS[tool_id].source_system}
        else:
            res = {"tool": tool_id, "args": args, **getattr(self, "_" + tool_id.lower())(ctx, **args)}
        res["ms"] = (time.perf_counter() - t0) * 1000
        self.calls += 1
        cache[tool_id] = res
        apply_result(ctx, tool_id, res)
        return res

    # ---- the tools ----------------------------------------------------------------------------

    def _check_iam_permission(self, ctx: Any, actor_id: str, target_id: str, operation: str) -> dict[str, Any]:
        g = self.world.iam(actor_id, target_id, operation)
        if not g:
            return {"decision": "UNKNOWN", "source": "iam", "detail": "no grant on record"}
        return {"decision": g["effect"], "source": "iam", "age_days": 0, "detail": g.get("note", "")}

    def _get_resource_label(self, ctx: Any, resource_id: str) -> dict[str, Any]:
        return {"label": self.world.label_of(resource_id) or "UNKNOWN", "source": "dlp_labels"}

    def _verify_recipient(self, ctx: Any, destination: str, label: str) -> dict[str, Any]:
        r = self.world.recipient(destination)
        if not r:
            return {"class": "unlisted_external", "max_label": "PUBLIC", "org": "not in the directory", "source": "directory"}
        return {"class": r["class"], "max_label": r.get("max_label"), "org": r.get("org", ""), "source": "directory"}

    def _get_provenance(self, ctx: Any, artifact_id: str) -> dict[str, Any]:
        lin = service_lineage(self.world, artifact_id)
        if lin is None:
            return {"error": "no record", "source": "provenance"}
        return {"known_sources": lin.known_sources, "untracked": lin.untracked, "complete": lin.complete,
                "derived_label": lin.derived_label, "provisional_label": lin.provisional_label, "source": "provenance", "_lineage": lin}


def apply_result(ctx: Any, tool_id: str, res: dict[str, Any]) -> None:
    """Merge a trusted result into the context. The latest signed authority wins over a stale cache."""
    now = ctx.now
    if res.get("error"):
        ctx.failed_tools.append(tool_id)
        return
    ctx.used_tools.append(tool_id)
    if tool_id == "CHECK_IAM_PERMISSION":
        old = ctx.fact("permission")
        new_val = res["decision"]
        if new_val == "UNKNOWN":
            return
        if old and old.status == "stale" and old.value and old.value != new_val:
            ctx.conflicts.append(f"permission: cached {old.value} ({old.age_days:.0f} d, stale) vs fresh {new_val} (iam): latest signed authority wins")
        ctx.facts["permission"] = old.model_copy(update={"status": "verified", "value": new_val, "source_system": "iam (fresh lookup)",
                                                          "observed_at": now, "age_days": 0, "note": res.get("detail") or None})
    elif tool_id == "GET_RESOURCE_LABEL":
        f = ctx.fact("resource_label")
        if res["label"] != "UNKNOWN":
            ctx.facts["resource_label"] = f.model_copy(update={"status": "verified", "value": res["label"], "source_system": "dlp_labels",
                                                                "observed_at": now, "age_days": 0, "note": None})
    elif tool_id == "VERIFY_RECIPIENT":
        ctx.dest = {"class": res["class"], "max_label": res.get("max_label"), "org": res.get("org", "")}
        f = ctx.fact("recipient")
        ctx.facts["recipient"] = f.model_copy(update={"status": "verified", "value": f"{res['class']} (allowed up to {res.get('max_label') or 'nothing'})",
                                                       "source_system": "directory", "observed_at": now, "age_days": 0, "note": res.get("org") or None})
    elif tool_id == "GET_PROVENANCE":
        lin = res.pop("_lineage")
        ctx.lineage = lin
        ctx.facts["lineage"] = ctx.fact("lineage").model_copy(update={"status": "verified" if lin.complete else "unknown",
                                                                        "value": lin.describe(ctx.world), "source_system": "provenance service",
                                                                        "observed_at": now, "age_days": 0})
        f = ctx.fact("artifact_label")
        if lin.derived_label != "UNKNOWN":
            ctx.facts["artifact_label"] = f.model_copy(update={"status": "verified", "value": lin.derived_label, "source_system": "provenance service",
                                                                "observed_at": now, "age_days": 0, "note": None})
        else:
            ctx.facts["artifact_label"] = f.model_copy(update={"note": f"gap remains after the provenance lookup; highest known source {lin.provisional_label}"})
