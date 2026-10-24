"""The synthetic enterprise (corp.example): registries the trusted services and the context builder read.

All data is fictional and deterministic (agent/data/*.json, reserved .example domains, no real
people or credentials). The registries play the trusted systems: IAM, the label service, the
recipient directory, the provenance store and the approval-policy store.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from .schemas import SecurityEvent, ToolCall

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
FILES = ("actors", "iam_grants", "resources", "recipients", "provenance", "approval_policies", "policy_bundle",
         "sessions", "events", "scenarios", "specialist_fixtures", "approvals_inbox")


def _read(name: str) -> Any:
    return json.loads((DATA_DIR / f"{name}.json").read_text())


class World:
    """Read-only view of the synthetic registries. Lookups only take normalized ids."""

    def __init__(self, data_dir: Path | None = None):
        d = data_dir or DATA_DIR
        raw = {n: json.loads((d / f"{n}.json").read_text()) for n in FILES}
        self.raw = raw
        self.actors = {a["actor_id"]: a for a in raw["actors"]}
        self.grants = list(raw["iam_grants"])
        self.resources = {r["resource_id"]: r for r in raw["resources"]}
        self.recipients = list(raw["recipients"])
        self.provenance = {p["artifact_id"]: p for p in raw["provenance"]}
        self.approval_policies = list(raw["approval_policies"])
        self.bundle = dict(raw["policy_bundle"])
        self.sessions = {s["session_id"]: s for s in raw["sessions"]}
        self.events_raw = {e["event_id"]: e for e in raw["events"]}
        self.scenarios = {s["scenario_id"]: s for s in raw["scenarios"]}
        self.fixtures = {(f["event_id"], f["analyzer"]): f for f in raw["specialist_fixtures"]}
        self.inbox = {a["submission_id"]: a for a in raw["approvals_inbox"]}

    # ---- trusted registries -------------------------------------------------------------------

    def iam(self, actor_id: str, target_id: str, operation: str) -> dict[str, Any] | None:
        """The current IAM decision: an explicit DENY on the resource wins, then a specific grant, then a wildcard."""
        rows = [g for g in self.grants if g["actor_id"] == actor_id and g["operation"] == operation and g["resource_id"] in (target_id, "*")]
        if not rows:
            return None
        for pick in (lambda g: g["effect"] == "DENY", lambda g: g["resource_id"] == target_id, lambda g: True):
            hit = [g for g in rows if pick(g)]
            if hit:
                return hit[0]
        return None

    def recipient(self, address: str) -> dict[str, Any] | None:
        a = (address or "").strip().lower()
        for r in self.recipients:
            if r["kind"] == "address" and a == r["match"]:
                return r
        for r in self.recipients:
            if r["kind"] == "domain" and a.endswith(r["match"]):
                return r
        return None

    def code_rule_recipient(self, address: str) -> dict[str, Any] | None:
        """Destinations known without a lookup: company mail and personal webmail domains (policy code rules)."""
        r = self.recipient(address)
        return r if r and r.get("code_rule") else None

    def provenance_record(self, artifact_id: str) -> dict[str, Any] | None:
        return self.provenance.get(artifact_id)

    def label_of(self, resource_id: str) -> str | None:
        r = self.resources.get(resource_id)
        return r["label"] if r else None

    def approval_policy(self, source_ids: list[str], operation: str, dest_class: str | None) -> dict[str, Any] | None:
        for p in self.approval_policies:
            if p["resource_id"] in source_ids and operation in p["operations"] and dest_class in p["destination_classes"]:
                return p
        return None

    # ---- events -------------------------------------------------------------------------------

    def event(self, event_id: str) -> SecurityEvent:
        e = dict(self.events_raw[event_id])
        provider = e.get("provider", "inline_hook_vendor")
        mode = "audit_only" if provider == "audit_only_vendor" else "inline"
        sess = self.sessions.get(e.get("session_id") or "", {})
        return SecurityEvent(
            event_id=e["event_id"], provider=provider, provider_event_type=e.get("provider_event_type",
                                                                                  "audit_record" if mode == "audit_only" else "tool_call"),
            interception_mode=mode, actor_id=e.get("actor_id"), claimed_actor_id=e.get("claimed_actor_id"),
            session_id=e.get("session_id"), step=e.get("step"), task_summary=sess.get("task"),
            operation=e.get("operation"), tool_name=e.get("tool_name"), resource_id=e.get("resource_id"),
            artifact_id=e.get("artifact_id"), destination=e.get("destination"), text_excerpt=e.get("excerpt"),
            stated_reason=e.get("stated_reason"), tool_result=e.get("tool_result"), t0=e.get("t0", {}),
            t0_lineage=e.get("t0_lineage"), deadline_ms=e.get("deadline_ms"), unavailable_tools=e.get("unavailable_tools", []),
            native_policy_effect=e.get("native_policy_effect"), retry_of=e.get("retry_of"),
            coverage_notes=e.get("coverage_notes", []),
            trusted_identity_context={"actor_id": e["actor_id"], "source": "vendor-verified identity"} if e.get("actor_id") else {},
            calls=[ToolCall(**c) for c in e.get("calls", [])])

    def event_ids(self) -> list[str]:
        return list(self.events_raw)

    def scenario_ids(self, split: str = "all") -> list[str]:
        return [s for s, v in self.scenarios.items() if split in ("all", "", None) or v["split"] == split]


@lru_cache(maxsize=1)
def world() -> World:
    return World()
