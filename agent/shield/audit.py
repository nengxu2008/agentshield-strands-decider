"""Minimised audit trail (R6a.8, R8.3): ids, labels, decisions, hashes and lengths of content, never raw text.

Each record keeps the proposed Decider action, its distribution and confidence, the effective
action, vetoes / fallbacks / overrides, the tools and analyzers run with their result codes, the
resolver statuses and the loop count. A retention limit caps memory; an optional JSONL file
(SHIELD_AUDIT_PATH) receives the same minimised records.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import deque
from pathlib import Path
from typing import Any


def _h(text: str | None) -> dict[str, Any] | None:
    if not text:
        return None
    return {"sha256": hashlib.sha256(text.encode()).hexdigest()[:16], "chars": len(text)}


class AuditLog:
    def __init__(self, max_records: int = 1000, path: str | None = None):
        self.records: deque[dict[str, Any]] = deque(maxlen=max_records)
        self.path = Path(path or os.environ["SHIELD_AUDIT_PATH"]) if (path or os.environ.get("SHIELD_AUDIT_PATH")) else None

    def append(self, out: Any, event: Any = None) -> dict[str, Any]:
        rec = {"event_id": out.event_id, "mode": out.mode, "disposition": out.disposition, "rule_id": out.rule_id,
               "tier0": out.tier0, "resolution_status": out.resolution_status, "fallback_reason": out.fallback_reason,
               "prevented": bool(out.enforcement and out.enforcement.prevented),
               "vendor_verdict": out.enforcement.vendor_verdict if out.enforcement else None,
               "evidence_calls": out.evidence_calls, "failed_evidence_calls": out.failed_evidence_calls,
               "analyzer_calls": out.analyzer_calls, "findings": [f.finding_code for f in out.findings],
               "decider_calls": out.decider_calls, "loop_steps": out.steps, "route_overrides": out.route_overrides, "vetoes": out.vetoes,
               "decisions": [{k: r.get(k) for k in ("stage", "proposed", "effective", "confidence", "plan", "low_confidence", "model",
                                                    "question_set", "decider_ms")} for r in out.decision_records],
               "routing": [r.model_dump(include={"step_index", "effective_option", "analyzer_or_evidence_tool", "resolution_status",
                                                 "resolution_rule_id", "decider_reinvoked", "override_rule"}) for r in out.routing_records]}
        if event is not None:
            rec["content"] = {"excerpt": _h(event.text_excerpt), "stated_reason": _h(event.stated_reason),
                              "tool_result": _h((event.tool_result or {}).get("text"))}
        self.records.append(rec)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as f:
                f.write(json.dumps(rec, default=str) + "\n")
        return rec
