"""Compact outcome briefs for the chat LLM, and a deterministic explanation when no LLM is used.

The brief is the only thing the chat LLM learns about an evaluation: it explains it, it cannot
change it. Wording rules: an audit-only outcome is never "prevented"; a held step is "denied now,
pending a data-owner decision".
"""

from __future__ import annotations

from typing import Any

WORDS = {"ALLOW": "allowed", "BLOCK": "blocked before it ran", "REQUIRE_APPROVAL": "denied now and held for a data-owner decision",
         "RECORD_ONLY": "recorded (already happened; no alert)", "AUDIT_ALERT": "alerted (already happened; nothing could be blocked)",
         "CREATE_REVIEW_CASE": "sent to a review case (already happened; nothing could be blocked)"}


def brief(out: Any) -> dict[str, Any]:
    first = out.decision_records[0] if out.decision_records else None
    path = []
    if out.tier0:
        path.append(f"Tier 0 hard rule {out.rule_id} (no model needed)")
    if first:
        pick = str(first.get("pick") or first.get("proposed") or "?")
        path.append(f"Strands Decider first pass: top eligible pick {pick} with probability {first['confidence']:.2f}"
                    + (f"; probability of high or critical harm {first['high_risk']:.2f}" if "high_risk" in first else "")
                    + f"; AgentShield acted on: {first['verdict']}"
                    + (" (low-confidence rule)" if first.get("low_confidence") else ""))
    for r in out.routing_records:
        if r.analyzer_or_evidence_tool and r.resolution_status:
            path.append(f"{r.analyzer_or_evidence_tool} -> resolver {r.resolution_status}" + (" -> Decider re-route" if r.decider_reinvoked else ""))
    for f in out.findings:
        path.append(f"analyzer {f.analyzer_id}: {f.finding_code} (evidence, not authorization)")
    if out.fallback_reason:
        path.append(f"safe fallback: {out.fallback_reason}")
    return {"event_id": out.event_id, "outcome": out.disposition, "meaning": WORDS.get(out.disposition, out.disposition),
            "rule": out.rule_id, "reason": out.reason, "path": path, "decider_calls": out.decider_calls,
            "lookups": out.evidence_calls, "analyzers": out.analyzer_calls,
            "prevented": bool(out.enforcement and out.enforcement.prevented),
            "approval_request": (out.approval_request or {}).get("request_id"), "advisory": out.advisory}


def plain_text(out: Any) -> str:
    b = brief(out)
    s = f"{b['event_id']}: {b['meaning']}" + (f" (rule {b['rule']})" if b["rule"] else "") + ". " + "; ".join(b["path"])
    if b["approval_request"]:
        s += f". Approval request {b['approval_request']} goes to the data owner; an approved, unchanged retry is re-evaluated."
    if b["advisory"]:
        s += " Advisory: " + " ".join(b["advisory"])
    return s
