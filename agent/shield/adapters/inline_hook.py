"""Simulated inline-hook vendor adapter (synthetic protocol `inline-hook-sim/v1`, R3.1-R3.4).

Models a vendor whose hook calls AgentShield before a prompt or a frame of tool calls runs and
accepts exactly one verdict per request: `allow` or `deny`. It cannot redact, pause or resume.

Request verification (raw bytes, before any parsing):
- body at most 64 KB (413);
- `X-Hook-Signature: v1=<hex>` = HMAC-SHA256(secret, timestamp + "." + request_id + "." + raw_body),
  compared in constant time (401): the request id is authenticated, so a replay cannot pass with a
  fresh `X-Hook-Request-Id`;
- `X-Hook-Timestamp` within +-300 s (401);
- replay: the authenticated request id and the signature digest are each accepted once while the
  timestamp is inside the window (401); entries expire with their window (an expired entry could only
  come back as a stale timestamp), and a full cache refuses new requests (503) instead of forgetting a
  live entry;
- then strict JSON and schema checks (400); the body's `request_id` must equal the authenticated
  header id (401). Unknown metadata is ignored and never trusted.
Every valid signed request gets HTTP 200 with a verdict; an intentional deny is a 200, not an error.
Internal outcomes the vendor cannot express (REQUIRE_APPROVAL, REDACT, GUIDE, WARN, ASK_CLARIFICATION)
become `deny` plus out-of-band remediation for a NEW request. The vendor's own failure behaviour
(fail-open / fail-closed when AgentShield does not answer) is the vendor's setting, reported as
such (see simulator.SimulatedInlineVendor).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections import OrderedDict
from typing import Any, Callable

from ..schemas import AdapterCapabilities, EnforcementOutcome, PolicyDecision, SecurityEvent, ToolCall
from .base import outcome_type

PROTOCOL = "inline-hook-sim/v1"
MAX_BODY = 64 * 1024
WINDOW_S = 300
SYNTHETIC_SECRET = b"agentshield-synthetic-hook-secret-for-tests-only"
DENY_WITH_REMEDIATION = {"REQUIRE_APPROVAL": "an approval request goes to the data owner; retry the same step after a grant",
                         "REDACT": "remove the sensitive part and send a new request",
                         "GUIDE": "a safer alternative is suggested out of band", "WARN": "a warning is sent out of band",
                         "ASK_CLARIFICATION": "the requester is asked for task details out of band"}


def sign_request(raw: bytes, timestamp: int | str, request_id: str, secret: bytes = SYNTHETIC_SECRET) -> str:
    """The synthetic vendor's signature: it covers the timestamp, the request id and the exact raw body bytes."""
    msg = str(timestamp).encode() + b"." + str(request_id).encode() + b"." + raw
    return "v1=" + hmac.new(secret, msg, hashlib.sha256).hexdigest()


class InlineHookAdapter:
    integration = "inline_hook_vendor"

    def __init__(self, secret: bytes = SYNTHETIC_SECRET, clock: Callable[[], float] = time.time, replay_capacity: int = 10000):
        self.secret, self.clock = secret, clock
        # replay cache: authenticated request id / signature digest -> the time its window closes (signed timestamp + WINDOW_S)
        self.seen: OrderedDict[str, float] = OrderedDict()
        self.replay_capacity = replay_capacity

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            integration=self.integration, label="inline-hook vendor", mode="inline",
            visibility=["prompt frames", "tool-call frames (the calls the vendor exposes)", "verified user id"],
            supported_verdicts=["allow", "deny"],
            internal_action_mapping={"ALLOW": "allow", "BLOCK": "deny", **{k: "deny + out-of-band remediation" for k in DENY_WITH_REMEDIATION}},
            can_pause=False, can_redact=False, can_prevent=True, latency_budget_ms=20000,
            enforcement_evidence="synthetic contract tests (signed requests, tamper, replay, grouped frames); no live tenant",
            coverage_notes=["one verdict per frame, never per call", "calls the vendor does not expose are not covered",
                            "the 20 s hook deadline is an assumption of the simulator, not a vendor fact"])

    # ---- request verification -------------------------------------------------------------------

    def verify(self, headers: dict[str, str], raw: bytes) -> tuple[int, str]:
        """(200, the authenticated request id) or (error status, reason). Runs on the raw bytes, before any parsing."""
        h = {k.lower(): v for k, v in headers.items()}
        if len(raw) > MAX_BODY:
            return 413, "request body too large"
        ts, sig, rid = h.get("x-hook-timestamp"), h.get("x-hook-signature"), h.get("x-hook-request-id")
        if not (ts and sig and rid):
            return 401, "missing signature headers"
        if not hmac.compare_digest(sig, sign_request(raw, ts, rid, self.secret)):
            return 401, "bad signature"
        try:
            signed_at = int(ts)
        except ValueError:
            return 401, "bad timestamp"
        now = self.clock()
        if abs(now - signed_at) > WINDOW_S:
            return 401, "stale timestamp"
        self._expire(now)
        keys = (f"id:{rid}", "sig:" + hashlib.sha256(sig.encode()).hexdigest())
        if any(k in self.seen for k in keys):
            return 401, "replayed request"
        if len(self.seen) + len(keys) > self.replay_capacity:
            return 503, "replay cache full; retry later"   # fail closed: never forget a live entry to make room
        for k in keys:
            self.seen[k] = signed_at + WINDOW_S
        return 200, rid

    def _expire(self, now: float) -> None:
        """Drop entries whose window has closed: a replay of those can only arrive with a stale timestamp."""
        for k in [k for k, until in self.seen.items() if until < now]:
            del self.seen[k]

    def normalize(self, payload: dict[str, Any]) -> SecurityEvent:
        """Strict schema; unknown keys are ignored (recorded as a coverage note), never trusted."""
        if payload.get("protocol") != PROTOCOL:
            raise ValueError("unsupported protocol")
        kind = payload.get("type")
        if kind not in ("prompt", "tool_call"):
            raise ValueError("type must be prompt or tool_call")
        ident = payload.get("identity") or {}
        actor = ident.get("user_id") if ident.get("verified") is True else None
        known = {"protocol", "request_id", "type", "event_id", "session", "identity", "calls", "prompt", "agent", "metadata"}
        notes = [f"ignored unknown field {k!r}" for k in payload if k not in known]
        if payload.get("metadata"):
            notes.append("vendor metadata ignored (untrusted)")
        sess = payload.get("session") or {}
        base = dict(event_id=str(payload.get("event_id") or payload.get("request_id")), provider="inline_hook_vendor",
                    provider_event_type=kind, interception_mode="inline", actor_id=actor,
                    claimed_actor_id=None if actor else ident.get("user_id"), session_id=sess.get("id"), step=sess.get("step"),
                    stated_reason=(payload.get("agent") or {}).get("stated_reason"), coverage_notes=notes)
        if kind == "prompt":
            if not isinstance(payload.get("prompt"), str):
                raise ValueError("prompt frames need a prompt string")
            return SecurityEvent(**base, operation="submit_prompt", tool_name="prompt", text_excerpt=payload["prompt"][:2000])
        calls = payload.get("calls")
        if not isinstance(calls, list) or not calls or not all(isinstance(c, dict) and c.get("tool") for c in calls):
            raise ValueError("tool_call frames need a non-empty list of calls with a tool name")
        tcs = [ToolCall(call_id=str(c.get("call_id") or f"{base['event_id']}.{i + 1}"), tool_name=c["tool"], operation=c.get("operation") or c["tool"],
                        resource_id=c.get("resource_id"), artifact_id=c.get("artifact_id"), destination=c.get("destination"),
                        excerpt=(c.get("content") or None), t0=dict(c.get("t0") or {})) for i, c in enumerate(calls)]
        if len(tcs) == 1:
            c = tcs[0]
            return SecurityEvent(**base, operation=c.operation, tool_name=c.tool_name, resource_id=c.resource_id, artifact_id=c.artifact_id,
                                 destination=c.destination, text_excerpt=c.excerpt, t0=c.t0)
        return SecurityEvent(**{**base, "provider_event_type": "tool_call_frame"}, calls=tcs)

    def handle(self, raw: bytes, headers: dict[str, str], evaluate: Callable[[SecurityEvent], Any]) -> tuple[int, dict[str, Any]]:
        status, detail = self.verify(headers, raw)
        if status != 200:
            return status, {"error": detail}
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError("body must be a JSON object")
        except (ValueError, UnicodeDecodeError):
            return 400, {"error": "malformed JSON"}
        if payload.get("request_id") != detail:   # the body must name the request id the signature authenticated
            return 401, {"error": "request id mismatch between the signed header and the body"}
        try:
            event = self.normalize(payload)
        except (ValueError, TypeError) as e:
            return 400, {"error": f"schema: {e}"}
        out = evaluate(event)
        disp = getattr(out, "disposition", out)
        verdict = "allow" if disp == "ALLOW" else "deny"
        body = {"protocol": PROTOCOL, "request_id": payload.get("request_id"), "verdict": verdict}
        if verdict == "deny":
            body["reason"] = getattr(out, "reason", "") or str(disp)
            if disp in DENY_WITH_REMEDIATION:
                body["remediation"] = DENY_WITH_REMEDIATION[disp]
        return 200, body

    # ---- enforcement mapping --------------------------------------------------------------------

    def enforce(self, ctx: Any, decision: PolicyDecision) -> EnforcementOutcome:
        d = decision.disposition
        if d == "ALLOW":
            return EnforcementOutcome(integration=self.integration, internal_action=d, vendor_verdict="allow", prevented=False,
                                      outcome_type=outcome_type(ctx, True), report_class="allowed")
        rem = [DENY_WITH_REMEDIATION[d]] if d in DENY_WITH_REMEDIATION else []
        return EnforcementOutcome(integration=self.integration, internal_action=d, vendor_verdict="deny", prevented=True,
                                  outcome_type=outcome_type(ctx, False), report_class="blocked_by_verdict", remediation=rem,
                                  note="denied before the step ran" + ("; the vendor cannot pause, so approval means deny now and a fresh, verified retry"
                                                                      if d == "REQUIRE_APPROVAL" else ""))
