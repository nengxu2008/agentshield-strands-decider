"""Simulated approvals (design.md section 7, R7): employee confirmation is NOT data-owner authorization.

- EMPLOYEE_CONFIRMATION: the requester confirms intent. It is recorded and never authorizes a
  restricted disclosure.
- DATA_OWNER_AUTHORIZATION: accepted only from the resource's registered data owner holding a role
  the approval policy lists (LOOKUP_APPROVAL_POLICY), signed over the exact action digest
  (actor, operation, target, destination, policy version), short-lived (policy TTL), single use,
  and never wider than the policy's scope. Hard-rule cases (H1-H4, P1) are never approvable.
- The inline-hook vendor cannot pause a request: the original step is denied now, and the next
  equivalent request is evaluated afresh; a matching unused grant satisfies the approval
  requirement once. A changed action has a different digest and gets a fresh evaluation.

Signatures use synthetic per-actor HMAC keys derived from a fixed test label (simulation only;
no real credentials). Submissions come from agent/data/approvals_inbox.json, never from LLM text.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .schemas import ApprovalGrant

SYNTHETIC_KEY_LABEL = b"agentshield-synthetic-approval-key:"


def action_digest(actor_id: str | None, operation: str, target_id: str | None, destination: str | None, policy_version: str) -> str:
    canon = json.dumps({"actor": actor_id, "op": operation, "target": target_id, "dest": (destination or "").lower(), "policy": policy_version},
                       sort_keys=True)
    return hashlib.sha256(canon.encode()).hexdigest()


def synthetic_key(actor_id: str) -> bytes:
    return hashlib.sha256(SYNTHETIC_KEY_LABEL + actor_id.encode()).digest()


def sign(actor_id: str, digest: str, issued_at: str, kind: str) -> str:
    return hmac.new(synthetic_key(actor_id), f"{kind}|{digest}|{issued_at}".encode(), hashlib.sha256).hexdigest()


class ApprovalService:
    def __init__(self, world: Any, policy: Any, clock: Callable[[], datetime] | None = None):
        self.world, self.policy = world, policy
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.requests: dict[str, dict[str, Any]] = {}
        self.grants: list[ApprovalGrant] = []
        self.confirmations: list[dict[str, Any]] = []
        self.log: list[dict[str, Any]] = []

    def digest_for(self, ctx: Any) -> str:
        return action_digest(ctx.event.actor_id, ctx.op, ctx.target, ctx.event.destination, self.policy.version)

    def lookup_policy(self, ctx: Any) -> dict[str, Any] | None:
        """LOOKUP_APPROVAL_POLICY: eligible approver roles for this exact action (not a grant)."""
        return self.policy.approval_policy(ctx)

    def request(self, ctx: Any) -> dict[str, Any]:
        pol = self.lookup_policy(ctx)
        owners = sorted({self.world.resources[s]["owner_id"] for s in ctx.source_ids() if s in self.world.resources})
        req = {"request_id": f"REQ-{ctx.event.event_id}", "event_id": ctx.event.event_id, "digest": self.digest_for(ctx),
               "actor_id": ctx.event.actor_id, "operation": ctx.op, "target_id": ctx.target, "destination": ctx.event.destination,
               "policy_id": pol["policy_id"] if pol else None, "approver_roles": pol["approver_roles"] if pol else [],
               "eligible_approvers": owners, "ttl_minutes": pol["ttl_minutes"] if pol else 0, "created_at": self.clock().isoformat(),
               "note": "the original request is denied now; an approved, unchanged retry is evaluated afresh"}
        self.requests[req["event_id"]] = req
        return req

    def submit(self, submission: dict[str, Any]) -> dict[str, Any]:
        """Verify one approval submission (from the synthetic inbox)."""
        sid, kind, who = submission["submission_id"], submission["kind"], submission["submitted_by"]
        req = self.requests.get(submission["for_event"])
        if not req:
            return self._result(sid, kind, who, False, "no pending approval request for this event (evaluate the event first)")
        issued = self.clock() - timedelta(minutes=float(submission.get("issued_minutes_ago", 0)))
        issued_s = issued.isoformat()
        sig = sign(submission.get("sign_with", who), req["digest"], issued_s, kind)
        if submission.get("tamper"):
            sig = sig[:-1] + ("0" if sig[-1] != "0" else "1")
        if not hmac.compare_digest(sig, sign(who, req["digest"], issued_s, kind)):
            return self._result(sid, kind, who, False, "signature does not match the action digest (tampered or wrong signer)")
        ttl = req["ttl_minutes"] or 0
        if self.clock() - issued > timedelta(minutes=ttl):
            return self._result(sid, kind, who, False, f"expired: older than the {ttl}-minute approval window")
        if kind == "EMPLOYEE_CONFIRMATION":
            self.confirmations.append({"submission_id": sid, "by": who, "digest": req["digest"], "at": issued_s})
            return self._result(sid, kind, who, True, "recorded the requester's confirmation of intent; it does not authorize the "
                                "disclosure (only the data owner can)", authorizes=False)
        actor = self.world.actors.get(who, {})
        if who not in req["eligible_approvers"] or not set(req["approver_roles"]) & set(actor.get("roles", [])):
            return self._result(sid, kind, who, False, f"{who} is not the registered data owner with authority over this action")
        g = ApprovalGrant(grant_id=f"GRANT-{sid}", kind="DATA_OWNER_AUTHORIZATION", approver_id=who, approver_role="data_owner",
                          actor_id=req["actor_id"], operation=req["operation"], target_id=req["target_id"], destination=req["destination"],
                          policy_version=self.policy.version, digest=req["digest"], issued_at=issued, expires_at=issued + timedelta(minutes=ttl),
                          single_use=True, scope_note=f"one {req['operation']} of {req['target_id']} to {req['destination']} ({req['policy_id']})")
        self.grants.append(g)
        return self._result(sid, kind, who, True, f"data-owner authorization accepted: {g.scope_note}, valid {ttl} minutes, single use",
                            authorizes=True, grant_id=g.grant_id)

    def _result(self, sid: str, kind: str, who: str, ok: bool, reason: str, authorizes: bool = False, grant_id: str | None = None) -> dict[str, Any]:
        r = {"submission_id": sid, "kind": kind, "submitted_by": who, "accepted": ok, "authorizes": authorizes and ok,
             "reason": reason, "grant_id": grant_id}
        self.log.append(r)
        return r

    def attach(self, ctx: Any) -> None:
        """Give the context a matching, unused, unexpired grant for exactly this action (if any)."""
        d, now = self.digest_for(ctx), self.clock()
        for g in self.grants:
            if g.used or g.expires_at < now:
                continue
            if g.digest == d:
                ctx.grant = g
                ctx.grant_note = f"{g.grant_id} by {g.approver_id} (data owner), single use"
                return
            if g.actor_id == ctx.event.actor_id and g.target_id == ctx.target:
                ctx.grant_note = f"{g.grant_id} does not cover this action (digest mismatch): fresh evaluation"

    def consume(self, ctx: Any) -> None:
        if ctx.grant is not None and not ctx.grant.used:
            ctx.grant.used = True
