"""Approvals: an employee's confirmation is not a data owner's authorization; grants are digest-scoped and single use."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from shield_support import W, ctx, oracle, router

from agent.shield.approvals import ApprovalService, action_digest
from agent.shield.policy import DeterministicPolicyEngine
from agent.shield.strategies import DeciderStrategy


def held(r, sid="EVT-126"):
    out = r.evaluate(sid, DeciderStrategy(oracle(sid)))
    assert out.disposition == "REQUIRE_APPROVAL" and out.enforcement.vendor_verdict == "deny"   # deny now: the vendor cannot pause
    assert out.approval_request["eligible_approvers"] == ["u-farah"]
    return out


def retry(r, eid="EVT-126R"):
    script = oracle("EVT-101")   # a confident allow if, and only if, policy lists it as eligible
    return r.evaluate(eid, DeciderStrategy(script))


def test_employee_confirmation_never_authorizes():
    r = router()
    held(r)
    res = r.approvals.submit(W.inbox["APR-1"])
    assert res["accepted"] and res["authorizes"] is False and "does not authorize" in res["reason"]
    out = retry(r)
    assert out.disposition != "ALLOW"


def test_data_owner_authorization_allows_the_unchanged_retry_once():
    r = router()
    held(r)
    res = r.approvals.submit(W.inbox["APR-2"])
    assert res["accepted"] and res["authorizes"] and res["grant_id"] == "GRANT-APR-2"
    out = retry(r)
    assert out.disposition == "ALLOW" and any(t.get("consumed") for t in out.trace)
    again = retry(r)                                            # single use: the next send needs a new decision
    assert again.disposition != "ALLOW"


def test_wrong_owner_tampered_and_expired_grants_are_rejected():
    r = router()
    held(r)
    for sid, why in (("APR-3", "not the registered data owner"), ("APR-4", "signature"), ("APR-5", "expired")):
        res = r.approvals.submit(W.inbox[sid])
        assert not res["accepted"] and why in res["reason"], sid
    assert r.approvals.grants == []


def test_changed_action_has_a_different_digest_and_gets_a_fresh_evaluation():
    r = router()
    held(r)
    r.approvals.submit(W.inbox["APR-2"])
    c = ctx("EVT-126X")
    r.approvals.attach(c)
    assert c.grant is None and "digest mismatch" in c.grant_note
    out = r.evaluate("EVT-126X", DeciderStrategy(oracle("EVT-101")))
    assert out.disposition != "ALLOW"


def test_submission_without_a_pending_request_is_rejected():
    r = router()
    assert not r.approvals.submit(W.inbox["APR-2"])["accepted"]


def test_hard_rule_cases_are_not_approvable():
    p = DeterministicPolicyEngine(W)
    assert not p.approvable(ctx("EVT-102")) and not p.approvable(ctx("EVT-122"))


def test_digest_covers_actor_operation_target_destination_and_policy():
    base = action_digest("u-ben", "send_email", "ART-26", "ops@newvendor.example", "pb-2026.10")
    assert base == action_digest("u-ben", "send_email", "ART-26", "OPS@newvendor.example", "pb-2026.10")
    for changed in (("u-eli", "send_email", "ART-26", "ops@newvendor.example", "pb-2026.10"),
                    ("u-ben", "share_file", "ART-26", "ops@newvendor.example", "pb-2026.10"),
                    ("u-ben", "send_email", "ART-07", "ops@newvendor.example", "pb-2026.10"),
                    ("u-ben", "send_email", "ART-26", "x@newvendor.example", "pb-2026.10"),
                    ("u-ben", "send_email", "ART-26", "ops@newvendor.example", "pb-2026.11")):
        assert action_digest(*changed) != base


def test_grant_expires_with_the_policy_ttl():
    t = [datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)]
    r = router(clock=lambda: t[0])
    held(r)
    r.approvals.submit(W.inbox["APR-2"])
    t[0] = t[0] + timedelta(minutes=20)
    c = ctx("EVT-126R")
    r.approvals.attach(c)
    assert c.grant is None


def test_approval_service_is_standalone():
    svc = ApprovalService(W, DeterministicPolicyEngine(W))
    req = svc.request(ctx("EVT-107"))
    assert req["policy_id"] == "AP-FORECAST-EXT" and req["approver_roles"] == ["data_owner"]
