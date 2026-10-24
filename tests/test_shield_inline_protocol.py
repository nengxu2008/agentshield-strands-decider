"""Inline-hook adapter protocol (synthetic `inline-hook-sim/v1`): signed requests, tampering, replay, frames."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from shield_support import oracle, router

from agent.shield.adapters.http_harness import make_app
from agent.shield.adapters.inline_hook import MAX_BODY, PROTOCOL, InlineHookAdapter, sign_request
from agent.shield.strategies import DeciderStrategy

NOW = 1_800_000_000


def body(**kw):
    b = {"protocol": PROTOCOL, "request_id": "req-1", "type": "tool_call", "event_id": "EVT-101", "session": {"id": "S-01", "step": 1},
         "identity": {"user_id": "u-ana", "verified": True},
         "calls": [{"tool": "read_document", "resource_id": "DOC-PUB-01", "t0": {"identity": "verified", "permission": "verified", "resource_label": "verified"}}]}
    b.update(kw)
    return json.dumps(b).encode()


def headers(raw, ts=NOW, rid="req-1", sig=None):
    return {"X-Hook-Timestamp": str(ts), "X-Hook-Signature": sig or sign_request(raw, ts, rid), "X-Hook-Request-Id": rid}


def adapter(clock=None):
    return InlineHookAdapter(clock=clock or (lambda: NOW))


def allow_all(event):
    return "ALLOW"


def test_valid_signed_request_gets_200_and_a_verdict():
    a, raw = adapter(), body()
    assert a.handle(raw, headers(raw), allow_all) == (200, {"protocol": PROTOCOL, "request_id": "req-1", "verdict": "allow"})
    raw2 = body(request_id="req-2")
    status, out = adapter().handle(raw2, headers(raw2, rid="req-2"), lambda e: "BLOCK")
    assert status == 200 and out["verdict"] == "deny"           # an intentional deny is a 200, not an error


def test_flipped_body_byte_is_rejected():
    raw = body()
    h = headers(raw)
    tampered = raw.replace(b"DOC-PUB-01", b"DOC-RES-05")
    assert adapter().handle(tampered, h, allow_all)[0] == 401


def test_altered_or_stale_timestamp_is_rejected():
    raw = body()
    h = headers(raw)
    h["X-Hook-Timestamp"] = str(NOW + 5)                         # signature no longer matches
    assert adapter().handle(raw, h, allow_all) == (401, {"error": "bad signature"})
    old = NOW - 301
    assert adapter().handle(raw, headers(raw, ts=old), allow_all) == (401, {"error": "stale timestamp"})


def test_replayed_request_id_is_rejected():
    a, raw = adapter(), body()
    assert a.handle(raw, headers(raw), allow_all)[0] == 200
    assert a.handle(raw, headers(raw), allow_all) == (401, {"error": "replayed request"})


def test_replay_with_a_fresh_header_id_is_rejected():
    """Review B1: the same signed body, timestamp and signature resent under a new X-Hook-Request-Id."""
    a, raw = adapter(), body()
    h = headers(raw)
    calls = []
    assert a.handle(raw, h, lambda e: calls.append(e) or "ALLOW")[0] == 200
    replay = {**h, "X-Hook-Request-Id": "req-1-replayed"}             # the signature covers the id: it no longer matches
    assert a.handle(raw, replay, lambda e: calls.append(e) or "ALLOW") == (401, {"error": "bad signature"})
    assert len(calls) == 1                                            # the replay never reached the evaluation


def test_header_and_body_request_ids_must_match():
    raw = body(request_id="req-1")
    h = headers(raw, rid="req-other")                                  # validly signed over a header id the body does not name
    status, out = adapter().handle(raw, h, allow_all)
    assert status == 401 and "mismatch" in out["error"]
    assert adapter().handle(raw, {**headers(raw), "X-Hook-Request-Id": ""}, allow_all)[0] == 401


def test_replay_cache_expires_by_time_window_and_fails_closed_when_full():
    t = [NOW]
    a, raw = adapter(clock=lambda: t[0]), body()
    assert a.handle(raw, headers(raw), allow_all)[0] == 200
    t[0] = NOW + 301                                                   # the window closed: the entry is dropped ...
    assert a.handle(raw, headers(raw), allow_all) == (401, {"error": "stale timestamp"})   # ... and a replay is stale anyway
    raw2 = body(request_id="req-2")
    assert a.handle(raw2, headers(raw2, ts=t[0], rid="req-2"), allow_all)[0] == 200
    assert not any(k.startswith("id:req-1") for k in a.seen)           # evicted by time, not by count
    small = InlineHookAdapter(clock=lambda: NOW, replay_capacity=2)
    assert small.handle(raw, headers(raw), allow_all)[0] == 200
    raw3 = body(request_id="req-3")
    assert small.handle(raw3, headers(raw3, rid="req-3"), allow_all) == (503, {"error": "replay cache full; retry later"})
    assert small.handle(raw, headers(raw), allow_all)[0] == 401      # the live entry was kept, not forgotten


def test_missing_headers_oversize_and_malformed_json():
    raw = body()
    assert adapter().handle(raw, {}, allow_all)[0] == 401
    big = b"{" + b" " * (MAX_BODY + 10) + b"}"
    assert adapter().handle(big, headers(big), allow_all)[0] == 413
    bad = b'{"protocol": "inline-hook-sim/v1", '
    assert adapter().handle(bad, headers(bad), allow_all) == (400, {"error": "malformed JSON"})
    nocalls = body(calls=[])
    assert adapter().handle(nocalls, headers(nocalls), allow_all)[0] == 400


def test_unknown_metadata_is_ignored_and_never_trusted():
    raw = body(metadata={"is_admin": True, "label": "PUBLIC"}, surprise="x", identity={"user_id": "u-ana", "verified": "yes"})
    ev = InlineHookAdapter().normalize(json.loads(raw))
    assert ev.actor_id is None and ev.claimed_actor_id == "u-ana"   # only a boolean True counts as verified
    assert any("surprise" in n for n in ev.coverage_notes) and any("metadata" in n for n in ev.coverage_notes)


def test_grouped_frame_with_one_unsafe_call_gets_a_single_deny():
    calls = [{"tool": "search_documents", "resource_id": "DOC-PUB-01", "t0": {"identity": "verified", "permission": "verified", "resource_label": "verified"}},
             {"tool": "send_email", "resource_id": "DOC-RES-05", "destination": "news@partner-one.example",
              "t0": {"identity": "verified", "permission": "verified", "resource_label": "verified", "recipient": "verified"}}]
    raw = body(event_id="FRM-T1", calls=calls, session={"id": "S-41", "step": 1})
    r = router()
    status, out = adapter().handle(raw, headers(raw), lambda e: r.evaluate(e, DeciderStrategy(oracle("FRM-301"))))
    assert status == 200 and out["verdict"] == "deny" and "whole frame" in out["reason"]


@pytest.mark.parametrize("mutate,code", [(lambda raw, h: (raw, h), 200), (lambda raw, h: (raw + b" ", h), 401),
                                          (lambda raw, h: (raw, {**h, "X-Hook-Signature": "v1=00"}), 401),
                                          (lambda raw, h: (raw, {**h, "X-Hook-Request-Id": "req-1-replayed"}), 401),
                                          (lambda raw, h: (raw, headers(raw, rid="req-other")), 401)])
def test_same_contract_through_the_http_harness(mutate, code):
    a = adapter()
    client = TestClient(make_app(a, allow_all))
    raw = body()
    raw, h = mutate(raw, headers(raw))
    r = client.post("/hook", content=raw, headers={**h, "content-type": "application/json"})
    assert r.status_code == code
    if code == 200:
        assert r.json()["verdict"] == "allow"
