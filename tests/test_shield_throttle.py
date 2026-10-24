"""Rate limiting, retries with backoff, the failure classes, and the bench cache (fake clock, fake errors)."""

from __future__ import annotations

import pytest
from fakes import FakeDecider

from agent.shield.throttle import BenchCache, RateLimiter, ServiceUnavailable, ThrottledDecider, cache_key, retryable, with_retries
from decider_kit.client import DeciderError


class Clock:
    def __init__(self):
        self.t = 0.0
        self.sleeps: list[float] = []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


def test_ten_per_minute_window():
    c = Clock()
    lim = RateLimiter(10, clock=c, sleep=c.sleep)
    waits = [lim.acquire() for _ in range(11)]
    assert waits[:10] == [0.0] * 10 and waits[10] > 59 and c.t > 59


def test_busy_and_rate_limited_errors_are_retried_with_growing_waits():
    c = Clock()
    errs = [DeciderError("decider returned 503 server busy; retry: x"), DeciderError("decider returned 429 rate limited; retry after a moment: y")]
    calls = []

    def fn():
        calls.append(1)
        if errs:
            raise errs.pop(0)
        return "ok"

    stats = {}
    assert with_retries(fn, "t1", 600, clock=c, sleep=c.sleep, stats=stats, lim=RateLimiter(100, clock=c, sleep=c.sleep)) == "ok"
    assert len(calls) == 3 and stats["retries"] == 2 and c.sleeps[1] > c.sleeps[0]


@pytest.mark.parametrize("msg", ["decider returned 401 check DECIDER_API_KEY: no", "decider returned 402 monthly quota used up: no"])
def test_bad_key_and_quota_are_not_retried(msg):
    c = Clock()
    n = []

    def fn():
        n.append(1)
        raise DeciderError(msg)

    with pytest.raises(DeciderError):
        with_retries(fn, "t2", 600, clock=c, sleep=c.sleep, lim=RateLimiter(100, clock=c, sleep=c.sleep))
    assert len(n) == 1 and not retryable(DeciderError(msg))


def test_retry_window_is_respected():
    c = Clock()

    def fn():
        raise DeciderError("decider returned 503 server busy; retry: z")

    with pytest.raises(ServiceUnavailable):
        with_retries(fn, "t3", 10, clock=c, sleep=c.sleep, lim=RateLimiter(100, clock=c, sleep=c.sleep))
    assert sum(c.sleeps) <= 10


def test_llm_calls_are_bounded_and_budgeted(monkeypatch):
    from agent.decision import questions_for
    from agent.shield import throttle

    seen = {}

    def fake_guarded(prompt, model_id=None, output_model=None, max_tokens=0, turns=0, **kw):
        seen.update(prompt=prompt, turns=turns, max_tokens=max_tokens, schema=output_model)
        return None, {"input_tokens": 10, "output_tokens": 0, "latency_ms": 1.0, "stop_reason": "limit_turns"}

    monkeypatch.setattr(throttle, "guarded_ask", fake_guarded)
    with pytest.raises(ValueError):   # a looping model that never answers: stopped by the limit, reported as malformed
        throttle.guarded_llm_answer("STATE", questions_for("first_pass", "inline"), model_id="m")
    assert seen["turns"] == 2 and seen["max_tokens"] <= 1024 and "STATE" in seen["prompt"] and "Meanings" in seen["prompt"]
    monkeypatch.setenv("SHIELD_LLM_TOKEN_BUDGET", "5")
    monkeypatch.setitem(throttle.LLM_STATS, "tokens", 5)
    with pytest.raises(throttle.TokenBudgetExceeded):
        throttle.throttled_llm_ask("x")


def test_cache_is_off_unless_given_and_keys_hold_no_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("DECIDER_API_KEY", "dcd_test_not_a_real_key")
    d = ThrottledDecider(FakeDecider())
    assert d.cache is None
    q = {"q": {"type": "noul", "instructions": "x?"}}
    cache = BenchCache(tmp_path / "decider.jsonl")
    d2 = ThrottledDecider(FakeDecider(), cache=cache)
    d2.ask("state", q)
    assert d2.live_requests == 1 and not d2.last_cached
    d2.ask("state", q)
    assert d2.live_requests == 1 and d2.cached_requests == 1 and d2.last_cached and d2.last_latency_ms == 12.0
    text = (tmp_path / "decider.jsonl").read_text()
    assert "dcd_test" not in text and "authorization" not in text.lower()
    assert len(cache_key("decider", "m", "s", q)) == 64
    assert len(BenchCache(tmp_path / "decider.jsonl")) == 1   # reloads for reruns
