"""Rate limits, retries and the benchmark cache for the hosted services (free tiers).

- A process-wide sliding-window limiter per service: SHIELD_DECIDER_RPM (default 10) and
  SHIELD_LLM_RPM (default 10), one call in flight at a time.
- Retries with exponential backoff (2 s, 4 s, 8 s ... capped at 60 s, +-20 % jitter) on
  429 / 503 / busy / throttling errors and dropped connections, within a retry window
  (60 s for chat, 600 s for benchmark runs); 401 (bad key) and 402 (quota used up) raise at once.
- An on-disk JSONL cache, used only by the benchmark for RERUNS and for identical calls across
  arms; every cached answer keeps the latency measured when it was made.
- Waits are measured and reported apart (`throttle_wait_ms`), never counted as service time.
No artificial sleeps: the only sleeps are rate-limit and retry waits.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable

from decider_kit.client import DeciderError, Decision


class ServiceUnavailable(RuntimeError):
    """The service stayed busy or unreachable for the whole retry window, or refused the key/quota."""


class RateLimiter:
    def __init__(self, rpm: int, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        self.rpm, self.clock, self.sleep = max(1, rpm), clock, sleep
        self.starts: deque[float] = deque()
        self.lock = threading.Lock()

    def acquire(self) -> float:
        """Block until a call may start; returns the seconds waited."""
        waited = 0.0
        while True:
            now = self.clock()
            while self.starts and now - self.starts[0] >= 60.0:
                self.starts.popleft()
            if len(self.starts) < self.rpm:
                self.starts.append(now)
                return waited
            pause = 60.0 - (now - self.starts[0]) + 0.05
            self.sleep(pause)
            waited += pause


_LIMITERS: dict[str, RateLimiter] = {}
_INFLIGHT: dict[str, threading.Lock] = {}


def limiter(service: str) -> RateLimiter:
    if service not in _LIMITERS:
        rpm = int(os.environ.get("SHIELD_DECIDER_RPM" if service == "decider" else "SHIELD_LLM_RPM", "10"))
        _LIMITERS[service] = RateLimiter(rpm)
        _INFLIGHT[service] = threading.Lock()
    return _LIMITERS[service]


def retryable(err: BaseException) -> bool:
    msg = f"{type(err).__name__} {err}".lower()
    if " 401 " in f" {msg} " or " 402 " in f" {msg} " or "quota" in msg and "429" not in msg:
        return False
    return any(s in msg for s in (" 429 ", " 503 ", "429", "503", "busy", "throttl", "rate limit", "ratelimit", "overloaded",
                                  "timed out", "timeout", "temporarily", "connection", "no strands decider at"))


def backoff(attempt: int, rnd: random.Random | None = None) -> float:
    base = min(60.0, 2.0 * (2 ** attempt))
    r = rnd or random
    return base * (0.8 + 0.4 * r.random())


def with_retries(fn: Callable[[], Any], service: str, window_s: float, max_attempts: int = 6,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 stats: dict[str, Any] | None = None, lim: RateLimiter | None = None) -> Any:
    """Run `fn` under the service's rate limit, retrying busy/throttled errors with backoff."""
    lim = lim or limiter(service)
    stats = stats if stats is not None else {}
    stats.setdefault("throttle_wait_s", 0.0)
    stats.setdefault("retry_wait_s", 0.0)
    stats.setdefault("retries", 0)
    stats.setdefault("errors", [])
    start = clock()
    attempt = 0
    while True:
        stats["throttle_wait_s"] += lim.acquire()
        try:
            with _INFLIGHT.setdefault(service, threading.Lock()):
                return fn()
        except Exception as e:  # noqa: BLE001 - classified below
            stats["errors"].append(f"{type(e).__name__}: {str(e)[:160]}")
            if not retryable(e):
                raise
            attempt += 1
            pause = backoff(attempt - 1)
            if attempt >= max_attempts or clock() - start + pause > window_s:
                raise ServiceUnavailable(f"{service} unavailable after {attempt} attempts over {clock() - start:.0f} s: {str(e)[:200]}") from e
            stats["retries"] += 1
            stats["retry_wait_s"] += pause
            sleep(pause)


# ---- the benchmark cache -----------------------------------------------------------------------

def cache_key(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()


class BenchCache:
    """Append-only JSONL map key -> value. Values never contain keys or credentials."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.data: dict[str, Any] = {}
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    row = json.loads(line)
                    self.data[row["k"]] = row["v"]

    def get(self, key: str) -> Any:
        return self.data.get(key)

    def put(self, key: str, value: Any) -> None:
        self.data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            f.write(json.dumps({"k": key, "v": value}, default=str) + "\n")

    def __len__(self) -> int:
        return len(self.data)


# ---- the Decider ------------------------------------------------------------------------------

class ThrottledDecider:
    """Same interface as decider_kit.Decider (ask, last_latency_ms, last_server_ms, url, health),
    plus rate limiting, retries, an optional bench cache, and the model id of the checkpoint."""

    def __init__(self, decider: Any = None, cache: BenchCache | None = None, window_s: float | None = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic):
        if decider is None:
            from decider_kit import Decider

            decider = Decider()
        self.inner = decider
        self.cache = cache
        self.window_s = window_s if window_s is not None else float(os.environ.get("SHIELD_RETRY_WINDOW_S", "60"))
        self.sleep, self.clock = sleep, clock
        self.url = getattr(decider, "url", "")
        self.last_latency_ms: float | None = None
        self.last_server_ms: float | None = None
        self.last_cached = False
        self.last_stats: dict[str, Any] = {}
        self.live_requests = 0
        self.live_decisions = 0
        self.cached_requests = 0
        self.retries = 0
        self.errors: list[str] = []
        self._model: str | None = None

    def health(self) -> dict[str, Any]:
        return self.inner.health()

    def model_id(self) -> str:
        if self._model is None:
            try:
                h = self.inner.health()
                self._model = h.get("checkpoint") or (h.get("data") or [{}])[0].get("id") or "unknown"
            except Exception:  # noqa: BLE001
                self._model = "unknown"
        return self._model

    def ask(self, state: Any, questions: dict[str, dict[str, Any]], images: Any = None) -> dict[str, Decision]:
        key = cache_key("decider", self.model_id(), state, questions) if self.cache is not None else None
        if key and (hit := self.cache.get(key)):
            self.last_latency_ms, self.last_server_ms, self.last_cached = hit["ms"], hit.get("server_ms"), True
            self.last_stats = {"throttle_wait_s": 0.0, "retry_wait_s": 0.0, "retries": 0, "errors": []}
            self.cached_requests += 1
            return {k: Decision.parse(v) for k, v in hit["answers"].items()}
        stats: dict[str, Any] = {}
        try:
            ans = with_retries(lambda: self.inner.ask(state, questions, images=images), "decider", self.window_s,
                               clock=self.clock, sleep=self.sleep, stats=stats)
        except DeciderError as e:
            self.errors += stats.get("errors", [])
            raise ServiceUnavailable(str(e)) from e
        finally:
            self.last_stats = stats
            self.retries += stats.get("retries", 0)
        self.last_latency_ms = self.inner.last_latency_ms
        self.last_server_ms = getattr(self.inner, "last_server_ms", None)
        self.last_cached = False
        self.live_requests += 1
        self.live_decisions += len(questions)
        if key:
            self.cache.put(key, {"answers": {k: v.raw for k, v in ans.items()}, "ms": self.last_latency_ms, "server_ms": self.last_server_ms,
                                 "model": self.model_id(), "at": time.time()})
        return ans


# ---- the LLM (always through the Strands Agents SDK; models from decider_kit.llm.agent_model) ----------

LLM_STATS: dict[str, Any] = {"live_calls": 0, "cached_calls": 0, "tokens": 0, "retries": 0, "limit_stops": 0}


class TokenBudgetExceeded(ServiceUnavailable):
    """The run-level LLM token budget (SHIELD_LLM_TOKEN_BUDGET) is used up; no further LLM calls are made."""


def _check_budget() -> None:
    cap = int(os.environ.get("SHIELD_LLM_TOKEN_BUDGET", "0") or 0)
    if cap and LLM_STATS["tokens"] >= cap:
        raise TokenBudgetExceeded(f"LLM token budget {cap} reached ({LLM_STATS['tokens']} used in this process)")


def guarded_ask(prompt: str, system: str = "", model_id: str | None = None, output_model: Any = None, max_tokens: int = 300,
                turns: int = 2, total_tokens: int | None = None) -> tuple[Any, dict[str, Any]]:
    """One bounded Strands Agent call (no tools). Like decider_kit.llm.ask, plus per-invocation limits.

    Strands' structured output can loop when a small model never emits the output tool call; `limits` caps the loop at
    `turns` model calls and `total_tokens` tokens (Strands stops with stop_reason limit_*; no exception)."""
    from strands import Agent

    from decider_kit import llm

    p = llm.provider()
    mid = model_id or llm.default_model_id(p)
    kw: dict[str, Any] = ({"max_tokens": max_tokens, "temperature": 0} if p in ("bedrock", "local")
                          else {"params": {"max_tokens": max_tokens, "temperature": 0}})
    agent = Agent(model=llm.agent_model(mid, p, **kw), system_prompt=system or None, callback_handler=None)
    cap = total_tokens or (len(prompt) // 2 + len(system) // 2 + turns * max_tokens + 1500)
    limits = {"turns": max(1, turns), "total_tokens": cap}
    t0 = time.perf_counter()
    result = agent(prompt, structured_output_model=output_model, limits=limits) if output_model else agent(prompt, limits=limits)
    ms = (time.perf_counter() - t0) * 1000
    u = result.metrics.accumulated_usage
    tin, tout = int(u.get("inputTokens", 0)), int(u.get("outputTokens", 0))
    stop = str(getattr(result, "stop_reason", "") or "")
    pin, pout = llm.price(mid, p)
    usage = {"input_tokens": tin, "output_tokens": tout, "latency_ms": ms, "cost_usd": tin / 1e6 * pin + tout / 1e6 * pout,
             "model_id": mid, "provider": p, "stop_reason": stop}
    if stop.startswith("limit"):
        LLM_STATS["limit_stops"] += 1
    if output_model:
        return getattr(result, "structured_output", None), usage
    return llm.strip_thinking(str(result)), usage


def guarded_llm_answer(state: Any, questions: dict[str, dict[str, Any]], model_id: str | None = None) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """decider_kit.llm.llm_answer's exact prompt and schema (the kit's LLM baseline), through guarded_ask."""
    from typing import Literal

    from pydantic import BaseModel, Field, create_model

    from decider_kit.llm import options_of

    fields: dict[str, Any] = {}
    lines = []
    for name, q in questions.items():
        opts = options_of(q)
        answer_t = Literal[tuple(opts)]  # type: ignore[valid-type]
        sub = create_model(f"A_{name}", answer=(answer_t, ...), confidence=(float, Field(ge=0, le=1)), __base__=BaseModel)
        fields[name] = (sub, ...)
        meaning = q.get("criteria") if q["type"] == "choice" else (
            {"yes": q.get("criteria", {}).get("true", ""), "no": q.get("criteria", {}).get("false", "")} if q["type"] == "noul" else None)
        lines.append(f'- "{name}": {q["instructions"]} Options: {opts}' + (f" Meanings: {meaning}" if meaning else ""))
    Answers = create_model("Answers", **fields, __base__=BaseModel)
    prompt = (f"Read the state and answer each question with exactly one of its options, plus your confidence (0 to 1).\n\n"
              f"STATE:\n{state}\n\nQUESTIONS:\n" + "\n".join(lines))
    out, usage = guarded_ask(prompt, model_id=model_id, output_model=Answers, max_tokens=400 + 80 * len(questions), turns=2)
    res = {}
    for name in questions:
        a = getattr(out, name, None) if out is not None else None
        res[name] = {"label": getattr(a, "answer", None), "confidence": float(getattr(a, "confidence", 0.0) or 0.0)}
    if out is None:
        raise ValueError(f"LLM router returned no structured answer (stop_reason {usage.get('stop_reason')})")
    return res, usage


def throttled_llm_ask(prompt: str, system: str = "", model_id: str | None = None, output_model: Any = None, max_tokens: int = 300,
                      window_s: float | None = None, cache: BenchCache | None = None) -> tuple[Any, dict[str, Any]]:
    window = window_s if window_s is not None else float(os.environ.get("SHIELD_RETRY_WINDOW_S", "60"))
    stats: dict[str, Any] = {}
    _check_budget()
    try:
        out, usage = with_retries(lambda: guarded_ask(prompt, system=system, model_id=model_id, output_model=output_model, max_tokens=max_tokens),
                                  "llm", window, stats=stats)
    finally:
        LLM_STATS["retries"] += stats.get("retries", 0)
    LLM_STATS["live_calls"] += 1
    LLM_STATS["tokens"] += int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))
    usage = {**usage, "service_ms": usage.get("latency_ms"), "throttle_wait_s": stats.get("throttle_wait_s", 0.0),
             "retry_wait_s": stats.get("retry_wait_s", 0.0)}
    return out, usage


def throttled_llm_answer(state: str, questions: dict[str, Any], model_id: str | None = None, window_s: float | None = None,
                         cache: BenchCache | None = None) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """The kit's llm_answer (same typed questions, structured output) under the rate limit, with the bench cache."""
    from decider_kit import llm

    mid = model_id or llm.default_model_id()
    key = cache_key("llm_answer", mid, llm.provider(), state, questions) if cache is not None else None
    if key and (hit := cache.get(key)):
        LLM_STATS["cached_calls"] += 1
        return hit["answers"], {**hit["usage"], "cached": True}
    window = window_s if window_s is not None else float(os.environ.get("SHIELD_RETRY_WINDOW_S", "60"))
    stats: dict[str, Any] = {}
    _check_budget()
    try:
        ans, usage = with_retries(lambda: guarded_llm_answer(state, questions, model_id=mid), "llm", window, stats=stats)
    finally:
        LLM_STATS["retries"] += stats.get("retries", 0)
    LLM_STATS["live_calls"] += 1
    LLM_STATS["tokens"] += int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))
    usage = {k: v for k, v in usage.items() if k in ("input_tokens", "output_tokens", "latency_ms", "cost_usd", "model_id", "provider", "stop_reason")}
    usage.update(throttle_wait_s=stats.get("throttle_wait_s", 0.0), retry_wait_s=stats.get("retry_wait_s", 0.0), cached=False)
    if key:
        cache.put(key, {"answers": ans, "usage": usage})
    return ans, usage


def quota() -> dict[str, Any] | None:
    """Month-to-date usage of the hosted API (GET /v1/usage: free, not counted). None when not hosted."""
    import urllib.request

    from decider_kit.config import settings

    s = settings()
    if s.decider_mode != "ugmdu" and not s.decider_api_key:
        return None
    req = urllib.request.Request(s.decider_url + "/v1/usage", headers={"authorization": f"Bearer {s.decider_api_key}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return dict(json.loads(r.read()))
    except Exception:  # noqa: BLE001
        return None
