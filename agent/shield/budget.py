"""Per-event budgets (design.md "Deadline and fallback budgets"): prototype defaults, not guarantees.

The deadline clock counts measured service time only (policy, routing, evidence, analyzer,
resolver, enforcement). Rate-limit waits of the free hosted tiers are excluded and reported apart.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Budget:
    max_evidence: int = 2
    max_analyzers: int = 1
    max_decider: int = 4
    max_steps: int = 6
    deadline_ms: int = 20000
    guard_ms: int = 1000
    expected_ms: dict[str, int] = field(default_factory=lambda: {"decider": 2500, "evidence": 50, "analyzer": 6000})
    evidence_used: int = 0
    analyzers_used: int = 0
    decider_used: int = 0
    steps_used: int = 0
    elapsed_ms: float = 0.0

    @classmethod
    def for_event(cls, bundle: dict[str, Any], mode: str, deadline_override: int | None = None) -> Budget:
        b = bundle.get("budgets", {})
        default_deadline = (_env_int("SHIELD_AUDIT_DEADLINE_MS", b.get("audit_deadline_ms", 120000)) if mode == "audit_only"
                            else _env_int("SHIELD_INLINE_DEADLINE_MS", b.get("inline_deadline_ms", 20000)))
        return cls(max_evidence=_env_int("SHIELD_MAX_EVIDENCE", b.get("max_evidence_calls", 2)),
                   max_analyzers=_env_int("SHIELD_MAX_ANALYZERS", b.get("max_analyzer_calls", 1)),
                   max_decider=_env_int("SHIELD_MAX_DECIDER", b.get("max_decider_calls", 4)),
                   max_steps=b.get("max_steps", 6), deadline_ms=deadline_override or default_deadline,
                   guard_ms=b.get("guard_ms", 1000), expected_ms=dict(b.get("expected_ms", {"decider": 2500, "evidence": 50, "analyzer": 6000})))

    @property
    def remaining_ms(self) -> int:
        return int(self.deadline_ms - self.elapsed_ms)

    def spend(self, ms: float) -> None:
        self.elapsed_ms += max(0.0, float(ms))

    def time_for(self, kind: str, reserve_routing: bool = False) -> bool:
        """Is there time for one more `kind` call (plus a routing call before it, if one is still ahead)?"""
        need = self.expected_ms.get(kind, 0) + (self.expected_ms.get("decider", 0) if reserve_routing else 0)
        return self.remaining_ms - self.guard_ms >= need

    @property
    def evidence_left(self) -> int:
        return self.max_evidence - self.evidence_used

    @property
    def analyzers_left(self) -> int:
        return self.max_analyzers - self.analyzers_used

    @property
    def decider_left(self) -> int:
        return self.max_decider - self.decider_used

    @property
    def steps_left(self) -> int:
        return self.max_steps - self.steps_used

    def summary(self) -> str:
        return (f"lookups {self.evidence_left}, analyzer calls {self.analyzers_left}, routing calls {self.decider_left}, "
                f"time ~{max(0, self.remaining_ms) / 1000:.0f} s")
