"""The AgentShield event pipeline (design.md "Bounded conditional routing procedure"; plan section A1).

    TIER 0  policy.tier0                     hard denies are final, no model call (measured short-circuit)
    TIER 1  strategy.first_pass              Strands Decider gatekeeper in the product (one batched call)
            policy.validate                  vetoes ineligible picks, forces mandatory analyzers (route_override)
    TIER 2  evidence tools / analyzers       bounded by budgets and the deadline clock
            resolver after every result      conclusive -> final policy validation (no extra Decider call)
                                             open + a queued step addresses it -> run it (no Decider call)
                                             open + nothing queued + an eligible step left -> strategy.reroute
                                             otherwise -> safe fallback (inline BLOCK / audit alert or review)
            policy.finalize -> adapter.enforce

All benchmark arms run through this one class; only the strategy differs.
"""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable

from decider_kit.client import DeciderError

from .adapters import default_adapters
from .analyzers import SPECS, AnalyzerRegistry, FixtureBackend
from .approvals import ApprovalService
from .audit import AuditLog
from .catalog import EVIDENCE_TOOLS
from .context import EventContext, build_context, call_event
from .data import World
from .evidence import EvidenceError, EvidenceService
from .policy import DeterministicPolicyEngine, Eligibility
from .resolver import resolve
from .schemas import EventOutcome, ResultResolution, RoutingRecord, SecurityEvent
from .throttle import ServiceUnavailable

# Any failure of the routing model (outage, quota, rate limit, malformed or missing answer) -> the failure policy
ROUTING_ERRORS = (ServiceUnavailable, DeciderError, ValueError, AssertionError, KeyError, TimeoutError, ConnectionError, Exception)
# Failures that are the model's own behaviour (it answered, but not in the schema): scored by the benchmark, not aborted
MODEL_MISBEHAVIOR = ("ValueError", "StructuredOutputException", "ValidationError", "KeyError")
# Failures of the service (not the model's judgement): the benchmark aborts rather than scoring them
INFRASTRUCTURE_MARKERS = ("ServiceUnavailable", "TokenBudgetExceeded", "APIStatusError", "APIConnectionError", "RateLimitError",
                          "AccessDenied", "Throttling", "ThrottlingException", "EventLoopException", "NotFoundError",
                          "Unavailable", " 402", " 429", " 503", "quota")


class ShieldRouter:
    def __init__(self, world: World | None = None, registry: AnalyzerRegistry | None = None, policy: Any = None,
                 evidence: EvidenceService | None = None, approvals: ApprovalService | None = None, adapters: dict[str, Any] | None = None,
                 audit: AuditLog | None = None, clock: Callable[[], datetime] | None = None):
        self.world = world or World()
        self.registry = registry or AnalyzerRegistry(FixtureBackend(self.world))
        self.policy = policy or DeterministicPolicyEngine(self.world, self.registry)
        if getattr(self.policy, "registry", None) is None:
            self.policy.registry = self.registry
        self.evidence = evidence or EvidenceService(self.world)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.approvals = approvals or ApprovalService(self.world, self.policy, clock=self.clock)
        self.adapters = adapters or default_adapters()
        self.audit = audit or AuditLog()

    # ---- public ---------------------------------------------------------------------------------

    def evaluate(self, event: SecurityEvent | str, strategy: Any, deadline_ms: int | None = None) -> EventOutcome:
        ev = self.world.event(event) if isinstance(event, str) else event
        t = time.perf_counter()
        out = self._frame(ev, strategy, deadline_ms) if ev.calls else self._single(ev, strategy, deadline_ms)
        out.wall_ms = (time.perf_counter() - t) * 1000
        self.audit.append(out, ev)
        return out

    # ---- one event --------------------------------------------------------------------------------

    def _single(self, event: SecurityEvent, strategy: Any, deadline_ms: int | None = None) -> EventOutcome:
        ctx = build_context(self.world, event, now=self.clock(), deadline_ms=deadline_ms)
        self.approvals.attach(ctx)
        out = EventOutcome(event_id=event.event_id, mode=ctx.mode, disposition="BLOCK", coverage_notes=list(event.coverage_notes))
        stage: dict[str, float] = defaultdict(float)
        run = _Run(self, ctx, out, stage, strategy)
        return run.go()

    # ---- grouped inline frames: one verdict per frame -------------------------------------------

    def _frame(self, frame: SecurityEvent, strategy: Any, deadline_ms: int | None = None) -> EventOutcome:
        out = EventOutcome(event_id=frame.event_id, mode="inline", disposition="BLOCK", coverage_notes=list(frame.coverage_notes),
                           frame_calls=[c.call_id for c in frame.calls])
        calls = [call_event(frame, c) for c in frame.calls]
        t = time.perf_counter()
        for ce in calls:   # Tier 0 over every exposed call first: one hard deny ends the whole frame
            ctx = build_context(self.world, ce, now=self.clock(), deadline_ms=deadline_ms)
            t0 = self.policy.tier0(ctx)
            if t0:
                out.stage_ms["policy"] = (time.perf_counter() - t) * 1000
                out.service_ms = out.stage_ms["policy"]
                out.tier0, out.rule_id = True, t0.rule_id
                out.reason = f"{ce.event_id}: {t0.reason}; one verdict for the whole frame"
                out.resolution_status = "TIER0_DENY"
                out.enforcement = self.adapters["inline_hook_vendor"].enforce(ctx, t0)
                out.trace.append({"stage": "tier0", "call": ce.event_id, "rule": t0.rule_id})
                return out
        out.stage_ms["policy"] = (time.perf_counter() - t) * 1000
        for ce in calls:   # then in order; the first non-allow ends the frame with deny (later calls are not evaluated)
            sub = self._single(ce, strategy, deadline_ms)
            for k in ("evidence_calls", "failed_evidence_calls", "analyzer_calls", "findings", "decision_records", "routing_records", "trace",
                      "vetoes", "route_overrides"):
                getattr(out, k).extend(getattr(sub, k))
            for k in ("decider_calls", "decider_questions", "routing_model_calls", "decider_calls_saved", "decider_calls_after_downstream",
                      "ineligible_proposals", "repeat_suppressed", "steps", "llm_tokens"):
                setattr(out, k, getattr(out, k) + getattr(sub, k))
            out.throttle_wait_ms += sub.throttle_wait_ms
            for k, v in sub.stage_ms.items():
                out.stage_ms[k] = out.stage_ms.get(k, 0.0) + v
            out.low_confidence = out.low_confidence or sub.low_confidence
            out.first_route = out.first_route or sub.first_route
            if sub.disposition != "ALLOW":
                out.disposition, out.rule_id, out.reason = "BLOCK", sub.rule_id, f"{ce.event_id}: {sub.reason}; one verdict for the whole frame"
                out.resolution_status, out.fallback_reason, out.enforcement = sub.resolution_status, sub.fallback_reason, sub.enforcement
                out.service_ms = sum(out.stage_ms.values())
                return out
        out.disposition, out.reason, out.resolution_status = "ALLOW", "every exposed call allowed", "SUFFICIENT_ALLOW_CANDIDATE"
        out.enforcement = sub.enforcement  # type: ignore[possibly-undefined]
        out.service_ms = sum(out.stage_ms.values())
        return out

    # ---- the Decider's view of an event (the state text is rendered from this) --------------------

    def view(self, ctx: EventContext, elig: Eligibility, stage: str) -> dict[str, Any]:
        ev, w = ctx.event, self.world
        inline = ctx.mode != "audit_only"
        tgt = ctx.target or "-"
        title = (w.resources.get(tgt) or w.provenance.get(tgt) or {}).get("title")
        kind = "artifact" if ctx.is_artifact else "resource"
        step = f"{ctx.op or ev.tool_name} {kind} {tgt}" + (f" ({title})" if title else "")
        if ev.destination:
            step += f" to {ev.destination}"
        verified = []
        for name in ("identity", "permission", "resource_label", "artifact_label", "lineage", "recipient"):
            f = ctx.fact(name)
            if not f:
                continue
            label = {"identity": "Actor identity", "permission": f"Permission {ctx.op} on {tgt}", "resource_label": f"Label of {tgt}",
                     "artifact_label": f"Label of {tgt}", "lineage": f"Lineage of {tgt}", "recipient": f"Recipient {ev.destination}"}[name]
            if f.status == "verified":
                val = f"{f.value} ({f.source_system}, {f.age_days or 0:.0f} d)"
            elif f.status == "stale":
                val = f"STALE: cached {f.value} ({f.source_system}, {f.age_days:.0f} d old)"
            else:
                val = "UNKNOWN" + (f" ({f.note})" if f.note else "")
            if name == "lineage" and f.status != "verified":
                val = f"{f.value} ({f.source_system})"
            verified.append(f"{label}: {val}")
        opt = (w.resources.get(ev.resource_id or "") or {}).get("optional_metadata") or {}
        for k, v in opt.items():
            if v is None:
                verified.append(f"Optional {k.replace('_', ' ')} of {tgt}: missing (not required by policy)")
        if ctx.grant_note:
            verified.append(f"Approval: {ctx.grant_note}")
        verified += [f"Resolved conflict: {c}" for c in ctx.conflicts]
        req = ", ".join(f"{n}={(ctx.fact(n).status if ctx.fact(n) else 'missing').upper() if not ctx.verified(n) else 'verified'}"
                        for n in self.policy.required_facts(ctx))
        mand = {a: rid for a, rid in self.policy.mandatory_analyzers(ctx)}
        notes = [f"{k}: {v}" for k, v in elig.notes.items()
                 if k in SPECS or k in EVIDENCE_TOOLS or k == "identity"]
        done = "; ".join(d["line"] for d in ctx.done) or "nothing"
        untrusted = list(ctx.untrusted) + [(f"Analyzer note ({f.analyzer_id})", f.untrusted_note[:200]) for f in ctx.findings if f.untrusted_note]
        return {"event_id": ev.event_id, "policy_version": self.policy.version,
                "vendor_line": ("inline-hook vendor (pending: it can allow or deny before the step runs)" if inline
                                else "audit-only vendor (observed after it happened: cannot be blocked)"),
                "session_line": f"session {ev.session_id or '-'}, step {ev.step or 1}", "task": ctx.task,
                "step_label": "Pending step" if inline else "Observed step", "step_text": step, "verified": verified,
                "session": ctx.session_lines if ctx.session_lines else None,
                "hard_rules": [], "mandatory": [f"{a} (policy {rid})" for a, rid in mand.items() if a in elig.mandatory],
                "required": req, "impact": self.policy.impact(ctx), "eligible_steps": list(elig.next_steps),
                "eligible_tools": [f"{t} ~{EVIDENCE_TOOLS[t].expected_ms} ms" for t in elig.tools],
                "eligible_analyzers": [f"{a} ~{SPECS[a].expected_latency_ms / 1000:.0f} s" for a in elig.analyzers],
                "not_eligible": notes, "done": done, "budget": ctx.budget.summary(), "estimates": list(ctx.estimates),
                "untrusted": untrusted, "stage": stage}

    def eligible_tool_ids(self, elig: Eligibility) -> list[str]:
        return list(elig.tools) + list(elig.analyzers)


class _Run:
    """One event's bounded loop (kept apart so every step can update the same counters)."""

    def __init__(self, router: ShieldRouter, ctx: EventContext, out: EventOutcome, stage: dict[str, float], strategy: Any):
        self.r, self.ctx, self.out, self.stage, self.s = router, ctx, out, stage, strategy
        self.policy = router.policy
        self.planned_analyzers: list[str] = []
        self.step_index = 0
        self.out_done: EventOutcome | None = None

    # timing helpers: measured service time feeds both the stage table and the deadline clock
    def timed(self, name: str, fn: Callable[..., Any], *a: Any, **kw: Any) -> Any:
        t = time.perf_counter()
        try:
            return fn(*a, **kw)
        finally:
            ms = (time.perf_counter() - t) * 1000
            self.stage[name] += ms
            self.ctx.budget.spend(ms)

    def go(self) -> EventOutcome:
        ctx, out = self.ctx, self.out
        t0 = self.timed("policy", self.policy.tier0, ctx)
        if t0:
            out.tier0 = True
            out.trace.append({"stage": "tier0", "rule": t0.rule_id, "reason": t0.reason})
            return self.finish(t0.disposition, t0.rule_id, t0.reason, status="TIER0_DENY")
        elig = self.timed("policy", self.policy.eligible, ctx, True)
        if self.s.routing_model and not ctx.budget.time_for("decider"):
            return self.fallback("deadline: no time left for the first-pass gatekeeper")
        plan = self.route("first_pass", elig)
        if plan is None:
            return self.out_done
        if plan.get("record") is None:
            out.first_route = plan.get("effective")   # baseline arms without a routing model
        if plan.get("terminal"):
            out.first_pass_resolved = True
            return self.terminal(plan)
        if plan.get("resolve_now") and not plan["steps"]:
            res = self.timed("resolver", resolve, ctx, self.policy, [], [])
            out.trace.append({"stage": "resolver", "status": res.status, "rule": res.rule_id, "reason": res.reason})
            return self.conclude(res)
        return self.loop(list(plan["steps"]))

    # ---- routing calls --------------------------------------------------------------------------

    def route(self, stage_name: str, elig: Eligibility) -> dict[str, Any] | None:
        ctx, out = self.ctx, self.out
        view = self.r.view(ctx, elig, stage_name)
        fn = self.s.first_pass if stage_name == "first_pass" else self.s.reroute
        try:
            plan = fn(ctx, elig, view)
        except ROUTING_ERRORS as e:
            self.out_done = self.failure_policy(f"{self.s.routing_model or 'router'} unavailable or malformed: {type(e).__name__}: {str(e)[:160]}",
                                                error_type=type(e).__name__)
            return None
        if plan is None:
            self.out_done = self.fallback("no routing decision available")
            return None
        rec = plan.get("record")
        if rec is not None:
            ctx.budget.decider_used += 1
            out.routing_model_calls += 1
            if self.s.routing_model == "decider":
                out.decider_calls += 1
                out.decider_questions += int(rec.get("questions_asked", 0))
                out.decision_records.append(rec)
            else:
                out.trace.append({"stage": f"llm_router_{stage_name}", **{k: rec[k] for k in ("verdict", "confidence", "plan", "llm_ms", "tokens", "cached")}})
            self.stage["routing"] += plan.get("routing_ms", 0.0)
            ctx.budget.spend(plan.get("routing_ms", 0.0))
            out.throttle_wait_ms += plan.get("throttle_wait_ms", 0.0)
            out.llm_tokens += int(plan.get("tokens", 0))
            if plan.get("low_confidence"):
                out.low_confidence = True
            if plan.get("ineligible_proposal"):
                out.ineligible_proposals += 1
            out.repeat_suppressed += len(plan.get("repeat_suppressed") or [])
            if stage_name == "first_pass":
                out.first_route = plan.get("effective")
            if ctx.mode != "audit_only" and ctx.budget.remaining_ms < 0:
                # A verdict after the deadline is worthless to an inline hook (the vendor has already applied its own
                # failure mode): end with the safest documented outcome instead of acting on a late answer.
                self.out_done = self.fallback(f"deadline exceeded while waiting for the routing model ({-ctx.budget.remaining_ms:,} ms over "
                                              f"the {ctx.budget.deadline_ms:,} ms budget)", status="UNRESOLVED_BUDGET")
                return None
        plan = self.timed("policy", self.policy.validate, ctx, plan, elig)
        executed = plan.get("terminal") or (("FETCH_EVIDENCE" if plan["steps"][0] in EVIDENCE_TOOLS else "ESCALATE_SEMANTIC")
                                            if plan["steps"] else None)
        if stage_name == "first_pass" and rec is not None and executed:
            out.first_route = executed   # what actually ran first, after policy validation (the raw pick stays in `proposed`)
        if rec is not None:
            rec["executed"] = executed
            if plan["vetoes"]:
                rec["veto"] = "; ".join(plan["vetoes"])
            if plan["overrides"]:
                rec["override"] = "; ".join(plan["overrides"])
                rec["verdict"] = ("investigate: " + " then ".join(x.lower().replace("_", " ") for x in plan["steps"])) if plan["steps"] else rec["verdict"]
                rec["plan"] = plan["steps"] or [plan.get("terminal")]
        out.vetoes += plan["vetoes"]
        out.route_overrides += plan["overrides"]
        self.planned_analyzers += [x for x in plan["steps"] if x in SPECS and x not in self.planned_analyzers]
        sev = None
        if rec is not None and "risk_severity" in (rec.get("probabilities") or {}):
            p = rec["probabilities"]["risk_severity"]
            sev = max(p, key=p.get) if p else None
        if rec is not None:
            ctx.estimates.append(f"{'First pass' if stage_name == 'first_pass' else 'Re-route'} ({'Strands Decider' if self.s.routing_model == 'decider' else 'router'}): "
                                 f"{plan.get('effective')}" + (f"; severity estimate {sev}" if sev else "")
                                 + (f"; planned {', '.join(plan['steps'])}" if plan["steps"] else ""))
        out.routing_records.append(RoutingRecord(
            event_id=ctx.event.event_id, step_index=self.step_index, eligible_options=list(elig.next_steps) + list(elig.tools) + list(elig.analyzers),
            decider_selected_option=plan.get("proposed"), decider_option_probabilities=(rec or {}).get("probabilities", {}).get(
                "next_step_audit" if ctx.mode == "audit_only" else "next_step"),
            effective_option=plan.get("terminal") or ("+".join(plan["steps"]) if plan["steps"] else str(plan.get("effective"))),
            override_rule="; ".join(plan["overrides"]) or None, deadline_ms_remaining=ctx.budget.remaining_ms,
            reroute_reason=plan.get("reroute_reason"), decider_reinvoked=stage_name != "first_pass"))
        if plan.get("fallback"):
            out.trace.append({"stage": "plan_fallback", "reason": plan["fallback"]})
        return plan

    # ---- the bounded loop -----------------------------------------------------------------------

    def loop(self, queue: list[str]) -> EventOutcome:
        ctx, out = self.ctx, self.out
        last: ResultResolution | None = None
        while True:
            if not queue:
                if last is None:
                    return self.fallback("empty plan")
                nxt = self.after_open(last, queue)
                if isinstance(nxt, EventOutcome):
                    return nxt
                queue = nxt
                continue
            step = queue.pop(0)
            if step in ctx.used_tools or step in ctx.failed_tools or step in ctx.used_analyzers:
                out.repeat_suppressed += 1
                out.trace.append({"stage": "repeat_suppressed", "step": step})
                continue
            if ctx.budget.steps_left <= 0:
                return self.fallback("step budget used up")
            now = self.timed("policy", self.policy.eligible, ctx, False)
            if step not in now.tools and step not in now.analyzers:
                out.vetoes.append(f"{step} no longer eligible ({now.notes.get(step, 'policy')})")
                out.trace.append({"stage": "skip", "step": step, "why": now.notes.get(step, "not eligible")})
                if not queue and last is None:
                    last = self.timed("resolver", resolve, ctx, self.policy, [], self.planned_analyzers)
                continue
            self.run_step(step)
            last = self.timed("resolver", resolve, ctx, self.policy, list(queue), self.planned_analyzers)
            self.step_index += 1
            out.routing_records.append(RoutingRecord(
                event_id=ctx.event.event_id, step_index=self.step_index, eligible_options=list(now.tools) + list(now.analyzers),
                effective_option=step, analyzer_or_evidence_tool=step, deadline_ms_remaining=ctx.budget.remaining_ms,
                result_evidence_ids=[step], resolution_status=last.status, resolution_rule_id=last.rule_id))
            out.trace.append({"stage": "resolver", "after": step, "status": last.status, "rule": last.rule_id, "reason": last.reason})
            if self.s.exhaustive:   # always-deep: every planned step runs regardless of intermediate results
                if queue:
                    continue
                return self.conclude(last)
            if self.s.always_reassess and self.s.routing_model:   # F: a Decider call after every downstream result
                elig = self.timed("policy", self.policy.eligible, ctx, True)
                if ctx.budget.decider_left > 0 and ctx.budget.time_for("decider"):
                    out.decider_calls_after_downstream += 1
                    plan = self.route("reroute", elig)
                    if plan is None:
                        return self.out_done
                    out.routing_records[-1].reroute_reason = "always reassess (v0.4 ablation)"
                    if plan.get("terminal"):
                        if last.status in ("SUFFICIENT_DENY",) and plan["terminal"] in ("ALLOW_IF_AUTHORIZED", "RECORD_ONLY"):
                            return self.conclude(last)   # final validation would refuse it anyway; keep the authoritative deny
                        return self.terminal(plan)
                    queue = [x for x in plan["steps"] if x not in queue] + queue
                    if not queue:
                        return self.conclude(last)
                    continue
                return self.conclude(last)
            if last.status in ("SUFFICIENT_DENY", "SUFFICIENT_ALLOW_CANDIDATE", "UNRESOLVED_BUDGET"):
                # conclusive (or nothing left that could change the outcome): no Decider call, queued steps skipped
                if self.s.routing_model:
                    out.decider_calls_saved += 1
                out.queued_steps_skipped = list(queue)
                if last.status == "UNRESOLVED_BUDGET":
                    return self.fallback(last.reason, status=last.status)
                return self.conclude(last)
            nxt = self.after_open(last, queue)
            if isinstance(nxt, EventOutcome):
                return nxt
            queue = nxt

    def after_open(self, res: ResultResolution, queue: list[str]) -> list[str] | EventOutcome:
        """NEEDS_* / CONFLICTING: a queued step that addresses it runs next (no model call); else re-route or fall back."""
        ctx, out = self.ctx, self.out
        if res.status in ("SUFFICIENT_DENY", "SUFFICIENT_ALLOW_CANDIDATE"):
            return self.conclude(res)
        if res.status == "UNRESOLVED_BUDGET":
            return self.fallback(res.reason, status=res.status)
        addressed = [q for q in queue if q in res.needs]
        if addressed:
            if self.s.routing_model:
                out.decider_calls_saved += 1
            return [addressed[0]] + [q for q in queue if q != addressed[0]]
        if not self.s.routing_model:
            return self.fallback(f"{res.status}: {res.reason} (no routing model in this arm)", status=res.status)
        elig = self.timed("policy", self.policy.eligible, ctx, True)
        if not (elig.tools or elig.analyzers):
            return self.fallback(f"{res.status}: no eligible step left", status=res.status)
        if ctx.budget.decider_left <= 0 or not ctx.budget.time_for("decider"):
            return self.fallback(f"{res.status}: routing budget or time used up", status="UNRESOLVED_BUDGET")
        out.decider_calls_after_downstream += 1
        plan = self.route("reroute", elig)
        if plan is None:
            return self.out_done
        out.routing_records[-1].reroute_reason = f"{res.status}: {res.reason}"
        if plan.get("terminal"):
            return self.terminal(plan)
        new = [x for x in plan["steps"] if x not in ctx.used_tools and x not in ctx.used_analyzers and x not in ctx.failed_tools]
        if not new:
            return self.fallback("re-route added no new eligible step (convergence guard)", status=res.status)
        return new

    def run_step(self, step: str) -> None:
        ctx, out = self.ctx, self.out
        ctx.budget.steps_used += 1
        if step in EVIDENCE_TOOLS:
            ctx.budget.evidence_used += 1
            try:
                res = self.timed("evidence", self.r.evidence.run, ctx, step)
            except EvidenceError as e:
                ctx.failed_tools.append(step)
                out.failed_evidence_calls.append(step)
                ctx.done.append({"step": step, "line": f"{step} -> rejected ({e})"})
                return
            if res.get("error"):
                out.failed_evidence_calls.append(step)
                ctx.done.append({"step": step, "line": f"{step} -> {res['error']} (fact stays UNKNOWN; not retried)"})
            else:
                out.evidence_calls.append(step)
                ctx.done.append({"step": step, "line": f"{step} -> {summarize(step, res, ctx)}"})
            return
        spec = SPECS[step]
        ctx.budget.analyzers_used += 1
        ctx.used_analyzers.append(step)
        t = time.perf_counter()
        f, payload = self.r.registry.run(step, ctx)
        local_ms = (time.perf_counter() - t) * 1000
        ms = f.latency_ms if f.latency_ms else local_ms   # a memoised finding is charged its measured live latency
        self.stage["analyzer"] += ms
        ctx.budget.spend(ms)
        out.llm_tokens += f.tokens   # a memoised finding is charged the tokens its live call used, like its latency
        out.analyzer_calls.append(step)
        if ctx.budget.remaining_ms < 0:
            f = f.model_copy(update={"finding_code": "INCONCLUSIVE", "error": f"deadline exceeded ({ms:.0f} ms)"})
        if f.error:
            out.trace.append({"stage": "analyzer_error", "analyzer": step, "error": f.error})
        ctx.findings.append(f)          # evidence for the resolver; it never changes ctx.facts
        out.findings.append(f)
        ctx.estimates.append(f"{step}: {f.finding_code} (self-reported {f.self_reported_confidence:.2f}, uncalibrated) - not authorization")
        # The VERIFIED section only says that the analyzer ran; what it found is a model estimate and is listed there.
        ctx.done.append({"step": step, "line": (f"{step} did not complete ({f.error.split(':')[0]}); no usable finding" if f.error
                                                else f"{step} ran (its finding is listed under MODEL ESTIMATES)")})

    # ---- endings --------------------------------------------------------------------------------

    def terminal(self, plan: dict[str, Any]) -> EventOutcome:
        term = plan["terminal"]
        if plan.get("fallback"):
            self.out.fallback_reason = plan["fallback"]
        reason = {"ALLOW_IF_AUTHORIZED": "fast path: gatekeeper allow, confirmed by final validation",
                  "BLOCK": "gatekeeper block", "REQUIRE_APPROVAL": "plausible need; only the data owner can grant an exception",
                  "RECORD_ONLY": "routine audit record", "AUDIT_ALERT": "gatekeeper alert", "CREATE_REVIEW_CASE": "review case"}.get(term, term)
        if plan.get("fallback"):
            reason = f"safe fallback: {plan['fallback']}"
        return self.finish(term, "ROUTE", reason, status="FIRST_PASS" if self.step_index == 0 else "REROUTE_TERMINAL")

    def conclude(self, res: ResultResolution) -> EventOutcome:
        if res.status in ("SUFFICIENT_DENY", "SUFFICIENT_ALLOW_CANDIDATE") and res.disposition:
            return self.finish(res.disposition, res.rule_id, res.reason, status=res.status)
        return self.fallback(f"{res.status}: {res.reason}", status=res.status)

    def fallback(self, reason: str, status: str | None = None) -> EventOutcome:
        ctx = self.ctx
        self.out.fallback_reason = reason
        if ctx.mode == "audit_only":
            disp = "AUDIT_ALERT" if self.policy.impact(ctx) in ("high", "critical") else "CREATE_REVIEW_CASE"
        else:
            disp = "BLOCK"
        return self.finish(disp, "FALLBACK", f"safe fallback: {reason}", status=status or "UNRESOLVED_BUDGET")

    def failure_policy(self, reason: str, error_type: str | None = None) -> EventOutcome:
        """R1.5: the routing model is unavailable or malformed -> configured failure policy, never a made-up answer."""
        self.out.trace.append({"stage": "failure_policy", "reason": reason, "error_type": error_type})
        self.out.fallback_reason = reason
        disp = "CREATE_REVIEW_CASE" if self.ctx.mode == "audit_only" else "BLOCK"
        return self.finish(disp, "FAILURE_POLICY", f"failure policy: {reason}", status="UNRESOLVED_BUDGET")

    def finish(self, disposition: str, rule_id: str | None, reason: str, status: str | None = None) -> EventOutcome:
        ctx, out = self.ctx, self.out
        decision = self.timed("policy", self.policy.finalize, ctx, disposition, rule_id, reason)
        if decision.rule_id == "FINAL" and disposition not in (decision.disposition,):
            out.vetoes.append(f"final validation turned {disposition} into {decision.disposition}: {decision.reason}")
        if decision.disposition == "REQUIRE_APPROVAL":
            out.approval_request = self.r.approvals.request(ctx)
        if decision.disposition == "ALLOW" and ctx.grant is not None:
            self.r.approvals.consume(ctx)
            out.trace.append({"stage": "approval", "grant": ctx.grant.grant_id, "consumed": True})
        adapter = self.r.adapters.get(ctx.event.provider) or self.r.adapters["simulator"]
        out.enforcement = self.timed("enforcement", adapter.enforce, ctx, decision)
        if decision.disposition == "ALLOW" and ctx.is_egress() and ctx.target and ctx.event.destination:
            ctx.graph.add_send(ctx.target, ctx.event.destination)
        out.disposition, out.rule_id, out.reason, out.advisory = decision.disposition, decision.rule_id, decision.reason, list(decision.advisory)
        out.resolution_status = out.resolution_status or status
        out.steps = ctx.budget.steps_used
        out.stage_ms = {k: round(v, 3) for k, v in self.stage.items()}
        out.service_ms = round(sum(self.stage.values()), 3)
        if out.decision_records:
            last = out.decision_records[-1]
            last["outcome"] = (f"{decision.disposition} ({decision.rule_id}): {decision.reason}"[:300])
        self.out_done = out
        return out


def summarize(step: str, res: dict[str, Any], ctx: EventContext) -> str:
    if step == "CHECK_IAM_PERMISSION":
        return f"{res.get('decision')} (iam)"
    if step == "GET_RESOURCE_LABEL":
        return f"{res.get('label')} (labels)"
    if step == "VERIFY_RECIPIENT":
        return f"{res.get('class')} (allowed up to {res.get('max_label') or 'nothing'})"
    if step == "GET_PROVENANCE":
        return ctx.lineage.describe(ctx.world) if ctx.lineage else "no record"
    return "done"
