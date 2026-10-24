"""Trusted policy engine (design.md section 4): replaceable interface + deterministic Python implementation.

`PolicyEngine` is the seam an OPA-backed engine would implement later: it declares EVERY member the
pipeline (router, resolver, approvals, strategies) calls, and the conformance test routes scenarios
through a wrapper that exposes nothing else. `OpaPolicyEngine` is the deferred stub (every member
raises NotImplementedError). `DeterministicPolicyEngine` enforces the mandatory checks from
agent/data/policy_bundle.json:

- hard rules (Tier 0 and final validation; never overridable by any model): H1 verified IAM deny,
  H2 RESTRICTED egress outside the company, H3 CONFIDENTIAL+ to a personal or blocklisted
  destination, H4 blocklisted destination, P1 label above the destination's level and not approvable;
- hold rule H5: label above the destination's level, approvable by exactly one data owner -> only
  that owner's grant can lift it;
- ALLOW is impossible without verified identity, permission, label and destination facts, a
  permitted destination, completed mandatory analyzers and no deny finding;
- analyzer findings are evidence: a DENY finding can end an event, but no finding ever sets a fact
  (permission, label, lineage, recipient). A derived artifact with a lineage gap keeps its label
  UNKNOWN (or its retained elevated label) until the provenance service closes the gap;
- audit-only events never get ALLOW / BLOCK / REDACT (R6a.9).

It also computes the eligible next steps, lookups and analyzers that the Decider may choose
from, post-validates every plan and finalizes every disposition (hard rules and deny findings first).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .analyzers import applicable
from .catalog import FACT_TO_TOOL
from .schemas import LABEL_RANK, PolicyDecision

UNRESOLVED = ("unknown", "stale", "conflicted", "untrusted")
# How restrictive a disposition is (used so that no later step can soften a conclusive deny)
RESTRICTIVENESS = {"ALLOW_IF_AUTHORIZED": 0, "ALLOW": 0, "RECORD_ONLY": 0, "REQUIRE_APPROVAL": 1, "CREATE_REVIEW_CASE": 1,
                   "AUDIT_ALERT": 2, "BLOCK": 2}


@dataclass
class Eligibility:
    next_steps: list[str]
    tools: list[str]
    analyzers: list[str]
    mandatory: list[str]
    notes: dict[str, str] = field(default_factory=dict)
    allow_blockers: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, list[str]]:
        return {"next_steps": list(self.next_steps), "tools": list(self.tools), "analyzers": list(self.analyzers)}


def supports(ctx: Any, spec: Any) -> bool:
    """Kept for compatibility; the prerequisite lives with the analyzer registry (analyzers.applicable)."""
    return applicable(ctx, spec)


@runtime_checkable
class PolicyEngine(Protocol):
    """Everything the AgentShield pipeline asks of a policy engine (a real OPA-backed engine implements exactly this)."""

    version: str
    registry: Any                     # the analyzer registry used for eligibility (set by the router)

    # facts the policy needs for the pending operation
    def required_facts(self, ctx: Any) -> list[str]: ...
    def unresolved(self, ctx: Any) -> list[str]: ...
    # hard rules (Tier 0 and final validation) and rule texts
    def hard_rules(self, ctx: Any) -> list[tuple[str, str]]: ...
    def tier0(self, ctx: Any) -> PolicyDecision | None: ...
    def rule_text(self, rule_id: str) -> str: ...
    # mandatory analyzers and the versioned finding map
    def mandatory_analyzers(self, ctx: Any) -> list[tuple[str, str]]: ...
    def pending_mandatory(self, ctx: Any) -> list[str]: ...
    def map_finding(self, finding_code: str) -> str: ...
    def finding_map_version(self) -> str: ...
    # approvals (LOOKUP_APPROVAL_POLICY and the H5 hold)
    def approval_policy(self, ctx: Any) -> dict[str, Any] | None: ...
    def approval_required(self, ctx: Any) -> dict[str, Any] | None: ...
    def approvable(self, ctx: Any) -> bool: ...
    def grant_valid(self, ctx: Any) -> bool: ...
    # allow conditions, eligibility, plan validation and the final word
    def allow_blockers(self, ctx: Any) -> list[str]: ...
    def eligible(self, ctx: Any, reserve_routing: bool = True) -> Eligibility: ...
    def validate(self, ctx: Any, plan: dict[str, Any], elig: Eligibility) -> dict[str, Any]: ...
    def finalize(self, ctx: Any, disposition: str, rule_id: str | None = None, reason: str = "") -> PolicyDecision: ...
    # policy impact: a policy axis, separate from the Decider's severity estimate
    def impact(self, ctx: Any) -> str: ...


POLICY_ENGINE_METHODS = ("required_facts", "unresolved", "hard_rules", "tier0", "rule_text", "mandatory_analyzers", "pending_mandatory",
                         "map_finding", "finding_map_version", "approval_policy", "approval_required", "approvable", "grant_valid",
                         "allow_blockers", "eligible", "validate", "finalize", "impact")
POLICY_ENGINE_ATTRIBUTES = ("version", "registry")


def _deferred(name: str) -> Any:
    def method(self: Any, *a: Any, **k: Any) -> Any:
        raise NotImplementedError(f"deferred: a real OPA server is not part of the MVP ({name}); use DeterministicPolicyEngine")
    method.__name__ = name
    return method


class OpaPolicyEngine:
    """Placeholder for a real OPA server (deferred: no OPA deployment in the MVP). It has the full PolicyEngine
    shape, so swapping it in is a constructor change; every call raises until a real server backs it."""

    version = "opa-deferred"
    registry: Any = None

    def __init__(self, url: str = ""):
        self.url = url


for _name in POLICY_ENGINE_METHODS:
    setattr(OpaPolicyEngine, _name, _deferred(_name))


class DeterministicPolicyEngine:
    def __init__(self, world: Any, registry: Any = None):
        self.world = world
        self.bundle = world.bundle
        self.version = self.bundle["version"]
        self.registry = registry   # analyzer registry (for eligibility); set by the router

    # ---- facts ----------------------------------------------------------------------------------

    def required_facts(self, ctx: Any) -> list[str]:
        req = ["identity", "permission"]
        req += ["artifact_label", "lineage"] if ctx.is_artifact else ["resource_label"]
        if ctx.is_egress():
            req.append("recipient")
        return req

    def unresolved(self, ctx: Any) -> list[str]:
        return [n for n in self.required_facts(ctx) if (f := ctx.fact(n)) is None or f.status in UNRESOLVED]

    def rule_text(self, rule_id: str) -> str:
        for section in ("hard_rules", "hold_rules", "audit_rules"):
            if rule_id in self.bundle.get(section, {}):
                return self.bundle[section][rule_id]
        for r in self.bundle.get("mandatory_analyzer_rules", []):
            if r["rule_id"] == rule_id:
                return r["reason"]
        return rule_id

    # ---- destination rules ----------------------------------------------------------------------

    def _dest_max(self, ctx: Any) -> int | None:
        if not ctx.dest:
            return None
        m = ctx.dest.get("max_label")
        return LABEL_RANK[m] if m in LABEL_RANK else -1   # blocklisted: nothing may go there

    def destination_permitted(self, ctx: Any) -> bool | None:
        """None while the label or destination is unknown."""
        if not ctx.is_egress():
            return True
        lab, mx = ctx.label(), self._dest_max(ctx)
        if lab == "UNKNOWN" or mx is None:
            return None
        return LABEL_RANK[lab] <= mx

    def approval_policy(self, ctx: Any) -> dict[str, Any] | None:
        """LOOKUP_APPROVAL_POLICY: the policy under which ONE data owner may grant this exception, or None.

        Only the sources whose own label is above what the destination may receive need an exception. If more
        than one source needs one, no single owner has authority over all of the material: not approvable."""
        srcs = ctx.source_ids()
        if not srcs:
            return None
        if ctx.is_egress():
            mx = self._dest_max(ctx)
            if mx is None:
                return None   # destination not verified yet: too early to say who could approve
            need = [s for s in srcs if LABEL_RANK.get(self.world.label_of(s) or "", 99) > mx]
        else:
            need = list(srcs)
        if len(need) != 1:
            return None
        return self.world.approval_policy(need, ctx.op, ctx.dest_class() if ctx.is_egress() else None)

    def approval_required(self, ctx: Any) -> dict[str, Any] | None:
        """H5: the destination is verified and below the label, and an approval policy covers it."""
        if ctx.is_egress() and self.destination_permitted(ctx) is False and ctx.dest_class() == "external_business":
            return self.approval_policy(ctx)
        return None

    # ---- hard rules (Tier 0, the resolver and final validation) ---------------------------------

    def hard_rules(self, ctx: Any) -> list[tuple[str, str]]:
        hits: list[tuple[str, str]] = []
        rules = self.bundle["hard_rules"]
        perm = ctx.fact("permission")
        if perm and perm.status == "verified" and perm.value == "DENY":
            hits.append(("H1", rules["H1"]))
        if ctx.is_egress():
            lab, dc = ctx.label(), ctx.dest_class()
            internal = dc == "internal"
            if lab == "RESTRICTED" and not internal:
                hits.append(("H2", rules["H2"]))
            if lab in ("CONFIDENTIAL", "RESTRICTED") and dc in ("personal", "blocklisted"):
                hits.append(("H3", rules["H3"]))
            if dc == "blocklisted":
                hits.append(("H4", rules["H4"]))
            if self.destination_permitted(ctx) is False and not hits and not self.approval_required(ctx):
                hits.append(("P1", rules["P1"]))
        return hits

    def tier0(self, ctx: Any) -> PolicyDecision | None:
        hits = self.hard_rules(ctx)
        if not hits:
            return None
        rid, why = hits[0]
        return PolicyDecision(disposition="AUDIT_ALERT" if ctx.mode == "audit_only" else "BLOCK", rule_id=rid, reason=why)

    # ---- mandatory analyzers and the finding map ------------------------------------------------

    def mandatory_analyzers(self, ctx: Any) -> list[tuple[str, str]]:
        out = []
        if not ctx.is_egress():
            return out
        srcs = set(ctx.source_ids())
        for r in self.bundle.get("mandatory_analyzer_rules", []):
            if r["when_source"] in srcs and ctx.op in r["operations"]:
                out.append((r["analyzer"], r["rule_id"]))
        return out

    def pending_mandatory(self, ctx: Any) -> list[str]:
        passed = {f.analyzer_id for f in ctx.findings if self.map_finding(f.finding_code) == "PASS"}
        return [a for a, _ in self.mandatory_analyzers(ctx) if a not in passed]

    def map_finding(self, finding_code: str) -> str:
        """DENY / PASS / INCONCLUSIVE. PASS only means 'this check found nothing'; it never establishes a fact."""
        return self.bundle["finding_map"].get(finding_code, "INCONCLUSIVE")

    def finding_map_version(self) -> str:
        return self.bundle["finding_map"]["version"]

    def _deny_findings(self, ctx: Any) -> list[Any]:
        return [f for f in ctx.findings if self.map_finding(f.finding_code) == "DENY"]

    # ---- allow conditions -----------------------------------------------------------------------

    def allow_blockers(self, ctx: Any) -> list[str]:
        out = []
        hits = self.hard_rules(ctx)
        if hits:
            out.append("hard rule " + ",".join(r for r, _ in hits))
        for n in self.unresolved(ctx):
            out.append(f"{n} {ctx.fact(n).status if ctx.fact(n) else 'missing'}")
        perm = ctx.fact("permission")
        if perm and perm.status == "verified" and perm.value != "ALLOW":
            out.append("permission not granted")
        dp = self.destination_permitted(ctx)
        if dp is False:
            if self.approval_required(ctx) and not self.grant_valid(ctx):
                out.append("data-owner approval required (H5)")
            elif not self.approval_required(ctx):
                out.append("destination not permitted for the label")
        for a in self.pending_mandatory(ctx):
            out.append(f"mandatory analyzer {a} pending")
        if self._deny_findings(ctx):
            out.append("deny finding")
        return out

    def grant_valid(self, ctx: Any) -> bool:
        return bool(ctx.grant is not None and not ctx.grant.used)

    # ---- eligibility ----------------------------------------------------------------------------

    def eligible(self, ctx: Any, reserve_routing: bool = True) -> Eligibility:
        b = ctx.budget
        notes: dict[str, str] = {}
        tools: list[str] = []
        unresolved = self.unresolved(ctx)
        for n in unresolved:
            t = FACT_TO_TOOL.get(n)
            if not t or t in tools:
                continue
            if t == "CHECK_IAM_PERMISSION" and not ctx.verified("identity"):
                notes[t] = "no verified actor id to look up"
                continue
            if t in ctx.used_tools or t in ctx.failed_tools:
                notes[t] = "already used for this event"
                continue
            if b.evidence_left <= 0:
                notes[t] = "lookup budget used up"
                continue
            if not b.time_for("evidence", reserve_routing):
                notes[t] = "not enough time left"
                continue
            tools.append(t)
        if "identity" in unresolved:
            notes["identity"] = "no lookup can verify identity"
        analyzers: list[str] = []
        lab = ctx.label()
        for spec in (self.registry.specs() if self.registry else []):
            aid = spec.analyzer_id
            if not applicable(ctx, spec):
                continue
            if aid in ctx.used_analyzers:
                notes[aid] = "already ran for this event"
            elif not spec.available or aid in ctx.unavailable_analyzers:
                notes[aid] = "unavailable"
            elif lab != "UNKNOWN" and LABEL_RANK[lab] > LABEL_RANK[spec.data_classification_clearance]:
                notes[aid] = f"not cleared for {lab} content"
            elif b.analyzers_left <= 0:
                notes[aid] = "analyzer budget used up"
            elif not (b.remaining_ms - b.guard_ms >= spec.expected_latency_ms + (b.expected_ms.get("decider", 0) if reserve_routing else 0)):
                notes[aid] = f"not enough time left (~{max(0, b.remaining_ms) / 1000:.0f} s) for ~{spec.expected_latency_ms / 1000:.0f} s"
            else:
                analyzers.append(aid)
        mandatory = self.pending_mandatory(ctx)
        blockers = self.allow_blockers(ctx)
        if ctx.mode == "audit_only":
            steps = (["RECORD_ONLY"] if not blockers else []) + ["AUDIT_ALERT", "CREATE_REVIEW_CASE"]
        else:
            steps = (["ALLOW_IF_AUTHORIZED"] if not blockers else []) + ["BLOCK"]
        if tools:
            steps.append("FETCH_EVIDENCE")
        if analyzers:
            steps.append("ESCALATE_SEMANTIC")
        if ctx.mode != "audit_only" and self.approvable(ctx):
            steps.append("REQUIRE_APPROVAL")
        return Eligibility(steps, tools, analyzers, mandatory, notes, blockers)

    def approvable(self, ctx: Any) -> bool:
        """REQUIRE_APPROVAL is offered only for a verified actor, a known destination, no deny finding and an approval policy."""
        if not ctx.verified("identity") or self.hard_rules(ctx) or self._deny_findings(ctx):
            return False
        perm = ctx.fact("permission")
        if perm and perm.status == "verified" and perm.value == "DENY":
            return False
        if ctx.is_egress() and not ctx.verified("recipient"):
            return False
        if self.grant_valid(ctx) and self.approval_required(ctx):
            return False   # a matching grant already covers it
        return self.approval_policy(ctx) is not None

    # ---- post-validation and final validation ---------------------------------------------------

    def validate(self, ctx: Any, plan: dict[str, Any], elig: Eligibility) -> dict[str, Any]:
        """Veto ineligible picks, drop ineligible steps, force mandatory analyzers (route_override)."""
        plan = dict(plan)
        plan.setdefault("vetoes", [])
        plan.setdefault("overrides", [])
        term = plan.get("terminal")
        if term and term not in elig.next_steps:
            plan["vetoes"].append(f"{term} not eligible ({'; '.join(elig.allow_blockers) or 'policy'})")
            plan["terminal"] = None
            term = None
        steps = []
        for s in plan.get("steps", []):
            if s in elig.tools or s in elig.analyzers:
                steps.append(s)
            else:
                plan["vetoes"].append(f"{s} not eligible")
        plan["steps"] = steps
        wants_allow = plan.get("demoted_allow") or plan.get("proposed") in ("ALLOW_IF_AUTHORIZED", "RECORD_ONLY")
        for a in elig.mandatory:
            if a in elig.analyzers and a not in steps and (term is None or term in ("ALLOW_IF_AUTHORIZED", "RECORD_ONLY") or wants_allow):
                plan["overrides"].append(f"route_override: mandatory {a}")
                plan["terminal"] = None
                plan["fallback"] = None
                plan["steps"] = [s for s in steps if s not in elig.analyzers] + [a]
                term = None
                steps = plan["steps"]
        if not plan.get("terminal") and not plan["steps"] and not plan.get("resolve_now"):
            plan["terminal"] = "BLOCK" if ctx.mode != "audit_only" else "CREATE_REVIEW_CASE"
            plan["fallback"] = plan.get("fallback") or "no eligible step after validation"
        return plan

    def finalize(self, ctx: Any, disposition: str, rule_id: str | None = None, reason: str = "") -> PolicyDecision:
        """The final word on EVERY disposition, whoever proposed it (gatekeeper, resolver, fallback, ablation re-route).

        1. a hard rule wins over any disposition: inline BLOCK / audit-only AUDIT_ALERT, with the rule's id;
        2. so does a finding mapped to DENY (REQUIRE_APPROVAL is never possible with one);
        3. ALLOW / RECORD_ONLY need every allow condition; REQUIRE_APPROVAL needs an approvable action."""
        d = {"ALLOW_IF_AUTHORIZED": "ALLOW"}.get(disposition, disposition)
        audit = ctx.mode == "audit_only"
        if audit and d in ("ALLOW", "BLOCK", "REDACT"):
            d = "RECORD_ONLY" if d == "ALLOW" else "AUDIT_ALERT"
        if not audit and d in ("RECORD_ONLY", "AUDIT_ALERT", "CREATE_REVIEW_CASE"):
            d = "BLOCK"
        deny = "AUDIT_ALERT" if audit else "BLOCK"
        hits = self.hard_rules(ctx)
        if hits:
            rid, why = hits[0]
            if d == deny and rule_id == rid:
                return PolicyDecision(disposition=deny, rule_id=rid, reason=reason or why)
            return PolicyDecision(disposition=deny, rule_id=rid,
                                  reason=f"final validation: hard rule {rid} ({why})" + (f"; proposed {disposition}" if d != deny else ""))
        denied = self._deny_findings(ctx)
        if denied:
            f = denied[0]
            frid = f"{self.finding_map_version()}:{f.finding_code}"
            if d == deny and rule_id == frid:
                return PolicyDecision(disposition=deny, rule_id=frid, reason=reason)
            return PolicyDecision(disposition=deny, rule_id=frid,
                                  reason=f"final validation: {f.analyzer_id} reported {f.finding_code} (mapped to DENY)"
                                  + (f"; proposed {disposition}" if d != deny else ""))
        blockers = self.allow_blockers(ctx)
        if d in ("ALLOW", "RECORD_ONLY") and blockers:
            fallback = "CREATE_REVIEW_CASE" if audit else "BLOCK"
            return PolicyDecision(disposition=fallback, rule_id="FINAL", reason="final validation: " + "; ".join(blockers))
        if d == "REQUIRE_APPROVAL" and not self.approvable(ctx):
            return PolicyDecision(disposition="BLOCK", rule_id="FINAL", reason="final validation: not approvable")
        advisory = []
        if audit and rule_id == "A2":
            advisory.append("RECOMMEND_POLICY_CHANGE: require the derivation review before files derived from board minutes can be shared")
        return PolicyDecision(disposition=d, rule_id=rule_id, reason=reason, advisory=advisory)  # type: ignore[arg-type]

    # ---- impact (a policy axis, separate from the Decider's severity estimate) -------------------

    def impact(self, ctx: Any) -> str:
        levels = ["low", "moderate", "high", "critical"]
        lab = ctx.label()
        rank = LABEL_RANK.get(lab)
        if not ctx.is_egress():
            i = {0: 0, 1: 0, 2: 1, 3: 2}.get(rank, 1) if rank is not None else 1
        else:
            dc = ctx.dest_class()
            if dc == "internal":
                i = {0: 0, 1: 0, 2: 1, 3: 2}.get(rank, 1) if rank is not None else 1
            elif dc in ("approved_partner", "nda_partner"):
                ok = self.destination_permitted(ctx)
                i = (0 if rank in (0, 1) else 1) if ok else (3 if rank == 3 else 2)
            elif dc in ("personal", "blocklisted"):
                i = 0 if rank == 0 and dc == "personal" else (2 if rank in (None, 0, 1) else 3)
            else:   # external business or not yet known
                i = {0: 0, 1: 1, 2: 2, 3: 3}.get(rank, 2) if rank is not None else 2
        res = ctx.world.resources.get(ctx.event.resource_id or "", {})
        if ctx.op == "export_records" or res.get("records", 0) > 1000 and ctx.is_egress():
            i += 1
        return levels[min(3, i)]
