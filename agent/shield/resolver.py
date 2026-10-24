"""Deterministic downstream-result resolver (design.md 2B, R6b.12). No model runs here.

After every evidence lookup or analyzer finding it decides, from verified facts, the versioned
finding map and the policy engine (PolicyEngine members only), whether the event can go straight to
final policy validation (SUFFICIENT_DENY / SUFFICIENT_ALLOW_CANDIDATE) or needs another step.
Strands Decider is asked again only when this returns NEEDS_* / CONFLICTING, no queued step
addresses it, and an eligible step remains ("When NOT to reinvoke Strands Decider", rules 1 to 5).

Analyzer findings are evidence: a finding mapped to DENY ends the event, a clean finding only
satisfies a planned or mandatory check. No finding ever establishes a fact, so a required fact that
no eligible lookup can establish means no allow is possible: the event ends with the safe fallback
and queued steps are skipped (rule 5: "otherwise hold/block or alert by provider mode").
"""

from __future__ import annotations

from typing import Any

from .analyzers import SPECS
from .catalog import FACT_TO_TOOL
from .schemas import ResultResolution


def resolve(ctx: Any, policy: Any, queued: list[str] | None = None, planned_analyzers: list[str] | None = None) -> ResultResolution:
    queued = list(queued or [])
    planned = list(planned_analyzers or [])
    audit = ctx.mode == "audit_only"
    deny = "AUDIT_ALERT" if audit else "BLOCK"

    # 1. a hard rule is now triggered by verified evidence (IAM deny, blocklisted recipient, RESTRICTED source...)
    hits = policy.hard_rules(ctx)
    if hits:
        return ResultResolution(status="SUFFICIENT_DENY", rule_id=hits[0][0], disposition=deny, reason=hits[0][1])
    # 2. a validated finding mapped to DENY by the versioned finding map
    fm = policy.finding_map_version()
    for f in ctx.findings:
        if policy.map_finding(f.finding_code) == "DENY":
            return ResultResolution(status="SUFFICIENT_DENY", rule_id=f"{fm}:{f.finding_code}", disposition=deny,
                                    reason=f"{f.analyzer_id} reported {f.finding_code} (mapped to DENY)")
    # 3. audit-only: a mandatory pre-egress analyzer that never ran before the data left -> review case (A2)
    if audit and policy.mandatory_analyzers(ctx):
        return ResultResolution(status="SUFFICIENT_DENY", rule_id="A2", disposition="CREATE_REVIEW_CASE", reason=policy.rule_text("A2"))
    # 4. the destination needs a data-owner exception (H5): hold, deny now, verified retry later
    if policy.approval_required(ctx) and not policy.grant_valid(ctx):
        return ResultResolution(status="SUFFICIENT_DENY", rule_id="H5", disposition="CREATE_REVIEW_CASE" if audit else "REQUIRE_APPROVAL",
                                reason=policy.rule_text("H5"))
    required = policy.required_facts(ctx)
    conflicted = [n for n in required if ctx.fact(n) and ctx.fact(n).status == "conflicted"]
    if conflicted:
        return ResultResolution(status="CONFLICTING", reason=f"conflicting trusted evidence for {', '.join(conflicted)}", needs=conflicted)

    elig = policy.eligible(ctx, reserve_routing=False)
    unresolved = policy.unresolved(ctx)
    # 5. a required fact that no eligible lookup can establish (findings never set facts): no allow is possible,
    #    so no further step can change the outcome
    stuck = [n for n in unresolved if FACT_TO_TOOL.get(n) not in elig.tools]
    if stuck and elig.analyzers and not ctx.used_analyzers and not ctx.findings:
        # rule LG1: an analyzer can still turn the fallback into an evidence-backed deny; it can never allow
        return ResultResolution(status="NEEDS_OTHER_SPECIALIST", rule_id="LG1", needs=list(elig.analyzers),
                                reason=f"{', '.join(stuck)} cannot be established by a lookup; only an analyzer deny can add evidence "
                                       "(analyzer findings never set facts)")
    if stuck:
        return ResultResolution(status="UNRESOLVED_BUDGET",
                                reason=f"{', '.join(stuck)} cannot be established (no eligible lookup; analyzer findings never set facts): "
                                       "no allow is possible")
    # 6. a planned or mandatory analyzer still has to run before anything can be allowed
    pending = [a for a in queued if a in SPECS] + [a for a in policy.pending_mandatory(ctx) if a not in ctx.used_analyzers]
    pending_ok = [a for a in dict.fromkeys(pending) if a in elig.analyzers]
    if pending_ok:
        return ResultResolution(status="NEEDS_OTHER_SPECIALIST", reason="a planned or mandatory analyzer has not run yet", needs=pending_ok)
    # 7. a required fact is still unknown/stale and an eligible lookup can settle it
    if unresolved:
        tools = [t for t in elig.tools if t in {FACT_TO_TOOL.get(n) for n in unresolved}]
        return ResultResolution(status="NEEDS_MORE_EVIDENCE", reason=f"unresolved: {', '.join(unresolved)}", needs=tools)
    # 8. a finding that cannot be mapped (INCONCLUSIVE / error) or a planned analyzer that could not run
    ran = {f.analyzer_id for f in ctx.findings if not f.error}
    unmapped = [f.analyzer_id for f in ctx.findings if policy.map_finding(f.finding_code) == "INCONCLUSIVE"]
    missing = [a for a in planned if a not in ran]
    if unmapped or missing:
        why = (f"{', '.join(unmapped)} inconclusive" if unmapped else "") + ("; " if unmapped and missing else "") + \
              (f"planned {', '.join(missing)} did not complete" if missing else "")
        if elig.analyzers or elig.tools:
            return ResultResolution(status="CONFLICTING", reason=why, needs=list(elig.tools) + list(elig.analyzers))
        return ResultResolution(status="UNRESOLVED_BUDGET", reason=why + "; no eligible step left")
    # 9. everything required is verified, permitted and checked
    blockers = policy.allow_blockers(ctx)
    if not blockers:
        return ResultResolution(status="SUFFICIENT_ALLOW_CANDIDATE", rule_id="PERMIT", disposition="RECORD_ONLY" if audit else "ALLOW",
                                reason="all required facts verified, destination permitted, required checks passed")
    return ResultResolution(status="UNRESOLVED_BUDGET", reason="; ".join(blockers))
