"""AgentShield v0.5: a Strands Decider-centric adaptive security router for third-party AI agents.

Pipeline for every observed event (one code path for the chat agent, the demo and every benchmark arm):

    adapter.verify_and_normalize -> context.build_context -> TIER 0 policy.tier0 (hard denies are final)
      -> policy.eligible -> TIER 1 Strands Decider first-pass gatekeeper (one batched call, <= 4 questions)
      -> plan (fast allow / fast block / approval, or evidence and/or semantic analysis)
      -> TIER 2 evidence tools and analyzers -> deterministic resolver after every result
      -> policy.finalize -> adapter.enforce (inline-hook vendor: allow/deny; audit-only vendor: record/alert/case)

The reusable decision pattern (questions, state layout, plan rules, convergence guard) is in
agent/decision.py. Everything here is the participant's own code; decider_kit/ is the AWS User
Group Madurai kit's library.
"""
