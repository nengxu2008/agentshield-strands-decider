# AgentShield — Kiro Project Brief v0.5

**Focus:** Strands Decider-powered **adaptive security routing**, not a generic LLM-based DLP scanner. This version refines v0.4 by keeping fast first-pass triage, targeted evidence collection, and specialist semantic escalation while **removing mandatory post-investigation Decider reassessment**. Only inconclusive findings trigger conditional re-routing; enterprise authorization remains authoritative.

## Product thesis

A fast, non-generative decision model can allocate enterprise security analysis to the minimum necessary depth for each third-party AI-agent event. Its `choice` outputs select a trusted next step; more capable analyzers and IAM/OPA return evidence; a deterministic result resolver proceeds directly to enforcement when findings suffice. Strands Decider only selects another step when further investigation is necessary. Hard security policy remains authoritative.

## Use with Kiro

1. Copy `.kiro/specs/agentshield/` into the root of your Kiro workspace.
2. In Kiro, enter this prompt:

> Read all of `.kiro/specs/agentshield/{requirements.md,design.md,tasks.md,evaluation-plan.md}`. Build AgentShield v0.5 as a **Strands Decider-centric adaptive security decision router with conditional re-routing**. The main design advantage is its low-latency first-pass triage and dynamic selection among: (a) directly propose allow/block when policy-evaluable, (b) target missing evidence using trusted read-only tools, and (c) request deeper semantic security analysis from an approved specialist model. Multiple investigative tiers may be combined. Do **not** automatically call Strands Decider again after evidence or specialist responses: resolve findings deterministically; if conclusive, validate policy and enforce immediately. Reinvoke Decider **only if** facts remain incomplete or conflicting and another eligible action/tool must be selected. Never treat specialist text as permission. Verify the current upstream API schemas. First complete Phase 0, Phase 1 and Phase 2A on synthetic data; then Phase 2B specialist mocks and benchmark comparisons. Do not substitute an LLM for Strands Decider routing, do not claim unsupported provider enforcement, and do not use real credentials. Produce runnable code and tests, not just a plan.

3. Run Kiro's implementation and evaluation against simulated agents before pursuing live Claude Enterprise integrations. Microsoft Copilot starts as an audit/native-policy adapter, not universal inline prevention.

## Files

- `requirements.md`: Testable business/security requirements, including tiered routing and privacy rules.
- `design.md`: Trust boundaries, schemas, event-to-action state machine, Decider questions, specialist registry, and provider adapters.
- `tasks.md`: Ordered Kiro implementation checklist, with newly added Phases 2A, 2B, 2C.
- `evaluation-plan.md`: Research baselines, metrics, scenario families, confounders and proof-of-value gates.

## Important principles

- **Core innovation:** Strands Decider decides *how much more security reasoning/evidence is necessary* and selects the next approved tool, making investigation conditional and cost-aware.
- **No false fast-pass:** Mandatory IAM/OPA/DLP checks are never skipped even with high model confidence.
- **No competing semantic orchestrator:** Deep models supply structured findings; Strands Decider remains the action router **when a next choice is needed**.
- **Conclusive-result shortcut:** Verified identity/policy results or validated specialist findings follow an approved deterministic disposition directly to enforcement.
- **Conditional re-routing:** Incomplete, stale, or conflicting findings trigger another Decider selection only when a useful authorized next step exists; otherwise safe fallback.
- **Context as needed:** Verified evidence completeness, business impact, semantic ambiguity, and provider capabilities control eligibility.
- **Honest vendor support:** Claude Inference Hooks issue allow/deny, not native redact/pause. Audit-only Microsoft observations cannot retrospectively block.
- **Measured, not assumed:** Low latency, avoided deep calls, and equal or better security are hypotheses to benchmark.

Official references:
- https://github.com/strands-labs/strands-decider
- https://github.com/strands-labs/strands-decider/blob/main/docs/inference.md
- https://github.com/strands-labs/strands-decider/blob/main/docs/architecture.md
- https://www.openpolicyagent.org/docs/agent-tool-calling
- https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint
