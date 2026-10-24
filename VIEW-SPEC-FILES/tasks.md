# AgentShield — Implementation Tasks

**Instruction to Kiro:** Strands Decider is required as the single shared semantic fast-triage and adaptive next-action/evidence/specialist router. Do not force a second model call after a conclusive downstream result; use deterministic policy validation instead. Do not silently substitute a generative LLM. Begin with an architecture and provider-capability verification, then implement and test an isolated simulator before attempting live integrations. Treat every unchecked task as not implemented.

## Phase 0: Verify interfaces and set guardrails

- [ ] Inspect current Strands Decider repo, CLI/server docs, actual `/v1/systemone` request/response schema, `choice` with runtime-defined options, and published model checkpoints.
- [ ] Confirm availability of `StrandsAgents/strands-decider-2B-qwen3.5-v1-2610` or select the nearest verified published model and document the substitution.
- [ ] Verify Claude Enterprise Inference Hooks protocol and its current availability/coverage/permission requirements.
- [ ] Verify Microsoft Purview DLP and Copilot audit integrations; write a capability matrix that distinguishes preventive and retrospective controls.
- [ ] Create a threat model showing endpoint bypass, agent/runtime trust, model inference, identity, approval, and vendor limitations.
- [ ] Define synthetic data and ensure tests contain no real sensitive records or credentials.

## Phase 1: Shared event architecture and hard policy baseline

- [ ] Initialize modular Python project with FastAPI/Pydantic, types, linting, tests, and documented local setup.
- [ ] Implement `SecurityEvent`, `DeciderResult`, `DeciderActionChoice`, `EvidenceState`, `SecurityAction`, `PolicyDecision`, `AdapterCapabilities`, and `ApprovalGrant` schemas.
- [ ] Implement synthetic enterprise actor, permissions, resources, labels, destination classes, and task descriptions.
- [ ] Create simulator adapter with deterministic fake access/read/send actions and interception modes.
- [ ] Implement hard policy engine that denies unauthorized operations independently of model output.
- [ ] Add structured audit with minimized sensitive-content storage.
- [ ] Write tests proving `BLOCK` happens before simulated execution and has no unsafe fall-through.

## Phase 2: Make Strands Decider the intelligence core

- [ ] Start Strands Decider locally, pin model/revision, and smoke-test health and typed questions.
- [ ] Create one shared context builder and versioned questions for both **risk assessment** and **next-security-action choice** (`noul`, `choice`, `score`).
- [ ] Implement batched/shared-context inference through `POST /v1/systemone`.
- [ ] Implement strict validation of model responses, latency metrics, and model availability checks.
- [ ] Keep risk outputs and confidence separate from verified IAM/ACL authorization.
- [ ] Implement **Action Catalog** with typed IDs, prerequisites, capabilities, and side-effect classifications, including `ESCALATE_SEMANTIC`.
- [ ] Build policy/capability prefilter that yields **only eligible actions** to Decider's `choice(next_action)`; include `FETCH_EVIDENCE`, `ESCALATE_SEMANTIC`, `REQUIRE_APPROVAL`, `BLOCK`, `ALLOW_IF_AUTHORIZED` only when prerequisites hold.
- [ ] Implement a second Decider `choice(evidence_tool)` from a vetted set of security tools when `FETCH_EVIDENCE` is selected.
- [ ] Implement security tools for verified IAM permissions, resource labels, destination/recipient approval, and provenance using synthetic services; construct typed parameters from trusted IDs, never generated model strings.
- [ ] Implement bounded Observe -> Decider -> Execute security tool -> **deterministic result resolution** -> (direct policy enforcement if conclusive; **conditional Decider re-routing** otherwise), with maximum steps, deadlines, caching/idempotency, and safe fallback.
- [ ] Implement hard-policy veto and log `proposed_action` versus `executed_action`, including fallback reason.
- [ ] Test prompt-injection content within model `state`, unknown resource classification, truncated evidence, invalid action suggestions, repeated evidence requests, unavailable tools, low-confidence routing, bad responses, and timeout handling.
- [ ] Compare rule-only versus rules + Decider across initial benchmark cases; this is an early baseline, not evidence of production effectiveness.

## Phase 2A: Decider-led fast triage and complete routing (v0.5 differentiator)

- [ ] Implement deterministic policy-derived **required facts** and typed evidence freshness/completeness; do not rely on Decider-generated guesses for identity or ACLs.
- [ ] Add distinct fields for impact severity, semantic complexity, evidence completeness, decision uncertainty, and provider coverage.
- [ ] Implement the unified adaptive routing engine: known violation -> immediate deterministic denial; verified eligible low-risk action -> Decider fast path; missing evidence -> Decider `FETCH_EVIDENCE`; deeper semantic ambiguity/high-impact -> Decider `ESCALATE_SEMANTIC`.
- [ ] Implement `next_security_step` `choice` with action options computed from real availability and authorization constraints; record all probabilities and route overrides.
- [ ] Prove via tests that a confident `ALLOW_IF_AUTHORIZED` result never bypasses IAM, DLP, required labels, or mandatory analysis rules.
- [ ] Demonstrate fast benign/obviously disallowed decisions that do not need an expensive specialist.

## Phase 2B: Add specialist analyzer registry and deep semantic branch

- [ ] Implement `AnalyzerRegistry`, `AnalyzerSpec`, structured `AnalyzerFinding`, and privacy/clearance controls.
- [ ] Add synthetic `SEMANTIC_DLP`, `PROMPT_INJECTION_FORENSICS`, and `SENSITIVE_DERIVATION_REVIEW` analyzers with deterministic fixture outputs; do not start with an external paid LLM.
- [ ] Add Decider `choice(specialist)` from currently eligible specialists (or safe deterministic singleton selection), including analyzer availability and budget.
- [ ] Treat specialist results as *untrusted findings*, never authorization or direct vendor verdicts.
- [ ] Implement typed `ResultResolution` statuses (`SUFFICIENT_ALLOW_CANDIDATE`, `SUFFICIENT_DENY`, `NEEDS_MORE_EVIDENCE`, `NEEDS_OTHER_SPECIALIST`, `CONFLICTING`, `UNRESOLVED_BUDGET`) and a **deterministic result resolver**; on sufficient findings proceed directly to policy enforcement **without reentering Decider**. On inconclusive/conflicting findings, reenter Decider **only** when another eligible investigation choice exists.
- [ ] Implement explicit `mandatory_escalation` rules for high-impact situations even if Decider wants fast approval.
- [ ] Test both evidence-then-specialist and specialist-then-evidence routes when permissible; each successive Decider call must be justified by a pending choice. Implement budget caps and loop detection.
- [ ] Unit-test no redundant Decider invocation after verified IAM `DENY`, verified recipient decision with complete policy facts, or validated specialist terminal finding. Test reroute on unknown/stale/conflicting evidence and no eligible next tool -> safe fallback.

## Phase 2C: Latency, privacy and routing benchmarks

- [ ] Implement stage-by-stage latency and cost logging: policy, Decider, evidence retrieval, specialist, deterministic result resolution, final enforcement. Record `decider_reinvoked`, `resolution_status`, and `reroute_reason`.
- [ ] Add provider-specific deadlines, protective safety margin, maximum evidence/specialist calls, cache TTL and timeout-safe fallbacks.
- [ ] Build labeled cases that distinguish low-risk/complete, high-risk/deterministic, unknown authorization, complex semantic disclosure, and combined uncertainty+severity.
- [ ] Run first comparisons against rules-only, fixed heuristic router, always-deep specialist, and a **v0.4 always-reassess Decider** at **matched mandatory authorization**. Verify that avoiding redundant inference does not change safe policy outcomes.
- [ ] Report routing errors where Decider skipped a useful investigation or triggered unnecessary deep analysis; include examples of forced policy overrides.

## Phase 3: Context, provenance and approvals

- [ ] Track `resource -> tool result -> context -> derived artifact -> destination` lineage through the simulated workflow.
- [ ] Conservatively propagate sensitivity labels and record incomplete lineage.
- [ ] Implement authenticated, TTL-limited, single-use approval grants tied to exact action digests.
- [ ] Support approval denial, expiry, tampering, and re-evaluation before retry.
- [ ] Test benign confidential access, unauthorized access, prohibited external disclosure, and paraphrase-derived disclosure.

## Phase 4: Claude Enterprise integration

- [ ] Build a local HTTP contract-test harness with realistic **synthetic** signed webhook fixtures.
- [ ] Implement request signature verification, replay/timestamp validation, and strict input normalization.
- [ ] Support `prompt` and grouped `tool_call` frames and return valid protocol `allow` or `deny` (HTTP 200 for intentional deny).
- [ ] Connect adapter to shared Strands Decider **triage and conditional re-routing**; conclusive downstream results must bypass any extra Decider inference. Ensure the total pipeline meets vendor hook deadline and returns only supported allow/deny responses.
- [ ] Map unsupported `REDACT`, `GUIDE`, and `REQUIRE_APPROVAL` to documented safe fallback (usually deny now, with out-of-band remediation for future retry).
- [ ] Test tool frames with mixed safe/unsafe calls, unexposed tools, unexpected metadata, failure and circuit-breaker cases.
- [ ] Only after authorized tenant access, implement a separately reviewed optional live smoke test. Never require live tenant access to complete the local MVP.

## Phase 5: Microsoft 365 Copilot integration (later)

- [ ] Build an explicit audit/native-policy capability matrix from currently documented Microsoft APIs.
- [ ] Implement a fixture-driven Copilot audit event parser and normalization adapter (no tenant required for tests).
- [ ] Send normalized observations to the **same Strands Decider core**, routing among eligible audit actions such as `AUDIT_ALERT` and `CREATE_REVIEW_CASE` (not retrospective blocking).
- [ ] Surface actionable security alerts and proposed Purview policy adjustments; do not change production policies autonomously.
- [ ] Clearly distinguish prevention by Microsoft-native DLP from post-event AgentShield detection.
- [ ] Add live Microsoft read-only integration only after tenant permissions and source API contracts are verified.

## Phase 6: Evaluation, documentation and demo

- [ ] Create labeled synthetic benign/adversarial scenarios with expected policy outcomes and per-provider coverage flags.
- [ ] Benchmark rules-only, stateless classifier, fixed heuristic routing, always-deep specialist, private generative-LLM routing (if an approved model is available), and Decider adaptive routing; hold mandatory authorization and tools constant.
- [ ] Report classifier precision/recall, severity-weighted unsafe-allow rate, **tier-routing accuracy, specialist escalation precision/recall, evidence acquisition value, avoided specialist calls, task completion, p50/p95 end-to-end latency, per-stage latency and estimated costs**, coverage gaps and approval burden.
- [ ] Demonstrate known-rule denial, low-risk fast path, **unknown-authorization -> Decider-selected evidence lookup -> direct policy enforcement**, **sensitive paraphrase -> Decider-selected semantic specialist -> direct policy enforcement when finding is conclusive**, **inconclusive finding -> conditional Decider re-routing**, combined evidence+specialist workflow, and scoped approval/retry.
- [ ] Produce operator docs, a clearly scoped capability matrix, known limitations, threat model, and installation/run instructions.
- [ ] Obtain user review of design/metrics before any production rollout or changes to enterprise security policies.

## Definition of done for MVP

The local demo must show **Strands Decider performing fast semantic triage and selecting when to call evidence tools or deeper semantic specialists; a deterministic resolver concluding when findings suffice; and conditional Decider re-routing only when another step is necessary**. The trusted policy engine enforces every final decision. Provider adapters must not contain independent competing semantic classifiers. Claude hook simulation must be protocol-accurate for tested cases. Microsoft integration may remain fixture-only/audit-only. Tests must demonstrate that unsupported preventive actions are never falsely presented as successful prevention. Successful MVP includes at least one scenario for each of FAST, EVIDENCE, DEEP_SEMANTIC, combined EVIDENCE+DEEP_SEMANTIC, and forced policy escalation; it must log actual latency/call savings rather than assume them.
