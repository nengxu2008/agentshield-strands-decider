# AgentShield — Requirements

**Status:** Prototype specification v0.5 (2026-10-23)  
**Intended user:** Enterprise security and compliance teams  
**Protected targets:** Third-party enterprise AI products (Claude Enterprise first; Microsoft 365 Copilot second)  
**Required intelligence engine:** Strands Decider (locally/private-network hosted)  
**Scope:** Decider-centric, multi-tier security triage; risk-based evidence retrieval; advanced semantic-analysis escalation; Decider-led action selection; verified enterprise enforcement

## Product goal

Build a vendor-independent, Strands Decider-centric security system that analyzes observable third-party AI agent events, uses the Decider to **rapidly triage risk, estimate evidence completeness and semantic complexity, route optional investigations or specialized analyzers, and select the next permitted security action**, and applies enterprise policy through the enforcement mechanisms each vendor genuinely offers. Protect access **and** disclosure where technically possible. Never present retrospective detections as prevented events.

## Definitions

- **Observed event:** Information supplied by a vendor inference hook, security connector, endpoint adapter, or audit event.
- **Inline event:** An event intercepted before the governed action happens, with a documented enforcement mechanism.
- **Audit-only event:** An event ingested after the action or without control over its execution.
- **Decider:** The Strands Decider model and versioned questions; it classifies risk **and routes the next security action/tool**, but its outputs are probabilistic recommendations, not verified permissions.
- **Policy engine:** Trusted deterministic enforcement logic and verified enterprise authorization, which prefilters eligible actions and may veto any model recommendation.
- **Security action:** A structured operation in the AgentShield security service (allow, deny, gather evidence, warn, request approval, etc.), not an arbitrary tool call inside the protected agent.
- **Security tool:** An allowlisted, read-only or explicitly authorized service such as IAM permission lookup, data-label lookup, recipient verification, or provenance retrieval.
- **Conditional routing loop:** Bounded sequence of Decider triage -> policy-constrained routing -> verified evidence/advanced analysis -> deterministic result-resolution check. Only if findings are inconclusive, inconsistent, or further investigation is required does control return to Strands Decider; otherwise continue directly to policy validation and enforcement.
- **Analysis tier:** `FAST`, `EVIDENCE`, or `DEEP_SEMANTIC` (not mutually exclusive across a case).
- **Enhanced analyzer:** An approved security specialist or isolated private model that returns structured evidence, never direct authorization.
- **Completeness:** A structured assessment of which facts required by policy are known, verified, fresh, and traceable; model-estimated completeness is merely an additional signal.
- **Routing decision:** A Decider `choice` result over an allowlisted, capability-filtered selection of terminal and nonterminal actions.
- **Enforcement adapter:** Vendor-specific translator from an authorized policy outcome to supported vendor operations.
- **Provenance label:** Conservative security classification inherited from known data sources or transformations, not proof that every fact in an output is confidential.

## Functional requirements (testable)

### R1 — Decider centrality
1. WHEN an event requires contextual assessment **or selection among policy-eligible actions**, THE SYSTEM SHALL submit its normalized state to **Strands Decider**, using versioned `noul`, `choice`, and/or `score` questions.
2. THE SYSTEM SHALL NOT substitute a generative LLM for Decider triage or routing. An approved larger model MAY operate as a **downstream evidence-producing analyzer** after Decider selects escalation. Its structured findings SHALL be validated by deterministic policy; a new Decider call is required **only if** additional action/tool selection is necessary. Downstream findings SHALL NOT independently grant access or execute provider verdicts.
3. THE SYSTEM SHALL retain the model identifier, question-set version, returned probabilities/distribution, and inference latency in the decision record.
4. WHEN hard policy already prohibits an event, THE SYSTEM MAY immediately deny it without querying the model; a model SHALL NEVER override the denial. For nontrivial contextual decisions, the Decider SHALL select the next proposed security action from a constrained list, not merely report risk scores.
5. WHEN Decider is unavailable or returns malformed data, THE SYSTEM SHALL apply the configured failure policy rather than fabricate model output.

### R2 — Observable behavior, not assumed hidden thoughts
1. THE SYSTEM SHALL classify observed prompts, proposed tool calls, tool results when available, resources, destinations, policy metadata, and task context.
2. THE SYSTEM SHALL NOT require hidden chain-of-thought, model weights, or internal state of third-party agents.
3. IF reasoning summaries are exposed, THE SYSTEM MAY treat them as **untrusted contextual signals**, never proof of authorization or actual access.
4. THE SYSTEM SHALL distinguish attempted access, actual completed access, attempted disclosure, and confirmed disclosure as separate event/outcome types.

### R3 — Third-party provider adapters
1. THE SYSTEM SHALL implement a **simulated Claude Inference Hooks adapter** with contract tests before any live integration.
2. THE SYSTEM SHALL support the documented Claude Enterprise request-signature verification, replay controls, request types, and `allow`/`deny` responses; signature verification MUST use raw request bytes.
3. WHEN Claude provides a grouped tool-call frame, THE SYSTEM SHALL return one verdict for the complete frame; it SHALL NOT claim granular authorization per call.
4. THE SYSTEM SHALL document tool actions and content not covered by the vendor hook.
5. THE SYSTEM SHALL implement a separate **Microsoft 365 Copilot audit/native-policy adapter** only after confirming relevant API permissions and available vendor interfaces. Unless an actual inline interface is established, it SHALL be labeled `audit_only` or `native_policy`, not `inline_block`.
6. THE SYSTEM SHALL maintain a capability registry per integration, including visibility, supported policy actions, latency budget, and evidence of enforcement.

### R4 — Access and disclosure
1. BEFORE executing a covered data-read tool action, THE SYSTEM SHALL check verified permissions and detect suspicious task-to-resource mismatch.
2. BEFORE executing a covered external-send action, THE SYSTEM SHALL check destination, permission, data classification, and known provenance.
3. WHEN visibility is incomplete, THE SYSTEM SHALL express that explicitly instead of asserting that all data access or disclosure is protected.
4. THE SYSTEM SHALL not infer that a resource was accessed solely from an agent's stated intention.

### R5 — Risk classification
1. THE SYSTEM SHALL submit one **structured shared state** with multiple scoped questions to Strands Decider, when supported by the model server.
2. THE SYSTEM SHALL evaluate at minimum: sensitive-content indication, task relevance, suspicious instruction likelihood, and destination mismatch. Unknown fields SHALL be represented as unknown, not guessed.
3. THE SYSTEM SHALL distinguish **model uncertainty** from **business impact**. A high-confidence classification of low impact is not equivalent to a low-confidence classification of high impact.
4. THE SYSTEM SHALL NOT treat the model's confidence as a calibrated probability of harm without independent evaluation on the project's security data.

### R6 — Policy and enforcement
1. THE SYSTEM SHALL implement trusted rules for permissions, prohibited destinations, labeled data, immutable restrictions, and approval authority.
2. THE SYSTEM SHALL support internal enforcement outcomes `ALLOW`, `BLOCK`, `WARN`, `REDACT`, `REQUIRE_APPROVAL`, `GUIDE`, `FETCH_EVIDENCE`, `ASK_CLARIFICATION`, and `AUDIT_ALERT`, plus proposed routing actions `ALLOW_IF_AUTHORIZED` and `ESCALATE_SEMANTIC`, but the candidate list passed to Decider SHALL be filtered by verified permissions, provider mode, and adapter capabilities. Every adapter SHALL map only to **documented supported actions**.
3. WHEN a vendor only supports `allow`/`deny`, THE SYSTEM SHALL map an unfulfilled approval requirement to `deny` plus separately initiated approval/retry; it SHALL NOT promise native pause/resume.
4. THE SYSTEM SHALL allow redaction only on a controllable data path with revalidation; Claude Inference Hooks shall not be advertised as allowing prompt transformation.
5. WHEN critical enforcement logic is unavailable for a truly intercepted high-impact operation, THE SYSTEM SHALL fail closed according to administrator-approved configuration and vendor failure handling. It SHALL never falsely claim that local fail-closed settings override a vendor-managed fail-open configuration.

### R6a — Decider-driven action selection and security-tool routing
1. THE SYSTEM SHALL implement a versioned **Action Catalog** with typed action IDs, purpose, risk class, prerequisites, side effects, provider capabilities, and allowed requester/reviewer roles.
2. AFTER assembling context and evaluating non-negotiable policy constraints, THE SYSTEM SHALL ask Strands Decider a `choice` question: **"Which eligible AgentShield security action should happen next?"** Candidate options SHALL be populated only from approved, supported actions; the Decider SHALL NOT invent action names or parameters.
3. WHEN evidence is missing, `FETCH_EVIDENCE` SHALL be a legitimate Decider-selected next action. For this outcome, THE SYSTEM SHALL ask a second typed `choice` question selecting from the **eligible, read-only security tools**, e.g. `CHECK_IAM_PERMISSION`, `GET_RESOURCE_LABEL`, `VERIFY_RECIPIENT`, or `GET_PROVENANCE`.
4. THE SYSTEM SHALL deterministically construct security-tool arguments from normalized event identifiers and authenticated/trusted context. Model text SHALL NOT become an unrestricted URL, filesystem path, SQL query, command, or arbitrary API argument.
5. AFTER an evidence tool returns, THE SYSTEM SHALL update the evidence state and run a **deterministic result-resolution check**. If findings conclusively satisfy a policy rule, THE SYSTEM SHALL proceed **directly** to final policy validation and enforcement without reinvoking Decider. It SHALL invoke Decider again only for unresolved/contradictory evidence or when another optional tool/action must be selected. Apply strict per-event step, time, and idempotency limits; never recurse without bounds.
6. Unknown permissions, missing classification, untrusted evidence, and timed-out checks SHALL NOT be reinterpreted as authorization. On exhausted budget, use a documented policy-safe fallback (`BLOCK`/hold for inline actions; `AUDIT_ALERT` for audit-only events).
7. `ASK_CLARIFICATION` only requests task details and SHALL NOT grant permission. `REQUIRE_APPROVAL` SHALL route to a reviewer with verified authority; neither choice can override a hard prohibition.
8. The system SHALL persist **proposed Decider action, action-choice distribution/confidence, effective action, veto/fallback reason, security tool invoked, result, and decision-loop count** in minimized audit metadata.
9. WHEN the provider is `audit_only`, THE SYSTEM SHALL exclude real-time `ALLOW`, `BLOCK`, or inline `REDACT` from available actions and may select `AUDIT_ALERT`, `CREATE_REVIEW_CASE`, or `RECOMMEND_POLICY_CHANGE` (advisory only, never automatic enterprise policy mutation in the MVP).
10. Any Decider choice uncertainty threshold used to trigger verification or escalation SHALL be tuned on this project's labeled security dataset. The published model's choice confidence is **not** a guarantee that the chosen action is secure.

### R6b — Adaptive analysis tiers, result resolution, and conditional re-routing (central v0.5 requirement)
1. THE SYSTEM SHALL implement three distinct evaluation tiers: (0) mandatory deterministic policy checks; (1) **Strands Decider fast triage and routing**; (2) targeted evidence acquisition and/or **enhanced semantic security analysis**. After any downstream response, a deterministic resolver SHALL choose either **direct policy enforcement** or **conditional re-routing through Decider**.
2. THE SYSTEM SHALL assess **severity, evidence completeness, semantic ambiguity, impact/irreversibility, and tool cost/deadline** separately. A low-confidence estimate of severity SHALL NOT be confused with low severity.
3. THE SYSTEM SHALL track **required_facts**, **verified_facts**, **unknown_facts**, **stale_facts**, **conflicted_facts**, and their **source and timestamp**. Mandatory facts SHALL be derived from trusted policy, not solely from the model's opinion.
4. WHEN the security violation is deterministic (e.g., verified denied access), THE SYSTEM SHALL deny without expensive model inference; this is an intentionally measured short-circuit, not a claim that Decider decided an explicit policy rule.
5. FOR eligible contextual cases, Strands Decider SHALL select a **next route or action** from runtime-defined supported candidates, including `ALLOW_IF_AUTHORIZED`, `BLOCK`, `FETCH_EVIDENCE`, `ESCALATE_SEMANTIC`, `REQUIRE_APPROVAL`, and safe provider-mode-specific alternatives.
6. WHEN evidence is materially missing, the Decider MAY route to a vetted evidence tool. WHEN semantic interpretation exceeds its capability, the Decider MAY route to an approved specialized analyzer; the system SHALL also apply **mandatory escalation overrides** for configured high-impact or low-coverage categories regardless of Decider confidence.
7. AN event MAY move through `EVIDENCE` then `DEEP_SEMANTIC`, or vice versa if safe and allowed; no architecture rule SHALL artificially require the paths to be mutually exclusive. Cycles must terminate under explicit limits.
8. AFTER either kind of investigation, THE SYSTEM SHALL evaluate result **sufficiency** before any additional model call. If authoritative evidence establishes a required permission/denial, or a validated specialist finding satisfies a predefined security-policy disposition with all mandatory prerequisites met, THE SYSTEM SHALL proceed directly to deterministic policy validation and provider enforcement. A specialist SHALL NOT itself execute `ALLOW` or `BLOCK`, invent permissions, or bypass the policy engine. Reinvoke Strands Decider **only** when another decision about *which investigation/action to take next* is needed.
9. THE SYSTEM SHALL record the proposed route, effective route, required/missing evidence, analyzer selected, reasons, costs, elapsed time, evidence identifiers, and all safety overrides.
10. THE SYSTEM SHALL prove by tests that `FAST` decisions are **not** fast-path policy bypasses: `ALLOW` is ineligible unless necessary verified permissions and provider protections are satisfied.
11. Missing mandatory facts, model uncertainty, and advanced analyzer disagreement SHALL lead to bounded further checks **when an eligible next step exists**, or a policy-safe fallback, never silent authorization. Decider re-routing SHALL be conditional, never automatic after every downstream call.
12. THE SYSTEM SHALL implement a typed `ResultResolution` with `SUFFICIENT_ALLOW_CANDIDATE`, `SUFFICIENT_DENY`, `NEEDS_MORE_EVIDENCE`, `NEEDS_OTHER_SPECIALIST`, `CONFLICTING`, and `UNRESOLVED_BUDGET`. The policy engine SHALL determine sufficiency using verified facts, approved finding-to-policy mappings, mandatory-check completion, source freshness, and vendor capabilities; the resolver SHALL NOT trust a specialist’s bare assertion of authorization. `SUFFICIENT_ALLOW_CANDIDATE` SHALL still require final authorization validation.
13. THE SYSTEM SHALL log whether a Decider re-routing call was **skipped** or **performed**, plus `resolution_status`, policy rule/reason, and any extra tool chosen; unnecessary model passes SHALL be counted in evaluation.

### R6c — Enhanced analyzer registry and safe escalation
1. THE SYSTEM SHALL define an `AnalyzerRegistry` of explicitly approved specialists (e.g., `SEMANTIC_DLP`, `PROMPT_INJECTION_FORENSICS`, `SENSITIVE_DERIVATION_REVIEW`) with versioned input/output schemas, capabilities, cost/latency estimates, data-access rules, and clearance level.
2. Enhanced analyzers MAY include specialized deterministic detectors, purpose-built security models, and privately deployed LLMs, but SHALL be treated as **tools invoked by Strands Decider**, not a replacement for Decider orchestration.
3. Every analyzer SHALL receive the **least information necessary**; enterprise confidential content MUST NOT be sent to public external model APIs without verified organizational approval and a documented data-processing boundary.
4. Analyzer output SHALL be structured as findings, supporting evidence references, limitations, and calibrated scores only when validated. Free-form claims of access permission SHALL have no authority. When specialist findings are mapped to a terminal policy disposition, the mapping must be explicitly approved, versioned, and deterministic; a negative specialist finding alone cannot establish missing IAM permission.
5. Security-service results, documents, and tool responses SHALL be treated as untrusted data for instruction-following purposes, even when sourced from approved tools. Do not allow a result to redefine policies, Decider options, or authorization facts.
6. The registry SHALL expose deterministic routing prerequisites, including maximum impact level requiring escalation, availability, safety clearance and remaining deadline. A mandatory analyzer cannot be skipped by a Decider `ALLOW` suggestion.
7. When a specialist is unavailable, timed out, or contradicted by authoritative data, the system SHALL use explicitly tested policy fallbacks and record the reason.

### R7 — Approvals
1. A human approval SHALL only be accepted from a verified principal with authority over the resource, recipient, and operation.
2. Approvals SHALL be short lived, scoped to a cryptographic digest of the proposed action/recipient/resource, and single-use by default.
3. Changed actions or expired grants SHALL require fresh evaluation.
4. For an `allow`/`deny`-only provider, after approval the **next equivalent request** SHALL be reevaluated; no claim of resuming the original request.

### R8 — Privacy and isolation
1. Decider inference SHALL run in an enterprise-controlled private environment for the MVP (localhost during simulation; managed private inference in production).
2. Prompt and document content SHALL NOT be copied to external model APIs or telemetry services by default.
3. Audit logs SHALL minimize raw-content retention and support configurable retention limits.
4. Untrusted tool output SHALL not be able to alter policies, question definitions, authentication metadata, or system directives.
5. The stock Strands Decider local inference server SHALL not be directly exposed to the public internet; place it behind a hardened authenticated service.

### R9 — Evaluation
1. THE SYSTEM SHALL include synthetic scenarios for benign access, inappropriate access, confidential-to-external disclosure, paraphrased leakage, prompt injection, grouped tool calls, approvals, missing metadata, timeout, replay, and unsupported integration paths.
2. THE SYSTEM SHALL compare (a) mandatory rules only, (b) always-run enhanced semantic analysis, (c) general-purpose LLM routing, (d) **Strands Decider adaptive routing**, and (e) fixed heuristic routing, all with the SAME required authorization checks and available evidence tools.
3. THE SYSTEM SHALL measure false positives, severity-weighted unsafe-allow rate, recall at matched false-positive rates, successful legitimate-task completion, missed enforcement opportunities, total inference/evidence costs, p50/p95 latency, intervention correctness, abstention/escalation rate, **next-route correctness, evidence-tool selection quality, escalation precision/recall, nonproductive calls, average/max decision steps, and factual completeness before/after investigation**.
4. THE SYSTEM SHALL report enforcement **coverage** separately from classifier accuracy.
5. THE SYSTEM SHALL establish benchmark scenarios where (i) high-impact action is obvious and directly denied; (ii) benign action is safely fast-pathed; (iii) unknown identity facts require targeted retrieval; (iv) high-impact semantic leakage requires a specialized analyzer; (v) both retrieval and deep semantic analysis are required.
6. The system SHALL report average savings **at matched security constraints**, compared with always-deep and LLM-router baselines, without inventing speed or quality gains prior to measurement.

## Explicit non-goals (MVP)

- Reading hidden chain-of-thought from third-party systems.
- Universal interception of Microsoft 365 Copilot's internal tool calls.
- Guaranteeing sensitive-information tracking through arbitrary LLM paraphrases.
- Bypassing native provider IAM/DLP or creating permissions employees do not have.
- Fully autonomous policy editing or grant issuance by a language model.
- Unreviewed deployment of enforcement to live enterprise tenants.

## Acceptance criteria

- The simulator demonstrably intercepts an unauthorized tool call and blocks it before simulated execution.
- A confidential-source-derived synthetic output sent to an external destination is denied by policy even if obvious PII patterns are absent.
- Every contextual result and eligible security-action proposal is sourced from Strands Decider (with model version, question set, and choice distribution recorded); a deterministic hard deny is never overridable.
- A missing-authorization test proves the Decider can select `FETCH_EVIDENCE`, choose `CHECK_IAM_PERMISSION`, and let a conclusive verified permit/deny proceed **directly to deterministic enforcement** without an unnecessary Decider call.
- Decision loops terminate within configured step/time limits and return safe fallback outcomes when evidence remains missing; no unauthorized security tool is executed.
- Three simulations demonstrate **fast Decider triage**, **Decider-selected targeted evidence gathering**, and **Decider-selected enhanced semantic analysis** using a typed analyzer registry.
- A combined scenario demonstrates targeted evidence collection followed by deeper semantic analysis; it re-routes through Decider **only if** a meaningful next investigation or action choice remains.
- High-impact overrides force deeper review even when Decider suggests `ALLOW`; downstream semantic tools never directly authorize execution.
- A conclusive specialist finding proceeds through a predefined policy disposition to enforcement **without** mandatory Decider reassessment; incomplete/contradictory findings trigger conditional re-routing or safe fallback.
- Tests verify fewer Decider inference calls on conclusive downstream outcomes than the v0.4 always-reassess baseline, without increased unsafe allows under the same policy.
- A benchmark compares Decider-driven adaptive routing against always-deep, fixed-routing, and generative LLM routing with common mandatory policy checks.
- A provider in audit-only mode can generate a review case but never claims it blocked a previously executed action.
- A Claude adapter passes synthetic signed-request and allow/deny protocol tests, including tampering/replay checks.
- Unsupported Microsoft inline enforcement is not presented as prevention in UI or reports.
- Timeouts, malformed results, and adapter limitations are exposed, tested, and documented.
