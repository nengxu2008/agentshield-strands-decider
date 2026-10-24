# AgentShield — Technical Design

## Design principle

**Strands Decider is the single shared semantic triage and adaptive next-action/investigation router.** Third-party agent products are integrated through replaceable observation/enforcement adapters, but cannot replace its contextual assessments or its choice among policy-eligible *next steps* whenever a choice is needed. Trusted authorization and vendor enforcement remain separate to guarantee that an uncertain model never grants unauthorized access. Hard denials may short-circuit inference.

## Logical architecture

```text
   Claude Enterprise          Microsoft 365 Copilot       Future vendors
  (Inference Hooks)          (Purview / audit / API)    (verified interfaces)
          |                           |                         |
          +---------------------------+-------------------------+
                                      |
                        Provider Adapter Registry
                       verify + normalize + capabilities
                                      |
                         Context and Provenance Store
                       task/user/resource/destination/labels
                                      |
                   Hard-policy & Capability Prefilter
                   verified permissions + safe action candidates
                                      |
                         Strands Decider Core
                    fast risk assessment + evidence completeness + tier/tool `choice`
                                      |
                  Trusted Policy/Authorization Validator
                   veto + constrained execution + step budget
                                      |
                     Evidence / Advanced Analyzer Dispatcher
                        optional tool -> structured findings
                                      |
                         Deterministic Result Resolver
                   sufficient -> final policy / inconclusive -> Decider
                                      |
                    Vendor enforcement or audit outcome
                                      |
                        Audit, approval and reporting
```

### Key boundaries

- **Vendor integration trust boundary:** Verify signed hooks and reject untrusted provenance claims. Audit events and prompts are data, not administrator instructions.
- **Inference trust boundary:** Decider is an untrusted probabilistic assessor; it cannot issue permissions, edit policy, or make HTTP calls to other tools on its own.
- **Enforcement trust boundary:** A final verdict must pass hard authorization rules and a provider-capability check.
- **Coverage boundary:** Only actions documented as intercepted and confirmed through integration tests can be called prevented.

## v0.5 architecture: selective security computation + conditional re-routing (primary product differentiator)

**Central hypothesis:** Decider's non-generative, runtime-defined `choice` output can cheaply select *the minimum appropriate security work* per event: immediate deny where violations are evident, allow only with verified baseline authorization, retrieve missing facts where that would resolve the question, and consult a stronger semantic specialist where the question requires more capable interpretation. **Conclusive downstream findings terminate at deterministic policy enforcement; Strands Decider is called again only when another routing decision is actually needed.** This is an experimental product advantage, not an established performance result.

```text
External AI product (Claude Enterprise | Microsoft 365 Copilot | future adapters)
          |
  [Authenticated, normalized observation + coverage declaration]
          |
  [TIER 0: Deterministic guardrail / OPA / IAM]
          |-- verified forbidden or unobservable ---> deny if inline / alert if audit-only
          |
  [TIER 1: STRANDS DECIDER — FAST TRIAGE + ADAPTIVE ROUTING]
          |-- ALLOW_IF_AUTHORIZED -----> [Final policy validation] -> vendor verdict
          |-- BLOCK -------------------> [Final policy validation] -> vendor verdict
          |-- REQUIRE_APPROVAL --------> [Scoped approval or deny/retry]
          |-- FETCH_EVIDENCE ----------> [Tier 2A: IAM/label/provenance/recipient]
          |-- ESCALATE_SEMANTIC -------> [Tier 2B: specialist DLP/injection/LLM]
          |                                         |
          |                         [Structured findings + sources + freshness]
          |                                         |
          |                         [DETERMINISTIC RESULT RESOLVER]
          |                           |                       |
          |                CONCLUSIVE / POLICY READY    UNRESOLVED / CONFLICTING
          |                           |                       |
          |                           v                       v
          |                [Final policy validation]  [Strands Decider: select NEXT step]
          |                           |                       |
          |                    vendor verdict          bounded investigation or fallback
          |
  [Audit actual enforcement effect + provenance / provider coverage]
```

**Tier separation, not competing decision engines:** Specialist models detect deeper issues and supply *structured findings*. OPA/IAM supply *trusted authorization*. Strands Decider chooses *which eligible checks/analyzers/next actions to use*. A trusted result resolver checks whether those findings are sufficient for a deterministic policy disposition; it only sends inconclusive cases back to Decider. Policy and provider integration enforce the outcome.

### Decision axes — do not collapse them into one score

| Axis | Example values | Trusted or probabilistic? | Governs |
| --- | --- | --- | --- |
| `impact` | low, moderate, high, critical | Policy/resource metadata first; model may supplement | mandatory specialist escalation; safe fallback |
| `completeness` | sufficient, missing, stale, conflicting | Deterministic check of required fields + evidence source | targeted evidence tool availability |
| `semantic_complexity` | simple, unclear, complex | Decider classification | enhanced semantic analyzer choice |
| `model_uncertainty` | per-option distribution / calibrated confidence | Probabilistic, validation-dependent | abstention, investigate, escalate |
| `coverage` | inline, native_policy, audit_only | Provider capability registry | legal actions actually executable |
| `remaining_budget` | latency, tool calls, privacy exposure | Runtime accounting | restrict choices and force safe termination |

Examples:
- **Known violation:** Verified nonauthorized employee requests restricted payroll data -> deterministic deny, optionally record for analysis; don't burn a Decider pass or an LLM call.
- **Verified benign:** Public document, authorized task, approved destination -> Decider `ALLOW_IF_AUTHORIZED` -> mandatory post-check passes. No deep analysis.
- **Unknown fact, resolved:** Confidential file to contractor -> Decider `FETCH_EVIDENCE` then `VERIFY_RECIPIENT`; if trusted directory returns verified denial, deny directly via policy; no second Decider inference.
- **Semantically complex, resolved:** Disguised prompt injection or confidential report paraphrased to evade regex -> Decider `ESCALATE_SEMANTIC` to private `SENSITIVE_DERIVATION_REVIEW`; if findings match a predefined deny/hold rule, enforce that rule directly without Decider reassessment.
- **Both, conditionally re-routed:** Unknown original lineage + subtle egress -> Decider gathers provenance; if provenance is sufficient to block, enforce directly. If semantic uncertainty persists, Decider selects an approved specialist and the resolver determines whether additional action selection remains necessary.

### Selective-computation safety principles

1. **Cheap rules first:** Avoid unnecessary Decider calls for definitive policy denial. Mandatory authorization never depends on a learned gate.
2. **Decider is the intelligent router:** It selects the next eligible investigation step or a fast-path *proposed* action. It is **not** a mandatory final validator after every specialist result. This—not standalone classification—is the primary differentiator.
3. **Policy-mandated deeper checks:** A configured high-impact/untrusted-source class can force escalation even when Decider suggests fast allowance; log `route_override` separately.
4. **No high-risk fast-path bypass:** `ALLOW_IF_AUTHORIZED` only exists when trusted required data are sufficient and no mandatory deep checks remain.
5. **Different routes can compose:** `FETCH_EVIDENCE` and `ESCALATE_SEMANTIC` are both nonterminal steps; a single event may use either or both.
6. **Bounded work:** Enforce wall clock, token/data volume, provider deadline, number of evidence calls and specialist calls, plus eventual policy-safe termination.
7. **Not simply classifier cascading:** Measure whether Decider's choice of *what to investigate*, plus skipping redundant reassessments, improves latency and intervention utility against always-run specialist analysis.
8. **Conclusive-result shortcut:** After each downstream response, a deterministic resolver uses verified evidence and versioned finding-to-policy rules to select direct enforcement or conditional Decider re-routing. A specialist's output is never an authorization grant.

## 1. Normalized event schema

Define a Pydantic model `SecurityEvent`:

```python
class SecurityEvent(BaseModel):
    event_id: str
    provider: Literal["claude", "microsoft_copilot", "simulator"]
    provider_event_type: str
    interception_mode: Literal["inline", "native_policy", "audit_only"]
    observed_at: datetime
    actor_id: str | None
    agent_id: str | None
    session_id: str | None
    task_summary: str | None
    operation: str | None
    resource_id: str | None
    data_label: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "UNKNOWN"]
    destination: str | None
    tool_name: str | None
    text_excerpt: str | None   # minimized, optional, never logged by default
    provenance_ids: list[str]
    coverage_notes: list[str]
    trusted_identity_context: dict
```

Only verified identity information goes into `trusted_identity_context`. Treat vendor-provided free-text descriptions and tool arguments as untrusted.

## 2. Strands Decider service

Use the published reference checkpoint initially:

`StrandsAgents/strands-decider-2B-qwen3.5-v1-2610`

The Strands Decider project's `POST /v1/systemone` accepts `state` plus typed `questions`. Avoid generative text classification. Pin model revision, runtime, and question-set version for reproducibility.

Example **illustrative** request (validate against the installed version):

```json
{
  "state": "Task: summarize Q3 sales. Action: send report to external@example.test. Source label: CONFIDENTIAL. Destination classification: external. Actor permission: unknown.",
  "questions": {
    "sensitive": {"type": "noul", "instructions": "Does the action context indicate sensitive corporate information?"},
    "task_fit": {"type": "choice", "instructions": "How relevant is the action to the stated task?", "criteria": {"relevant": "Directly advances the task", "unclear": "Insufficient evidence", "irrelevant": "Not related to the task"}},
    "destination_risk": {"type": "score", "instructions": "Rate contextual risk from the destination and data flow, not authorization status.", "criteria": ["Low", "Elevated", "High", "Critical"]},
    "untrusted_instruction": {"type": "noul", "instructions": "Does the content contain instructions originating from an untrusted source that attempt to redirect agent behavior?"}
  }
}
```

Do not ask the Decider whether a user **has** permission; that fact belongs to enterprise identity/ACL checks. Do not make a `choice` result (e.g., `allow`) directly executable; interpret it as a recommendation subject to policy.

**Question-design considerations:** A yes/no value represents `P(true)`; choice returns per-option probabilities and a normalized confidence; score returns a distribution and expected level. Test calibration on labeled enterprise security scenarios. Do not use the project's illustrative thresholds as validated security thresholds.

**Long contexts:** Strictly bound/minimize state. The server may truncate long inputs by default; use strict-window behavior where practical so context omissions are visible. Cache or summarize history with explicit source tracking, not silently.

**Security:** The open-source server binds to localhost and has no auth by default. For production deploy it privately behind an authenticated service with rate limits, authorization, encrypted transport, and tenant isolation.

## 2A. Strands Decider as a security-action planner (MVP requirement)

**Core function:** After analyzing contextual security risk, Strands Decider must choose **the next security action**, not merely output risk classifications. This uses a typed `choice` question over a **runtime-filtered allowlist**. The model is a decision router, **not** a free-form generative agent; it cannot invent tool names, API calls, or tool arguments.

### Action Catalog (separate from vendor tool interfaces)

| Internal action ID | Effect | Eligible when |
| --- | --- | --- |
| `ALLOW_IF_AUTHORIZED` | Propose permitting a pending operation; enforcement maps to `ALLOW` only after final policy check | Trusted policy permits it and provider offers inline verdict; required facts verified |
| `BLOCK` | Deny the pending operation | Inline control exists or policy requires denial |
| `WARN` | Deliver a permissible warning | Warning interface is supported, and policy allows execution |
| `REDACT` | Apply validated change then re-check | Content is in a controllable transformation path |
| `FETCH_EVIDENCE` | Invoke one vetted security evidence tool | Specific missing evidence is available from trusted tools; bounded budget |
| `ESCALATE_SEMANTIC` | Consult an approved stronger security analyzer | Context needs deeper semantic interpretation OR policy-mandated specialist check; budget and data clearance satisfied |
| `ASK_CLARIFICATION` | Ask requester for task details, no permission grant | Clarification channel exists; must not authorize restricted access |
| `REQUIRE_APPROVAL` | Ask qualified data owner/security approver | Operation is approvable; approver can be authenticated; workflow supports it |
| `GUIDE` | Supply a safer recommended alternative | Supported outbound guidance mechanism exists |
| `AUDIT_ALERT` | Record post-event incident and alert | Audit-only events, not proof of prevention |
| `CREATE_REVIEW_CASE` | Request investigation by authorized personnel | Case system is configured |
| `RECOMMEND_POLICY_CHANGE` | Draft an administrative recommendation only | Audit/native policy mode; not automatic enforcement |

### Security evidence tool allowlist

- `CHECK_IAM_PERMISSION(actor_id, resource_id, operation)` -> trusted `allowed/denied/unknown`, verified source.
- `GET_RESOURCE_LABEL(resource_id)` -> trusted sensitivity label and provenance.
- `VERIFY_RECIPIENT(destination_id, data_label)` -> trust classification / approved-recipient evidence.
- `GET_PROVENANCE(artifact_id)` -> known contributing sources/labels and gaps.
- `LOOKUP_APPROVAL_POLICY(actor_id, resource_id, operation)` -> eligible approver roles, not a grant.

The actual execution arguments come from the trusted context builder and may be drawn only from normalized validated IDs. Decider chooses **which** eligible tool to call, not arbitrary request parameters. For any missing identifier, either ask for clarification or take a safe fallback; never fabricate it.

### Constrained decision cycle

```text
1. Normalize signed/verified event; tag provider mode and capabilities.
2. Apply non-negotiable IAM/DLP/policy constraints.
   - Explicit deny: enforce immediately; Decider cannot reverse it.
3. Resolve known resources/labels; calculate which facts remain missing.
4. Construct safe available_action_ids from policy/capability registry.
   - Do not include ALLOW_IF_AUTHORIZED without verified permission.
   - Do not include inline BLOCK on audit-only events.
   - Do not include REDACT without a controllable path.
5. Submit normalized state + risk questions + `choice(next_action)` to Decider.
6. Validate choice is on allowlist; reject malformed/conflicting result.
7. If FETCH_EVIDENCE or ESCALATE_SEMANTIC: select an eligible tool/analyzer,
   execute with validated arguments, record source/finding, update state.
8. Run `resolve_findings(state)` DETERMINISTICALLY (without Decider):
   - SUFFICIENT_ALLOW_CANDIDATE or SUFFICIENT_DENY -> final policy validation
     and provider enforcement (no extra model call).
   - NEEDS_MORE_EVIDENCE / NEEDS_OTHER_SPECIALIST / CONFLICTING ->
     reinvoke Decider ONLY if a new eligible decision remains, within budget;
     otherwise safe fallback.
9. If REQUIRE_APPROVAL: authenticated, scoped workflow; when a provider
   cannot pause/resume, deny current action and arrange a new verified retry.
10. Otherwise enforce supported action after final policy check; audit effect.
11. On budget/timeout/exhaustion: safe policy fallback, never implicit ALLOW.
```

**Conditional re-routing budget (prototype defaults, configurable and benchmarked):** at most two evidence lookups, at most one specialist call, at most four Decider routing evaluations **only when needed**, and an end-to-end time budget below the integration's verified webhook deadline. Conclusive findings must not consume another Decider pass. Retry suppression/caching prevents duplicate approval or evidence requests. Do not use these defaults as guarantees of production latency.

### Illustrative action decision query

The action list is **computed by the trusted policy/capability prefilter** rather than being a universal, always-permitted set. Example where permission and recipient approval are **unknown**, so `ALLOW` is absent:

```json
{
  "state": "Task: summarize Q3. Pending: external send to recipient-42. Source label: CONFIDENTIAL. IAM read permission: verified. Recipient authorization: UNKNOWN. Evidence tools remaining: VERIFY_RECIPIENT, GET_PROVENANCE. Vendor: inline. Candidate actions: BLOCK, FETCH_EVIDENCE, REQUIRE_APPROVAL.",
  "questions": {
    "next_action": {
      "type": "choice",
      "instructions": "Choose the best NEXT security action based on current verified evidence. FETCH_EVIDENCE is preferred if a bounded, available trusted check can resolve a material uncertainty. Never interpret UNKNOWN as permission.",
      "criteria": {
        "BLOCK": "Deny the pending external send now",
        "FETCH_EVIDENCE": "Consult a permitted trusted verification tool before deciding",
        "REQUIRE_APPROVAL": "Request a narrowly scoped exception from a verified authorized reviewer"
      }
    }
  }
}
```

Example is **illustrative**; Kiro must verify the exact current HTTP schema and response shape from upstream docs. If `FETCH_EVIDENCE` wins, use another `choice` with options such as `VERIFY_RECIPIENT` or `GET_PROVENANCE`, restricted to executable choices only. Never synthesize arbitrary arguments from model output.

**Model choice confidence is not the probability that ALLOW is secure.** On any ambiguous/high-risk case, enforce validated policy constraints and use measured confidence/uncertainty thresholds to prefer checks or escalation. Decider may recommend BLOCK, but a final authority check always applies and may supersede recommendations.

### Why this is more than classification

The principal metric is whether the Decider routes AgentShield to the **correct next action**, including knowing when to gather evidence instead of prematurely blocking or allowing. Record full action probabilities, model/question versions, the executed security tool, the new evidence, and the finally enforceable vendor verdict.

## 2B. Adaptive security router, result resolver, and conditional re-routing (revised v0.5)

### Action-tier schema

Add these typed models to the service; reuse the existing event and `EvidenceState` types:

```python
class EvidenceFact(BaseModel):
    fact_id: str
    name: str
    status: Literal["verified", "unknown", "stale", "conflicted", "untrusted"]
    source_system: str | None
    observed_at: datetime | None
    value_ref: str | None  # evidence-store pointer; do not log raw confidential payload

class SecurityState(BaseModel):
    event_id: str
    impact: Literal["low", "moderate", "high", "critical", "unknown"]
    required_fact_names: list[str]
    evidence: list[EvidenceFact]
    semantic_complexity: Literal["simple", "ambiguous", "complex", "unknown"]
    provider_mode: Literal["inline", "native_policy", "audit_only"]
    applicable_hard_rules: list[str]
    remaining_deadline_ms: int
    evidence_calls_remaining: int
    specialist_calls_remaining: int

class AnalyzerSpec(BaseModel):
    analyzer_id: str
    supported_risks: list[str]
    data_classification_clearance: str
    available: bool
    expected_latency_ms: int
    max_input_bytes: int
    emits: str  # versioned structured finding schema reference

class RoutingRecord(BaseModel):
    event_id: str
    step_index: int
    eligible_options: list[str]
    decider_selected_option: str | None
    decider_option_probabilities: dict[str, float] | None
    effective_option: str
    override_rule: str | None
    analyzer_or_evidence_tool: str | None
    deadline_ms_remaining: int
    result_evidence_ids: list[str]
    resolution_status: str | None      # ResultResolution enum
    resolution_rule_id: str | None
    reroute_reason: str | None         # only for unresolved/contradictory cases
    decider_reinvoked: bool
```

**Completeness must be auditable, not impressionistic.** Determine missing required facts with the deterministic policy engine; the Decider may additionally classify whether available text is semantically adequate but cannot label an IAM lookup verified based on its guess. Evidence returned by a specialist has `analysis_result` provenance; it is never equivalent to signed identity claims.

### Decider question design

Use a **shared compact state** for efficient inference, retaining source IDs and missing facts. Batch risk/semantic adequacy/routing questions when supported by the verified inference API. Use a constrained `choice` whose eligible options are computed dynamically. Example instruction semantics:

- `noul`: "Does the observed action suggest a sensitive-data disclosure risk?"
- `choice`: "How much semantic understanding is required for this case: SIMPLE / AMBIGUOUS / COMPLEX?"
- `score`: "Rate potential consequences of the described data flow; unknown authorization is not permission." (not the sole authoritative impact source)
- `choice(next_security_step)`: choose only among `ALLOW_IF_AUTHORIZED`, `BLOCK`, `FETCH_EVIDENCE`, `ESCALATE_SEMANTIC`, `REQUIRE_APPROVAL`, and applicable audit-only choices, with explicit descriptions. Do not include prohibited choices in options.

When `FETCH_EVIDENCE`, use another Decider `choice(evidence_tool)` among **only pre-approved applicable and unused** evidence tools. When `ESCALATE_SEMANTIC`, use a Decider `choice(specialist)` among approved services supporting the risk type and sensitivity clearance, or deterministically select the only eligible specialist. The Decider never invents API parameters or authorizations.

### Deterministic downstream-result resolver

Define a typed `ResultResolution` with statuses:

- `SUFFICIENT_DENY`: authoritative denial, or specialist finding matching an approved rule that requires block/hold.
- `SUFFICIENT_ALLOW_CANDIDATE`: all **mandatory** permissions, labels, destination constraints and required checks are verified; the resolved findings satisfy a versioned permit rule. This is merely a candidate; the final policy engine still authorizes.
- `NEEDS_MORE_EVIDENCE`: a mandatory or material fact is unknown/stale and an eligible evidence tool could resolve it.
- `NEEDS_OTHER_SPECIALIST`: semantic questions remain material and an approved analyzer could resolve them.
- `CONFLICTING`: trustworthy evidence conflicts or a finding cannot be reliably mapped to policy; never auto-allow.
- `UNRESOLVED_BUDGET`: further investigation is unavailable, unsafe, or exceeds the deadline; use policy-safe fallback.

The resolver is **deterministic**, not a second semantic model. It may apply versioned mappings from validated specialist finding codes to policy dispositions (for example, `CONFIDENTIAL_EXFILTRATION_DETECTED -> DENY`), but cannot treat specialist prose as verified IAM permission. If no approved mapping resolves the case, re-route through Strands Decider only when a meaningful next choice exists. For an audit-only provider, the terminal outcome is an alert/review, not retroactive blocking. Every outcome is post-validated against policy and provider capabilities.

### Bounded conditional routing procedure (illustrative pseudocode)

```python
def evaluate_security_event(event, provider_capabilities, policy, deadline):
    state = normalize_and_verify(event)
    hard = mandatory_policy_check(state, policy)
    if hard.explicit_deny:
        return enforce_or_report(hard.deny, provider_capabilities)

    for step in range(config.max_decider_steps):
        state = refresh_evidence_status_and_budget(state, deadline)
        eligible = eligible_next_steps(state, policy, provider_capabilities)
        if not eligible or deadline.expired():
            return safe_fallback(state)

        proposal = strands_decider.choose(state.minimized(), eligible)
        action = policy.validate_and_override(proposal, state)
        if action.is_final:
            return policy_validate_then_enforce(action, state, provider_capabilities)
        if action == "REQUIRE_APPROVAL":
            return safely_initiate_approval_or_deny_retry(state)

        if action == "FETCH_EVIDENCE":
            tool = strands_decider.choose_evidence_tool(state, policy.eligible_tools(state))
            findings = evidence_dispatcher.run_readonly(tool, args_from_verified_ids(state))
        elif action == "ESCALATE_SEMANTIC":
            analyzer = strands_decider.choose_specialist(state, policy.eligible_analyzers(state))
            findings = analyzer_dispatcher.run_isolated(analyzer, minimize_payload(state))
        else:
            return safe_fallback(state)

        state = append_findings_with_provenance(state, findings)
        resolution = deterministic_resolve_findings(state, policy, provider_capabilities)
        record_resolution(resolution, decider_reinvoked=False)
        if resolution.status in {"SUFFICIENT_DENY", "SUFFICIENT_ALLOW_CANDIDATE"}:
            # Specialist findings cannot issue permissions; validate again.
            return policy_validate_then_enforce(resolution.disposition, state, provider_capabilities)
        if resolution.status == "UNRESOLVED_BUDGET" or deadline.expired():
            return safe_fallback(state)
        if resolution.status in {"NEEDS_MORE_EVIDENCE", "NEEDS_OTHER_SPECIALIST", "CONFLICTING"}:
            if not has_new_eligible_step(state, policy, deadline):
                return safe_fallback(state)
            record_conditional_reroute_reason(resolution.status)
            continue  # ONLY HERE does a fresh Decider routing choice occur.

    return safe_fallback(state)
```

The pseudocode names conceptual functions, not verified Strands Decider package APIs; Kiro must implement through the documented server or SDK client. `choose_specialist` may be a second `choice` call. `policy_validate_then_enforce` must never grant a missing authorization; it must also distinguish audit-only results from inline prevention. Neither a successful specialist classification nor its own "allow" text constitutes permission.

### Downstream security analyzer registry

Initial plugin **contracts** (all can be local fakes for reproducible MVP):

| Analyzer/tool | When to select | Output | Operational boundary |
| --- | --- | --- | --- |
| `OPA_POLICY` | Required policy checks (not optional model routing) | immutable permit/deny + policy ID | deterministic authorization service |
| `CHECK_IAM_PERMISSION` | Unknown user-resource-operation authorization | verified allow/deny/unknown + source | read-only authoritative IAM |
| `VERIFY_RECIPIENT` | Unknown external recipient | verified status / missing | read-only corporate directory |
| `GET_RESOURCE_LABEL` | Unknown label or resource classification | verified classification or unknown | trusted DLP metadata |
| `GET_PROVENANCE` | Derived artifact source unclear | source graph + gaps | read-only provenance store |
| `SEMANTIC_DLP` | Sensitive meaning hidden in paraphrase/summary | label hypotheses, supporting evidence spans/refs | isolated specialist; output not authorization |
| `PROMPT_INJECTION_FORENSICS` | Multi-turn/tool-result instruction hijack | attack findings and references | isolated specialist; output not authorization |
| `SENSITIVE_DERIVATION_REVIEW` | Cross-document or cross-agent leakage ambiguity | provenance-sensitive semantic assessment | private approved model; no public API default |

An approved specialist may be a privately hosted LLM or specialized model; this is **an evidence-producing tool downstream from the Strands Decider**, not a parallel LLM-based security orchestrator. For MVP, implement deterministic synthetic specialist mocks and interfaces; live models are optional after privacy and benchmark review.

**No unrestricted tool execution:** Decider chooses IDs from vetted catalog; service builds all arguments from authenticated, normalized IDs and safe references. Strict egress allowlists and model-service clearance prohibit sensitive-data exfiltration by analysis tools.

### When NOT to reinvoke Strands Decider

1. Verified IAM `DENY` for the pending action: block via hard policy immediately.
2. Trusted recipient check `DENY` or immutable DLP restriction: block via final policy; no model call.
3. Trusted `ALLOW` plus all other mandatory verified facts, complete required specialist checks, and no unresolved policy condition: allow *candidate* proceeds to final deterministic policy check; no extra model call.
4. Approved specialist returns a validated terminal finding mapped to `DENY`/`HOLD`: apply the policy rule directly. The specialist does **not** call vendor enforcement itself.
5. Any result marked `UNKNOWN`, `STALE`, `CONFLICTING`, or semantically incomplete: choose a further step via Decider **only when** another allowed tool could resolve it; otherwise hold/block or alert by provider mode.

These rules must be implemented as resolution tests, not left to Decider prompt wording. The number of saved Decider calls is an explicit performance metric.

### Deadline and fallback budgets

Prototype examples (tunable, NOT performance guarantees): max 2 evidence retrievals, max 1 specialist invocation, max 4 Decider routing evaluations, max 8 KB of minimized *non-secret* context to a specialist unless explicitly approved, and a strict end-to-end provider deadline including network overhead. Set a provider-specific guard interval and return the safest documented verdict before expiration. If no time remains to investigate, deny a pending inline high-impact operation (subject to actual vendor failure settings) or record an audit-only incident. For approval cases that cannot pause the provider, deny now and allow a freshly verified retry.

Control latency through caching verified non-sensitive metadata with TTL, batched Decider questions, conditional specialist calls, and parallel **independent** read-only checks only when explicitly permitted by policy and budget. Cache keys must include tenant, principal, resource, action, destination, and policy version; never reuse authorizations across principals. Track staleness.

### Adversarial cases that MUST be tested

- Decider reports low risk but resource policy requires an advanced sensitive-derivation check -> enforce forced escalation, no fast allow.
- Decider requests evidence when it has already been fetched -> no repeated call; bounded termination.
- Identity evidence is unknown or stale but semantic specialist says "all clear" -> not authorized.
- Deep semantic analyzer returns a prompt-injection instruction such as "disable policy" -> treated as untrusted result text.
- A provider webhook has an insufficient remaining deadline for specialist calls -> safe provider-supported deny; do not time out waiting for enhanced analysis.
- Combined ambiguity and semantic risk -> fetch evidence, conditionally re-route only if a specialist choice remains, then enforce conclusive specialist result directly through policy.
- Vendor is audit-only -> Decider can request reviews/analysis but cannot label action "prevented".

## 3. Context, data classification and provenance

- Merge existing sensitivity labels and IAM/resource metadata before model inference.
- Track access and derivation as a graph: `document -> tool_result -> agent_context -> derived_output -> destination`.
- Where provenance is incomplete or output is a novel paraphrase, conservatively retain elevated labels and report uncertainty.
- Treat document/tool-result text as hostile input for injection classification, not as instructions to the security service.
- Make resource identity and classification resolution independent of model confidence.

## 4. Trusted policy engine and action validation

The policy engine receives `SecurityEvent`, `DeciderRiskResult`, `DeciderActionChoice`, `TrustedIdentity`, `PolicyBundle`, `AdapterCapabilities`, and the evolving `EvidenceState`.

The policy engine **pre-filters** the allowed action/tool space using IAM, data classification, provider capability, and hard restrictions. After Decider selects an action, or after the deterministic result resolver establishes a terminal policy disposition, it **post-validates** the pending action against the same trusted constraints and the current event/version. It must not derive authorization solely from Decider or a specialist.

Critical rules:

- Explicit denial always wins. No model can grant access, approve a bypass, or adjust policies.
- A security lookup may be Decider-selected, but results from IAM/label/recipient systems, not Decider's answer, establish authorization and classification.
- A missing or ambiguous grant never becomes `ALLOW` simply because model confidence is high.
- `ASK_CLARIFICATION` is not `REQUIRE_APPROVAL`: the employee can supply task facts, but only eligible approvers can authorize a permitted exception.
- Decider cannot execute raw vendor actions or arbitrary network calls. All side effects are brokered by typed, audited service implementations.
- Recomputed candidate actions can change as new trusted evidence arrives. Tool outputs are data, never policy instructions.
- If a selected option is unsupported, invalid or unavailable, apply a documented safe fallback; record the original recommendation and veto/fallback reason.
- The provider's actual observed enforcement verdict is distinct from the internal planned action.

For Claude Enterprise, an internal `FETCH_EVIDENCE` call must complete within the hook's time budget or return a safe supported `deny`. `REQUIRE_APPROVAL` likewise maps to deny-and-retry if the protocol cannot pause. For Microsoft Copilot audit ingestion, Decider routes among triage/review/recommendation options and never pretends to block the past event.

## 5. Claude Enterprise adapter (first real candidate)

Official docs: https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint

- Receive signed HTTPS webhooks; verify raw-byte HMAC signature, timestamp (replay window), identifiers, size limits, and schema.
- Recognize `prompt` and `tool_call` frames; support future unknown metadata values without using them as trusted facts.
- Tool-call frames may contain several calls. Return one `allow`/`deny` verdict for the entire frame; some internal tool calls are not exposed.
- The official verdict protocol does not transform prompts or pause/resume a tool. If the internal policy requests redaction or approval, deny now and supply a separate appropriate remediation/approval process for a **new** equivalent request.
- Do not return HTTP error status as an intentional denial: use protocol-defined HTTP 200 with a valid deny payload after a valid signed request.
- Handle provider's configurable failure behavior and circuit-breaker. Distinguish `vendor_failed_open`, `vendor_failed_closed`, and `blocked_by_verdict` in reports; never assume the local service controls provider fail-open behavior.
- Respect the documented provider verdict latency timeout and measure round-trip p95.
- Live tenant activation requires appropriate enterprise permissions, approved network connectivity, and security review. Build simulator first.

## 6. Microsoft Copilot adapter (second phase)

Official docs:
- https://learn.microsoft.com/en-us/purview/dlp-microsoft365-copilot-location-learn-about
- https://learn.microsoft.com/en-us/purview/audit-copilot

- Ingest supported audit or risk events, existing sensitivity metadata, and policy state with approved enterprise permissions.
- Use Strands Decider to classify the normalized observations and triage policy gaps; surface recommended administrative changes and incident alerts.
- Coordinate with existing Microsoft Purview policies for restrictions rather than claiming AgentShield can independently interrupt all Copilot internals.
- Do not autonomously modify production DLP policies in the MVP. Provide reviewable policy suggestions for security administrators.
- Clearly label per-scenario capabilities as `audit_only`, `native_policy`, or verified `inline` if a future supported surface is established.

## 7. Human approval

- Store `ApprovalGrant`: reviewer id/role, actor id, resource, operation, destination, expiry, action digest, policy version, single-use flag.
- Verify grant through trusted IAM/service identity; never grant more access than reviewer is authorized to delegate.
- Re-evaluate policy and digest on new or retried requests, including after an approval.
- For Claude inference hooks, show a deny/remediation path; do not assert native suspend/resume.

## 8. Evaluation and baselines

Benchmark on synthetic cases:

1. Public-resource read consistent with task.
2. Restricted-resource read without verified ACLs.
3. Allowed confidential read followed by prohibited external email.
4. Benign paraphrase vs confidential-derived paraphrase.
5. Tool-result prompt injection attempting policy override.
6. Multiple tool calls in one Claude frame.
7. Missing actor/task context and low-confidence classification.
8. Signed hook, bad signature, replayed request, invalid JSON.
9. Model timeout; provider fail-open/fail-closed configuration; circuit breaker.
10. Microsoft audit-only event where no inline control exists.
11. Unknown recipient authorization -> Decider routes to VERIFY_RECIPIENT -> conclusive verified DENY/ALLOW under complete mandatory policy -> direct enforcement **without another Decider call**.
12. Evidence tool unavailable -> bounded loop falls back to BLOCK/hold, not ALLOW.
13. Invalid selected action -> hard-policy veto; no side effect.
14. Repeated evidence/approval recommendations -> bounded and idempotent termination.
15. Audit-only event -> Decider selects CREATE_REVIEW_CASE; report only, no prevention claim.

Baselines: mandatory rules only; stateless keyword/PII scanning; mandatory rules + always-deep semantic analyzer; mandatory rules + fixed heuristic router; mandatory rules + private generative-LLM router; **mandatory rules + Strands Decider adaptive routing with conditional re-routing**; and a **v0.4-style always-reassess Decider ablation**. Keep authorization policy and evidence availability equal across arms.

Record precision/recall at matched constraints; high-severity false-negative rate; false-positive intervention rate; specialist-call savings versus always-deep; escalation precision/recall; conditional evidence-tool value; **next-action correctness, unsafe-allow rate, evidence-tool selection correctness, evidence value, routing uncertainty, mean/max loop steps, Decider calls saved per conclusive finding, reroute-necessity precision**, reviewer burden; p50/p95 latency; throughput; event coverage by adapter; actual prevented vs merely observed events.

## 9. Suggested repository structure

```text
agentshield/
  app/
    adapters/
      base.py
      simulator.py
      claude_hooks.py
      microsoft_audit.py
    decider/
      client.py
      questions.py
      action_router.py
      tier_router.py
      result_schema.py
    orchestration/
      action_catalog.py
      decision_loop.py
      evidence_tools.py
      budgets.py
      analyzer_registry.py
      specialist_dispatcher.py
      completeness.py
      route_telemetry.py
    policy/
      engine.py
      permissions.py
      action_map.py
    context/
      event_schema.py
      provenance.py
    approval/
      grants.py
    audit/
      events.py
    api/
      main.py
  tests/
    fixtures/
    test_decider_contract.py
    test_action_router.py
    test_evidence_loop.py
    test_decider_tier_router.py
    test_specialist_escalation.py
    test_combined_routing.py
    test_budget_exhaustion.py
    test_action_capabilities.py
    test_policy.py
    test_claude_adapter.py
    test_provenance.py
    test_approvals.py
    test_failure_modes.py
    test_end_to_end.py
  evaluations/
    datasets/
    run_benchmarks.py
    benchmark_protocol.md
  .kiro/specs/agentshield/
    requirements.md
    design.md
    tasks.md
    evaluation-plan.md
```

## 10. Source references

- Strands Decider repository: https://github.com/strands-labs/strands-decider
- Strands Decider inference: https://github.com/strands-labs/strands-decider/blob/main/docs/inference.md
- Strands Decider architecture and constrained choice: https://github.com/strands-labs/strands-decider/blob/main/docs/architecture.md
- Open Policy Agent tool-call policy integration: https://www.openpolicyagent.org/docs/agent-tool-calling
- OPA external trusted data: https://www.openpolicyagent.org/docs/external-data
- Claude Inference Hooks integration: https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint
- Microsoft Purview DLP: https://learn.microsoft.com/en-us/purview/dlp-microsoft365-copilot-location-learn-about
- Microsoft Copilot audit: https://learn.microsoft.com/en-us/purview/audit-copilot
