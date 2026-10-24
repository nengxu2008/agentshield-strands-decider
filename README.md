# AgentShield

**A security router for third-party AI agents: Strands Decider 2B gatekeeps every step in one fast pass and spends deeper checks only where they change the outcome.**

An agent on AWS that hands one decision to **Strands Decider 2B** and the conversation to **Amazon Bedrock**. Decision pattern: `#tool-selection`. Tags: `#strands-decider-2b` `#tool-selection`.

- Video: https://youtu.be/tGztQFYy4Eg
- Article: https://builder.aws.com/project/3Kn0o7ft6nX6fuIWpvgNMsiD0rZ/agentshield-a-strands-decider-first-pass-gatekeeper-that-routes-security-checks-for-third-party-ai-agents
- Deployed: Amazon Bedrock AgentCore Runtime, us-east-1

## The project

- **Pitch:** a security router for third-party AI agents: Strands Decider 2B gatekeeps every step in one fast pass and spends deeper checks only where they change the outcome.
- **Who it is for:** enterprise security and compliance teams whose staff use third-party AI agents (an inline-hook vendor that lets a security service allow or deny each step, and an audit-only vendor that only reports what already happened), and who must stop data leaks without blocking legitimate work.
- **Features:**
  - a first-pass gatekeeper on every event: evidently safe and fully verified steps go through, evidently risky steps are blocked, everything else is routed;
  - targeted evidence collection with trusted read-only lookups (IAM permission, resource label, recipient directory, provenance), chosen by the Decider, with arguments built only from verified ids;
  - escalation to a stronger semantic analyzer (semantic DLP, prompt-injection forensics, sensitive-derivation review) only when the meaning needs it; a case can get both, in either order;
  - context and provenance across a session: the original business task, the actor, what was read, what was derived from it (a confidential report paraphrased into a "harmless" note keeps its label), where it is going;
  - a deterministic policy engine (replaceable by OPA later) with hard rules no model can override, and a resolver that enforces conclusive results directly, with no extra model call;
  - simulated approvals that tell an employee's "yes, I meant it" apart from a data owner's signed, single-use exception;
  - honest vendor adapters: the inline-hook vendor gets only allow / deny (no pause, no redaction), the audit-only vendor never gets "prevented";
  - a reproducible 5-arm routing benchmark (rules-only, fixed heuristic, always-deep, LLM router, Strands Decider) plus the v0.4 always-reassess ablation.
- **The decision handed to Strands Decider 2B:** which security step comes next for this event: a fast allow or block, which trusted lookup, which semantic analyzer, or a data-owner approval (`#tool-selection`). One batched call asks four typed questions about one shared state (next step, risk severity, which lookup, which analyzer), so severity, missing information and semantic complexity are separate, calibrated signals, not one confidence threshold.
- **Why a decision model:** it runs on every event, so it must be fast, cheap and private; it returns calibrated probabilities the code can branch on; and it cannot generate, so it can only pick from options the policy engine allows. Expensive LLM analysis is reserved for the minority of events that need it.
- **Amazon Bedrock:** Amazon Nova Pro (model id from `SPECIALIST_MODEL_ID`, default `BEDROCK_LARGE_MODEL_ID`) is the optional enhanced semantic analyzer, called only when the Decider routes there (or policy mandates it), and returns structured findings that never authorize anything; Amazon Bedrock (`BEDROCK_MODEL_ID`, Amazon Nova Pro by default) also writes the analyst-facing explanation in the chat. The same code runs on this machine (`LLM_PROVIDER=bedrock`) and on Amazon Bedrock AgentCore Runtime. Every model call goes through the Strands Agents SDK and is bounded per call.

## How a step is decided

1. **Tier 0, no model:** hard rules from the policy bundle (verified IAM deny, restricted data leaving the company, confidential data to a personal or blocklisted address, blocklisted destination, a label above what the destination may receive). A hard deny is final.
2. **Tier 1, Strands Decider first pass:** one call, four questions. Code masks every choice to the options the policy engine marked eligible, then applies the plan rules in `agent/decision.py` (fast allow only with high confidence, low severity and no lookup or analysis needed; otherwise up to two investigation steps; explicit low-confidence handling).
3. **Tier 2, investigation:** the planned lookups and analyzers run within budgets (2 lookups, 1 analyzer call, 4 Decider calls, a deadline). After every result the deterministic resolver decides: conclusive deny or allow candidate goes straight to final policy validation; an open case runs the next queued step; only if nothing queued addresses it and an eligible step remains is the Decider asked again (3 questions). Otherwise: a safe fallback, never an implicit allow.
4. **Enforcement:** the policy engine finalizes, and the adapter maps the outcome to what the vendor really supports.

## Capability matrix (simulated vendors, neutral names)

| Integration | Sees | Can enforce | Cannot |
|---|---|---|---|
| inline-hook vendor (synthetic protocol `inline-hook-sim/v1`) | prompts and tool-call frames before they run, a verified user id | `allow` / `deny`, one verdict per frame | pause, redact, per-call verdicts; calls it does not expose |
| audit-only vendor (fixture records) | records after a step ran | record, alert, review case, advisory policy recommendation | block, redact, or claim anything was prevented |

## Honest scope

- The vendors are simulated (signed-request protocol tests with tamper and replay checks; fixture audit records). No live tenant, no real credentials, no real OPA server: those are deferred.
- All data is synthetic (`agent/data/`, a fictional company at `corp.example`).
- Strands Decider runs on the AWS User Group Madurai hosted API, which serves the published checkpoint `strands-decider-2b-hobson-v19` (the spec names `strands-decider-2B-qwen3.5-v1-2610`; switching to it locally is one `./kit setup` away).
- Analyzer findings, the LLM-router baseline and the chat explanations come from Amazon Nova Pro on Amazon Bedrock, called from this machine for the benchmark; the Decider latency is the hosted API's, measured over the network.
- Thresholds are tuned on the tune split only; reported numbers come from the held-out test split.
- Threat model in brief: AgentShield only sees what a vendor exposes (endpoint bypass and unexposed calls are out of reach and listed as coverage gaps); the third-party agent, its tool results and analyzer prose are untrusted text; model outputs are probabilistic recommendations and never authorization; identity and approvals are trusted only when verified (signed hook identity, a data owner's signature over the exact action digest).

## Known limitations (being fixed)

An internal code review of v0.5 raised seven blocking findings. Some have code changes and passing tests in this snapshot, but none has been re-reviewed yet, so treat all seven as open:

- **Inline-hook replay protection (B1):** the first version keyed the replay cache on an unsigned request-id header, so a replay with a fresh header id was accepted. The signature now covers the request id and new tests reject that replay, but the simulated protocol has not been re-reviewed. Do not rely on it as complete replay protection.
- **Analyzer-established labels (B2, rule LG1):** a clean analyzer finding could settle an unknown lineage label and lead to an external allow. In this snapshot findings never set facts: an analyzer can only add an evidence-backed deny, and an unknown label ends in the safe fallback. The policy bundle text for LG1 still describes the old behaviour.
- **Analyzer findings in the VERIFIED part of the Decider state (B3):** model findings should sit in their own untrusted section, apart from verified evidence. Not fixed.
- **Final validation for non-allow outcomes (B4):** the always-reassess ablation arm could replace a hard-rule deny with a weaker outcome. Final validation now lets a hard rule win over any disposition (tested), pending re-review.
- **Grouped inline frames (B5):** calls grouped in one inline frame do not yet share one hook deadline. Not fixed.
- **PolicyEngine interface (B6):** the replaceable interface (for a future OPA engine) is not yet complete or fully checked. Being fixed.
- **Coverage report (B7):** enforcement coverage (what each vendor exposes) is not yet reported separately from routing accuracy. Not fixed.

<!-- agentshield-bench:start -->
## AgentShield routing benchmark: test split (16 scenarios)

Strands Decider: `strands-decider-2b-hobson-v19` (ugmdu (da25tnxy06gjk.cloudfront.net)). LLM router: `us.amazon.nova-pro-v1:0` (Amazon Bedrock (us.amazon.nova-pro-v1:0)). Analyzers: live `us.amazon.nova-pro-v1:0` on Amazon Bedrock (us.amazon.nova-pro-v1:0), memoised per (scenario, analyzer, payload). Question set `agentshield-qs-v2`, policy `pb-2026.10`.

| Metric | A rules-only | B fixed heuristic | C always-deep | D LLM router | E Strands Decider | F always-reassess (v0.4) |
|---|---|---|---|---|---|---|
| Unsafe-allow rate (inline) | 20.0% | 10.0% | 10.0% | 10.0% | 0.0% | 0.0% |
| Severity-weighted unsafe-allow rate | 19.4% | 9.7% | 9.7% | 9.7% | 0.0% | 0.0% |
| Missed incidents (audit-only) | 0 | 0 | 0 | 0 | 0 | 0 |
| Disposition accuracy | 75.0% | 93.8% | 93.8% | 93.8% | 100.0% | 93.8% |
| Routing accuracy (disposition + minimal investigation) | 50.0% | 93.8% | 68.8% | 68.8% | 75.0% | 68.8% |
| First-route accuracy | - | - | - | 61.5% | 76.9% | 76.9% |
| Legitimate-task disruption | 20.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| Held for approval correctly | 1 | 2 | 2 | 2 | 2 | 1 |
| Specialist (analyzer) calls | 0 | 3 | 7 | 4 | 3 | 4 |
| Evidence lookups | 0 | 5 | 6 | 5 | 5 | 5 |
| Routing-model calls | 0 | 0 | 0 | 13 | 13 | 21 |
| Decider decisions (questions) | 0 | 0 | 0 | 0 | 52 | 76 |
| LLM tokens (router + analyzers; memoised calls charged to every arm that uses them) | 0 | 3,510 | 9,709 | 33,837 | 3,432 | 4,678 |
| Router answers unusable (failure policy applied) | 0 | 0 | 0 | 0 | 0 | 0 |
| Latency median (measured service time) | 0 ms | 0 ms | 0 ms | 2,107 ms | 6,612 ms | 11,203 ms |
| Latency p90 | 0 ms | 1,824 ms | 2,062 ms | 4,361 ms | 10,063 ms | 17,693 ms |
| Rate-limit waits (excluded above) | 0 ms | 0 ms | 0 ms | 38,720 ms | 0 ms | 0 ms |

### Strands Decider as the first-pass gatekeeper (arm E)

- Events that reached the Decider: 13 of 16 (3 ended at Tier 0 with no model call).
- Resolved by the first pass alone (fast allow, fast block, approval hold): 38.5% of the events that reached it.
- Low-confidence handling applied: 6 events (46.2%).
- Ineligible raw proposals vetoed by masking: 1; mandatory-analyzer overrides: 0; repeat suppressions: 0.
- Decider calls saved by the deterministic resolver (downstream results not followed by a Decider call): 7.
- Versus always-deep: 4 specialist calls avoided (57.1%), 1 evidence lookups avoided (16.7%).
- Versus the always-reassess ablation (F): 13 vs 21 Decider calls (8 saved); unsafe allows E vs F: 0 vs 0.

Full per-scenario results: `submission/bench/agentshield/results.md`.
<!-- agentshield-bench:end -->

Built with the AWS User Group Madurai Strands Decider hackathon kit. The kit's reusable library (`decider_kit/`, the demo UI, the video and article tooling, the Kiro skills) is the user group's; AgentShield in `agent/` is the participant's own.

![Demo: the conversation and the live decision panel](submission/article/img/demo.png)

## How it is built

Strands Agents with Amazon Bedrock for the generative part, the tools in `agent/tools.py`, deployed to Amazon Bedrock AgentCore Runtime, and one decision handed to Strands Decider 2B at a clear seam in the agent's path.

Every Amazon Bedrock model id is set in `.env` (`BEDROCK_MODEL_ID`, and `BEDROCK_SMALL/MEDIUM/LARGE_MODEL_ID` for routing), Amazon Nova by default.

![Architecture](submission/article/img/architecture.png)

## Reusable decision pattern: Decider-first security gatekeeper and investigation router (#tool-selection)

The implementation is labelled `REUSABLE DECISION PATTERN` in [`agent/decision.py`](agent/decision.py). Strands Decider 2B selects the next security step from a policy-filtered catalog; deterministic code validates the plan, resolves investigation results and enforces the outcome.

### What the Decider answers

The first pass asks **four typed questions about one shared state in one batched call**: next step, risk severity, evidence tool and analyzer. A re-route asks three questions, omitting severity. Missing information and semantic complexity are separate signals: a case can need a trusted lookup, a semantic analyzer, both or neither.

| Question | Type | Options |
|---|---|---|
| `next_step` (inline) | Choice | `ALLOW_IF_AUTHORIZED`, `BLOCK`, `FETCH_EVIDENCE`, `ESCALATE_SEMANTIC`, `REQUIRE_APPROVAL` |
| `next_step_audit` (replaces `next_step` for audit-only events) | Choice | `RECORD_ONLY`, `AUDIT_ALERT`, `CREATE_REVIEW_CASE`, `FETCH_EVIDENCE`, `ESCALATE_SEMANTIC` |
| `risk_severity` (first pass only) | Ordered score | `low` < `moderate` < `high` < `critical` |
| `evidence_tool` | Choice | `CHECK_IAM_PERMISSION`, `GET_RESOURCE_LABEL`, `VERIFY_RECIPIENT`, `GET_PROVENANCE`, `none` |
| `analyzer` | Choice | `SEMANTIC_DLP`, `PROMPT_INJECTION_FORENSICS`, `SENSITIVE_DERIVATION_REVIEW`, `none` |

The `none` options mean no extra work is needed on that axis. Audit-only events have already happened, so their options never include allow or block. Full question wording and option descriptions live in [`QUESTIONS` and the option catalogs](agent/decision.py).

### Where it runs

[`agent/shield/router.py`](agent/shield/router.py) runs the gatekeeper for each event:

```mermaid
flowchart TD
    A["Verify adapter input and build trusted context"] --> B{"Tier 0 hard deny?"}
    B -->|Yes| I["Finalize policy and enforce through adapter"]
    B -->|No| C["Compute eligibility and ask Decider"]
    C --> D["Validate plan against policy"]
    D -->|Terminal candidate| I
    D -->|Investigation| E["Run next eligible lookup or analyzer"]
    E --> F{"Deterministic resolver"}
    F -->|Conclusive| I
    F -->|Open; queued step remains| E
    F -->|Open; unused eligible step and budget remain| C
    F -->|No further step or budget| H["Safe fallback"]
    H --> I
```

The first visit to the Decider uses `first_pass(...)`; later visits use `reroute(...)`. The chat agent in [`agent/agent.py`](agent/agent.py) runs this pipeline before its LLM explains the outcome. The chat LLM cannot choose a security action.

### How probabilities become actions

[`plan_from_answers`](agent/decision.py) converts the returned distributions into a plan of at most two investigation steps:

1. **Mask to eligible options.** Remove choices the policy engine disallows and renormalize. Record both raw and masked distributions; veto ineligible proposals.
2. **Gate the fast path.** Allow requires masked confidence `>= ALLOW_MIN_CONF`, severe-risk probability `< SEVERE_P`, and both lookup-needed and analyzer-needed probabilities `< NEED_P`. An allow that fails these checks receives low-confidence handling. Other terminal choices require confidence `>= LOW_CONF`; every candidate still goes through final policy validation.
3. **Plan targeted investigation.** `FETCH_EVIDENCE` selects the best eligible lookup and can queue an analyzer; `ESCALATE_SEMANTIC` selects an analyzer and can queue a lookup. With low confidence, prefer an available authoritative lookup first.
4. **Handle uncertainty explicitly.** Try an eligible lookup, adding analysis when the analysis or severity signal requires it; use an analyzer alone if no lookup remains. If neither is eligible, fall back to `BLOCK` for inline events or `CREATE_REVIEW_CASE` for audit-only events. Unknown facts never grant permission.
5. **Resolve and stop.** After each result, the deterministic resolver either finalizes, runs the next queued step, or requests a re-route only while an unused eligible step remains. Per-event limits are two lookups, one analyzer call, four Decider calls and a deadline. Completed lookups and analyzers are never repeated.

Each Decider call is logged with its probabilities, selected `pick`, `confidence`, acted-on `verdict`, latency, model and question-set version. The log also records low-confidence handling, vetoes and suppressed repeats.

### Reuse the pattern

1. Copy [`agent/decision.py`](agent/decision.py) and replace the next-step, lookup and analyzer catalogs. Keep the `none` options.
2. Build a `view` that separates **VERIFIED**, **MODEL ESTIMATES** and **UNTRUSTED** content; `render_state` formats it. Compute eligibility in your own deterministic policy code.
3. Call `DeciderGatekeeper(decider).first_pass(view, eligible, mode, event_id)`. Validate and execute the returned plan, resolve after every result, and call `reroute` only for an unresolved case with further eligible work.
4. Tune `LOW_CONF`, `ALLOW_MIN_CONF`, `SEVERE_P` and `NEED_P` on a labelled tune split (`./kit bench --split tune`), then report the held-out test split.

The [known limitations](#known-limitations-being-fixed) above still apply to this implementation.

## Decision-model benchmark

This separate benchmark compares individual typed-question answers with Amazon Nova Pro on the test split. Its 15 labelled cases contain 54 scored answers; these are different units and cases from the 16-scenario routing benchmark above. The four figures below come from this decision-model run.

Decider: strands-decider-2b-hobson-v19 (ugmdu). 15 labelled cases, 54 decisions.

| | Strands Decider 2B | us.amazon.nova-pro-v1:0 |
|---|---|---|
| Accuracy | 61.1% | 61.1% |
| Latency p50 per decision | 6824 ms | 2085 ms |
| Latency p95 | 9937 ms | 2656 ms |
| Cost per 1,000 decisions | $0.0350 | $0.6003 |
| Answered alone at confidence >= 0.7 | 7% | 100% |
| Accuracy when confident | 100.0% | 61.1% |

At the median the LLM was 3.2x faster than the decider on this setup (ugmdu).

### Accuracy

![Decision-model accuracy: Strands Decider 2B and Amazon Nova Pro both score 61.1 percent](submission/bench/bench-accuracy.png)

*Figure 1. Accuracy across the 54 scored typed-question answers. This measures question-level agreement with labels, rather than final security dispositions.*

### Latency

![Median latency: Strands Decider 2B 6824 milliseconds; Amazon Nova Pro 2085 milliseconds](submission/bench/bench-latency.png)

*Figure 2. Median measured request latency in the decision-model benchmark. The hosted Decider includes network time and was slower than the Bedrock LLM in this run.*

### Cost

![Reported cost per 1000 scored answers: Strands Decider 2B 0.0350 dollars; Amazon Nova Pro 0.6003 dollars](submission/bench/bench-cost.png)

*Figure 3. Cost per 1,000 scored answers using the benchmark's accounting: configured hosting cost for the Decider and token-based cost for the LLM. These are decision-model costs, excluding the full investigation pipeline.*

### Confidence and coverage

![Accuracy versus share of typed-question answers accepted at different confidence thresholds](submission/bench/bench-confidence.png)

*Figure 4. Accuracy among answers above each confidence threshold versus the share accepted. The rest are marked for human review by this benchmark; the runtime uses the bounded investigation and fallback rules described above.*

At the table's threshold of `0.7`, the Decider answered 7% alone with 100.0% accuracy on that subset. Nova Pro answered 100% alone with 61.1% accuracy. The small accepted subset limits what the Decider's confident accuracy establishes.

[Benchmark report](submission/bench/results.md) · [Raw results](submission/bench/results.json)

Reproduce with `./kit bench --split test` (cases in [`agent/eval_cases.jsonl`](agent/eval_cases.jsonl); figures in [`submission/bench/`](submission/bench/)).

## Run it

```bash
./kit setup        # checks your machine and AWS, sets up Strands Decider 2B (local model or hosted API)
./kit demo         # web UI at http://localhost:8501
./kit bench        # the decision vs an Amazon Bedrock LLM
./kit deploy       # Amazon Bedrock AgentCore Runtime
```

Requirements: Python 3.10+, AWS credentials with Amazon Bedrock access, and for deploying, Node 20+ with the AgentCore CLI (`./kit agentcore-cli`).

## Credits

Built with the AWS User Group Madurai Strands Decider hackathon kit (https://github.com/awsugmdu). The kit's reusable library (`decider_kit/`, the demo UI, the video and article tooling, and the Kiro steering, skills and hooks) is the user group's; the agent in `agent/` is mine. Strands Decider: https://github.com/strands-labs/strands-decider (Apache-2.0).

Licence: Apache-2.0 (see LICENSE).
