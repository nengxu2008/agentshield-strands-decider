# AgentShield: a Strands Decider first-pass gatekeeper that routes security checks for third-party AI agents
By (your name)

## Hook

Staff at many companies now let third-party AI agents read documents, send email and share files for them. A security team has to stop the steps that leak data without blocking the ones that do real work, and it cannot afford a large LLM call on every step. I built AgentShield, a security router in which Strands Decider 2B is the first-pass gatekeeper on every agent step: one batched decision call picks a fast allow, a fast block, a targeted trusted lookup, a deeper semantic analyzer on Amazon Bedrock, or both. On my held-out test cases the decision cost $0.0350 per 1,000 decisions against $0.6003 for Amazon Nova Pro asked the same questions, with the same 61.1% accuracy, but the hosted decider was slower (6824 ms median against 2085 ms). The details, including the weak spots, are below.

## The project

AgentShield is for enterprise security and compliance teams whose staff use third-party AI agents. It works with two kinds of simulated vendors: an inline-hook vendor that lets a security service allow or deny each step before it runs, and an audit-only vendor that only reports what already happened. All data is synthetic, for a fictional company.

What it does:

- A first-pass gatekeeper on every event: evidently safe and fully verified steps go through, evidently risky steps are blocked, everything else is routed.
- Targeted evidence collection with trusted read-only lookups (IAM permission, resource label, recipient directory, provenance), chosen by the Decider, with arguments built only from verified ids.
- Escalation to a stronger semantic analyzer (semantic DLP, prompt-injection forensics, sensitive-derivation review) on Amazon Bedrock only when the meaning needs it. A case can get both a lookup and an analyzer.
- Provenance across a session, so a confidential report paraphrased into a harmless-looking note keeps its label.
- A deterministic policy engine with hard rules no model can override, and a resolver that enforces conclusive results directly, with no extra model call.
- Simulated approvals that tell an employee's "yes, I meant it" apart from a data owner's signed, single-use exception.
- Honest vendor adapters: the inline-hook vendor gets only allow or deny, and the audit-only vendor is never told a step was "prevented".

Here is what the deployed agent did in the demo, running on Amazon Bedrock AgentCore Runtime:

- EVT-101, a marketing agent reading the public brand guide: the Decider picked ALLOW_IF_AUTHORIZED at 0.929 in 6247 ms, and final validation confirmed the fast-path allow. No lookup, no analyzer.
- EVT-105, a confidential forecast summary emailed to an unchecked outside address: the Decider's top pick was FETCH_EVIDENCE at only 0.35, so the low-confidence rule planned VERIFY_RECIPIENT then SEMANTIC_DLP. The recipient lookup alone was conclusive (hard rule H3), so the resolver blocked the step and the analyzer never ran.
- EVT-109, an internal partner FAQ whose wording sounds like the unreleased roadmap: the Decider leaned to allow at 0.538, which is not enough for a fast allow, so it routed to SEMANTIC_DLP. The analyzer reported CONFIDENTIAL_CONTENT_DETECTED, and the policy engine's finding map turned that into a block.
- EVT-114, a partner briefing built from an internal FAQ plus pasted text of unknown origin: the Decider planned GET_PROVENANCE then SENSITIVE_DERIVATION_REVIEW, a combined investigation. The analyzer reported CONFIDENTIAL_DERIVATION_DETECTED and the step was blocked.

Each of these took one Decider call.

< FIGURE 1 of 6: upload submission/article/img/demo.png here >
Alt text: The demo UI: the conversation on the left, the decider's typed answers and verdict on the right

## How I built it

Every event goes through four tiers. Tier 0 is the hard policy rules, with no model: a verified IAM deny, restricted data leaving the company, confidential data to a personal or blocklisted address, a label above what the destination may receive. Tier 1 is the Strands Decider first pass: one call with four typed questions about one shared state. Tier 2 is the investigation, within budgets (2 lookups, 1 analyzer call, 4 Decider calls and a deadline). After each result, a deterministic resolver decides whether the case is settled. The Decider is asked again only when the case is still open and an eligible, unused step remains. Last, the policy engine finalizes the outcome and the vendor adapter maps it to what that vendor can really enforce.

The chat agent is a Strands Agents agent on Amazon Bedrock (Amazon Nova Pro). It runs this pipeline before it speaks and only explains the outcome; it never chooses a security action. Amazon Nova Pro is also the enhanced semantic analyzer. It returns structured findings from a closed schema and never authorizes anything. The agent is deployed to Amazon Bedrock AgentCore Runtime in us-east-1. I wrote the spec (requirements, design, tasks and an evaluation plan) in Kiro and built from it with the AWS User Group Madurai kit.

< FIGURE 2 of 6: upload submission/article/img/architecture.png here >
Alt text: Architecture: the user, the agent with its tools and decision, Amazon Bedrock and Strands Decider 2B

## The decision handed to Strands Decider 2B

The decision is which security step comes next for this event (`#tool-selection`). It runs on every event that passes Tier 0, so it has to be cheap and private. It also has to return calibrated probabilities the code can branch on. And because the decision model cannot generate text, it can only pick from the options the policy engine marked eligible. Severity, missing information and semantic complexity are separate questions, so they come back as separate signals instead of one confidence number.

```python
QUESTIONS = {
    "next_step": Decider.choice(
        "Pick the next security action for the pending step. Only options listed under 'Eligible next steps' are possible. "
        "UNKNOWN is never permission.",
        NEXT_STEP_OPTIONS),
    "next_step_audit": Decider.choice(
        "The step already happened (audit-only: it cannot be blocked). Pick the next security action. Only options listed under "
        "'Eligible next steps' are possible.",
        NEXT_STEP_AUDIT_OPTIONS),
    "risk_severity": Decider.score(
        "How serious would the harm be if this step goes ahead? low: the data stays within its allowed scope. moderate: limited "
        "harm, or facts still unverified. high: confidential data may leave its scope, or the agent looks manipulated. critical: "
        "restricted or bulk sensitive data may leave the company.",
        SEVERITY_LEVELS),
    "evidence_tool": Decider.choice(
        "Which eligible lookup settles the most important missing fact? Answer none if no lookup is needed.",
        EVIDENCE_TOOL_OPTIONS),
    "analyzer": Decider.choice(
        "Does the content need a deeper semantic analyzer, and which eligible one? Answer none if not.",
        ANALYZER_OPTIONS),
}
```

The options are ALLOW_IF_AUTHORIZED, BLOCK, FETCH_EVIDENCE, ESCALATE_SEMANTIC and REQUIRE_APPROVAL for the next step (audit-only events get RECORD_ONLY, AUDIT_ALERT, CREATE_REVIEW_CASE, FETCH_EVIDENCE and ESCALATE_SEMANTIC instead), four trusted lookups, three analyzers, and none. A first pass asks four of these questions in one call.

The model classifies and my code decides. Each choice is masked to the eligible options and renormalised. A fast allow needs a masked confidence of at least 0.6, P(high or critical) below 0.5, and P(lookup needed) and P(analyzer needed) both below 0.5. Otherwise the allow is demoted. When the chosen step's confidence is below 0.5, AgentShield never guesses: it runs a bounded further check (the best eligible lookup and/or analyzer). If nothing eligible is left, the event ends in the safe fallback (block inline, review case for audit-only), never an implicit allow. In the demo, three of the four first passes were low confidence, and the low-confidence rule is what sent them to the right checks.

## Measured

I measured the four first-pass questions on the 15 held-out test cases (54 decisions), with thresholds tuned on a separate tune split. The decider ran on the AWS User Group Madurai hosted API (strands-decider-2b-hobson-v19), called over the network from my machine. The baseline is Amazon Nova Pro on Amazon Bedrock (us.amazon.nova-pro-v1:0), asked the same questions about the same states.

| | Strands Decider 2B | us.amazon.nova-pro-v1:0 |
|---|---|---|
| Accuracy | 61.1% | 61.1% |
| Latency p50 per decision | 6824 ms | 2085 ms |
| Latency p95 | 9937 ms | 2656 ms |
| Cost per 1,000 decisions | $0.0350 | $0.6003 |
| Answered alone at confidence >= 0.7 | 7% | 100% |
| Accuracy when confident | 100.0% | 61.1% |

At the median the LLM was 3.2x faster than the decider on this setup. The hosted API is shared and its latency includes the network. Running the decider on a GPU or close to the agent should be much faster, but I did not measure that.

Overall accuracy is the same, but the questions differ. The decider was better on risk severity (69.2% against 38.5%) and on the analyzer choice (60% against 46.7%). The LLM was better on the next step (63.6% against 36.4%) and on the lookup (100% against 69.2%). The decider's next-step question is the weakest part of my pattern, and it is the reason AgentShield does not trust a low-confidence pick. The decider was calibrated: when it was confident (7% of decisions) it was always right. The LLM said it was confident every time and was right 61.1% of the time, so a threshold on its confidence would catch nothing.

Per-question accuracy is not the whole story, because the code around the decider masks, thresholds and verifies. So I also ran the whole pipeline end to end on the 16 held-out test scenarios with six arms. Every arm has the same policy bundle, Tier 0 rules, tools, analyzers, budgets and resolver: A rules-only, B fixed heuristic routing, C always-deep (always run the analyzer), D LLM router (Amazon Nova Pro answering the same typed questions), E Strands Decider adaptive routing, and F an always-reassess ablation that asks the Decider again after every result.

| Metric | A rules-only | B fixed heuristic | C always-deep | D LLM router | E Strands Decider | F always-reassess |
|---|---|---|---|---|---|---|
| Unsafe-allow rate (inline) | 20.0% | 10.0% | 10.0% | 10.0% | 0.0% | 0.0% |
| Disposition accuracy | 75.0% | 93.8% | 93.8% | 93.8% | 100.0% | 93.8% |
| Routing accuracy (disposition + minimal investigation) | 50.0% | 93.8% | 68.8% | 68.8% | 75.0% | 68.8% |
| Legitimate-task disruption | 20.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| Specialist (analyzer) calls | 0 | 3 | 7 | 4 | 3 | 4 |
| Evidence lookups | 0 | 5 | 6 | 5 | 5 | 5 |
| Routing-model calls | 0 | 0 | 0 | 13 | 13 | 21 |
| LLM tokens (router + analyzers) | 0 | 3,510 | 9,709 | 33,837 | 3,432 | 4,678 |
| Latency median (measured service time) | 0 ms | 0 ms | 0 ms | 2,107 ms | 6,612 ms | 11,203 ms |

Only the two Decider arms (E and its ablation F) had no unsafe allow, and only E got every final disposition right. E used 3 analyzer calls where always-deep used 7. The fixed heuristic routed more efficiently (93.8% routing accuracy against 75.0%), but its unsafe-allow rate was 10.0%. The LLM router used 33,837 LLM tokens against 3,432 for E. E was slower than the LLM router at the median (6,612 ms against 2,107 ms), because every routing call went to the shared hosted API. The deterministic resolver saved 7 Decider calls, and against the always-reassess ablation the Decider arm made 13 calls instead of 21 with the same unsafe-allow rate. This is a small benchmark (16 scenarios, synthetic data), so I read it as a direction, not a proof.

< FIGURE 3 of 6: upload submission/article/img/bench-accuracy.png here >
Alt text: Accuracy of Strands Decider 2B and the Bedrock LLM on the labelled cases

< FIGURE 4 of 6: upload submission/article/img/bench-latency.png here >
Alt text: Median latency per decision for both

< FIGURE 5 of 6: upload submission/article/img/bench-cost.png here >
Alt text: Cost per 1,000 decisions for both

< FIGURE 6 of 6: upload submission/article/img/bench-confidence.png here >
Alt text: Accuracy against the share of decisions answered without a human, as the confidence threshold moves

## The reusable decision pattern

The pattern lives in `agent/decision.py`, labelled `REUSABLE DECISION PATTERN: Decider-first security gatekeeper and investigation router`. It holds the typed questions and options, the thresholds, the code that turns distributions into a plan of at most two steps, and the low-confidence handling. The wiring is in `agent/shield/router.py`: adapter verify, trusted context, Tier 0, eligibility, `DeciderGatekeeper.first_pass`, policy validation, lookups and analyzers with the resolver after each result, an optional `reroute`, then `policy.finalize` and the adapter.

To reuse it, keep the shape and swap the options: list your own trusted lookups and analyzers, let your policy code mark which are eligible for each event, render the event and its verified facts as the state, and keep the rule that a conclusive result goes straight to policy without another model call.

## Known limitations (being fixed)

An internal review of v0.5 raised seven blocking findings. Some have code changes and passing tests in the published snapshot, but none has been re-reviewed, so I treat all seven as open:

- Inline-hook replay protection: the first version could be bypassed with a fresh request-id header. The signature now covers the request id and has tests, but the simulated protocol has not been re-reviewed, so I do not claim complete replay protection.
- Analyzer-established labels (rule LG1): a clean analyzer finding could settle an unknown lineage label. Findings no longer set facts in this snapshot; the policy bundle text still describes the old rule.
- Analyzer findings still appear in the VERIFIED part of the Decider state instead of a separate untrusted section.
- The always-reassess ablation arm could override a hard-rule deny at final validation; a fix is in, pending re-review.
- Calls grouped in one inline frame do not yet share one hook deadline.
- The replaceable PolicyEngine interface (for a future OPA engine) is not complete yet.
- Enforcement coverage is not yet reported separately from routing accuracy.

## What I learned / what's next

Splitting one routing judgement into separate questions (severity, missing facts, semantic depth) and letting code combine them worked better than one confidence threshold, because the calibrated probabilities tell me when not to trust a pick. The next-step question needs sharper option descriptions, and the decider needs to run closer to the agent to win on speed. Next I will fix the open review findings, move the analyzer findings into their own state section, and grow the multi-arm benchmark beyond 16 scenarios.

## Footer

Repo: https://github.com/nengxu2008/agentshield-strands-decider | Video: (paste the public YouTube link) | Strands Decider: https://github.com/strands-labs/strands-decider | Tags: #strands-decider-2b #tool-selection

The reusable library in `decider_kit/`, the demo UI and the tooling come from the kit; AgentShield in `agent/` is my own.

Built with the AWS User Group Madurai Strands Decider hackathon kit.
