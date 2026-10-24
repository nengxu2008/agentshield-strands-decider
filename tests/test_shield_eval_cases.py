"""agent/eval_cases.jsonl is exactly what the generator renders from the runtime state layout."""

from __future__ import annotations

import json
from pathlib import Path

from agent.decision import INPUT_MAX_CHARS, QUESTIONS, STATE_MAX_CHARS
from agent.shield.eval_cases import build_cases, render
from decider_kit.llm import options_of

ROOT = Path(__file__).resolve().parent.parent
CASES = [json.loads(x) for x in (ROOT / "agent" / "eval_cases.jsonl").read_text().splitlines() if x.strip()]


def test_committed_file_matches_the_generator():
    assert (ROOT / "agent" / "eval_cases.jsonl").read_text() == render(build_cases())


def test_size_and_splits():
    assert len(CASES) >= 24 and sum(c["split"] == "test" for c in CASES) >= 12
    assert {c["split"] for c in CASES} == {"tune", "test"}


def test_labels_are_valid_options_and_at_most_four_questions():
    for c in CASES:
        assert 1 <= len(c["expected"]) <= 4, c["id"]
        for q, label in c["expected"].items():
            assert label in options_of(QUESTIONS[q]), (c["id"], q, label)


def test_states_respect_the_input_limits():
    for c in CASES:
        qs = {k: QUESTIONS[k] for k in c["expected"]}
        assert len(c["state"]) <= STATE_MAX_CHARS and len(c["state"]) + len(json.dumps(qs)) <= INPUT_MAX_CHARS
        assert c["state"].startswith("AGENTSHIELD SECURITY EVENT")


def test_every_branch_is_covered():
    seen = {q: {c["expected"][q] for c in CASES if q in c["expected"]} for q in QUESTIONS}
    assert set(QUESTIONS["next_step"]["criteria"]) == seen["next_step"]
    assert {"FETCH_EVIDENCE", "RECORD_ONLY"} <= seen["next_step_audit"]
    assert set(QUESTIONS["evidence_tool"]["criteria"]) == seen["evidence_tool"]
    assert set(QUESTIONS["analyzer"]["criteria"]) == seen["analyzer"]
    assert set(QUESTIONS["risk_severity"]["criteria"]) == seen["risk_severity"]
