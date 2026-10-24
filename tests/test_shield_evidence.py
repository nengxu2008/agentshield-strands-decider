"""Evidence tools: arguments only from normalized, registered ids; idempotent; an outage leaves facts UNKNOWN."""

from __future__ import annotations

import pytest
from shield_support import W, ctx

from agent.shield.evidence import EvidenceError, EvidenceService, build_args, validate_args


def test_arguments_come_from_the_trusted_context():
    c = ctx("EVT-103")
    assert build_args(c, "CHECK_IAM_PERMISSION") == {"actor_id": "u-ben", "target_id": "DOC-CONF-03", "operation": "read_document"}
    assert build_args(ctx("EVT-105"), "VERIFY_RECIPIENT") == {"destination": "investor-relations@lumen-advisory.example", "label": "CONFIDENTIAL"}


def test_anything_else_is_rejected():
    c = ctx("EVT-103")
    with pytest.raises(EvidenceError):
        validate_args(c, "CHECK_IAM_PERMISSION", {"actor_id": "u-farah", "target_id": "DOC-CONF-03", "operation": "read_document"})
    with pytest.raises(EvidenceError):
        build_args(ctx("EVT-130"), "CHECK_IAM_PERMISSION")                  # no verified actor id
    with pytest.raises(EvidenceError):
        build_args(ctx("EVT-101", resource_id="../../etc/passwd"), "GET_RESOURCE_LABEL")
    with pytest.raises(EvidenceError):
        build_args(ctx("EVT-105", destination="http://evil.example/upload?x=1"), "VERIFY_RECIPIENT")
    with pytest.raises(EvidenceError):
        build_args(c, "DROP_TABLES")


def test_each_tool_runs_once_per_event():
    svc, c = EvidenceService(W), ctx("EVT-105")
    first = svc.run(c, "VERIFY_RECIPIENT")
    again = svc.run(c, "VERIFY_RECIPIENT")
    assert svc.calls == 1 and again["repeat"] and first["class"] == "blocklisted"
    assert c.used_tools == ["VERIFY_RECIPIENT"] and c.facts["recipient"].source_system == "directory"


def test_unavailable_service_keeps_the_fact_unknown_and_is_not_retried():
    svc, c = EvidenceService(W), ctx("EVT-119")
    res = svc.run(c, "CHECK_IAM_PERMISSION")
    assert res["error"] == "unavailable" and c.facts["permission"].status == "unknown" and c.failed_tools == ["CHECK_IAM_PERMISSION"]
    svc.run(c, "CHECK_IAM_PERMISSION")
    assert svc.calls == 1


def test_results_are_trusted_facts_with_source_and_time():
    svc, c = EvidenceService(W), ctx("EVT-124")
    svc.run(c, "GET_RESOURCE_LABEL")
    f = c.facts["resource_label"]
    assert (f.status, f.value, f.source_system) == ("verified", "INTERNAL", "dlp_labels") and f.observed_at is not None


def test_unlisted_destination_is_verified_as_unlisted():
    svc, c = EvidenceService(W), ctx("EVT-126X")
    svc.run(c, "VERIFY_RECIPIENT")
    assert c.dest["class"] == "unlisted_external" and c.dest["max_label"] == "PUBLIC"
