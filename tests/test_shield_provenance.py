"""Provenance across a session: read CONFIDENTIAL -> paraphrase (no PII patterns) -> external send is denied."""

from __future__ import annotations

import re

from shield_support import W, ctx, oracle, router

from agent.shield.evidence import EvidenceService
from agent.shield.provenance import ProvenanceGraph, derive_label, replay_session, service_lineage
from agent.shield.strategies import DeciderStrategy, RulesOnly


def test_paraphrase_exfiltration_is_denied_at_tier0_through_the_propagated_label():
    r = router()
    first = r.evaluate("EVT-132", DeciderStrategy(oracle("EVT-132")))    # step 1: the read is legitimate
    assert first.disposition == "ALLOW"
    c = ctx("EVT-133")
    excerpt = W.events_raw["EVT-133"]["excerpt"]
    assert not re.search(r"\d|@|\$", excerpt)                               # nothing a pattern-based DLP would catch
    assert c.lineage.known_sources == ["DOC-CONF-03"] and c.lineage.transformation == "paraphrase"
    assert c.label() == "CONFIDENTIAL"                                       # provenance-derived, not stored
    for strat in (RulesOnly(), DeciderStrategy(oracle("EVT-133"))):
        out = r.evaluate("EVT-133", strat)
        assert out.tier0 and out.rule_id == "H3" and out.disposition == "BLOCK" and out.decider_calls == 0


def test_session_replay_tracks_task_reads_and_derivations():
    g, lines = replay_session(W, "S-04", 3)
    assert any("EVT-132 read DOC-CONF-03" in x for x in lines) and any("derived ART-35 by paraphrase" in x for x in lines)
    assert ("agent_context:S-04", "derived_output:ART-35", "paraphrase") in g.edges
    c = ctx("EVT-133")
    assert c.task == "Summarise Q3 for the finance team." and c.event.actor_id == "u-ben"


def test_lineage_gaps_keep_the_label_unknown_or_elevated():
    assert derive_label(W, ["DOC-INT-02"], ["pasted text"]) == ("UNKNOWN", "INTERNAL")
    assert derive_label(W, ["DOC-CONF-04"], ["pasted text"]) == ("CONFIDENTIAL", "CONFIDENTIAL")   # elevated label retained
    assert derive_label(W, ["DOC-PUB-01", "DOC-INT-02"], []) == ("INTERNAL", "INTERNAL")
    c = ctx("EVT-114")
    assert c.lineage.untracked and c.facts["artifact_label"].status == "unknown" and c.facts["lineage"].status == "unknown"


def test_untrusted_web_reads_are_tracked_but_never_lower_a_label():
    g = ProvenanceGraph()
    g.add_read("S-X", "WEB-08", "S-X.1", untrusted=True)
    g.add_read("S-X", "DOC-CONF-10", "S-X.2")
    lin = g.derive(W, "S-X", "ART-X", "summary")
    assert lin.known_sources == ["DOC-CONF-10"] and lin.context_sources == ["WEB-08"] and lin.derived_label == "CONFIDENTIAL"


def test_provenance_service_can_reveal_a_restricted_source():
    c = ctx("EVT-113")
    assert c.label() == "UNKNOWN"
    EvidenceService(W).run(c, "GET_PROVENANCE")
    assert c.label() == "RESTRICTED" and service_lineage(W, "ART-13").known_sources == ["DOC-PUB-14", "DOC-RES-05"]


def test_audit_record_with_untracked_lineage_is_recorded_as_incomplete():
    c = ctx("AUD-202")
    assert c.lineage.known_sources == [] and not c.lineage.complete and "origin not recorded" in c.lineage.untracked[0]
