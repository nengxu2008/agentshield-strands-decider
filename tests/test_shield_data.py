"""Synthetic data integrity: every fixture loads, every referenced id exists, nothing real or secret."""

from __future__ import annotations

import re
from pathlib import Path

from shield_support import W

from agent.shield.schemas import LABEL_RANK, ApprovalGrant  # noqa: F401 - schemas import cleanly

ROOT = Path(__file__).resolve().parent.parent
VENDOR_NAMES = re.compile(r"claude|anthropic|microsoft|copilot|purview|openai", re.I)


def test_every_event_and_scenario_loads_into_its_schema():
    for eid in W.events_raw:
        ev = W.event(eid)
        assert ev.event_id == eid and ev.provider in ("inline_hook_vendor", "audit_only_vendor")
    assert set(W.scenarios) <= set(W.events_raw)
    splits = [s["split"] for s in W.scenarios.values()]
    assert splits.count("tune") >= 12 and splits.count("test") >= 12


def test_referenced_ids_exist():
    for e in W.events_raw.values():
        targets = [e.get("resource_id"), e.get("artifact_id")] + [c.get("resource_id") for c in e.get("calls", [])]
        for t in filter(None, targets):
            assert t in W.resources or t in W.provenance, t
        if e.get("actor_id"):
            assert e["actor_id"] in W.actors
        assert e["session_id"] in W.sessions
    for p in W.provenance.values():
        assert all(s in W.resources for s in p["sources"])
    for g in W.grants:
        assert g["actor_id"] in W.actors and (g["resource_id"] == "*" or g["resource_id"] in W.resources)
    for r in W.resources.values():
        assert r["owner_id"] is None or r["owner_id"] in W.actors
        assert r["label"] in LABEL_RANK or r["label"] == "UNTRUSTED_SOURCE"
    for a in W.inbox.values():
        assert a["for_event"] in W.events_raw and a["submitted_by"] in W.actors
    for s in W.sessions.values():
        for st in s["steps"]:
            if st["kind"] == "event":
                assert st["event_id"] in W.events_raw


def test_only_reserved_example_domains_and_no_secrets():
    text = "".join(p.read_text() for p in (ROOT / "agent" / "data").glob("*.json"))
    for dom in re.findall(r"@([a-z0-9.-]+)", text) + re.findall(r'"match": "@?[a-z0-9.-]*@?([a-z0-9.-]+\.[a-z]+)"', text):
        assert dom.endswith(".example"), dom
    for p in list((ROOT / "agent").rglob("*")) + list((ROOT / "tests").glob("test_shield_*.py")):
        if p.is_file() and p.suffix in (".py", ".json", ".jsonl", ".md", ".yaml"):
            body = p.read_text()
            assert ("dcd_" + "live_") not in body and not re.search(r"AKIA[0-9A-Z]{16}", body), p


def test_no_third_party_vendor_names_in_demo_visible_files():
    files = [ROOT / "agent" / "demo_script.yaml", ROOT / "agent" / "AGENT.md", *(ROOT / "agent").rglob("*.py"), *(ROOT / "agent" / "data").glob("*.json")]
    hits = [str(p.relative_to(ROOT)) for p in files if VENDOR_NAMES.search(p.read_text())]
    assert hits == []
