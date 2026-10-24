"""The versioned Action Catalog and the evidence-tool allowlist (design.md 2A, R6a.1).

The Decider can only ever pick ids from here (through the typed questions in agent/decision.py);
the policy engine decides which of them are eligible for an event, and every adapter maps them to
the actions its vendor really supports.
"""

from __future__ import annotations

from dataclasses import dataclass, field

CATALOG_VERSION = "catalog-2026.10"


@dataclass(frozen=True)
class ActionSpec:
    action_id: str
    effect: str
    terminal: bool
    side_effect: str            # none | enforcement | read_only_lookup | analysis | workflow | advisory
    risk_class: str             # how much harm a wrong use can cause
    prerequisites: str
    modes: tuple[str, ...]      # interception modes where it can be proposed
    decider_option: bool        # offered as a Decider option (the rest are produced by deterministic mappings)
    roles: tuple[str, ...] = field(default_factory=tuple)  # who may act on it (requester / reviewer)


ACTIONS: dict[str, ActionSpec] = {a.action_id: a for a in [
    ActionSpec("ALLOW_IF_AUTHORIZED", "propose permitting the pending operation; ALLOW only after the final policy check", True,
               "enforcement", "high", "identity, permission, label and destination verified; no mandatory check pending",
               ("inline",), True),
    ActionSpec("BLOCK", "deny the pending operation", True, "enforcement", "low", "inline control exists", ("inline",), True),
    ActionSpec("WARN", "deliver a permissible warning", True, "enforcement", "moderate",
               "a warning channel exists and policy allows execution", ("inline",), False),
    ActionSpec("REDACT", "apply a validated change, then re-check", True, "enforcement", "moderate",
               "content is on a controllable transformation path (not the inline-hook vendor)", (), False),
    ActionSpec("FETCH_EVIDENCE", "call one vetted read-only evidence tool", False, "read_only_lookup", "low",
               "a decisive fact is unknown/stale and an unused tool can settle it; budget left", ("inline", "audit_only"), True),
    ActionSpec("ESCALATE_SEMANTIC", "consult an approved semantic security analyzer", False, "analysis", "low",
               "content needs deeper semantic reading, or policy mandates it; clearance, budget and deadline allow", ("inline", "audit_only"), True),
    ActionSpec("ASK_CLARIFICATION", "ask the requester for task details; grants nothing", True, "workflow", "low",
               "a clarification channel exists", (), False, ("requester",)),
    ActionSpec("REQUIRE_APPROVAL", "ask the data owner for a scoped, single-use exception", True, "workflow", "moderate",
               "identity verified; an approval policy covers the action; the approver can be authenticated", ("inline",), True,
               ("data_owner",)),
    ActionSpec("GUIDE", "suggest a safer alternative", True, "workflow", "low", "an outbound guidance channel exists", (), False),
    ActionSpec("RECORD_ONLY", "keep the audit record; no alert", True, "advisory", "high",
               "audit-only event; facts verified and the data stayed in scope", ("audit_only",), True),
    ActionSpec("AUDIT_ALERT", "record a post-event incident and alert (never proof of prevention)", True, "advisory", "low",
               "audit-only event", ("audit_only",), True, ("security_reviewer",)),
    ActionSpec("CREATE_REVIEW_CASE", "open an investigation case for authorized reviewers", True, "workflow", "low",
               "a case system is configured", ("audit_only",), True, ("security_reviewer",)),
    ActionSpec("RECOMMEND_POLICY_CHANGE", "draft an advisory recommendation for administrators (never applied automatically)", True,
               "advisory", "low", "audit or native-policy mode", ("audit_only",), False, ("security_reviewer",)),
]}


@dataclass(frozen=True)
class ToolSpec:
    tool_id: str
    resolves: str               # the required fact it settles
    args: tuple[str, ...]       # argument kinds, all built from normalized, validated ids
    source_system: str
    expected_ms: int = 50
    description: str = ""


EVIDENCE_TOOLS: dict[str, ToolSpec] = {t.tool_id: t for t in [
    ToolSpec("CHECK_IAM_PERMISSION", "permission", ("actor_id", "target_id", "operation"), "iam",
             description="trusted allow / deny / unknown for actor + resource + operation"),
    ToolSpec("GET_RESOURCE_LABEL", "resource_label", ("resource_id",), "dlp_labels",
             description="trusted sensitivity label of a stored resource"),
    ToolSpec("VERIFY_RECIPIENT", "recipient", ("destination", "label"), "directory",
             description="trust class of a destination and the highest label it may receive"),
    ToolSpec("GET_PROVENANCE", "lineage", ("artifact_id",), "provenance",
             description="known sources, labels and gaps of a derived artifact"),
    ToolSpec("LOOKUP_APPROVAL_POLICY", "approval_policy", ("actor_id", "target_id", "operation"), "approval_policies",
             description="eligible approver roles for an exception (not a grant); called by the approval flow"),
]}

DECIDER_TOOLS = ("CHECK_IAM_PERMISSION", "GET_RESOURCE_LABEL", "VERIFY_RECIPIENT", "GET_PROVENANCE")
FACT_TO_TOOL = {"permission": "CHECK_IAM_PERMISSION", "resource_label": "GET_RESOURCE_LABEL",
                "recipient": "VERIFY_RECIPIENT", "lineage": "GET_PROVENANCE", "artifact_label": "GET_PROVENANCE"}
TERMINAL_INLINE = ("ALLOW_IF_AUTHORIZED", "BLOCK", "REQUIRE_APPROVAL")
TERMINAL_AUDIT = ("RECORD_ONLY", "AUDIT_ALERT", "CREATE_REVIEW_CASE")
INVESTIGATIVE = ("FETCH_EVIDENCE", "ESCALATE_SEMANTIC")
