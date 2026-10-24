"""The spec in .kiro/specs/agentshield/ is a byte-identical copy of VIEW-SPEC-FILES/ (the user's originals)."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILES = ("README.md", "requirements.md", "design.md", "tasks.md", "evaluation-plan.md")


@pytest.mark.skipif(not (ROOT / "VIEW-SPEC-FILES").exists(), reason="VIEW-SPEC-FILES/ is not in this checkout")
@pytest.mark.parametrize("name", FILES)
def test_spec_copy_is_byte_identical(name):
    assert (ROOT / ".kiro" / "specs" / "agentshield" / name).read_bytes() == (ROOT / "VIEW-SPEC-FILES" / name).read_bytes()
