"""Documentation-reference integrity (round-seven followup finding 3).

Every repo-relative file path cited anywhere under docs/ must exist: a
launch checklist citing documents or code that are not in the tree is a
false claim about the release."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_REFERENCE_RE = re.compile(r"\b((?:docs|cathedral|tests|scripts)/[A-Za-z0-9_./-]+\.(?:md|py))\b")


def test_every_doc_cited_repo_path_exists():
    missing: list[str] = []
    for document in sorted((REPO_ROOT / "docs").glob("*.md")):
        for reference in sorted(set(_REFERENCE_RE.findall(document.read_text()))):
            if not (REPO_ROOT / reference).exists():
                missing.append(f"{document.name} -> {reference}")
    assert missing == [], f"docs cite nonexistent repo files: {missing}"


def test_launch_docs_exist_and_carry_the_required_content():
    """The item-7/8 documents exist and cover their mandated topics."""
    provenance = (REPO_ROOT / "docs" / "PROVENANCE.md").read_text()
    mrtd = (REPO_ROOT / "docs" / "MRTD.md").read_text()
    budget = (REPO_ROOT / "docs" / "BUDGET.md").read_text()
    for needle in (
        "provenance verify",
        "NOT_PROVEN",
        "cathedral-tdx-challenge-v2",
        "independent",
    ):
        assert needle in provenance, needle
    for needle in ("min_tcb", "Rollback", "cathedral_measurement_approval.py"):
        assert needle in mrtd, needle
    for needle in ("10% burn", "spend ceiling", "Security exceptions", "NOT_PROVEN"):
        assert needle in budget, needle
    # The claim stays exactly this narrow, everywhere it is stated
    # (whitespace-normalized: markdown wraps lines).
    for text in (provenance, mrtd):
        assert "SN39 mainnet: validated Intel TDX CPU compute" in " ".join(text.split())
