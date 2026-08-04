"""Keep the required cross-repository CI job on the reviewed contract set."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
DISTILL_REVISION = "a80119cb21c2e1ba4da4d05a500387f2d8ca0e4b"
VALIDATOR_REVISION = "77157996c51193a531149f538c581ea788054fbf"


def _checkout_ref(workflow: str, repository: str) -> str:
    match = re.search(
        rf"repository: {re.escape(repository)}\n(?:\s*#.*\n)*\s*ref: ([0-9a-f]{{40}})",
        workflow,
    )
    assert match is not None, f"missing immutable checkout for {repository}"
    return match.group(1)


def test_required_cross_repository_job_uses_the_reviewed_contract_revisions() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert _checkout_ref(workflow, "cathedralai/cathedral-distill") == DISTILL_REVISION
    assert _checkout_ref(workflow, "cathedralai/cathedral-validator") == VALIDATOR_REVISION
    assert 'CATHEDRAL_REQUIRED_CROSS_REPO_CONTRACT: "1"' in workflow
    assert "tests/test_cross_repo_receipt_v2_contract.py" in workflow
