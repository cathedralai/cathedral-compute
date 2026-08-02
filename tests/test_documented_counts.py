"""Every documented test count must match the suite, or the suite says so.

Ported from cathedral-distill, which added this after the same drift: a count
appears in the docs a newcomer reads first, nothing checks it, and it quietly
stops being true. Here it had drifted into two different values describing one
suite — `1,247 passed` in BUILD_STATUS.md and `1162 passed` in
docs/LAUNCH_CANDIDATE.md — each written at a different moment and then left,
while the suite had moved to 1399 collected. A number nobody verifies is worse
than no number: it is a specific, checkable claim about the project that happens
to be false.

**Collected, not passing — and a "N passed" claim is REFUSED, not validated.**
This repository's hardware suites skip unless the machine can run them:
`CATHEDRAL_RUN_TDX_HW` needs a real Intel TDX CVM and `CATHEDRAL_RUN_SNP_HW` an
SEV-SNP guest. So the number that *passes* on a laptop is not the number that
passes on the TDX box, and neither is wrong — which is exactly the kind of number
that cannot be maintained in a document. The collected count is identical
everywhere, so that is what is claimed and checked.

`CLAIM` still matches the "N passed" phrasing, but only in order to reject it.
Both stale claims here used that phrasing, so a guard that only looked for
"N tests" would have seen neither.

Collection runs in a subprocess so the answer does not depend on how this test
was invoked: running one file must not report a smaller suite and fail.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Every file that states a count. Add a file here when it starts making the
# claim; the test then holds it to the same number.
CLAIM = re.compile(r"(\d[\d,]*)\s*(?:passing\s+)?(tests|passed)\b", re.IGNORECASE)
DOCUMENTED = (
    "BUILD_STATUS.md",
    "docs/LAUNCH_CANDIDATE.md",
)


def _collected() -> int:
    """How many tests the suite collects, asked of pytest itself."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-o", "addopts=",
         "-p", "no:cacheprovider", "tests"],
        capture_output=True, text=True, cwd=ROOT, timeout=600,
    )
    match = re.search(r"(\d+) tests? collected", result.stdout)
    if match is None:
        pytest.fail(
            "could not read a collected-test count from pytest:\n"
            f"exit={result.returncode}\n{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
        )
    return int(match.group(1))


def _claims(relative: str) -> list[tuple[int, int, str, str]]:
    """`(line_number, count, kind, line)` for every stated count in one file."""
    path = ROOT / relative
    found: list[tuple[int, int, str, str]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for match in CLAIM.finditer(line):
            # Skip ordinals and code identifiers: only a bare integer is a claim.
            digits = match.group(1).replace(",", "")
            if digits.isdigit():
                found.append((number, int(digits), match.group(2).lower(), line.strip()))
    return found


def test_the_suite_still_collects_what_the_docs_claim():
    collected = _collected()
    wrong: list[str] = []
    fragile: list[str] = []
    seen = 0
    for relative in DOCUMENTED:
        for line_number, claimed, kind, text in _claims(relative):
            seen += 1
            if kind == "passed":
                fragile.append(f"  {relative}:{line_number} says {claimed} passed — {text[:80]}")
            elif claimed != collected:
                wrong.append(f"  {relative}:{line_number} says {claimed} tests — {text[:80]}")
    assert seen, "no file states a test count any more; drop this test or fix DOCUMENTED"
    assert not fragile, (
        "these state a PASSED count, which is not the same on two honest checkouts:\n"
        + "\n".join(fragile)
        + "\n\nThe TDX and SEV-SNP suites skip unless CATHEDRAL_RUN_TDX_HW /\n"
        "CATHEDRAL_RUN_SNP_HW and the hardware are present, so the passing total\n"
        f"moves with the machine. State the collected count instead:\n"
        f"  {collected} tests"
    )
    assert not wrong, (
        f"the suite collects {collected} tests, but these disagree:\n"
        + "\n".join(wrong)
        + f"\n\nUpdate them to {collected}."
    )


def test_every_listed_file_exists_and_states_a_count():
    """A renamed or reworded file must not silently stop being checked."""
    for relative in DOCUMENTED:
        path = ROOT / relative
        assert path.is_file(), f"{relative} is listed in DOCUMENTED but does not exist"
        assert _claims(relative), (
            f"{relative} no longer states a test count; remove it from DOCUMENTED "
            "rather than leaving a check that silently passes"
        )


def test_the_count_is_collected_rather_than_passing():
    """The documented number must be the environment-independent one.

    A `passing` count would differ between a laptop and the TDX box, so it cannot
    be stated in a document that is true everywhere. This asserts the gap exists,
    so if the hardware gate ever goes away the choice can be revisited
    deliberately rather than by accident.
    """
    gated = [
        path for path in (ROOT / "tests").glob("*.py")
        if "CATHEDRAL_RUN_TDX_HW" in path.read_text(encoding="utf-8")
        or "CATHEDRAL_RUN_SNP_HW" in path.read_text(encoding="utf-8")
    ]
    assert gated, (
        "nothing gates on CATHEDRAL_RUN_TDX_HW or CATHEDRAL_RUN_SNP_HW any more; "
        "if nothing skips by default, a `passing` count is now stable and this "
        "module's choice of `collected` can be reconsidered"
    )
