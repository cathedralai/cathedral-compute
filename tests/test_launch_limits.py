"""Contract: the frozen launch cardinality is actually frozen.

`cathedral/launch_limits.py` calls itself a "Frozen SN39 Intel TDX launch
cardinality contract" and says its limits are "shared by the score producer,
evidence exporter, and independent verifier". Nothing froze them. Four of the
six could be changed with the whole suite still green:

    MAX_LAUNCH_CANDIDATES               SURVIVED
    MAX_LAUNCH_VERIFIED_CANDIDATES      caught
    MAX_LAUNCH_HOTKEY_BYTES             SURVIVED
    MAX_LAUNCH_WIRE_REPORT_BYTES        SURVIVED
    MAX_LAUNCH_SCORE_REPORT_BYTES       caught
    MAX_LAUNCH_EVIDENCE_BASE_URI_BYTES  SURVIVED

The two that were caught are caught incidentally, by tests that use the symbol
as a bound rather than assert its value, so they only object to some changes.

Why a literal pin rather than a derived one. Several of these are *exact*
ceilings belonging to a system this repository does not control: the subnet
publisher's authenticated intake, and the public evidence verifier's fetch
limit. A test that re-derives a ceiling from the symbol agrees with itself no
matter what the symbol says. Only a literal can disagree.

The failure a drift produces is expensive and late. Raise the wire ceiling and
the producer will freeze and post a report the publisher then refuses: the
epoch is already committed and immutable, `retry-publish` resends the same
bytes forever, and the only exit is `abandon-complete`. The work is done, paid
for in compute, and unpublishable. Lowering one strands reports the other side
would have accepted.

So changing any of these is a deliberate cross-system decision. This file makes
it fail here first, next to the reason, rather than in production against a
service that is entitled to say no.
"""

from __future__ import annotations

from cathedral.launch_limits import (
    MAX_LAUNCH_CANDIDATES,
    MAX_LAUNCH_EVIDENCE_BASE_URI_BYTES,
    MAX_LAUNCH_HOTKEY_BYTES,
    MAX_LAUNCH_SCORE_REPORT_BYTES,
    MAX_LAUNCH_VERIFIED_CANDIDATES,
    MAX_LAUNCH_WIRE_REPORT_BYTES,
)


def test_launch_cardinality_is_frozen():
    """The candidate-set bounds. Raising these changes what an epoch may hold."""
    assert MAX_LAUNCH_CANDIDATES == 4096
    assert MAX_LAUNCH_VERIFIED_CANDIDATES == 28


def test_subnet_intake_ceilings_are_frozen():
    """Exact ceilings owned by the subnet publisher, not by this repository.

    `MAX_LAUNCH_HOTKEY_BYTES` is "the exact upper bound accepted by the SN39
    confidential-score intake", and `MAX_LAUNCH_WIRE_REPORT_BYTES` is the
    "exact authenticated intake ceiling on the subnet publisher". Raising
    either lets the producer publish something the publisher must reject, which
    is precisely what keeping them here is meant to prevent.
    """
    assert MAX_LAUNCH_HOTKEY_BYTES == 128
    assert MAX_LAUNCH_WIRE_REPORT_BYTES == 1024 * 1024


def test_public_verifier_ceilings_are_frozen():
    """Bounds the independent verifier fetches under.

    The 2 MiB score-report ceiling exists because a maximal 4,096-candidate
    report at the launch hotkey bound must fit beneath it; the former 1 MiB cap
    did not. So this one is not independent of the two above, and changing
    either without the other reopens that gap.
    """
    assert MAX_LAUNCH_SCORE_REPORT_BYTES == 2 * 1024 * 1024
    assert MAX_LAUNCH_EVIDENCE_BASE_URI_BYTES == 2048


def test_a_maximal_report_still_fits_beneath_the_verifier_ceiling():
    """The relationship the comment asserts, checked rather than trusted.

    This is the reason the score-report ceiling is 2 MiB and not 1 MiB. Pinning
    the numbers individually would not notice if the relationship between them
    stopped holding, so it is asserted directly: a maximal candidate set at the
    maximal hotkey length must not exceed what the verifier will fetch.
    """
    # A generous per-entry allowance for JSON structure around each identity.
    per_entry_overhead = 128
    worst_case = MAX_LAUNCH_CANDIDATES * (MAX_LAUNCH_HOTKEY_BYTES + per_entry_overhead)
    assert worst_case <= MAX_LAUNCH_SCORE_REPORT_BYTES, (
        f"a maximal report ({worst_case} bytes) no longer fits beneath the "
        f"verifier's {MAX_LAUNCH_SCORE_REPORT_BYTES}-byte fetch ceiling"
    )
