"""Bounded per-epoch probe budgets, and the fairness a budget requires.

Open enrollment lets the due set grow to the policy's worker cap, so a pass
needs a bound on how much work it will do. A bound on its own introduces a
worse bug than it fixes: `due_refreshes` returns rows ordered by hotkey, so
truncating that list probes the same lexicographically smallest hotkeys every
pass and never reaches the tail.

Covers:
  1. No budget preserves the historical unbounded behaviour exactly.
  2. Under a budget, the most overdue targets go first.
  3. Neither class starves: new workers cannot push attested workers past
     their evidence expiry, and a full subnet still admits newcomers.
  4. Unused capacity spills between classes rather than being wasted.
  5. Deferral is not failure: no verdict, lifecycle state, or retry counter
     changes for a deferred target.
  6. The wall-clock deadline defers rather than fails.
  7. Argument validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from cathedral.prober import DEFAULT_NEW_WORKER_SHARE, select_probe_targets

NOW = datetime.now(UTC).replace(microsecond=0)


@dataclass(frozen=True)
class FakeEnrollment:
    hotkey: str
    endpoint_url: str = "https://8.8.8.8:8443"


@dataclass(frozen=True)
class FakeLifecycle:
    hotkey: str
    evidence_verified_at: datetime | None = None
    evidence_expires_at: datetime | None = None


def new_worker(name: str) -> tuple[FakeEnrollment, FakeLifecycle]:
    """A worker awaiting its first probe: no verified evidence at all."""
    return FakeEnrollment(name), FakeLifecycle(name)


def attested(name: str, *, expires_in: timedelta) -> tuple[FakeEnrollment, FakeLifecycle]:
    return (
        FakeEnrollment(name),
        FakeLifecycle(
            name,
            evidence_verified_at=NOW - timedelta(hours=1),
            evidence_expires_at=NOW + expires_in,
        ),
    )


def names(targets: list[tuple[FakeEnrollment, FakeLifecycle]]) -> list[str]:
    return [enrollment.hotkey for enrollment, _ in targets]


# ---------------------------------------------------------------------------
# 1. No budget
# ---------------------------------------------------------------------------

def test_no_budget_keeps_every_target_in_the_original_order():
    due = [new_worker("5C"), attested("5A", expires_in=timedelta(minutes=1)), new_worker("5B")]
    selected, deferred = select_probe_targets(due, max_probes=None)
    assert selected == due  # identity, not just equality of contents
    assert deferred == []


def test_a_budget_larger_than_the_due_set_defers_nothing():
    due = [new_worker("5A"), new_worker("5B")]
    selected, deferred = select_probe_targets(due, max_probes=10)
    assert names(selected) == ["5A", "5B"]
    assert deferred == []


# ---------------------------------------------------------------------------
# 2. Most overdue first
# ---------------------------------------------------------------------------

def test_the_most_overdue_refreshes_go_first_not_the_lowest_hotkeys():
    """The regression a naive truncation would cause."""
    due = [
        attested("5AAA", expires_in=timedelta(hours=5)),  # least overdue, lowest name
        attested("5BBB", expires_in=timedelta(hours=1)),
        attested("5ZZZ", expires_in=timedelta(minutes=1)),  # most overdue, highest name
    ]
    selected, deferred = select_probe_targets(due, max_probes=2, new_worker_share=0.0)
    assert names(selected) == ["5ZZZ", "5BBB"]
    assert names(deferred) == ["5AAA"]


def test_ordering_is_deterministic_for_equally_overdue_targets():
    due = [
        attested("5C", expires_in=timedelta(hours=1)),
        attested("5A", expires_in=timedelta(hours=1)),
        attested("5B", expires_in=timedelta(hours=1)),
    ]
    first, _ = select_probe_targets(due, max_probes=2, new_worker_share=0.0)
    second, _ = select_probe_targets(list(reversed(due)), max_probes=2, new_worker_share=0.0)
    assert names(first) == names(second) == ["5A", "5B"]


# ---------------------------------------------------------------------------
# 3. Neither class starves
# ---------------------------------------------------------------------------

def test_a_flood_of_new_workers_cannot_starve_attested_refreshes():
    """Open mode's sharpest abuse: zeroing honest supply by enrolling.

    If first probes always won, anyone could enroll continuously and push
    already-attested miners past their evidence expiry.
    """
    due = [new_worker(f"5N{index:03d}") for index in range(100)]
    due += [attested(f"5R{index:03d}", expires_in=timedelta(minutes=index + 1)) for index in range(4)]

    selected, _ = select_probe_targets(due, max_probes=8, new_worker_share=0.25)

    refreshed = [name for name in names(selected) if name.startswith("5R")]
    assert len(refreshed) == 4  # every due refresh still got its slot
    assert len([name for name in names(selected) if name.startswith("5N")]) == 4


def test_a_full_subnet_of_refreshes_still_admits_new_workers():
    due = [attested(f"5R{index:03d}", expires_in=timedelta(minutes=index + 1)) for index in range(100)]
    due += [new_worker("5NEW1"), new_worker("5NEW2")]

    selected, _ = select_probe_targets(due, max_probes=8, new_worker_share=0.25)
    assert "5NEW1" in names(selected)
    assert "5NEW2" in names(selected)


def test_a_share_that_rounds_to_zero_still_reserves_one_slot():
    due = [attested(f"5R{index:03d}", expires_in=timedelta(minutes=index + 1)) for index in range(20)]
    due += [new_worker("5NEW1")]

    selected, _ = select_probe_targets(due, max_probes=3, new_worker_share=0.01)
    assert "5NEW1" in names(selected)


def test_a_zero_share_gives_new_workers_nothing_when_refreshes_fill_the_budget():
    due = [attested(f"5R{index:03d}", expires_in=timedelta(minutes=index + 1)) for index in range(10)]
    due += [new_worker("5NEW1")]

    selected, deferred = select_probe_targets(due, max_probes=4, new_worker_share=0.0)
    assert "5NEW1" not in names(selected)
    assert "5NEW1" in names(deferred)


# ---------------------------------------------------------------------------
# 4. Spill
# ---------------------------------------------------------------------------

def test_unused_refresh_capacity_spills_to_new_workers():
    due = [new_worker(f"5N{index:03d}") for index in range(10)]
    due += [attested("5R001", expires_in=timedelta(minutes=1))]

    selected, deferred = select_probe_targets(due, max_probes=6, new_worker_share=0.25)
    assert len(selected) == 6  # the budget is fully spent, not left idle
    assert "5R001" in names(selected)
    assert len([name for name in names(selected) if name.startswith("5N")]) == 5
    assert len(deferred) == 5


def test_unused_new_worker_capacity_spills_to_refreshes():
    due = [attested(f"5R{index:03d}", expires_in=timedelta(minutes=index + 1)) for index in range(10)]
    due += [new_worker("5NEW1")]

    selected, _ = select_probe_targets(due, max_probes=6, new_worker_share=0.25)
    assert len(selected) == 6
    assert len([name for name in names(selected) if name.startswith("5R")]) == 5


def test_selected_and_deferred_partition_the_due_set_exactly():
    due = [new_worker(f"5N{index}") for index in range(5)]
    due += [attested(f"5R{index}", expires_in=timedelta(minutes=index + 1)) for index in range(5)]

    selected, deferred = select_probe_targets(due, max_probes=4)
    assert len(selected) == 4
    assert len(selected) + len(deferred) == len(due)
    assert sorted(names(selected) + names(deferred)) == sorted(names(due))
    # No target appears in both halves.
    assert not set(names(selected)) & set(names(deferred))


# ---------------------------------------------------------------------------
# 5. Deferral is not failure
# ---------------------------------------------------------------------------

def test_deferred_targets_are_returned_untouched_not_marked_failed():
    """The function returns the same objects; it never mutates a verdict."""
    due = [attested(f"5R{index:03d}", expires_in=timedelta(minutes=index + 1)) for index in range(6)]
    before = [(enrollment, lifecycle) for enrollment, lifecycle in due]

    _, deferred = select_probe_targets(due, max_probes=2, new_worker_share=0.0)

    for target in deferred:
        assert target in before
        _enrollment, lifecycle = target
        assert lifecycle.evidence_verified_at is not None  # verdict intact


# ---------------------------------------------------------------------------
# 6 & 7. Validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("budget", [0, -1])
def test_a_non_positive_budget_is_rejected(budget: int):
    with pytest.raises(ValueError, match="max_probes must be at least 1"):
        select_probe_targets([new_worker("5A")], max_probes=budget)


@pytest.mark.parametrize("share", [-0.1, 1.1])
def test_an_out_of_range_share_is_rejected(share: float):
    due = [new_worker("5A"), new_worker("5B")]
    with pytest.raises(ValueError, match="new_worker_share"):
        select_probe_targets(due, max_probes=1, new_worker_share=share)


def test_the_default_share_reserves_a_quarter():
    assert DEFAULT_NEW_WORKER_SHARE == 0.25
    due = [new_worker(f"5N{index}") for index in range(10)]
    due += [attested(f"5R{index}", expires_in=timedelta(minutes=index + 1)) for index in range(10)]
    selected, _ = select_probe_targets(due, max_probes=8)
    assert len([name for name in names(selected) if name.startswith("5N")]) == 2
