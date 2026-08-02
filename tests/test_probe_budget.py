"""Bounded per-epoch probe budgets, and the fairness a budget requires.

Open enrollment lets the due set grow to the policy's worker cap, so a pass
needs a bound on how much work it will do. A bound on its own introduces a
worse bug than it fixes: `due_refreshes` returns rows ordered by hotkey, so
truncating that list probes the same lexicographically smallest hotkeys every
pass and never reaches the tail.

Covers:
  1. No budget preserves the historical unbounded behaviour exactly.
  2. Under a budget, the most overdue targets go first.
  3. Interior shares prevent either class from starving. The 0 and 1 endpoints
     preserve their explicit single-class priority.
  4. Unused capacity spills between classes rather than being wasted.
  5. Deferral is not failure: no verdict, lifecycle state, or retry counter
     changes for a deferred target.
  6. The wall-clock deadline defers rather than fails.
  7. Argument validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import cathedral.prober as prober_module
import pytest

from cathedral.common import Policy
from cathedral.enroll import RegistryStore
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
    state_changed_at: datetime | None = None
    generation: int = 1
    revision: int = 1


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
    due += [
        attested(f"5R{index:03d}", expires_in=timedelta(minutes=index + 1)) for index in range(4)
    ]

    selected, _ = select_probe_targets(due, max_probes=8, new_worker_share=0.25)

    refreshed = [name for name in names(selected) if name.startswith("5R")]
    assert len(refreshed) == 4  # every due refresh still got its slot
    assert len([name for name in names(selected) if name.startswith("5N")]) == 4


def test_a_full_subnet_of_refreshes_still_admits_new_workers():
    due = [
        attested(f"5R{index:03d}", expires_in=timedelta(minutes=index + 1)) for index in range(100)
    ]
    due += [new_worker("5NEW1"), new_worker("5NEW2")]

    selected, _ = select_probe_targets(due, max_probes=8, new_worker_share=0.25)
    assert "5NEW1" in names(selected)
    assert "5NEW2" in names(selected)


def test_a_share_that_rounds_to_zero_still_reserves_one_slot():
    due = [
        attested(f"5R{index:03d}", expires_in=timedelta(minutes=index + 1)) for index in range(20)
    ]
    due += [new_worker("5NEW1")]

    selected, _ = select_probe_targets(due, max_probes=3, new_worker_share=0.01)
    assert "5NEW1" in names(selected)


def test_a_zero_share_gives_new_workers_nothing_when_refreshes_fill_the_budget():
    due = [
        attested(f"5R{index:03d}", expires_in=timedelta(minutes=index + 1)) for index in range(10)
    ]
    due += [new_worker("5NEW1")]

    selected, deferred = select_probe_targets(due, max_probes=4, new_worker_share=0.0)
    assert "5NEW1" not in names(selected)
    assert "5NEW1" in names(deferred)


def test_a_one_slot_mixed_budget_is_rejected_instead_of_starving_refreshes():
    due = [
        waiting("5NEW", since=timedelta(hours=1)),
        attested("5REFRESH", expires_in=timedelta(minutes=1)),
    ]

    with pytest.raises(ValueError, match="at least 2"):
        select_probe_targets(due, max_probes=1, new_worker_share=0.25)


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
    due = [
        attested(f"5R{index:03d}", expires_in=timedelta(minutes=index + 1)) for index in range(10)
    ]
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
    due = [
        attested(f"5R{index:03d}", expires_in=timedelta(minutes=index + 1)) for index in range(6)
    ]
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


# ---------------------------------------------------------------------------
# 8. Fairness inside the fresh class, and dispatch order under a deadline
# ---------------------------------------------------------------------------


def waiting(name: str, *, since: timedelta) -> tuple[FakeEnrollment, FakeLifecycle]:
    """A worker awaiting its first probe, enrolled *since* ago."""
    return (
        FakeEnrollment(name),
        FakeLifecycle(name, state_changed_at=NOW - since),
    )


def test_the_fresh_class_is_first_come_first_served_not_lowest_hotkey():
    """Ordering the fresh class by hotkey is grindable.

    Both evidence timestamps are None for a worker awaiting its first probe,
    so without an age key the whole class collapses onto the hotkey
    tie-break, and an attacker who grinds a low-sorting ss58 takes the
    reserved share every pass.
    """
    due = [
        waiting("5ZZZ_oldest", since=timedelta(hours=3)),
        waiting("5AAA_newest", since=timedelta(minutes=1)),
        waiting("5MMM_middle", since=timedelta(hours=1)),
    ]
    selected, deferred = select_probe_targets(due, max_probes=2, new_worker_share=1.0)
    assert names(selected) == ["5ZZZ_oldest", "5MMM_middle"]
    assert names(deferred) == ["5AAA_newest"]


def test_a_ground_low_sorting_hotkey_cannot_jump_the_fresh_queue():
    honest = [waiting(f"5H{index:03d}", since=timedelta(hours=2)) for index in range(4)]
    attacker = [waiting(f"1A{index:03d}", since=timedelta(seconds=1)) for index in range(20)]

    selected, _ = select_probe_targets(honest + attacker, max_probes=4, new_worker_share=1.0)
    assert all(name.startswith("5H") for name in names(selected))


def test_selection_preserves_refresh_priority_before_deadline_reordering():
    """Selection stays refresh-first; probe_once makes the first wave fair."""
    due = [waiting(f"5N{index}", since=timedelta(hours=1)) for index in range(4)]
    due += [attested(f"5R{index}", expires_in=timedelta(minutes=index + 1)) for index in range(4)]

    selected, _ = select_probe_targets(due, max_probes=8, new_worker_share=0.5)
    dispatched = names(selected)
    assert all(name.startswith("5R") for name in dispatched[:4])
    assert all(name.startswith("5N") for name in dispatched[4:])


def test_deadline_without_count_budget_still_uses_the_fair_order():
    due = [
        waiting("5AAA_newest", since=timedelta(minutes=1)),
        waiting("5ZZZ_oldest", since=timedelta(hours=3)),
        attested("5REFRESH", expires_in=timedelta(minutes=1)),
    ]

    selected, deferred = select_probe_targets(
        due,
        max_probes=None,
        deadline_active=True,
    )

    assert names(selected) == ["5REFRESH", "5ZZZ_oldest", "5AAA_newest"]
    assert deferred == []


def test_deadline_deferral_does_not_mutate_lifecycle_or_retry_state(monkeypatch, tmp_path):
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkeys = ["5" + letter * 47 for letter in ("A", "B", "D")]
    for index, hotkey in enumerate(hotkeys):
        store.enroll(hotkey, f"http://127.0.0.1:{9000 + index}")
    deferred_hotkey = hotkeys[-1]
    before = store.lifecycle_snapshot(deferred_hotkey)
    monotonic_values = iter((0.0, 2.0))

    class FakeTime:
        @staticmethod
        def monotonic():
            return next(monotonic_values)

    monkeypatch.setattr(prober_module, "time", FakeTime())
    starts: list[str] = []

    def fail_started_probe(_url, hotkey, _nonce, **_kwargs):
        starts.append(hotkey)
        raise OSError("synthetic first-wave failure")

    monkeypatch.setattr(prober_module, "_request_evidence", fail_started_probe)

    assert not prober_module.probe_once(
        store,
        Policy(),
        max_workers=2,
        max_probes=3,
        new_worker_share=1.0,
        deadline_seconds=1.0,
    )

    after = store.lifecycle_snapshot(deferred_hotkey)
    assert deferred_hotkey not in starts
    assert after == before


def test_a_two_class_deadline_rejects_one_effective_worker(tmp_path):
    store = RegistryStore(str(tmp_path / "registry.sqlite"))

    with pytest.raises(ValueError, match="at least 2 effective workers"):
        prober_module.probe_once(
            store,
            Policy(),
            max_workers=1,
            max_probes=2,
            new_worker_share=0.25,
            deadline_seconds=1.0,
        )


@pytest.mark.parametrize(
    ("new_worker_share", "expected_prefix"),
    [(0.0, "5REFRESH"), (1.0, "5FRESH")],
)
def test_deadline_endpoint_shares_keep_their_single_class_priority(
    new_worker_share: float,
    expected_prefix: str,
):
    due = [
        attested(f"5REFRESH{index}", expires_in=timedelta(minutes=index + 1)) for index in range(3)
    ]
    due += [waiting(f"5FRESH{index}", since=timedelta(hours=3 - index)) for index in range(3)]
    selected, _deferred = select_probe_targets(
        due,
        max_probes=4,
        new_worker_share=new_worker_share,
        deadline_active=True,
    )

    ordered = prober_module._deadline_fair_dispatch_order(
        selected,
        worker_count=1,
        new_worker_share=new_worker_share,
    )

    assert ordered[0][0].hotkey.startswith(expected_prefix)


def test_slow_refreshes_cannot_consume_the_fresh_reservation_across_passes(
    monkeypatch,
):
    due = [
        attested(f"5REFRESH{index}", expires_in=timedelta(minutes=index + 1)) for index in range(3)
    ]
    due.append(waiting("5FRESH", since=timedelta(hours=2)))
    starts: list[str] = []

    class FakeStore:
        verification_ttl_seconds = 3600

        def due_refreshes(self, **_kwargs):
            return tuple(lifecycle for _enrollment, lifecycle in due)

        def enrollments(self):
            return tuple(enrollment for enrollment, _lifecycle in due)

        def record_verdict(self, *_args, **_kwargs):
            return None

        def record_probe_failure(self, *_args, **_kwargs):
            return None

    # Per pass: compute expiry at 0, admit the two-worker first wave, then
    # expire the deadline before the remaining two start. With the old
    # refresh-first queue, both admitted starts were refreshes forever.
    monotonic_values = iter((0.0, 2.0, 2.0) * 4)

    class FakeTime:
        @staticmethod
        def monotonic():
            return next(monotonic_values)

    # Replace only the prober's module reference. Patching the process-wide
    # time.monotonic would also perturb ThreadPoolExecutor's own scheduling.
    monkeypatch.setattr(prober_module, "time", FakeTime())

    def record_start(_url, hotkey, _nonce, **_kwargs):
        starts.append(hotkey)
        return []

    monkeypatch.setattr(prober_module, "_request_evidence", record_start)
    monkeypatch.setattr(
        prober_module,
        "verify_cc_evidence_bundle",
        lambda *_args, **_kwargs: object(),
    )

    store = FakeStore()
    for pass_number in range(4):
        before = len(starts)
        assert not prober_module.probe_once(
            store,
            Policy(),
            max_workers=2,
            max_probes=4,
            new_worker_share=0.25,
            deadline_seconds=1.0,
        )
        assert "5FRESH" in starts[before:], f"fresh class starved in pass {pass_number + 1}"

    assert starts.count("5FRESH") == 4


def test_successful_first_waves_rotate_through_both_class_tails():
    @dataclass
    class MutableLifecycle:
        hotkey: str
        evidence_verified_at: datetime | None = None
        evidence_expires_at: datetime | None = None
        state_changed_at: datetime | None = None

    due: list[tuple[FakeEnrollment, MutableLifecycle]] = []
    for index in range(3):
        name = f"5REFRESH{index}"
        due.append(
            (
                FakeEnrollment(name),
                MutableLifecycle(
                    name,
                    evidence_verified_at=NOW - timedelta(hours=1),
                    evidence_expires_at=NOW + timedelta(minutes=index + 1),
                    state_changed_at=NOW - timedelta(hours=1),
                ),
            )
        )
    for index in range(3):
        name = f"5FRESH{index}"
        due.append(
            (
                FakeEnrollment(name),
                MutableLifecycle(
                    name,
                    state_changed_at=NOW - timedelta(hours=3 - index),
                ),
            )
        )

    started: list[str] = []
    for pass_number in range(3):
        selected, _deferred = select_probe_targets(
            due,
            max_probes=4,
            new_worker_share=0.25,
            deadline_active=True,
        )
        first_wave = prober_module._deadline_fair_dispatch_order(
            selected,
            worker_count=2,
            new_worker_share=0.25,
        )[:2]
        for _enrollment, lifecycle in first_wave:
            started.append(lifecycle.hotkey)
            lifecycle.evidence_verified_at = NOW + timedelta(seconds=pass_number + 1)
            lifecycle.evidence_expires_at = NOW + timedelta(hours=1, seconds=pass_number + 1)

    assert {f"5REFRESH{index}" for index in range(3)} <= set(started)
    assert {f"5FRESH{index}" for index in range(3)} <= set(started)


@pytest.mark.parametrize("deadline", [float("nan"), float("inf")])
def test_non_finite_deadlines_are_rejected(deadline: float, tmp_path):
    store = RegistryStore(str(tmp_path / "registry.sqlite"))

    with pytest.raises(ValueError, match="finite and positive"):
        prober_module.probe_once(
            store,
            Policy(),
            deadline_seconds=deadline,
        )


@pytest.mark.parametrize("raw_deadline", ["nan", "inf"])
def test_cli_rejects_non_finite_deadlines(
    raw_deadline: str,
    monkeypatch,
    tmp_path,
    capsys,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "cathedral-prober",
            "--once",
            "--db",
            str(tmp_path / "registry.sqlite"),
            "--pass-deadline-seconds",
            raw_deadline,
        ],
    )

    with pytest.raises(SystemExit):
        prober_module.main()

    assert "finite and positive" in capsys.readouterr().err
