"""Contract: shadow work timing is captured for every dispatched work item.

warm_supply M0: the producer stamps its own monotonic clock at dispatch and at
certificate verification and persists the pair per challenge. Nothing on the
scoring or export path reads the table, so these tests also pin the property
that timing capture never moves a weight and never enters the signed report.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cathedral.ledger import Ledger, LedgerError

from tests.test_runtime import CANARY, MinerSpec, default_specs, make_runtime


def _run_verified_epoch(tmp_path: Path):
    runtime, ledger, _factory = make_runtime(
        tmp_path,
        [("miner", "http://127.0.0.1:9001")],
        default_specs(**{"9001": MinerSpec("chip-1")}),
    )
    run = runtime.run_epoch(1, CANARY)
    assert run.status == "complete"
    assert run.scores["miner"] == 1.0
    return runtime, ledger, run


def _timing_rows(ledger: Ledger, epoch_id: int):
    with ledger._lock:
        rows = ledger._connection.execute(
            "SELECT t.challenge_id, t.dispatch_monotonic_ns, t.verified_monotonic_ns, "
            "t.job_class, t.producer_boot_id FROM work_timing t "
            "JOIN challenges c ON c.challenge_id = t.challenge_id "
            "WHERE c.epoch_id = ?",
            (epoch_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def test_verified_epoch_records_canonical_timing(tmp_path: Path) -> None:
    _runtime, ledger, run = _run_verified_epoch(tmp_path)
    rows = _timing_rows(ledger, run.epoch_id)
    assert rows, "a verified epoch must capture timing for its dispatched work"
    for row in rows:
        assert row["job_class"] == "canonical"
        assert row["verified_monotonic_ns"] >= row["dispatch_monotonic_ns"] >= 0
        assert row["producer_boot_id"]
        timing = ledger.work_timing_for_challenge(row["challenge_id"])
        assert timing is not None
        assert timing["job_class"] == "canonical"


def test_timing_rows_share_one_boot_id_per_process(tmp_path: Path) -> None:
    _runtime, ledger, run = _run_verified_epoch(tmp_path)
    rows = _timing_rows(ledger, run.epoch_id)
    assert len({row["producer_boot_id"] for row in rows}) == 1


def test_timing_capture_never_enters_the_frozen_report(tmp_path: Path) -> None:
    import json

    _runtime, ledger, run = _run_verified_epoch(tmp_path)
    report = bytes(ledger.get_epoch(run.epoch_id)["report_body"])
    assert "timing" not in json.loads(report)
    assert b"monotonic" not in report


def test_failed_work_still_records_timing(tmp_path: Path) -> None:
    runtime, ledger, _factory = make_runtime(
        tmp_path,
        [("miner", "http://127.0.0.1:9001")],
        default_specs(**{"9001": MinerSpec("chip-1", invalid_sat=True)}),
    )
    run = runtime.run_epoch(1, CANARY)
    rows = _timing_rows(ledger, run.epoch_id)
    assert rows, "failed work is still a latency sample"
    assert all(row["job_class"] == "canonical" for row in rows)


def test_record_work_timing_fails_closed_on_invalid_rows(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "ledger.sqlite")
    epoch_id = ledger.begin_epoch(1)
    ledger.issue_challenge("challenge-1", "miner", epoch_id)
    good = dict(
        dispatch_monotonic_ns=100,
        verified_monotonic_ns=200,
        job_class="canonical",
        producer_boot_id="boot-1",
    )
    for corruption in (
        {"dispatch_monotonic_ns": -1},
        {"verified_monotonic_ns": 99},
        {"dispatch_monotonic_ns": True},
        {"job_class": "probe"},
        {"producer_boot_id": ""},
    ):
        with pytest.raises(LedgerError):
            ledger.record_work_timing("challenge-1", **{**good, **corruption})
    assert ledger.work_timing_for_challenge("challenge-1") is None


def test_recorded_timing_is_immutable(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "ledger.sqlite")
    epoch_id = ledger.begin_epoch(1)
    ledger.issue_challenge("challenge-1", "miner", epoch_id)
    kwargs = dict(
        dispatch_monotonic_ns=100,
        verified_monotonic_ns=200,
        job_class="canonical",
        producer_boot_id="boot-1",
    )
    ledger.record_work_timing("challenge-1", **kwargs)
    ledger.record_work_timing("challenge-1", **kwargs)  # identical replay is fine
    with pytest.raises(LedgerError):
        ledger.record_work_timing("challenge-1", **{**kwargs, "verified_monotonic_ns": 201})
