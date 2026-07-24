"""Envelope-digest schema migration: ordering, preservation, fail-closed gate."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from cathedral.ledger import Ledger, LedgerError

ENVELOPE = "sha256:" + "a" * 64


def _legacy_cpu_schema(path: Path, *, with_envelope: bool, envelope_value: str | None):
    """Recreate the historical CPU-only epoch_attestations table."""
    ledger = Ledger(path)
    epoch_id = ledger.begin_epoch(11)
    ledger.close()
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE epoch_attestations")
        envelope_column = "envelope_digest TEXT," if with_envelope else ""
        connection.execute(
            "CREATE TABLE epoch_attestations ("
            "epoch_id INTEGER NOT NULL REFERENCES epochs(epoch_id),"
            "hotkey TEXT NOT NULL,"
            "verdict TEXT NOT NULL CHECK (verdict = 'VERIFIED'),"
            "tee_type TEXT NOT NULL CHECK (tee_type = 'TDX'),"
            "workload TEXT NOT NULL CHECK (workload = 'CPU'),"
            "evidence_digest TEXT NOT NULL,"
            f"{envelope_column}"
            "attested_at TEXT NOT NULL,"
            "PRIMARY KEY (epoch_id,hotkey))"
        )
        if with_envelope:
            connection.execute(
                "INSERT INTO epoch_attestations VALUES (?,?,?,?,?,?,?,?)",
                (
                    epoch_id,
                    "legacy-hotkey",
                    "VERIFIED",
                    "TDX",
                    "CPU",
                    "sha256:" + "b" * 64,
                    envelope_value,
                    "2026-07-01T00:00:00.000000+00:00",
                ),
            )
        else:
            connection.execute(
                "INSERT INTO epoch_attestations VALUES (?,?,?,?,?,?,?)",
                (
                    epoch_id,
                    "legacy-hotkey",
                    "VERIFIED",
                    "TDX",
                    "CPU",
                    "sha256:" + "b" * 64,
                    "2026-07-01T00:00:00.000000+00:00",
                ),
            )
    return epoch_id


def _columns(path: Path) -> set[str]:
    with sqlite3.connect(path) as connection:
        return {
            row[1]
            for row in connection.execute("PRAGMA table_info(epoch_attestations)")
        }


def test_legacy_cpu_schema_migrates_and_envelope_survives_reopen(tmp_path: Path):
    path = tmp_path / "ledger.sqlite"
    epoch_id = _legacy_cpu_schema(path, with_envelope=False, envelope_value=None)

    reopened = Ledger(path)  # runs policy_mode + GPU rebuild + envelope adds
    columns = _columns(path)
    assert {"policy_mode", "score_eligible", "envelope_digest"} <= columns

    rows = reopened.attestation_rows(epoch_id)
    assert rows[0]["hotkey"] == "legacy-hotkey"
    assert rows[0]["envelope_digest"] is None  # historical rows: NOT PROVEN

    # New writes carry the envelope binding and survive a further reopen.
    second_epoch = epoch_id  # the legacy epoch is still running
    reopened.add_attestation(
        second_epoch,
        "modern-hotkey",
        verdict="VERIFIED",
        tee_type="TDX",
        workload="CPU",
        evidence_digest="sha256:" + "c" * 64,
        policy_mode="strict",
        envelope_digest=ENVELOPE,
    )
    reopened.close()

    third = Ledger(path)  # a further reopen must not rebuild the column away
    by_hotkey = {row["hotkey"]: row for row in third.attestation_rows(second_epoch)}
    assert by_hotkey["modern-hotkey"]["envelope_digest"] == ENVELOPE
    assert by_hotkey["legacy-hotkey"]["envelope_digest"] is None
    third.close()


def test_gpu_rebuild_preserves_a_preexisting_envelope_column(tmp_path: Path):
    """A database that gained envelope_digest before the GPU widening must
    keep both the column and its values through the rebuild."""
    path = tmp_path / "ledger.sqlite"
    epoch_id = _legacy_cpu_schema(path, with_envelope=True, envelope_value=ENVELOPE)

    reopened = Ledger(path)
    columns = _columns(path)
    assert "envelope_digest" in columns
    with sqlite3.connect(path) as connection:
        table_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='epoch_attestations'"
        ).fetchone()[0]
    assert "TDX+GPU_CC" in table_sql  # the GPU rebuild really ran
    rows = reopened.attestation_rows(epoch_id)
    assert rows[0]["envelope_digest"] == ENVELOPE  # value preserved
    reopened.close()


def test_production_scoring_attestation_requires_envelope(tmp_path: Path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    epoch_id = ledger.begin_epoch(11)
    with pytest.raises(LedgerError, match="requires a retained envelope"):
        ledger.add_attestation(
            epoch_id,
            "hotkey",
            verdict="VERIFIED",
            tee_type="TDX",
            workload="CPU",
            evidence_digest="sha256:" + "d" * 64,
            policy_mode="strict",
            envelope_digest=None,
            envelope_required=True,
        )
    # Malformed digests are rejected outright.
    with pytest.raises(LedgerError, match="envelope digest is invalid"):
        ledger.add_attestation(
            epoch_id,
            "hotkey",
            verdict="VERIFIED",
            tee_type="TDX",
            workload="CPU",
            evidence_digest="sha256:" + "d" * 64,
            policy_mode="strict",
            envelope_digest="not-a-digest",
        )
    ledger.close()


def test_idempotent_attestation_compares_envelope_exactly(tmp_path: Path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    epoch_id = ledger.begin_epoch(11)
    base = dict(
        verdict="VERIFIED",
        tee_type="TDX",
        workload="CPU",
        evidence_digest="sha256:" + "d" * 64,
        policy_mode="strict",
    )
    ledger.add_attestation(epoch_id, "hk", envelope_digest=ENVELOPE, **base)
    # Exact idempotent replay (same envelope) is accepted.
    ledger.add_attestation(
        epoch_id, "hk", envelope_digest=ENVELOPE, envelope_required=True, **base
    )
    # A different envelope for the same row is rejected.
    with pytest.raises(LedgerError, match="immutable"):
        ledger.add_attestation(
            epoch_id, "hk", envelope_digest="sha256:" + "f" * 64, **base
        )
    # Dropping the envelope on replay is rejected too.
    with pytest.raises(LedgerError, match="immutable"):
        ledger.add_attestation(epoch_id, "hk", envelope_digest=None, **base)
    # Legacy NULL row + envelope_required fails closed even on replay.
    ledger.add_attestation(epoch_id, "legacy", envelope_digest=None, **base)
    with pytest.raises(LedgerError, match="requires a retained envelope"):
        ledger.add_attestation(
            epoch_id, "legacy", envelope_digest=None, envelope_required=True, **base
        )
    ledger.close()


def test_idempotent_retry_with_conflicting_challenge_digest_rejected(tmp_path: Path):
    """Defect-9 proof: an attestation retry that changes the committed
    challenge randomness is equivocation, never an idempotent success."""
    ledger = Ledger(tmp_path / "ledger.sqlite")
    epoch_id = ledger.begin_epoch(11)
    base = dict(
        verdict="VERIFIED",
        tee_type="TDX",
        workload="CPU",
        evidence_digest="sha256:" + "d" * 64,
        policy_mode="strict",
        envelope_digest=ENVELOPE,
    )
    ledger.add_attestation(
        epoch_id, "hk", challenge_digest="sha256:" + "1" * 64, **base
    )
    ledger.add_attestation(  # exact retry OK
        epoch_id, "hk", challenge_digest="sha256:" + "1" * 64, **base
    )
    with pytest.raises(LedgerError, match="immutable"):
        ledger.add_attestation(
            epoch_id, "hk", challenge_digest="sha256:" + "2" * 64, **base
        )
    ledger.close()
