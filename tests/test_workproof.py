"""Independent SAT work replay: the item-A counterexample matrix."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal

import pytest

from cathedral.lanes.sat import _compute_challenge_id
from cathedral.lanes.sat_types import SatCertificate, SatInstance, SatWorkItem
from cathedral.runtime import _sat_manifest_bytes, _sat_result_bytes
from cathedral.workproof import WorkProofError, verify_work_artifacts

HOTKEY = "tdx-miner"
_DEFAULT_INSTANCE = SatInstance(n_vars=3, clauses=[[1, 2, -3]] * 20)
# The DERIVED id: sha256 over the canonical instance + seed, exactly as the
# producer computes it. Fabricated ids no longer replay.
CHALLENGE = _compute_challenge_id(_DEFAULT_INSTANCE, 7)


def _artifacts(
    *,
    hotkey: str = HOTKEY,
    challenge: str | None = None,
    n_clauses: int = 20,
    assignment: list[int] | None = None,
) -> tuple[bytes, bytes]:
    instance = SatInstance(n_vars=3, clauses=[[1, 2, -3]] * n_clauses)
    challenge_id = challenge if challenge is not None else _compute_challenge_id(instance, 7)
    item = SatWorkItem(instance=instance, seed=7, challenge_id=challenge_id)
    certificate = SatCertificate(
        satisfiable=True,
        assignment=assignment if assignment is not None else [1, 2, -3],
        work_units=float(n_clauses),
        challenge_id=challenge_id,
        assigned_hotkey=hotkey,
    )
    return _sat_manifest_bytes(item), _sat_result_bytes(item, certificate)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _verify(item_bytes: bytes, result_bytes: bytes, **overrides) -> None:
    arguments = {
        "expected_manifest_digest": _digest(item_bytes),
        "expected_result_digest": _digest(result_bytes),
        "expected_challenge_id": CHALLENGE,
        "expected_hotkey": HOTKEY,
        "expected_units": Decimal(20),
    }
    arguments.update(overrides)
    verify_work_artifacts(item_bytes, result_bytes, **arguments)


def test_real_work_replays_cleanly():
    item_bytes, result_bytes = _artifacts()
    _verify(item_bytes, result_bytes)


def test_swapped_result_from_another_miner_is_rejected():
    item_bytes, _ = _artifacts()
    _, other_result = _artifacts(hotkey="other-miner")
    with pytest.raises(WorkProofError, match="different hotkey"):
        _verify(
            item_bytes,
            other_result,
            expected_result_digest=_digest(other_result),
        )


def test_swapped_work_item_from_another_challenge_is_rejected():
    # A legitimately derived item for a DIFFERENT instance cannot stand in
    # for the receipt's bound challenge.
    other_item, _ = _artifacts(n_clauses=19)
    _, result_bytes = _artifacts()
    with pytest.raises(WorkProofError, match="challenge"):
        _verify(
            other_item,
            result_bytes,
            expected_manifest_digest=_digest(other_item),
        )


def test_fabricated_challenge_id_fails_the_producer_derivation():
    """Round-seven F1: an item whose challenge_id was NOT derived from the
    canonical instance+seed fails the recomputation even when every digest
    and receipt binding is self-consistent."""
    item_bytes, result_bytes = _artifacts(challenge="a" * 64)
    with pytest.raises(WorkProofError, match="challenge_id mismatch"):
        _verify(
            item_bytes,
            result_bytes,
            expected_manifest_digest=_digest(item_bytes),
            expected_result_digest=_digest(result_bytes),
            expected_challenge_id="a" * 64,
        )


def test_out_of_producer_bounds_items_never_replay():
    """Round-seven F1: 100k trivial clauses (or any instance outside the
    PRODUCER bounds - clause count, total literals, per-clause size) can
    never replay, so fabricated unit inflation is structurally impossible."""
    item_bytes, result_bytes = _artifacts(n_clauses=8193)  # > MAX_CLAUSES
    challenge = json.loads(item_bytes)["challenge_id"]
    with pytest.raises(WorkProofError, match="producer contract"):
        _verify(
            item_bytes,
            result_bytes,
            expected_manifest_digest=_digest(item_bytes),
            expected_result_digest=_digest(result_bytes),
            expected_challenge_id=challenge,
            expected_units=Decimal(8193),
        )


def test_corrupted_bytes_fail_the_digest_binding():
    item_bytes, result_bytes = _artifacts()
    with pytest.raises(WorkProofError, match="manifest digest"):
        _verify(
            item_bytes.replace(b"7", b"8", 1),
            result_bytes,
            expected_manifest_digest=_digest(item_bytes),  # pin to ORIGINAL
        )
    with pytest.raises(WorkProofError, match="result digest"):
        _verify(
            item_bytes,
            result_bytes.replace(b"tdx", b"tdy", 1),
            expected_result_digest=_digest(result_bytes),  # pin to ORIGINAL
        )


def test_inconsistent_receipt_units_are_rejected():
    item_bytes, result_bytes = _artifacts()
    with pytest.raises(WorkProofError, match="signer-only assertion never earns"):
        _verify(item_bytes, result_bytes, expected_units=Decimal(400))


def test_unsatisfying_assignment_is_not_real_work():
    # Assignment [-1, -2, 3] falsifies every clause [1, 2, -3].
    item_bytes, result_bytes = _artifacts(assignment=[-1, -2, 3])
    with pytest.raises(WorkProofError, match="not real work"):
        _verify(item_bytes, result_bytes)


def test_contradictory_assignment_is_rejected():
    item_bytes, result_bytes = _artifacts(assignment=[1, -1, 2])
    with pytest.raises(WorkProofError, match="cover the variables"):
        _verify(item_bytes, result_bytes)


def test_signer_only_assertion_never_reaches_full():
    """A verified quote + signed receipt WITHOUT published work artifacts
    must fail at verification (when artifact checking is requested) and can
    never reach FULL assurance."""
    import tempfile
    from pathlib import Path

    # Re-create the standard exported chain fixture inline.
    import tests.test_provenance as tp
    from cathedral.provenance import ProvenanceError
    from tests.test_provenance import _verify as verify_chain

    with tempfile.TemporaryDirectory() as scratch:
        ledger, epoch_id = tp._completed_receipt_epoch(Path(scratch))
        report = tp._export_score_class(ledger, epoch_id)
        receipts = tp._receipts_from_ledger(ledger, epoch_id)
        ledger.close()
        with pytest.raises(ProvenanceError, match="signer-only work assertion"):
            verify_chain(report, receipts, work_artifacts_by_receipt={})


def test_tampered_units_inside_result_change_the_digest():
    """The miner's claimed units are bound (auditable) even though they are
    never trusted: editing them breaks the result digest."""
    item_bytes, result_bytes = _artifacts()
    document = json.loads(result_bytes)
    document["work_units"] = 1e300
    forged = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    with pytest.raises(WorkProofError, match="result digest"):
        _verify(
            item_bytes,
            forged,
            expected_result_digest=_digest(result_bytes),  # receipt-signed
        )


def test_challenge_derivation_is_deterministic_and_slot_unique():
    """Defect-5: nonces derive from public chain state; every
    (epoch, hotkey) slot is distinct and reproducible."""
    from cathedral.challenge import (
        ChallengeError,
        derive_challenge_nonce,
        expected_challenge_digest,
    )

    kwargs = {
        "block": 100,
        "block_hash": "0x" + "ab" * 32,
        "network": "finney",
        "netuid": 39,
        "source_epoch": 11,
        "miner_hotkey": "tdx-miner",
    }
    first = derive_challenge_nonce(**kwargs)
    assert first == derive_challenge_nonce(**kwargs)  # deterministic
    assert len(first) == 32
    assert first != derive_challenge_nonce(**{**kwargs, "source_epoch": 12})
    assert first != derive_challenge_nonce(**{**kwargs, "miner_hotkey": "other"})
    assert first != derive_challenge_nonce(**{**kwargs, "netuid": 40})
    # v2 binds the finalized HEIGHT as well as the hash.
    assert first != derive_challenge_nonce(**{**kwargs, "block": 101})
    # 0x prefix is normalized away.
    assert derive_challenge_nonce(**{**kwargs, "block_hash": "ab" * 32}) == first
    assert expected_challenge_digest(**kwargs).startswith("sha256:")
    with pytest.raises(ChallengeError):
        derive_challenge_nonce(**{**kwargs, "block_hash": "zz" * 32})


def test_customer_job_units_follow_the_versioned_rule():
    """Round-seven F2: a legitimate ONE-CLAUSE customer job is worth exactly
    CUSTOMER_SAT_WORK_UNITS under sat_work_units_v1 — full replay accepts
    the producer-signed 20 units instead of falsely rejecting them, and a
    clause-count claim on the same customer item is rejected."""
    item_bytes, result_bytes = _artifacts(n_clauses=1)
    challenge = json.loads(item_bytes)["challenge_id"]
    common = {
        "expected_manifest_digest": _digest(item_bytes),
        "expected_result_digest": _digest(result_bytes),
        "expected_challenge_id": challenge,
    }
    _verify(item_bytes, result_bytes, expected_units=Decimal(20), **common)
    with pytest.raises(WorkProofError, match="sat_work_units_v1"):
        _verify(item_bytes, result_bytes, expected_units=Decimal(1), **common)


def test_customer_clause_inflation_never_earns_clause_count():
    """Round-seven F1+F2: even INSIDE producer bounds, a many-clause
    customer item is worth the fixed CUSTOMER_SAT_WORK_UNITS — clause
    stuffing cannot inflate units."""
    item_bytes, result_bytes = _artifacts(n_clauses=500)
    challenge = json.loads(item_bytes)["challenge_id"]
    common = {
        "expected_manifest_digest": _digest(item_bytes),
        "expected_result_digest": _digest(result_bytes),
        "expected_challenge_id": challenge,
    }
    with pytest.raises(WorkProofError, match="sat_work_units_v1"):
        _verify(item_bytes, result_bytes, expected_units=Decimal(500), **common)
    _verify(item_bytes, result_bytes, expected_units=Decimal(20), **common)


def test_canonical_audit_work_earns_its_clause_count():
    """sat_work_units_v1, audit half: an instance EXACTLY equal to the
    canonical derivation from its own seed is validator-derived work worth
    its clause count — the rule is a pure function of committed bytes, and
    producer and replayer share the one implementation."""
    from cathedral.lanes.sat import (
        _canonical_instance,
        derived_work_units,
        solve_sat,
    )

    seed = 12345
    instance = _canonical_instance(seed)
    challenge = _compute_challenge_id(instance, seed)
    item = SatWorkItem(instance=instance, seed=seed, challenge_id=challenge)
    assert derived_work_units(item) == float(len(instance.clauses)) == 20.0
    assignment = solve_sat(instance)
    assert assignment is not None  # satisfiable by construction
    certificate = SatCertificate(
        satisfiable=True,
        assignment=assignment,
        work_units=20.0,
        challenge_id=challenge,
        assigned_hotkey=HOTKEY,
    )
    item_bytes = _sat_manifest_bytes(item)
    result_bytes = _sat_result_bytes(item, certificate)
    _verify(
        item_bytes,
        result_bytes,
        expected_manifest_digest=_digest(item_bytes),
        expected_result_digest=_digest(result_bytes),
        expected_challenge_id=challenge,
        expected_units=Decimal(20),
    )
