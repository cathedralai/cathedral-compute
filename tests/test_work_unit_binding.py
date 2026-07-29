"""What a receipt's `work.work_units` actually binds, end to end.

The distinction matters because a signature proves who ASSERTED a number, not
that the number was derived. These tests pin the exact boundary this repo
implements today, so the cross-repo derivation question (documented in
docs/RECEIPTS.md) is argued from checked behavior:

  * BOUND, inside this repo: the runtime never signs a miner's claimed units
    (`cathedral/lanes/sat.py` re-derives them under `sat_work_units_v1` from
    the committed work item, and the ledger refuses verified work that is not
    validator-derived), and full provenance re-derives them independently from
    the published work artifacts and requires equality with the receipt's
    signed units (`cathedral/workproof.py`).
  * ASSERTED, at the receipt boundary: `ReceiptIssuer.issue()` signs the units
    it is handed, and `verify_receipt` checks only that they are canonical
    decimal and zero for non-passing work. A verifier holding the receipt
    ALONE cannot tell a derived number from an inflated one.

The gap is closed by requiring the work artifacts, which is exactly what FULL
provenance does and what a receipt-only consumer does not do.
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal

import pytest

from cathedral.assurance import (
    AssuranceDimension,
    ClaimStatus,
    attestation_claims,
    evaluated_claim,
    with_verified_channel,
)
from cathedral.lanes.sat import (
    _canonical_instance,
    _compute_challenge_id,
    derived_work_units,
    solve_sat,
)
from cathedral.lanes.sat_types import SatCertificate, SatWorkItem
from cathedral.receipt import ReceiptIssuer, verify_receipt
from cathedral.runtime import SAT_WORK_POLICY_DIGEST, _sat_manifest_bytes, _sat_result_bytes
from cathedral.workproof import WorkProofError, verify_work_artifacts

from tests.test_receipt import (
    ISSUED,
    ISSUED_TEXT,
    RECEIPT_SEED_1,
    _attested,
    _snapshot,
    _worker_lifecycle,
)

SEED = 7
HOTKEY = "public-hotkey"


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _real_work_artifacts() -> tuple[SatWorkItem, bytes, bytes, Decimal]:
    """Canonical validator-derived audit work plus its durable artifacts."""
    instance = _canonical_instance(SEED)
    item = SatWorkItem(
        instance=instance,
        seed=SEED,
        challenge_id=_compute_challenge_id(instance, SEED),
    )
    assignment = solve_sat(instance)
    assert assignment is not None
    certificate = SatCertificate(
        satisfiable=True,
        # The MINER's claim, bound into the result digest for audit but never
        # trusted by the derivation rule.
        work_units=10.0**300,
        assignment=assignment,
        challenge_id=item.challenge_id,
        assigned_hotkey=HOTKEY,
    )
    return (
        item,
        _sat_manifest_bytes(item),
        _sat_result_bytes(item, certificate),
        Decimal(str(derived_work_units(item))),
    )


def _receipt_for(item: SatWorkItem, manifest_bytes: bytes, result_bytes: bytes, units: float):
    """A genuine signed receipt over those exact artifacts, with any units."""
    snapshot = _snapshot()
    policy = snapshot.to_policy(at=ISSUED)
    claims = attestation_claims(b"raw-quote-secret", policy, verified_at=ISSUED_TEXT)
    claims = with_verified_channel(claims, b"channel-binding-material", verified_at=ISSUED_TEXT)
    claims = claims.with_claim(
        AssuranceDimension.WORK,
        # The work claim's evidence digest is the digest of the real result
        # bytes, so the receipt and the artifacts are the same work.
        evaluated_claim(
            ClaimStatus.PASSED,
            result_bytes,
            SAT_WORK_POLICY_DIGEST,
            verified_at=ISSUED_TEXT,
        ),
    )
    receipt = ReceiptIssuer(snapshot, "receipt-test-1", RECEIPT_SEED_1).issue(
        epoch_id=7,
        source_epoch=11,
        subject_hotkey=HOTKEY,
        attested=_attested(claims),
        policy=policy,
        assurance=claims,
        worker_lifecycle=_worker_lifecycle(policy, claims, HOTKEY),
        challenge_id=item.challenge_id,
        manifest_digest=_digest(manifest_bytes),
        work_units=units,
        issued_at=ISSUED,
    )
    return snapshot, receipt


def _replay(receipt, manifest_bytes: bytes, result_bytes: bytes) -> None:
    work = json.loads(receipt.receipt_bytes)["work"]
    verify_work_artifacts(
        manifest_bytes,
        result_bytes,
        expected_manifest_digest=str(work["manifest_digest"]),
        expected_result_digest=str(work["result_digest"]),
        expected_challenge_id=str(work["challenge_id"]),
        expected_hotkey=HOTKEY,
        expected_units=Decimal(str(work["work_units"])),
    )


def test_derived_units_are_bound_by_independent_replay():
    item, manifest_bytes, result_bytes, derived = _real_work_artifacts()
    snapshot, receipt = _receipt_for(item, manifest_bytes, result_bytes, float(derived))
    verified = verify_receipt(receipt.receipt_bytes, snapshot)
    assert Decimal(str(verified.document["work"]["work_units"])) == derived
    # The receipt's signed units equal the independent re-derivation from the
    # committed bytes, so this receipt earns.
    _replay(receipt, manifest_bytes, result_bytes)


def test_the_receipt_boundary_alone_does_not_bind_units():
    # ReceiptIssuer signs the units it is handed. This is the honest statement
    # of the gap: verification of the receipt ALONE accepts an inflated number
    # because nothing in the schema re-derives it.
    item, manifest_bytes, result_bytes, derived = _real_work_artifacts()
    inflated = float(derived) + 979.0
    snapshot, receipt = _receipt_for(item, manifest_bytes, result_bytes, inflated)
    verified = verify_receipt(receipt.receipt_bytes, snapshot)
    assert Decimal(str(verified.document["work"]["work_units"])) == Decimal(str(inflated))
    assert Decimal(str(inflated)) != derived


def test_independent_replay_rejects_correctly_signed_inflated_units():
    # The same correctly signed receipt, checked against the artifacts it names:
    # a signer-only assertion never earns.
    item, manifest_bytes, result_bytes, derived = _real_work_artifacts()
    snapshot, receipt = _receipt_for(
        item, manifest_bytes, result_bytes, float(derived) + 979.0
    )
    verify_receipt(receipt.receipt_bytes, snapshot)
    with pytest.raises(WorkProofError, match="sat_work_units_v1"):
        _replay(receipt, manifest_bytes, result_bytes)


def test_the_miner_claim_inside_the_result_bytes_is_never_the_derivation():
    # The certificate the miner returned claims 1e300 units. It is bound into
    # the signed result digest for auditability, and the derivation ignores it.
    item, manifest_bytes, result_bytes, derived = _real_work_artifacts()
    assert json.loads(result_bytes)["work_units"] > 10**299
    assert derived == Decimal(len(item.instance.clauses))
    snapshot, receipt = _receipt_for(item, manifest_bytes, result_bytes, float(derived))
    _replay(receipt, manifest_bytes, result_bytes)
