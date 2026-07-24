"""Full-provenance verification: happy path plus the adversarial matrix.

The threat model here is a *compromised or buggy Cathedral*: every forged
report in these tests is signed by the genuine trusted report key, so a
signature check alone would accept it. Full provenance must still reject any
claim that is not backed by a verifiable assurance receipt bound to the signed
policy registry.
"""

from __future__ import annotations

import json
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.ledger import Ledger
from cathedral.policy_registry import canonical_json
from cathedral.provenance import (
    MECHANISMS,
    ProvenanceError,
    compare_with_vector,
    verify_and_recompute,
)
from cathedral.score_class import _sign_report
from tests.test_receipt import (
    CHALLENGE_ID,
    ISSUED,
    ISSUED_TEXT,
    RECEIPT_SEED_2,
    TRUSTED,
    _completed_receipt_epoch,
    _export_score_class,
    _issued_receipt,
    _registry_document,
    _snapshot,
    _worker_lifecycle,
)

NOW = ISSUED + timedelta(minutes=1)
VERIFIER_DIGEST = "sha256:" + "d" * 64
REPORT_KEYS = {
    "score-test-1": Ed25519PrivateKey.from_private_bytes(RECEIPT_SEED_2)
    .public_key()
    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
}
REGISTRY_BYTES = canonical_json(_registry_document())


def _receipts_from_ledger(ledger: Ledger, epoch_id: int) -> dict[str, bytes]:
    snapshot = ledger.score_class_snapshot(epoch_id)
    return {
        str(row["receipt_id"]): bytes(row["receipt_body"])
        for row in snapshot["rows"]
        if row["receipt_id"] is not None and row["receipt_body"] is not None
    }


def _verify(report: bytes, receipts: dict[str, bytes], **overrides):
    arguments = {
        "report_bytes": report,
        "receipts_by_id": receipts,
        "registry_bytes": REGISTRY_BYTES,
        "trusted_registry_keys": TRUSTED,
        "report_signing_keys": REPORT_KEYS,
        "expected_network": "local",
        "expected_netuid": 1,
        "expected_verifier_digest": VERIFIER_DIGEST,
        "now": NOW,
    }
    arguments.update(overrides)
    return verify_and_recompute(**arguments)


def _reforge(report: bytes, mutate) -> bytes:
    """Re-sign a mutated report with the *genuine* trusted key.

    This simulates a compromised Cathedral: the signature and report id are
    valid, only the receipt-backed facts no longer support the claims.
    """
    document = json.loads(report)
    document.pop("report_id", None)
    document.pop("signature", None)
    mutate(document)
    return _sign_report(document, RECEIPT_SEED_2)


@pytest.fixture()
def exported(tmp_path: Path):
    ledger, epoch_id = _completed_receipt_epoch(tmp_path)
    report = _export_score_class(ledger, epoch_id)
    receipts = _receipts_from_ledger(ledger, epoch_id)
    yield report, receipts
    ledger.close()


def test_happy_path_recomputes_the_single_verified_miner(exported):
    report, receipts = exported
    result = _verify(report, receipts)
    assert result.mechanism_id == "validated_supply_v1"
    assert result.policy_release == 1
    assert result.verifier_digest == VERIFIER_DIGEST
    assert result.recomputed_hotkey_weights == {"public-hotkey": 1.0}
    by_hotkey = {miner.hotkey: miner for miner in result.miners}
    assert by_hotkey["public-hotkey"].receipt_verified is True
    assert by_hotkey["public-hotkey"].verified_work_units == Decimal("3.5")
    assert by_hotkey["zero-hotkey"].receipt_verified is False
    assert by_hotkey["zero-hotkey"].verified_work_units == 0


def test_two_verified_miners_share_proportionally_to_work_units(tmp_path: Path):
    snapshot = _snapshot()
    ledger = Ledger(tmp_path / "ledger.sqlite")
    epoch_id = ledger.begin_epoch(
        11,
        policy_registry_release=snapshot.release,
        policy_registry_digest=snapshot.digest,
    )
    second_challenge = "b" * 64
    for hotkey, challenge, units in (
        ("public-hotkey", CHALLENGE_ID, 3.5),
        ("second-hotkey", second_challenge, 10.5),
    ):
        _snap, policy, claims, receipt = _issued_receipt(
            epoch_id=epoch_id,
            subject_hotkey=hotkey,
            challenge_id=challenge,
            work_units=units,
        )
        ledger.issue_challenge(challenge, hotkey, epoch_id)
        ledger.resolve_challenge_with_receipt(
            challenge,
            "verified",
            units,
            validator_derived=True,
            receipt_id=receipt.receipt_id,
            receipt_body=receipt.receipt_bytes,
            receipt_digest=receipt.receipt_digest,
            issued_at=ISSUED_TEXT,
        )
        ledger.add_attestation(
            epoch_id,
            hotkey,
            verdict="VERIFIED",
            tee_type="TDX",
            workload="CPU",
            evidence_digest=claims.hardware.evidence_digest,
            policy_mode="strict",
        )
        ledger.add_lifecycle_snapshot(
            epoch_id,
            _worker_lifecycle(policy, claims, hotkey),
            snapshot_at=ISSUED_TEXT,
        )
    ledger.complete_epoch(
        epoch_id,
        {"public-hotkey", "second-hotkey"},
        generated_at=ISSUED_TEXT,
        score_network="local",
        score_netuid=1,
    )
    report = _export_score_class(ledger, epoch_id)
    receipts = _receipts_from_ledger(ledger, epoch_id)
    ledger.close()

    result = _verify(report, receipts)
    weights = result.recomputed_hotkey_weights
    assert weights["public-hotkey"] == pytest.approx(0.25)
    assert weights["second-hotkey"] == pytest.approx(0.75)


def test_report_tampered_bytes_are_rejected(exported):
    report, receipts = exported
    tampered = report.replace(b"public-hotkey", b"public-h0tkey", 1)
    with pytest.raises(ProvenanceError):
        _verify(tampered, receipts)


def test_report_signed_by_untrusted_key_is_rejected(exported):
    report, receipts = exported
    document = json.loads(report)
    document.pop("report_id", None)
    document.pop("signature", None)
    forged = _sign_report(document, bytes(range(96, 128)))  # unknown key seed
    with pytest.raises(ProvenanceError, match="signature is invalid"):
        _verify(forged, receipts)


def test_unknown_signing_key_id_is_rejected(exported):
    report, receipts = exported

    def rename_key(document):
        document["signing_key_id"] = "score-test-rogue"

    with pytest.raises(ProvenanceError, match="unknown key id"):
        _verify(_reforge(report, rename_key), receipts)


def test_inflated_work_units_without_receipt_backing_are_rejected(exported):
    report, receipts = exported

    def inflate(document):
        for entry in document["entries"]:
            if entry["miner_hotkey"] == "public-hotkey":
                entry["metrics"]["verified_work_units"] = "400"

    with pytest.raises(ProvenanceError, match="work units"):
        _verify(_reforge(report, inflate), receipts)


def test_invented_positive_miner_without_receipt_is_rejected(exported):
    report, receipts = exported

    def invent(document):
        document["entries"].append(
            {
                "miner_hotkey": "sybil-hotkey",
                "metrics": {"verified_work_units": "50"},
                "asserted_score": None,
                "reason_codes": ["receipt_verified", "work_verified"],
                "evidence": [],
            }
        )

    # Even a compromised signer that forges BOTH the entry and the snapshot
    # binding still fails the deeper receipt requirement.
    def invent_with_snapshot(document):
        invent(document)
        document["candidate_snapshot"]["hotkeys"] = sorted(
            [*document["candidate_snapshot"]["hotkeys"], "sybil-hotkey"]
        )

    with pytest.raises(ProvenanceError, match="outside its anchored snapshot"):
        _verify(_reforge(report, invent), receipts)
    with pytest.raises(ProvenanceError, match="exactly one receipt"):
        _verify(_reforge(report, invent_with_snapshot), receipts)


def test_receipt_reassigned_to_another_hotkey_is_rejected(exported):
    report, receipts = exported

    def reassign(document):
        for entry in document["entries"]:
            if entry["miner_hotkey"] == "public-hotkey":
                entry["miner_hotkey"] = "thief-hotkey"
        document["candidate_snapshot"]["hotkeys"] = sorted(
            "thief-hotkey" if hotkey == "public-hotkey" else hotkey
            for hotkey in document["candidate_snapshot"]["hotkeys"]
        )

    with pytest.raises(ProvenanceError, match="subject hotkey"):
        _verify(_reforge(report, reassign), receipts)


def test_missing_receipt_fails_closed(exported):
    report, _receipts = exported
    with pytest.raises(ProvenanceError, match="was not provided"):
        _verify(report, {})


def test_corrupt_receipt_bytes_fail_closed(exported):
    report, receipts = exported
    corrupted = {receipt_id: body[:-2] + b" }" for receipt_id, body in receipts.items()}
    with pytest.raises(ProvenanceError, match="does not match its digest"):
        _verify(report, corrupted)


def test_zero_entry_carrying_evidence_is_rejected(exported):
    report, receipts = exported
    real_reference = None
    document = json.loads(report)
    for entry in document["entries"]:
        if entry["evidence"]:
            real_reference = entry["evidence"][0]

    def graft(document):
        for entry in document["entries"]:
            if entry["miner_hotkey"] == "zero-hotkey":
                entry["evidence"] = [dict(real_reference)]

    with pytest.raises(ProvenanceError, match="must not carry receipt evidence"):
        _verify(_reforge(report, graft), receipts)


def test_stale_report_is_rejected(exported):
    report, receipts = exported
    with pytest.raises(ProvenanceError, match="stale"):
        _verify(report, receipts, now=ISSUED + timedelta(hours=2))


def test_wrong_network_and_netuid_are_rejected(exported):
    report, receipts = exported
    with pytest.raises(ProvenanceError, match="network/netuid"):
        _verify(report, receipts, expected_network="finney")
    with pytest.raises(ProvenanceError, match="network/netuid"):
        _verify(report, receipts, expected_netuid=39)


def test_wrong_pinned_verifier_digest_is_rejected(exported):
    report, receipts = exported
    with pytest.raises(ProvenanceError, match="verifier_digest"):
        _verify(report, receipts, expected_verifier_digest="sha256:" + "e" * 64)


def test_policy_digest_must_match_the_verified_registry(exported):
    report, receipts = exported
    other_registry = canonical_json(_registry_document(release=2))
    with pytest.raises(ProvenanceError, match="policy_digest"):
        _verify(report, receipts, registry_bytes=other_registry)


def test_registry_signed_by_untrusted_key_is_rejected(exported):
    report, receipts = exported
    rogue = {"cathedral-policy-test-1": bytes(32)}
    with pytest.raises(ProvenanceError, match="registry failed verification"):
        _verify(report, receipts, trusted_registry_keys=rogue)


def test_unknown_reward_mechanism_fails_closed(exported):
    report, receipts = exported
    with pytest.raises(ProvenanceError, match="unknown reward mechanism"):
        _verify(report, receipts, mechanism_id="validated_supply_v99")


def test_chain_enforcement_rejects_a_broken_predecessor(exported):
    report, receipts = exported
    with pytest.raises(ProvenanceError, match="export chain"):
        _verify(
            report,
            receipts,
            enforce_chain=True,
            expected_previous_report_id="sha256:" + "e" * 64,
        )
    # And the true chain head (previous None) verifies when enforced.
    result = _verify(report, receipts, enforce_chain=True, expected_previous_report_id=None)
    assert result.previous_report_id is None


def test_mechanism_registry_is_versioned_and_frozen():
    assert list(MECHANISMS) == ["validated_supply_v1"]
    assert MECHANISMS["validated_supply_v1"]([]) == {}


def test_vector_comparison_agreement_and_discrepancies(exported):
    report, receipts = exported
    result = _verify(report, receipts)
    matching = {
        "weights": [
            {
                "miner_hotkey": "public-hotkey",
                "weight": 1.0,
                "base_component": 0.0,
                "external_component": 1.0,
            }
        ]
    }
    agree, discrepancies = compare_with_vector(result, matching)
    assert agree and discrepancies == []

    drifted = {
        "weights": [
            {
                "miner_hotkey": "public-hotkey",
                "weight": 0.8,
                "base_component": 0.0,
                "external_component": 0.8,
            }
        ]
    }
    agree, discrepancies = compare_with_vector(result, drifted)
    assert not agree and "public-hotkey" in discrepancies[0]

    stranger = {
        "weights": [
            {
                "miner_hotkey": "public-hotkey",
                "weight": 1.0,
                "base_component": 0.0,
                "external_component": 1.0,
            },
            {
                "miner_hotkey": "unverified-hotkey",
                "weight": 0.4,
                "base_component": 0.0,
                "external_component": 0.4,
            },
        ]
    }
    agree, discrepancies = compare_with_vector(result, stranger)
    assert not agree
    assert any("unverified-hotkey" in item for item in discrepancies)

    empty_vector = {"weights": []}
    agree, discrepancies = compare_with_vector(result, empty_vector)
    assert not agree  # earning miner missing from the signed vector is a finding


def test_candidate_omission_cannot_inflate_a_survivor(exported):
    """Defect-1 proof: candidate omission fails in BOTH directions — a
    manifest set that drifts from the report's anchored snapshot, and a
    report that drops an entry for an anchored candidate."""
    report, receipts = exported
    candidate_set = {
        "source": "sn39_metagraph",
        "network": "local",
        "netuid": 1,
        "block": 100,
        "block_hash": "0x" + "ab" * 32,
        "candidates": [
            {"hotkey": "public-hotkey", "outcome": "verified", "reason": "receipt_verified"},
            {"hotkey": "zero-hotkey", "outcome": "rejected", "reason": "no_verified_work"},
            {"hotkey": "omitted-miner", "outcome": "verified", "reason": "receipt_verified"},
        ],
    }
    with pytest.raises(ProvenanceError, match="does not equal the report's anchored snapshot"):
        _verify(report, receipts, candidate_set=candidate_set)

    def drop_zero_entry(document):
        document["entries"] = [
            entry for entry in document["entries"] if entry["miner_hotkey"] != "zero-hotkey"
        ]

    with pytest.raises(ProvenanceError, match="omits anchored snapshot candidates"):
        _verify(_reforge(report, drop_zero_entry), receipts)


def test_current_block_outside_report_window_fails(exported):
    """Defect-3 proof: a trusted finalized block outside
    valid_from_block..valid_until_block rejects the report."""
    report, receipts = exported
    with pytest.raises(ProvenanceError, match="outside the report's validity"):
        _verify(report, receipts, current_block=10_000)  # window is 100..200
    _verify(report, receipts, current_block=150)  # inside: verifies


def test_report_snapshot_binding_shape_is_enforced(exported):
    """Defect-4 verification side: a tampered snapshot binding (unsorted,
    bad digest, missing field, unnormalized hash) is rejected even when the
    signature itself is re-forged as valid."""
    report, receipts = exported

    def unsorted(document):
        document["candidate_snapshot"]["hotkeys"] = list(
            reversed(document["candidate_snapshot"]["hotkeys"])
        )

    def bad_digest(document):
        document["candidate_snapshot"]["digest"] = "not-a-digest"

    def missing_block(document):
        document["candidate_snapshot"].pop("block")

    def unnormalized_hash(document):
        document["candidate_snapshot"]["block_hash"] = "0x" + "ab" * 32

    for mutate, message in (
        (unsorted, "sorted"),
        (bad_digest, "digest is invalid"),
        (missing_block, "missing or unknown fields"),
        (unnormalized_hash, "block hash is invalid"),
    ):
        with pytest.raises(ProvenanceError, match=message):
            _verify(_reforge(report, mutate), receipts)


def test_zero_replays_never_mint_full_even_when_all_rejected(tmp_path):
    """Round-seven F3 counterexamples: with ZERO raw replays an
    all-rejected epoch (a) hard-fails when the pinned verifier bytes do
    not authenticate, and (b) even with authenticated bytes REMAINS
    receipts_only, because exhaustive candidate-specific raw rejection
    evidence is not present — assurance=full is never minted unexercised."""
    import hashlib
    from unittest import mock

    from cathedral.ledger import Ledger
    from cathedral.provenance import load_registry, replay_positive_miners
    from tests.test_receipt import _completed_zero_epoch

    ledger = Ledger(tmp_path / "zero-ledger.sqlite")
    epoch_id = _completed_zero_epoch(ledger, 11)
    report = _export_score_class(ledger, epoch_id)
    ledger.close()

    registry = load_registry(REGISTRY_BYTES, TRUSTED, now=NOW, max_age_seconds=172800)
    junk = b"definitely-not-a-static-elf-verifier"
    kwargs = {
        "registry": registry,
        "envelopes_by_hotkey": {},
        "attestation_bindings": {},
        "verifier_binary": junk,
        "verifier_blob_digest": "sha256:" + hashlib.sha256(junk).hexdigest(),
        "verifier_command": ("/opt/cathedral/bin/verifier",),
        "verifier_artifacts": ("/opt/cathedral/bin/verifier",),
        "candidates_all_rejected": True,
        "independent_candidates": {"zero-hotkey"},
        "independent_block_hash": "0x" + "ab" * 32,
    }

    # (a) The pinned verifier bytes MUST authenticate even with zero
    # replays: invalid/unexercised bytes are a hard failure, never FULL.
    with pytest.raises(ProvenanceError, match="failed authentication"):
        replay_positive_miners(_verify(report, {}), **kwargs)

    # (b) Authenticated bytes still cannot mint FULL: raw rejection
    # evidence for every active candidate is not present, so the claim
    # stays receipts_only (NOT PROVEN) — fail closed.
    with mock.patch("cathedral.replay.authenticate_verifier_bytes"):
        outcome = replay_positive_miners(_verify(report, {}), **kwargs)
    assert outcome.assurance_level == "receipts_only"

    # Sanity: candidates_all_rejected=False behaves identically.
    with mock.patch("cathedral.replay.authenticate_verifier_bytes"):
        plain = replay_positive_miners(
            _verify(report, {}), **{**kwargs, "candidates_all_rejected": False}
        )
    assert plain.assurance_level == "receipts_only"


def test_full_requires_the_independent_candidate_oracle(tmp_path):
    """Round-seven followup finding 1: mutually consistent Cathedral
    artifacts are NOT an oracle. FULL demands the independently captured
    historical candidate set + block hash, equal to the report's signed
    binding: a missing oracle, an omitted registered hotkey, and a
    fabricated anchor each fail closed BEFORE any replay."""
    import hashlib

    from cathedral.ledger import Ledger
    from cathedral.provenance import load_registry, replay_positive_miners
    from tests.test_receipt import _completed_zero_epoch

    ledger = Ledger(tmp_path / "oracle-ledger.sqlite")
    epoch_id = _completed_zero_epoch(ledger, 11)
    report = _export_score_class(ledger, epoch_id)
    ledger.close()
    registry = load_registry(REGISTRY_BYTES, TRUSTED, now=NOW, max_age_seconds=172800)
    junk = b"verifier-bytes"
    base = {
        "registry": registry,
        "envelopes_by_hotkey": {},
        "attestation_bindings": {},
        "verifier_binary": junk,
        "verifier_blob_digest": "sha256:" + hashlib.sha256(junk).hexdigest(),
        "verifier_command": ("/opt/cathedral/bin/verifier",),
        "verifier_artifacts": ("/opt/cathedral/bin/verifier",),
        "candidates_all_rejected": True,
    }

    # Missing oracle: fail closed, before anything else.
    with pytest.raises(ProvenanceError, match="not an oracle"):
        replay_positive_miners(_verify(report, {}), **base)

    # Omitted hotkey: the chain says a second hotkey was registered at the
    # anchored block; the mutually consistent report+manifest omitted it.
    with pytest.raises(ProvenanceError, match=r"omitted from report.*omitted-real-miner"):
        replay_positive_miners(
            _verify(report, {}),
            independent_candidates={"zero-hotkey", "omitted-real-miner"},
            independent_block_hash="0x" + "ab" * 32,
            **base,
        )

    # Fabricated candidate: the report claims a hotkey that history never
    # registered at the anchored block.
    with pytest.raises(ProvenanceError, match="not registered at the anchored block"):
        replay_positive_miners(
            _verify(report, {}),
            independent_candidates={"only-other-miner"},
            independent_block_hash="0x" + "ab" * 32,
            **base,
        )
    # An empty independent capture is malformed history, never a pass.
    with pytest.raises(ProvenanceError, match="empty or malformed"):
        replay_positive_miners(
            _verify(report, {}),
            independent_candidates=set(),
            independent_block_hash="0x" + "ab" * 32,
            **base,
        )

    # Fabricated anchor: an independent hash that disagrees with the bound
    # snapshot can never reach FULL.
    with pytest.raises(ProvenanceError, match="fabricated anchor"):
        replay_positive_miners(
            _verify(report, {}),
            independent_candidates={"zero-hotkey"},
            independent_block_hash="0x" + "cd" * 32,
            **base,
        )


def test_vector_rows_are_validated_before_comparison(exported):
    """Round-seven followup finding 2: NaN, negative, duplicate, malformed,
    and unknown-field vector rows FAIL the comparison. Previously a NaN or
    negative external_component was silently discarded (<= 0 filter), so a
    corrupted vector could 'agree' with the recomputation."""
    report, receipts = exported
    result = _verify(report, receipts)

    def row(**overrides):
        base = {
            "miner_hotkey": "public-hotkey",
            "weight": 1.0,
            "base_component": 0.0,
            "external_component": 1.0,
        }
        base.update(overrides)
        return base

    # The exact prior leak: a NaN row vanished and the vector "agreed".
    agree, notes = compare_with_vector(result, {"weights": [row(external_component=float("nan"))]})
    assert not agree and "non-finite" in notes[0]

    agree, notes = compare_with_vector(result, {"weights": [row(external_component=-0.4)]})
    assert not agree and "negative" in notes[0]

    # A duplicate that hid behind the <= 0 filter is now caught.
    agree, notes = compare_with_vector(result, {"weights": [row(), row(external_component=0.0)]})
    assert not agree and "duplicates" in notes[0]

    agree, notes = compare_with_vector(result, {"weights": [row(external_component="1.0")]})
    assert not agree and "not numeric" in notes[0]

    agree, notes = compare_with_vector(result, {"weights": [row(surprise=1)]})
    assert not agree and "unknown fields" in notes[0]

    agree, notes = compare_with_vector(result, {"weights": [{"weight": 1.0}]})
    assert not agree and "miner_hotkey" in notes[0]

    # A well-formed matching vector still agrees.
    agree, notes = compare_with_vector(result, {"weights": [row()]})
    assert agree and notes == []
