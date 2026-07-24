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
    MECHANISM_REVISIONS,
    MECHANISMS,
    MinerProvenance,
    ProvenanceError,
    ProvenanceResult,
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
    assert MECHANISM_REVISIONS == {"validated_supply_v1": 1}


def test_unsupported_mechanism_revision_fails_before_recomputation(exported):
    """Repair 2: dispatch is on the exact (id, revision) pair; any other
    revision fails closed before any recomputation."""
    report, receipts = exported
    with pytest.raises(ProvenanceError, match=r"unsupported mechanism pair.*revision=2"):
        _verify(report, receipts, mechanism_revision=2)
    result = _verify(report, receipts, mechanism_revision=1)
    assert result.mechanism_revision == 1


BURN_HOTKEY = "burn-destination-hotkey"
WIRE_INGEST_DIGEST = "3e" * 32


def _launch_vector(rows, *, source_epoch: int = 11, positive: bool | None = None) -> dict:
    """The REAL validated_supply_v1 signed wire shape, mirroring the subnet
    publisher (scaffold/publisher/weights.py build_signed_vector): PRE-burn
    confidential_primary rows (base 0, weight == external, positive supply
    summing to 1.0), the burn resolved by HOTKEY (``burn_uid`` null, fixed
    10% for every epoch shape), the launch-locked validated_supply policy
    block, the confidential_primary mass assertions, and the signed
    external_scores ingest binding."""
    if positive is None:
        positive = any(
            isinstance(row, dict) and float(row.get("weight") or 0.0) > 0.0 for row in rows
        )
    mass = 1.0 if positive else 0.0
    return {
        "burn_snapshot": {
            "burn_uid": None,
            "burn_hotkey": BURN_HOTKEY,
            "forced_burn_percentage": 10.0,
        },
        "policy_metadata": {
            "score_source": "confidential_primary:cathedral_confidential_tdx",
            "validated_supply": {
                "contract_version": "v1",
                "intel_tdx_allocation": 0.90,
                "verified_gpu_allocation": 0.10,
                "verified_gpu_admitted": False,
                "burn_hotkey": BURN_HOTKEY,
            },
            "confidential_primary": {
                "contract_version": "v1",
                "mode": "confidential_primary",
                "source": "cathedral_confidential_tdx",
                "base_mass": 0.0,
                "confidential_mass": mass,
                "complete": True,
                "fresh": True,
                "confirmed": True,
            },
            "external_scores": {
                "enabled": True,
                "source": "cathedral_confidential_tdx",
                "mode": "confidential_primary",
                "latest_epoch": source_epoch,
                "latest_complete": True,
                "latest_fresh": True,
                "latest_report_sha256": "11" * 32,
            },
        },
        "weights": [dict(row) for row in rows],
    }


def _compare(result, vector, **overrides):
    kwargs = {"wire_report_sha256": WIRE_INGEST_DIGEST}
    kwargs.update(overrides)
    return compare_with_vector(result, vector, **kwargs)


def _launch_row(hotkey: str, external: float, *, base: float = 0.0, **overrides) -> dict:
    row = {
        "miner_hotkey": hotkey,
        "weight": base + external,
        "base_component": base,
        "external_component": external,
    }
    row.update(overrides)
    return row


def test_vector_comparison_agreement_and_discrepancies(exported):
    report, receipts = exported
    result = _verify(report, receipts)
    # The REAL launch shape: PRE-burn rows — the verified miner carries the
    # whole 1.0 unit mass (weight == external, base == 0) and the fixed 10%
    # burn is declared in the burn snapshot but applied by the subnet
    # validator at UID-mapping time, never inside the rows.
    matching = _launch_vector([_launch_row("public-hotkey", 1.0)])
    agree, discrepancies = _compare(result, matching)
    assert agree and discrepancies == []

    # Drifted attribution: half the class mass leaks to an unverified
    # hotkey. Both the shortfall and the stranger are discrepancies.
    drifted = _launch_vector(
        [_launch_row("public-hotkey", 0.5), _launch_row("unverified-hotkey", 0.5)]
    )
    agree, discrepancies = _compare(result, drifted)
    assert not agree
    assert any("public-hotkey" in item for item in discrepancies)
    assert any("unverified-hotkey" in item for item in discrepancies)

    # Symmetric omission: a structurally valid vector paying the WRONG
    # miner flags both the missing earner and the stranger.
    swapped = _launch_vector([_launch_row("unverified-hotkey", 1.0)])
    agree, discrepancies = _compare(result, swapped)
    assert not agree
    assert any("public-hotkey" in item for item in discrepancies)
    assert any("unverified-hotkey" in item for item in discrepancies)

    # An empty vector against verified supply cannot even conserve emission.
    agree, discrepancies = _compare(result, _launch_vector([], positive=True))
    assert not agree and "conserve" in discrepancies[0]


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
        "candidate_outcomes": {"zero-hotkey": "rejected"},
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
    assert any("not independently replayable" in reason for reason in outcome.not_proven_reasons)

    # A retired-only epoch has nothing active to prove either: still
    # receipts_only, never FULL, with the reason surfaced.
    with mock.patch("cathedral.replay.authenticate_verifier_bytes"):
        retired = replay_positive_miners(
            _verify(report, {}),
            **{**kwargs, "candidate_outcomes": {"zero-hotkey": "retired"}},
        )
    assert retired.assurance_level == "receipts_only"
    assert any("no positive raw replays" in reason for reason in retired.not_proven_reasons)


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
        "candidate_outcomes": {"zero-hotkey": "rejected"},
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
        base = _launch_row("public-hotkey", 1.0)
        base.update(overrides)
        return base

    # The exact prior leak: a NaN row vanished and the vector "agreed".
    agree, notes = _compare(result, _launch_vector([row(external_component=float("nan"))]))
    assert not agree and "non-finite" in notes[0]

    agree, notes = _compare(result, _launch_vector([row(external_component=-0.4)]))
    assert not agree and "negative" in notes[0]

    # A duplicate that hid behind the <= 0 filter is now caught.
    agree, notes = _compare(
        result,
        _launch_vector([row(), row(weight=0.0, external_component=0.0)]),
    )
    assert not agree and "duplicates" in notes[0]

    agree, notes = _compare(result, _launch_vector([row(external_component="1.0")]))
    assert not agree and "not numeric" in notes[0]

    agree, notes = _compare(result, _launch_vector([row(surprise=1)]))
    assert not agree and "unknown fields" in notes[0]

    agree, notes = _compare(result, _launch_vector([{"weight": 1.0}]))
    assert not agree and "miner_hotkey" in notes[0]

    # A well-formed matching vector still agrees.
    agree, notes = _compare(result, _launch_vector([row()]))
    assert agree and notes == []


# ---------------------------------------------------------------------------
# Complete validated_supply_v1 signed-vector contract (Codex finding 1)
# ---------------------------------------------------------------------------


def _synthetic_result(weights: dict[str, float], mechanism_id: str = "validated_supply_v1"):
    """A recomputation result carrying only what compare_with_vector reads."""
    return ProvenanceResult(
        report_id="sha256:" + "0" * 64,
        previous_report_id=None,
        signing_key_id="score-test-1",
        policy_release=1,
        policy_digest="sha256:" + "1" * 64,
        verifier_digest=VERIFIER_DIGEST,
        mechanism_id=mechanism_id,
        source_epoch=11,
        generated_at="2026-07-11T12:00:00.000000Z",
        valid_until="2026-07-11T12:30:00.000000Z",
        recomputed_hotkey_weights=dict(weights),
    )


def test_launch_vector_compares_pre_burn_unit_rows():
    """The REAL launch shape: pre-burn rows summing to 1.0 (the subnet
    validator applies the 10% burn after UID mapping). Shares compare
    directly against the recomputed 1.0-sum unit shares."""
    result = _synthetic_result({"alpha": 0.6, "bravo": 0.4})
    vector = _launch_vector([_launch_row("alpha", 0.6), _launch_row("bravo", 0.4)])
    agree, notes = _compare(result, vector)
    assert agree and notes == []

    # And a proportional drift inside the same mass is still caught.
    drifted = _launch_vector([_launch_row("alpha", 0.5), _launch_row("bravo", 0.5)])
    agree, notes = _compare(result, drifted)
    assert not agree
    assert any("alpha" in note for note in notes)

    # The FABRICATED legacy post-burn shape (rows carrying 0.9 total with
    # the burn subtracted in-row) is exactly what the real validator would
    # refuse; the comparator refuses it too.
    legacy_post_burn = _launch_vector([_launch_row("alpha", 0.54), _launch_row("bravo", 0.36)])
    agree, notes = _compare(result, legacy_post_burn)
    assert not agree and "conserve" in notes[0]


def test_vector_rows_require_explicit_complete_components():
    """No fallback: a row missing any of weight/base_component/
    external_component fails outright. Previously a missing
    external_component silently fell back to the row's weight."""
    result = _synthetic_result({"alpha": 1.0})
    for missing in ("weight", "base_component", "external_component"):
        row = _launch_row("alpha", 1.0)
        row.pop(missing)
        agree, notes = _compare(result, _launch_vector([row]))
        assert not agree and f"lacks an explicit {missing}" in notes[0]


def test_vector_row_composition_is_enforced():
    """weight must equal base_component + external_component exactly, and
    the base share must be exactly zero (confidential_primary rows)."""
    result = _synthetic_result({"alpha": 1.0})
    row = _launch_row("alpha", 1.0)
    row["external_component"] = 0.8  # weight stays 1.0
    agree, notes = _compare(result, _launch_vector([row]))
    assert not agree and "does not compose" in notes[0]

    smuggled = _launch_vector([_launch_row("alpha", 0.5, base=0.5)])
    agree, notes = _compare(result, smuggled)
    assert not agree and "exactly zero" in notes[0]


def test_vector_burn_snapshot_grammar_is_enforced():
    """Repairs 5+8: the REAL burn grammar — burn_uid null, nonempty
    burn_hotkey, fixed 10.0 — and the legacy integer-uid shape rejected."""
    result = _synthetic_result({"alpha": 1.0})
    rows = [_launch_row("alpha", 1.0)]

    payload = _launch_vector(rows)
    payload.pop("burn_snapshot")  # no burn_snapshot at all
    agree, notes = _compare(result, payload)
    assert not agree and "burn_snapshot is missing or malformed" in notes[0]

    extra = _launch_vector(rows)
    extra["burn_snapshot"]["surprise"] = 1
    agree, notes = _compare(result, extra)
    assert not agree and "burn_snapshot is missing or malformed" in notes[0]

    # The legacy two-field {burn_uid, forced_burn_percentage} grammar the
    # old fabricated fixtures used carries no burn_hotkey: malformed.
    legacy = _launch_vector(rows)
    legacy["burn_snapshot"] = {"burn_uid": 0, "forced_burn_percentage": 10.0}
    agree, notes = _compare(result, legacy)
    assert not agree and "burn_snapshot is missing or malformed" in notes[0]

    # A historical pinned integer burn uid is REJECTED, never required:
    # validators resolve the burn hotkey against the live metagraph.
    for pinned_uid in (0, 204, True):
        pinned = _launch_vector(rows)
        pinned["burn_snapshot"]["burn_uid"] = pinned_uid
        agree, notes = _compare(result, pinned)
        assert not agree and "burn_uid must be null" in notes[0]

    for bad_hotkey in ("", None, 7):
        unhotkeyed = _launch_vector(rows)
        unhotkeyed["burn_snapshot"]["burn_hotkey"] = bad_hotkey
        agree, notes = _compare(result, unhotkeyed)
        assert not agree and "burn_hotkey must be the nonempty" in notes[0]

    stringly = _launch_vector(rows)
    stringly["burn_snapshot"]["forced_burn_percentage"] = "10"
    agree, notes = _compare(result, stringly)
    assert not agree and "not numeric" in notes[0]

    for bad_burn in (0.0, 25.0, 100.0, -5.0, float("nan")):
        drifted = _launch_vector(rows)
        drifted["burn_snapshot"]["forced_burn_percentage"] = bad_burn
        agree, notes = _compare(result, drifted)
        assert not agree and "violates the fixed" in notes[0]


def test_vector_mass_conservation_is_enforced():
    result = _synthetic_result({"alpha": 1.0})

    # Mass leakage: pre-burn rows must carry the whole 1.0 unit mass.
    leaked = _launch_vector([_launch_row("alpha", 0.7)])
    agree, notes = _compare(result, leaked)
    assert not agree and "conserve" in notes[0]


def test_vector_zero_supply_is_the_degraded_burn_shape():
    """No verified supply: the REAL vector still signs the fixed 10% burn
    with ZERO row mass (the validator burns 100% because no positive rows
    exist). Explicit revocation zero rows stay valid; riding mass fails."""
    empty = _synthetic_result({})

    agree, notes = _compare(empty, _launch_vector([], positive=False))
    assert agree and notes == []

    zero_rows = _launch_vector([_launch_row("revoked", 0.0)], positive=False)
    agree, notes = _compare(empty, zero_rows)
    assert agree and notes == []

    # The OLD fabricated zero-supply grammar (forced 100% burn) is not the
    # real contract: the publisher signs 10.0 for every epoch shape.
    legacy_full_burn = _launch_vector([], positive=False)
    legacy_full_burn["burn_snapshot"]["forced_burn_percentage"] = 100.0
    agree, notes = _compare(empty, legacy_full_burn)
    assert not agree and "violates the fixed" in notes[0]

    external_rider = _launch_vector([_launch_row("rider", 0.5)], positive=False)
    agree, notes = _compare(empty, external_rider)
    assert not agree and "carries positive mass" in notes[0]


def test_vector_uid_rows_are_validated():
    result = _synthetic_result({"alpha": 0.6, "bravo": 0.4})
    valid = _launch_vector([_launch_row("alpha", 0.6, uid=7), _launch_row("bravo", 0.4, uid=9)])
    agree, notes = _compare(result, valid)
    assert agree and notes == []

    duplicate_uid = _launch_vector(
        [_launch_row("alpha", 0.6, uid=7), _launch_row("bravo", 0.4, uid=7)]
    )
    agree, notes = _compare(result, duplicate_uid)
    assert not agree and "duplicates uid" in notes[0]

    for bad_uid in (True, -1, "7", 1.5, None):
        vector = _launch_vector([_launch_row("alpha", 0.6, uid=bad_uid), _launch_row("bravo", 0.4)])
        agree, notes = _compare(result, vector)
        assert not agree and "invalid uid" in notes[0]


def test_vector_comparison_refuses_unknown_mechanism_pairs():
    """The contract is versioned WITH the mechanism PAIR: a result under an
    unknown id or an unsupported revision never 'agrees'."""
    result = _synthetic_result({"alpha": 1.0}, mechanism_id="validated_supply_v99")
    agree, notes = _compare(result, _launch_vector([_launch_row("alpha", 1.0)]))
    assert not agree and "unsupported mechanism pair" in notes[0]

    revised = _synthetic_result({"alpha": 1.0})
    revised.mechanism_revision = 2
    agree, notes = _compare(revised, _launch_vector([_launch_row("alpha", 1.0)]))
    assert not agree and "unsupported mechanism pair" in notes[0]


# ---------------------------------------------------------------------------
# Signed policy blocks + epoch/report binding (repairs 3, 5, 8)
# ---------------------------------------------------------------------------


def test_vector_requires_the_signed_validated_supply_block():
    result = _synthetic_result({"alpha": 1.0})
    rows = [_launch_row("alpha", 1.0)]

    naked = _launch_vector(rows)
    naked.pop("policy_metadata")
    agree, notes = _compare(result, naked)
    assert not agree and "no policy_metadata" in notes[0]

    absent = _launch_vector(rows)
    absent["policy_metadata"].pop("validated_supply")
    agree, notes = _compare(result, absent)
    assert not agree and "validated_supply block is missing" in notes[0]

    extra = _launch_vector(rows)
    extra["policy_metadata"]["validated_supply"]["surprise"] = 1
    agree, notes = _compare(result, extra)
    assert not agree and "fields mismatch" in notes[0]

    versioned = _launch_vector(rows)
    versioned["policy_metadata"]["validated_supply"]["contract_version"] = "v2"
    agree, notes = _compare(result, versioned)
    assert not agree and "unsupported" in notes[0]

    for field, value in (
        ("intel_tdx_allocation", 0.80),
        ("verified_gpu_allocation", 0.20),
        ("intel_tdx_allocation", "0.90"),
    ):
        drifted = _launch_vector(rows)
        drifted["policy_metadata"]["validated_supply"][field] = value
        agree, notes = _compare(result, drifted)
        assert not agree and "0.90 Intel TDX + 0.10 Verified GPU" in notes[0]

    admitted = _launch_vector(rows)
    admitted["policy_metadata"]["validated_supply"]["verified_gpu_admitted"] = True
    agree, notes = _compare(result, admitted)
    assert not agree and "cannot admit the Verified GPU" in notes[0]

    mismatched = _launch_vector(rows)
    mismatched["policy_metadata"]["validated_supply"]["burn_hotkey"] = "other-destination"
    agree, notes = _compare(result, mismatched)
    assert not agree and "does not match the burn_snapshot" in notes[0]


def test_vector_requires_consistent_confidential_primary_mass():
    result = _synthetic_result({"alpha": 1.0})
    rows = [_launch_row("alpha", 1.0)]

    absent = _launch_vector(rows)
    absent["policy_metadata"].pop("confidential_primary")
    agree, notes = _compare(result, absent)
    assert not agree and "confidential_primary block is missing" in notes[0]

    # A degraded (mass 0) block under a positive recomputation is a lie.
    degraded = _launch_vector(rows)
    degraded["policy_metadata"]["confidential_primary"]["confidential_mass"] = 0.0
    agree, notes = _compare(result, degraded)
    assert not agree and "does not match the recomputed epoch supply" in notes[0]

    # A mass-1 block over a zero-supply epoch is equally a lie.
    empty = _synthetic_result({})
    inflated = _launch_vector([], positive=True)
    agree, notes = _compare(empty, inflated)
    assert not agree and "does not match the recomputed epoch supply" in notes[0]

    unconfirmed = _launch_vector(rows)
    unconfirmed["policy_metadata"]["confidential_primary"]["confirmed"] = False
    agree, notes = _compare(result, unconfirmed)
    assert not agree and "complete/fresh/confirmed" in notes[0]


def test_vector_burn_hotkey_reused_as_miner_is_rejected():
    """The burn destination must never earn: a vector paying the burn
    hotkey as a miner is rejected outright."""
    result = _synthetic_result({BURN_HOTKEY: 0.6, "bravo": 0.4})
    vector = _launch_vector([_launch_row(BURN_HOTKEY, 0.6), _launch_row("bravo", 0.4)])
    agree, notes = _compare(result, vector)
    assert not agree and "reused as a miner hotkey" in notes[0]


def test_vector_epoch_binding_gates_agreement():
    """Repair 3: agreement requires the SIGNED external_scores binding to
    the verified evidence epoch — historical, publisher-advanced, and
    coincidentally-equal vectors never agree; the exact match does."""
    result = _synthetic_result({"alpha": 0.6, "bravo": 0.4})
    rows = [_launch_row("alpha", 0.6), _launch_row("bravo", 0.4)]

    # Exact match: bound to source_epoch 11, complete, well-formed digest.
    agree, notes = _compare(result, _launch_vector(rows, source_epoch=11))
    assert agree and notes == []

    # Historical: the verifier audits epoch 11 but the vector is signed
    # against an OLDER ingest (epoch 10) with identical proportions.
    agree, notes = _compare(result, _launch_vector(rows, source_epoch=10))
    assert not agree and "never prove the same epoch" in notes[0]

    # Publisher-advanced: the publisher already ingested epoch 12; equal
    # proportions must not report agreement for epoch 11.
    agree, notes = _compare(result, _launch_vector(rows, source_epoch=12))
    assert not agree and "never prove the same epoch" in notes[0]

    # Coincidentally-equal: same proportions but NO signed binding at all.
    unbound = _launch_vector(rows)
    unbound["policy_metadata"].pop("external_scores")
    agree, notes = _compare(result, unbound)
    assert not agree and "external_scores block is missing" in notes[0]

    incomplete = _launch_vector(rows)
    incomplete["policy_metadata"]["external_scores"]["latest_complete"] = False
    agree, notes = _compare(result, incomplete)
    assert not agree and "latest_complete" in notes[0]

    disabled = _launch_vector(rows)
    disabled["policy_metadata"]["external_scores"]["enabled"] = False
    agree, notes = _compare(result, disabled)
    assert not agree and "enabled" in notes[0]

    blended = _launch_vector(rows)
    blended["policy_metadata"]["external_scores"]["mode"] = "blend"
    agree, notes = _compare(result, blended)
    assert not agree and "confidential_primary" in notes[0]

    unlabeled = _launch_vector(rows)
    unlabeled["policy_metadata"]["external_scores"]["latest_report_sha256"] = "nope"
    agree, notes = _compare(result, unlabeled)
    assert not agree and "latest_report_sha256" in notes[0]

    relabeled = _launch_vector(rows)
    relabeled["policy_metadata"]["score_source"] = "proportional"
    agree, notes = _compare(result, relabeled)
    assert not agree and "score_source" in notes[0]


def test_vector_binding_requires_the_manifest_ingest_digest():
    """The evidence manifest must carry wire_report_sha256; without it the
    vector cannot be bound to the verified epoch's ingest at all."""
    result = _synthetic_result({"alpha": 1.0})
    vector = _launch_vector([_launch_row("alpha", 1.0)])
    agree, notes = _compare(result, vector, wire_report_sha256=None)
    assert not agree and "no publisher ingest report digest" in notes[0]

    agree, notes = _compare(result, vector, wire_report_sha256="sha256:" + WIRE_INGEST_DIGEST)
    assert agree and notes == []


def test_vector_body_digest_binding_is_enforced_when_present():
    """The documented subnet pin-advance: when the signed block echoes the
    raw ingest body digest, it MUST equal the manifest's wire digest."""
    result = _synthetic_result({"alpha": 1.0})

    bound = _launch_vector([_launch_row("alpha", 1.0)])
    bound["policy_metadata"]["external_scores"]["latest_body_sha256"] = WIRE_INGEST_DIGEST
    agree, notes = _compare(result, bound)
    assert agree and notes == []

    swapped = _launch_vector([_launch_row("alpha", 1.0)])
    swapped["policy_metadata"]["external_scores"]["latest_body_sha256"] = "ab" * 32
    agree, notes = _compare(result, swapped)
    assert not agree and "DIFFERENT ingested report body" in notes[0]


# ---------------------------------------------------------------------------
# Mixed rejection gate (repair 1): FULL only when every ACTIVE candidate
# outcome is independently proven.
# ---------------------------------------------------------------------------


def _replayable_result(positive: tuple[str, ...], zero: tuple[str, ...] = ()):
    """A verified-shaped result whose positive miners can pass every
    pre-replay gate of replay_positive_miners (the subprocess replay itself
    is mocked in these tests)."""
    miners = [
        MinerProvenance(
            hotkey=hotkey,
            verified_work_units=Decimal("3.5"),
            receipt_id="receipt-sha256:" + "a" * 64,
            receipt_digest="sha256:" + "b" * 64,
            reason_codes=(),
            receipt_verified=True,
            measurement="ab" * 24,
            issued_at=ISSUED_TEXT,
            hardware_evidence_digest="sha256:" + "c" * 64,
            work_verified=True,
        )
        for hotkey in positive
    ] + [
        MinerProvenance(
            hotkey=hotkey,
            verified_work_units=Decimal(0),
            receipt_id=None,
            receipt_digest=None,
            reason_codes=(),
            receipt_verified=False,
        )
        for hotkey in zero
    ]
    hotkeys = sorted([*positive, *zero])
    share = 1.0 / len(positive) if positive else 0.0
    return ProvenanceResult(
        report_id="sha256:" + "0" * 64,
        previous_report_id=None,
        signing_key_id="score-test-1",
        policy_release=1,
        policy_digest="sha256:" + "1" * 64,
        verifier_digest=VERIFIER_DIGEST,
        mechanism_id="validated_supply_v1",
        source_epoch=11,
        generated_at=ISSUED_TEXT,
        valid_until="2026-07-11T12:30:00.000000Z",
        candidate_snapshot={
            "digest": "sha256:" + "5" * 64,
            "block": 100,
            "block_hash": "ab" * 32,
            "hotkeys": hotkeys,
        },
        miners=miners,
        recomputed_hotkey_weights={hotkey: share for hotkey in positive},
    )


def _replay_kwargs(result, outcomes):
    import hashlib

    from cathedral.challenge import expected_challenge_digest
    from cathedral.provenance import load_registry

    registry = load_registry(REGISTRY_BYTES, TRUSTED, now=NOW, max_age_seconds=172800)
    bindings = {}
    envelopes = {}
    for miner in result.miners:
        if not miner.receipt_verified:
            continue
        envelope = b"envelope-" + miner.hotkey.encode()
        envelopes[miner.hotkey] = envelope
        bindings[miner.hotkey] = {
            "envelope_digest": "sha256:" + hashlib.sha256(envelope).hexdigest(),
            "evidence_digest": "sha256:" + "9" * 64,
            "challenge_digest": expected_challenge_digest(
                block=100,
                block_hash="ab" * 32,
                network="local",
                netuid=1,
                source_epoch=11,
                miner_hotkey=miner.hotkey,
            ),
        }
    verifier = b"pinned-verifier-bytes"
    return {
        "registry": registry,
        "envelopes_by_hotkey": envelopes,
        "attestation_bindings": bindings,
        "verifier_binary": verifier,
        "verifier_blob_digest": "sha256:" + hashlib.sha256(verifier).hexdigest(),
        "verifier_command": ("/opt/cathedral/bin/verifier",),
        "verifier_artifacts": ("/opt/cathedral/bin/verifier",),
        "candidate_outcomes": outcomes,
        "epoch_generated_at": ISSUED_TEXT,
        "challenge_anchor": {
            "block": 100,
            "block_hash": "ab" * 32,
            "network": "local",
            "netuid": 1,
        },
        "independent_candidates": set(result.candidate_snapshot["hotkeys"]),
        "independent_block_hash": "0x" + "ab" * 32,
    }


def test_positive_only_epoch_reaches_full():
    """Every active candidate replayed positive: the epoch-level FULL claim
    holds and every positive miner is raw_verified."""
    from unittest import mock

    from cathedral.provenance import replay_positive_miners

    result = _replayable_result(("alpha-hotkey", "bravo-hotkey"))
    kwargs = _replay_kwargs(result, {"alpha-hotkey": "verified", "bravo-hotkey": "verified"})
    with mock.patch("cathedral.replay.replay_evidence") as replayed:
        outcome = replay_positive_miners(result, **kwargs)
    assert replayed.call_count == 2
    assert outcome.assurance_level == "full"
    assert outcome.not_proven_reasons == ()
    assert all(miner.raw_verified for miner in outcome.miners)


def test_mixed_positive_and_rejected_epoch_never_mints_full():
    """Repair 1's exact counterexample: one positive miner replays cleanly
    while another active candidate is rejected by Cathedral's signed
    assertion alone. The positive replay still runs, but the epoch stays
    receipts_only with the unproven rejection named."""
    from unittest import mock

    from cathedral.provenance import replay_positive_miners

    result = _replayable_result(("alpha-hotkey",), zero=("rejected-hotkey",))
    kwargs = _replay_kwargs(result, {"alpha-hotkey": "verified", "rejected-hotkey": "rejected"})
    with mock.patch("cathedral.replay.replay_evidence") as replayed:
        outcome = replay_positive_miners(result, **kwargs)
    assert replayed.call_count == 1  # the positive replay DID run
    assert outcome.assurance_level == "receipts_only"
    assert any("rejected-hotkey" in reason for reason in outcome.not_proven_reasons)
    assert any("not independently replayable" in r for r in outcome.not_proven_reasons)


def test_retired_candidates_do_not_block_full():
    """A retired candidate is out of the active set: positive-only among
    active candidates still reaches FULL."""
    from unittest import mock

    from cathedral.provenance import replay_positive_miners

    result = _replayable_result(("alpha-hotkey",), zero=("retired-hotkey",))
    kwargs = _replay_kwargs(result, {"alpha-hotkey": "verified", "retired-hotkey": "retired"})
    with mock.patch("cathedral.replay.replay_evidence"):
        outcome = replay_positive_miners(result, **kwargs)
    assert outcome.assurance_level == "full"


def test_malformed_or_inconsistent_outcomes_hard_fail():
    """Malformed/inconsistent outcome evidence is a hard ProvenanceError,
    never a silent downgrade: missing outcomes, unknown values, coverage
    drift, and outcome/receipt inconsistency in both directions."""
    from unittest import mock

    from cathedral.provenance import replay_positive_miners

    result = _replayable_result(("alpha-hotkey",), zero=("zero-hotkey",))

    kwargs = _replay_kwargs(result, None)
    with pytest.raises(ProvenanceError, match="exhaustive per-candidate outcomes"):
        replay_positive_miners(result, **kwargs)

    kwargs = _replay_kwargs(result, {"alpha-hotkey": "verified", "zero-hotkey": "vaporized"})
    with pytest.raises(ProvenanceError, match="unknown values"):
        replay_positive_miners(result, **kwargs)

    kwargs = _replay_kwargs(result, {"alpha-hotkey": "verified"})
    with pytest.raises(ProvenanceError, match="cover exactly"):
        replay_positive_miners(result, **kwargs)

    kwargs = _replay_kwargs(result, {"alpha-hotkey": "rejected", "zero-hotkey": "rejected"})
    with (
        mock.patch("cathedral.replay.replay_evidence"),
        pytest.raises(ProvenanceError, match="inconsistent evidence"),
    ):
        replay_positive_miners(result, **kwargs)

    kwargs = _replay_kwargs(result, {"alpha-hotkey": "verified", "zero-hotkey": "verified"})
    with (
        mock.patch("cathedral.replay.replay_evidence"),
        pytest.raises(ProvenanceError, match="inconsistent evidence"),
    ):
        replay_positive_miners(result, **kwargs)
