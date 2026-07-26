"""Cross-repo validated_supply_v2 signed-vector contract (launch repairs 5+8).

The fixture below reproduces, field by field, the vector the REAL subnet
publisher signs in validated_supply mode (read from the read-only worktree:
``scaffold/publisher/weights.py`` ``build_signed_vector`` +
``validated_supply_metadata``, consumed by ``scaffold/validator_thin.py``
``_validated_supply_meta``/``_resolve_burn_hotkey``):

  * ``burn_snapshot = {burn_uid: null, burn_hotkey: <nonempty>,
    forced_burn_percentage: 10.0}`` — the validator resolves the burn HOTKEY
    against the current metagraph and rejects pinned historical UIDs;
  * ``policy_metadata.validated_supply = {contract_version: "v2",
    intel_tdx_allocation: 0.90, fixed_burn_allocation: 0.10,
    burn_hotkey}`` (exact field set);
  * ``policy_metadata.confidential_primary`` asserting the epoch's
    confidential mass, and ``policy_metadata.external_scores`` carrying the
    signed ingest binding (``latest_epoch``, ``latest_report_sha256``,
    ``latest_complete``);
  * PRE-burn weight rows: ``base_component == 0``, ``weight ==
    external_component``, positive supply summing to 1.0 (the validator
    applies the 10% burn after UID mapping).

The comparator must AGREE with this truthful launch vector and REJECT the
legacy/fabricated shapes older fixtures used (integer ``burn_uid: 0``,
post-burn 0.9 rows, 100%-burn zero-supply grammar, missing policy blocks).
"""

from __future__ import annotations

import base64
import copy
import json
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.cli import _verify_wire_vector
from cathedral.provenance import ProvenanceResult, compare_with_vector

NETWORK = "finney"
NETUID = 39
SOURCE_EPOCH = 11
BURN_HOTKEY = "5FburnDestinationColdStorage11111111111111111111"
MINERS = {
    "5FAlphaMinerHotkey1111111111111111111111111111": 0.75,
    "5FBravoMinerHotkey2222222222222222222222222222": 0.25,
}
WIRE_INGEST_DIGEST = "3e" * 32
SIGNING_SEED = bytes(range(64, 96))
PUBLIC_HEX = (
    Ed25519PrivateKey.from_private_bytes(SIGNING_SEED)
    .public_key()
    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    .hex()
)


def _real_subnet_vector(*, positive: bool = True) -> dict:
    """Byte-shape of scaffold/publisher/weights.py build_signed_vector under
    CATHEDRAL_VALIDATED_SUPPLY_ENABLED (confidential_primary mode)."""
    weights = (
        [
            {
                "miner_hotkey": hotkey,
                "weight": share,
                "base_component": 0.0,
                "external_component": share,
            }
            for hotkey, share in sorted(MINERS.items())
        ]
        if positive
        else []
    )
    return {
        "vector_id": "3e6c1f7a-real-launch-vector",
        "policy_version": 1_753_000_000_000,
        "network": NETWORK,
        "netuid": NETUID,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + "000Z",
        "expires_at": (datetime.now(UTC) + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S.")
        + "000Z",
        "burn_snapshot": {
            "burn_uid": None,
            "burn_hotkey": BURN_HOTKEY,
            "forced_burn_percentage": 10.0,
        },
        "policy_hash": "sha256:" + "ab" * 32,
        "key_id": "cathedral-weight-policy",
        "policy_reason": "v4_flat_recent_24h_window",
        "policy_metadata": {
            "miner_count": len(weights),
            "composer": "scaffold.weights",
            "score_source": "confidential_primary:cathedral_confidential_tdx",
            "validated_supply": {
                "contract_version": "v2",
                "intel_tdx_allocation": 0.90,
                "fixed_burn_allocation": 0.10,
                "burn_hotkey": BURN_HOTKEY,
            },
            "confidential_primary": {
                "contract_version": "v1",
                "mode": "confidential_primary",
                "source": "cathedral_confidential_tdx",
                "base_mass": 0.0,
                "confidential_mass": 1.0 if positive else 0.0,
                "complete": True,
                "fresh": True,
                "confirmed": True,
                "require_registered": True,
                "external_miner_count": len(weights),
                "degradation_reason": None,
            },
            "external_scores": {
                "enabled": True,
                "source": "cathedral_confidential_tdx",
                "mode": "confidential_primary",
                "window_secs": 3600.0,
                "latest_epoch": SOURCE_EPOCH,
                "latest_complete": True,
                "latest_fresh": True,
                "latest_report_sha256": "c1" * 32,
                "latest_body_sha256": WIRE_INGEST_DIGEST,
                "active_score_count": len(weights),
            },
        },
        "weights": weights,
    }


def _signed(payload: dict) -> dict:
    body = {key: value for key, value in payload.items() if key != "signature"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    signed = dict(body)
    signed["signature"] = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(SIGNING_SEED).sign(canonical)
    ).decode("ascii")
    return signed


def _result(weights: dict[str, float]) -> ProvenanceResult:
    return ProvenanceResult(
        report_id="sha256:" + "0" * 64,
        previous_report_id=None,
        signing_key_id="score-test-1",
        policy_release=1,
        policy_digest="sha256:" + "1" * 64,
        verifier_digest="sha256:" + "d" * 64,
        mechanism_id="validated_supply_v2",
        source_epoch=SOURCE_EPOCH,
        generated_at="2026-07-11T12:00:00.000000Z",
        valid_until="2026-07-11T12:30:00.000000Z",
        recomputed_hotkey_weights=dict(weights),
    )


def _compare(result, vector, **overrides):
    kwargs = {"wire_report_sha256": WIRE_INGEST_DIGEST}
    kwargs.update(overrides)
    return compare_with_vector(result, vector, **kwargs)


def test_real_launch_vector_verifies_and_agrees():
    """The truthful signed launch vector passes the exact wire signature
    check the thin validator applies AND the full comparator contract."""
    vector = _signed(_real_subnet_vector())
    _verify_wire_vector(
        vector,
        public_key_hex=PUBLIC_HEX,
        expected_key_id="cathedral-weight-policy",
        network=NETWORK,
        netuid=NETUID,
    )
    agree, notes = _compare(_result(MINERS), vector)
    assert agree and notes == []


def test_real_zero_supply_vector_agrees_with_empty_recomputation():
    """The degraded shape: zero rows, confidential_mass 0, and STILL the
    signed 10% burn (the validator burns 100% because no positive rows
    exist) — truthful agreement with an empty recomputation."""
    vector = _signed(_real_subnet_vector(positive=False))
    agree, notes = _compare(_result({}), vector)
    assert agree and notes == []


def test_legacy_and_fabricated_shapes_are_rejected():
    """Repair 8: every fixture shape the old tests used is refused against
    the real contract."""
    result = _result(MINERS)

    # Legacy two-field burn snapshot with a pinned integer burn uid.
    legacy_uid = _real_subnet_vector()
    legacy_uid["burn_snapshot"] = {"burn_uid": 0, "forced_burn_percentage": 10.0}
    agree, notes = _compare(result, _signed(legacy_uid))
    assert not agree and "burn_snapshot is missing or malformed" in notes[0]

    # Real grammar but a pinned historical uid alongside the hotkey.
    pinned_uid = _real_subnet_vector()
    pinned_uid["burn_snapshot"]["burn_uid"] = 204
    agree, notes = _compare(result, _signed(pinned_uid))
    assert not agree and "burn_uid must be null" in notes[0]

    # Fabricated post-burn rows (0.9 total with the burn taken in-row).
    post_burn = _real_subnet_vector()
    for row in post_burn["weights"]:
        row["weight"] = round(row["weight"] * 0.9, 9)
        row["external_component"] = row["weight"]
    agree, notes = _compare(result, _signed(post_burn))
    assert not agree and "conserve" in notes[0]

    # Fabricated zero-supply grammar: forced 100% burn is not the contract.
    full_burn = _real_subnet_vector(positive=False)
    full_burn["burn_snapshot"]["forced_burn_percentage"] = 100.0
    agree, notes = _compare(_result({}), _signed(full_burn))
    assert not agree and "violates the fixed" in notes[0]

    # A vector with no signed policy blocks at all.
    unpolicied = _real_subnet_vector()
    unpolicied.pop("policy_metadata")
    agree, notes = _compare(result, _signed(unpolicied))
    assert not agree and "no policy_metadata" in notes[0]


def test_malformed_validated_supply_blocks_are_rejected():
    result = _result(MINERS)
    for mutate, needle in (
        (lambda v: v["policy_metadata"].pop("validated_supply"), "block is missing"),
        (
            lambda v: v["policy_metadata"]["validated_supply"].pop("burn_hotkey"),
            "fields mismatch",
        ),
        (
            lambda v: v["policy_metadata"]["validated_supply"].update({"contract_version": "v1"}),
            "unsupported",
        ),
        (
            lambda v: v["policy_metadata"]["validated_supply"].update(
                {"intel_tdx_allocation": 0.85}
            ),
            "0.90 Intel TDX",
        ),
        (
            lambda v: v["policy_metadata"]["validated_supply"].update(
                {"burn_hotkey": "5FSomeOtherDestination"}
            ),
            "does not match the burn_snapshot",
        ),
    ):
        vector = _real_subnet_vector()
        mutate(vector)
        agree, notes = _compare(result, _signed(vector))
        assert not agree and needle in notes[0], (needle, notes)


def test_burn_hotkey_reused_as_miner_is_rejected():
    """The burn destination must never earn: even a proportionally perfect
    vector paying the burn hotkey as a miner is refused (the subnet
    validator would reject the UID collision; the comparator rejects the
    hotkey reuse without chain access)."""
    reused_shares = {BURN_HOTKEY: 0.75, next(iter(sorted(MINERS))): 0.25}
    vector = _real_subnet_vector()
    vector["weights"] = [
        {
            "miner_hotkey": hotkey,
            "weight": share,
            "base_component": 0.0,
            "external_component": share,
        }
        for hotkey, share in sorted(reused_shares.items())
    ]
    agree, notes = _compare(_result(reused_shares), _signed(vector))
    assert not agree and "reused as a miner hotkey" in notes[0]


def test_epoch_binding_rejects_historical_and_advanced_vectors():
    """Repair 3 at the cross-repo fixture level: identical proportions with
    a different SIGNED ingest epoch never agree; the exact epoch and exact
    authenticated body digest are mandatory."""
    result = _result(MINERS)

    for other_epoch in (SOURCE_EPOCH - 1, SOURCE_EPOCH + 1):
        vector = _real_subnet_vector()
        vector["policy_metadata"]["external_scores"]["latest_epoch"] = other_epoch
        agree, notes = _compare(result, _signed(vector))
        assert not agree and "never prove the same epoch" in notes[0]

    unbound = _real_subnet_vector()
    unbound["policy_metadata"].pop("external_scores")
    agree, notes = _compare(result, _signed(unbound))
    assert not agree and "external_scores block is missing" in notes[0]

    # Manifest without the ingest digest: nothing to bind against.
    agree, notes = _compare(result, _signed(_real_subnet_vector()), wire_report_sha256=None)
    assert not agree and "no publisher ingest report digest" in notes[0]

    missing_body = _real_subnet_vector()
    missing_body["policy_metadata"]["external_scores"].pop("latest_body_sha256")
    agree, notes = _compare(result, _signed(missing_body))
    assert not agree and "latest_body_sha256 is missing" in notes[0]

    # The subnet's signed raw authenticated-body digest must match.
    echoed = _real_subnet_vector()
    agree, notes = _compare(result, _signed(echoed))
    assert agree and notes == []

    forged = copy.deepcopy(echoed)
    forged["policy_metadata"]["external_scores"]["latest_body_sha256"] = "ab" * 32
    agree, notes = _compare(result, _signed(forged))
    assert not agree and "DIFFERENT ingested report body" in notes[0]
