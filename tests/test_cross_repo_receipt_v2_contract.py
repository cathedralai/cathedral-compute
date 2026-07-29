"""Executable cross-repo compatibility for `cathedral_assurance_receipt_v2`.

These tests verify real receipts across three repositories with the private
packages actually installed, because a parser extension on its own does not
create compatibility. Each leg is proved or refused with a concrete reason:

  * a genuine Cathedral-issued receipt, extended with the exact CPU-TDX
    `platform` block and re-signed by its registry-anchored key, verifies in
    cathedral-distill's compute lane through the authenticated registry
    adapter (`cathedral.receipt_bridge.AnchoredReceiptKeyResolver`);
  * the same receipt reaches the validator seam's `verify_lane_receipt` as a
    PASS contribution;
  * the same receipt without `platform` still verifies here, and is refused by
    distill's compute lane on schema grounds (its `platform` is required), so
    the legacy behavior is explicit rather than assumed;
  * a distill-shaped receipt does NOT verify here, and the structural gaps are
    asserted directly, so "the reverse direction is a rewrite" is a checked
    fact rather than a claim about an exception;
  * unknown top-level keys, plain SEV, and TEE/class conflicts fail on both
    sides.

Skips cleanly when the private packages are absent. When they are present
these tests RUN; a skip is not evidence of compatibility.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from cathedral.policy_registry import canonical_json
from cathedral.receipt import ReceiptError, verify_receipt
from cathedral.receipt_bridge import AnchoredReceiptKeyResolver

from tests.test_receipt import (
    ISSUED,
    ISSUED_TEXT,
    RECEIPT_SEED_1,
    _issued_receipt,
    _receipt_key,
    _resign,
    _snapshot,
)

compute_receipt = pytest.importorskip(
    "cathedral_distill.compute_receipt",
    reason="cathedral-distill (private) is not installed in this environment",
)
integrated_feed = pytest.importorskip(
    "cathedral_distill.integrated_feed",
    reason="cathedral-distill (private) is not installed in this environment",
)
distill_testing = pytest.importorskip(
    "cathedral_distill.testing",
    reason="cathedral-distill (private) is not installed in this environment",
)
thin_integration = pytest.importorskip(
    "cathedral_thin.integration",
    reason="cathedral-validator (private) is not installed in this environment",
)
distill_receipt = pytest.importorskip("cathedral_distill.distill_receipt")

# distill's compute lane requires a full 64-hex TDX measurement, so the test
# registry publishes one instead of the shorter sample label used elsewhere.
CROSS_MEASUREMENT = "tdx-measurement-sha256:" + "5c" * 32
CPU_PLATFORM = {"class": "confidential_cpu", "cpu_tee": "intel_tdx"}
NOW = datetime(2026, 7, 17, 12, 30, tzinfo=UTC)
NOW_ISO = "2026-07-17T12:30:00.000000Z"
SOURCE_EPOCH = 11
LANE_CPU = "cathedral_confidential_tdx"


def _cross_repo_receipt(platform: object | None = CPU_PLATFORM):
    """A genuine Cathedral-issued receipt, optionally extended and re-signed."""
    snapshot, _policy, _claims, receipt = _issued_receipt(measurement=CROSS_MEASUREMENT)
    if platform is None:
        return snapshot, json.loads(receipt.receipt_bytes), receipt.receipt_bytes
    document = json.loads(receipt.receipt_bytes)
    document["platform"] = platform
    receipt_bytes = _resign(document)
    return snapshot, document, receipt_bytes


def _resolver(snapshot) -> AnchoredReceiptKeyResolver:
    return AnchoredReceiptKeyResolver(snapshot)


def _distill_verify(document, snapshot, **overrides):
    kwargs = {
        "now_iso": NOW_ISO,
        "source_epoch": SOURCE_EPOCH,
    }
    kwargs.update(overrides)
    return compute_receipt.verify_receipt(document, _resolver(snapshot), **kwargs)


# --- leg (a) / audit minimum test 4 ---------------------------------------- #


def test_extended_cathedral_receipt_verifies_in_the_distill_compute_lane():
    snapshot, document, receipt_bytes = _cross_repo_receipt()
    # It is a genuine receipt here first.
    assert verify_receipt(receipt_bytes, snapshot).document["platform"] == CPU_PLATFORM
    # And it verifies in distill through the authenticated registry adapter.
    verified = _distill_verify(document, snapshot)
    assert compute_receipt.platform_class(verified) == compute_receipt.PLATFORM_CPU
    assert compute_receipt.cpu_tee(verified) == compute_receipt.CPU_TEE_TDX
    assert compute_receipt.lane_contribution(verified) == {
        "miner_hotkey": "public-hotkey",
        "receipt_id": document["receipt_id"],
        "work_units": "3.5",
    }


def test_distill_refuses_the_extended_receipt_when_the_key_is_not_anchored():
    # The adapter is the trust boundary, not a convenience: a registry that
    # does not carry the receipt's key resolves nothing, so the receipt is
    # refused even though its body is well formed.
    snapshot, document, _bytes = _cross_repo_receipt()
    other = _snapshot(
        receipt_keys=[_receipt_key("receipt-other-1", bytes(range(96, 128)))],
        measurement=CROSS_MEASUREMENT,
    )
    with pytest.raises(compute_receipt.ComputeReceiptError, match="signing key"):
        compute_receipt.verify_receipt(
            document,
            AnchoredReceiptKeyResolver(other),
            now_iso=NOW_ISO,
            source_epoch=SOURCE_EPOCH,
        )


def test_distill_refuses_the_extended_receipt_when_the_key_is_revoked():
    snapshot, document, _bytes = _cross_repo_receipt()
    revoked = _snapshot(
        receipt_keys=[
            _receipt_key(
                "receipt-test-1",
                RECEIPT_SEED_1,
                status="revoked",
                revoked_at="2026-07-17T02:00:00Z",
                changed="2026-07-17T02:00:00Z",
            )
        ],
        measurement=CROSS_MEASUREMENT,
    )
    with pytest.raises(compute_receipt.ComputeReceiptError, match="signing key"):
        compute_receipt.verify_receipt(
            document,
            AnchoredReceiptKeyResolver(revoked),
            now_iso=NOW_ISO,
            source_epoch=SOURCE_EPOCH,
        )


def test_the_adapter_refuses_an_unauthenticated_registry_snapshot():
    from dataclasses import replace as dataclass_replace

    snapshot = _snapshot(measurement=CROSS_MEASUREMENT)
    # A copy loses the verified-signature marker, which is exactly the case the
    # adapter must refuse rather than resolve on structure alone.
    unverified = dataclass_replace(snapshot)
    assert not unverified.signature_verified
    with pytest.raises(ReceiptError, match="signature is not verified"):
        AnchoredReceiptKeyResolver(unverified)


# --- leg (b) / audit minimum test 8: explicit legacy behavior --------------- #


def test_the_same_receipt_without_platform_still_verifies_here():
    snapshot, _document, receipt_bytes = _cross_repo_receipt(platform=None)
    verified = verify_receipt(receipt_bytes, snapshot)
    assert "platform" not in verified.document
    assert verified.receipt_bytes == receipt_bytes


def test_a_platform_less_cathedral_receipt_is_refused_by_distill_on_schema_grounds():
    # The legacy shape this runtime actually emits today. distill requires
    # `platform`, so the refusal is a missing-key schema refusal, not a key or
    # signature failure. Stated here so nobody reads leg (a) as "any Cathedral
    # receipt is admissible".
    snapshot, document, _bytes = _cross_repo_receipt(platform=None)
    with pytest.raises(compute_receipt.ComputeReceiptError, match="platform"):
        _distill_verify(document, snapshot)


# --- leg (c) / audit minimum test 6 ---------------------------------------- #


def test_platform_plus_an_unknown_top_level_key_is_rejected_on_both_sides():
    snapshot, document, receipt_bytes = _cross_repo_receipt()
    document["evaluation"] = {"schema": distill_receipt.EVALUATION_SCHEMA}
    extended = _resign(document)
    with pytest.raises(ReceiptError, match="missing, unknown, or unsupported"):
        verify_receipt(extended, snapshot)
    with pytest.raises(compute_receipt.ComputeReceiptError, match="unknown keys"):
        _distill_verify(document, snapshot)


@pytest.mark.parametrize("cpu_tee", ["amd_sev", "sev", "intel_sgx"])
def test_a_non_attestable_cpu_tee_is_rejected_on_both_sides(cpu_tee):
    # Plain "amd_sev" is what the live G4 GCP profile emits and has no
    # attestation interface at all. Neither repo may admit it.
    snapshot, document, receipt_bytes = _cross_repo_receipt(
        platform={"class": "confidential_cpu", "cpu_tee": cpu_tee}
    )
    with pytest.raises(ReceiptError, match="not in the attestable set"):
        verify_receipt(receipt_bytes, snapshot)
    with pytest.raises(compute_receipt.ComputeReceiptError, match="cpu_tee"):
        _distill_verify(document, snapshot)


def test_a_class_and_tee_conflict_is_rejected_on_both_sides():
    # confidential_gpu without the GPU evidence block: refused here because the
    # composite class is not accepted at all, and refused in distill because
    # the class demands evidence that is absent.
    snapshot, document, receipt_bytes = _cross_repo_receipt(
        platform={"class": "confidential_gpu", "cpu_tee": "intel_tdx"}
    )
    with pytest.raises(ReceiptError, match="class is unsupported"):
        verify_receipt(receipt_bytes, snapshot)
    with pytest.raises(compute_receipt.ComputeReceiptError, match="platform"):
        _distill_verify(document, snapshot)


# --- leg (d): the reverse direction is still a structural rewrite ----------- #


def test_a_distill_shaped_receipt_does_not_verify_here():
    fixtures = distill_testing.IntegrationFixtures()
    distill_shaped = fixtures.cpu_receipt()
    snapshot = _snapshot(measurement=CROSS_MEASUREMENT)
    with pytest.raises(ReceiptError):
        verify_receipt(canonical_json(distill_shaped), snapshot)


def test_the_reverse_direction_gaps_are_structural_not_just_registry_mismatch():
    # Pin WHY the reverse direction is a rewrite, so the previous test cannot
    # be satisfied by a mere registry-digest mismatch. distill's compute
    # receipt omits this repo's entire v2 worker-lifecycle binding and carries
    # status-only assurance claims with none of the audit fields v2 requires.
    from cathedral.receipt import _CLAIM_KEYS, _LIFECYCLE_KEYS_V2

    distill_shaped = distill_testing.IntegrationFixtures().cpu_receipt()
    assert _LIFECYCLE_KEYS_V2 - frozenset(distill_shaped["lifecycle"]) == frozenset(
        {
            "worker_state",
            "worker_generation",
            "worker_revision",
            "worker_event_id",
            "worker_reason",
        }
    )
    for claim in distill_shaped["assurance"]["claims"].values():
        assert frozenset(claim) != _CLAIM_KEYS
        assert _CLAIM_KEYS - frozenset(claim) == frozenset(
            {"evidence_digest", "policy_digest", "verified_at", "reason"}
        )


# --- leg (e) / audit minimum test 5: the validator seam -------------------- #


class _CompositeResolver:
    """Resolve receipt keys from Cathedral's signed registry, config keys from
    the distill fixture registry. The validator seam takes ONE registry object
    for both, and each id keeps its own authenticated source."""

    def __init__(self, receipt_resolver, config_registry) -> None:
        self._receipt_resolver = receipt_resolver
        self._config_registry = config_registry

    def resolve(self, key_id, *, at):
        try:
            return self._receipt_resolver.resolve(key_id, at=at)
        except ReceiptError:
            return self._config_registry.resolve(key_id, at=at)


def _validator_preview(document, snapshot, *, lane_receipts=None):
    fixtures = distill_testing.IntegrationFixtures(
        source_epoch=SOURCE_EPOCH,
        config_generated_at="2026-07-17T12:00:00Z",
        config_valid_from="2026-07-17T00:00:00Z",
        config_valid_until="2026-07-24T00:00:00Z",
    )
    receipts = (
        lane_receipts
        if lane_receipts is not None
        else [
            thin_integration.LaneReceipt(
                integrated_feed.KIND_COMPUTE_CPU, LANE_CPU, document
            )
        ]
    )
    return thin_integration.preview_integrated_vector(
        burn_config=fixtures.burn_config(),
        allocation_config=fixtures.allocation_config(
            [{"lane": LANE_CPU, "allocation": "0.90", "enabled": True}]
        ),
        key_registry=_CompositeResolver(_resolver(snapshot), fixtures.registry),
        receipts=receipts,
        network="finney",
        netuid=39,
        source_epoch=SOURCE_EPOCH,
        now=NOW,
        now_iso=NOW_ISO,
    )


def test_the_extended_receipt_reaches_the_validator_preview_as_pass():
    snapshot, document, _bytes = _cross_repo_receipt()
    out = _validator_preview(document, snapshot)
    audit = out["audit"]
    assert audit["verdicts"]["pass"] == 1, audit
    assert audit["verdicts"]["fail"] == 0
    assert audit["verdicts"]["not_proven"] == 0
    assert out["feed"]["weights"], out["feed"]
    lane = next(item for item in audit["lanes"] if item["lane"] == LANE_CPU)
    assert lane["contributing"] is True


def test_a_platform_less_receipt_is_not_credited_by_the_validator_preview():
    # The same seam, the legacy receipt shape: no contribution, and the lane
    # allocation goes to burn rather than crediting unverified work.
    snapshot, document, _bytes = _cross_repo_receipt(platform=None)
    out = _validator_preview(document, snapshot)
    audit = out["audit"]
    assert audit["verdicts"]["pass"] == 0, audit
    lane = next(item for item in audit["lanes"] if item["lane"] == LANE_CPU)
    assert lane["contributing"] is False
